"""TiTaN — single-service multi-protocol proxy panel.

FastAPI app: admin UI + REST API + subscription endpoints. Xray-core does the
actual proxying; nginx fronts both. SQLite for storage.
"""
import asyncio
import base64
import gzip
import io
import json
import os
import re
import secrets
import time
import uuid as uuid_lib
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import quote

import httpx
import psutil
import qrcode
from PIL import Image as PILImage
from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import APP_NAME, APP_VERSION, config, db, security, state, xray
from . import tasks as bg
from .colo_map import describe_colo
from .geo import detect_location, flag_from_code
from .links import build_links, subscription_text

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

DOH_PRIMARY = "https://1.1.1.1/dns-query"
DOH_SECONDARY = "https://8.8.8.8/dns-query"
doh_client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)


# ------------------------------------------------------------------ lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    try:
        xray.write_xray_config()
        xray.restart_xray()
    except Exception:  # noqa: BLE001
        pass
    bg.start_background_tasks(app)
    yield
    for t in app.state.titan_tasks:
        t.cancel()
    await doh_client.aclose()


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


# ------------------------------------------------------------------ helpers
def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _public_host(request: Request) -> str:
    settings = db.get_settings()
    override = settings.get("public_domain") or ""
    if override:
        return override.strip().split(":")[0].split("/")[0]
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.hostname
        or ""
    )
    if host.startswith("["):
        return host.split("]")[0].lstrip("[")
    return host.split(":")[0]


def _link_port(settings: dict) -> int:
    """The port written into client links. 443 behind TLS by default; the admin
    can override it from Settings → Network (e.g. a non-443 exposed port)."""
    try:
        port = int(settings.get("public_port") or 443)
    except (TypeError, ValueError):
        port = 443
    return port if 1 <= port <= 65535 else 443


def _set_session(response: Response, username: str, remember: bool = False):
    token = security.make_token(db.get_secret_key(), {"u": username})
    # "remember me" extends the session; otherwise it stays short-lived.
    max_age = config.SESSION_MAX_AGE * 4 if remember else config.SESSION_MAX_AGE
    response.set_cookie(
        config.SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=False,  # TLS terminated by the platform/nginx
        path="/",
    )


def _current_username(request: Request) -> Optional[str]:
    admin = db.get_admin()
    if not admin:
        return None
    token = request.cookies.get(config.SESSION_COOKIE)
    if not token:
        return None
    data = security.read_token(db.get_secret_key(), token, config.SESSION_MAX_AGE)
    if not data or data.get("u") != admin["username"]:
        return None
    return admin["username"]


def _require_auth(request: Request) -> str:
    user = _current_username(request)
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user


def _user_status(u: dict) -> dict:
    now = time.time()
    used = (u.get("used_up") or 0) + (u.get("used_down") or 0)
    quota = u.get("quota_bytes") or 0
    quota_exceeded = quota > 0 and used >= quota
    expired = bool(u.get("expire_at")) and now >= u["expire_at"]
    enabled = bool(u["enabled"]) and not quota_exceeded and not expired
    return {
        "used": used,
        "quota_bytes": quota,
        "quota_exceeded": quota_exceeded,
        "expired": expired,
        "live_enabled": enabled,
        "active_connections": state.active_count(u["uid"]),
        "days_left": (
            max(0, int((u["expire_at"] - now) // 86400)) if u.get("expire_at") else None
        ),
    }


def _serialize_user(u: dict, with_links: bool = False, request: Request | None = None) -> dict:
    out = {k: v for k, v in u.items() if k != "password_hash"}
    if "allowed_ips" in out and isinstance(out["allowed_ips"], str):
        try:
            out["allowed_ips"] = json.loads(out["allowed_ips"])
        except (json.JSONDecodeError, TypeError):
            out["allowed_ips"] = []
    out["status"] = _user_status(u)
    out["used_gb"] = round(out["status"]["used"] / (1024 ** 3), 3)
    out["quota_gb"] = round((u.get("quota_bytes") or 0) / (1024 ** 3), 3)
    out["avatar_url"] = _resolve_avatar(u.get("avatar") or "")["url"]
    if with_links and request is not None:
        settings = db.get_settings()
        links = build_links(_public_host(request), _link_port(settings), u, settings)
        host = _public_host(request)
        out["links"] = links["all"]
        out["main_link"] = links["main"]
        out["sub_url"] = f"https://{host}/sub/{u['uid']}"
        out["status_url"] = f"https://{host}/status/{u['uid']}"
        out["qr_data"] = links["main"]
    return out


def _flag_for(code: str) -> str:
    """Regional-indicator emoji from a 2-letter ISO country code."""
    return flag_from_code(code)


# ------------------------------------------------------------------ node status service
_node_status_cache: dict = {}


async def _tcp_latency(host: str, port: int, timeout: float = 2.0) -> int | None:
    try:
        t0 = time.time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        lat = (time.time() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return round(lat)
    except Exception:  # noqa: BLE001
        return None


async def _node_status(node: dict) -> dict:
    """Compute live status for a node. Cached for 30s."""
    now = time.time()
    cached = _node_status_cache.get(node["id"])
    if cached and now - cached["ts"] < 30:
        return cached["data"]

    data = {"online": False, "latency_ms": None, "cpu": None, "ram": None, "disk": None}
    if node.get("is_local"):
        data["online"] = True
        data["cpu"] = psutil.cpu_percent(interval=0.1)
        data["ram"] = psutil.virtual_memory().percent
        data["disk"] = psutil.disk_usage(config.DATA_DIR).percent
        data["latency_ms"] = await _tcp_latency("1.1.1.1", 443)
    else:
        addr = (node.get("address") or "").strip()
        if addr:
            url = addr if addr.startswith(("http://", "https://")) else "http://" + addr
            try:
                async with httpx.AsyncClient(timeout=3, follow_redirects=True) as cl:
                    t0 = time.time()
                    r = await cl.get(url.rstrip("/") + "/health")
                    lat = (time.time() - t0) * 1000
                data["online"] = r.status_code in (200, 401, 404)
                data["latency_ms"] = round(lat)
            except Exception:  # noqa: BLE001
                data["online"] = False
    _node_status_cache[node["id"]] = {"ts": now, "data": data}
    return data


def _serialize_node(node: dict, status: dict) -> dict:
    out = dict(node)
    out["status"] = status
    out["version"] = APP_VERSION if node.get("is_local") else None
    return out


# ------------------------------------------------------------------ pages
@app.get("/", response_class=HTMLResponse)
async def page_root(request: Request):
    # Default admin ("TiTaN") is always present — no setup flow.
    if _current_username(request):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/setup", response_class=HTMLResponse)
async def page_setup(request: Request):
    # Registration is disabled — the default admin ("TiTaN") is created
    # automatically on first run. Route everything to the login page.
    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
async def page_login(request: Request):
    if _current_username(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse(request, "login.html", {"app_version": APP_VERSION})


@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    if not _current_username(request):
        return RedirectResponse("/login")
    return templates.TemplateResponse(
        request, "dashboard.html", {"app_version": APP_VERSION, "panel": APP_NAME}
    )


@app.get("/status/{uid}", response_class=HTMLResponse)
async def page_status(request: Request, uid: str):
    user = db.get_user(uid)
    if not user:
        return HTMLResponse("<h1>404</h1><p>Not found.</p>", status_code=404)
    return templates.TemplateResponse(
        request, "status.html",
        {"uid": uid, "app_version": APP_VERSION, "panel": APP_NAME},
    )


# ------------------------------------------------------------------ auth api
@app.get("/api/setup-status")
async def api_setup_status():
    # The default admin is auto-created on first run, so setup is never needed.
    return {"needs_setup": False}


@app.post("/api/setup")
async def api_setup(request: Request):
    payload = await request.json()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if db.get_admin():
        raise HTTPException(400, "already-configured")
    if not re.match(r"^[a-zA-Z0-9_]{3,32}$", username):
        raise HTTPException(400, "invalid-username")
    if len(password) < 6:
        raise HTTPException(400, "weak-password")
    hp = security.hash_password(password)
    db.set_admin(username, hp["hash"], hp["salt"])
    db.add_event("info", "setup", f"admin created: {username}", ip=_client_ip(request))
    resp = JSONResponse({"ok": True})
    _set_session(resp, username)
    return resp


@app.post("/api/login")
async def api_login(request: Request):
    payload = await request.json()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    ip = _client_ip(request)

    # simple brute-force guard
    key = f"login_attempts:{ip}"
    raw = db.get_meta(key)
    locked_until = 0.0
    count = 0
    if raw:
        try:
            blob = json.loads(raw)
            locked_until = blob.get("locked_until", 0)
            count = blob.get("count", 0)
        except (json.JSONDecodeError, TypeError):
            pass
    if locked_until > time.time():
        raise HTTPException(429, f"locked:{int(locked_until - time.time())}")

    admin = db.get_admin()
    default_auth = db.get_meta("auth_is_default") == "1"
    if default_auth and admin:
        # First-run state: default username "TiTaN", no password required.
        ok = username == admin["username"]
    else:
        ok = bool(admin) and admin["username"] == username and security.verify_password(
            password, admin["salt"], admin["password_hash"]
        )

    if ok:
        db.set_meta(key, json.dumps({"count": 0, "locked_until": 0}))
        db.add_event("info", "login", "admin login", ip=ip)
        resp = JSONResponse({"ok": True})
        _set_session(resp, username, remember=bool(payload.get("remember")))
        return resp

    count += 1
    blob = {"count": count, "locked_until": 0}
    if count >= config.LOGIN_MAX_ATTEMPTS:
        blob = {"count": 0, "locked_until": time.time() + config.LOGIN_LOCK_SECONDS}
    db.set_meta(key, json.dumps(blob))
    db.add_event("warn", "login-failed", f"username={username}", ip=ip)
    raise HTTPException(401, "invalid-credentials")


@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(config.SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    user = _current_username(request)
    settings = db.get_settings()
    return {
        "logged_in": bool(user),
        "username": user,
        "settings": settings,
        "avatar": _resolve_avatar(settings.get("admin_avatar")),
        "app_version": APP_VERSION,
        "default_auth": db.get_meta("auth_is_default") == "1",
    }


@app.post("/api/change-password")
async def api_change_password(request: Request, _: str = Depends(_require_auth)):
    payload = await request.json()
    old = payload.get("old_password") or ""
    new = payload.get("new_password") or ""
    admin = db.get_admin()
    default_auth = db.get_meta("auth_is_default") == "1"
    # In first-run mode there is no old password yet, so skip verification.
    if not default_auth:
        if not admin or not security.verify_password(old, admin["salt"], admin["password_hash"]):
            raise HTTPException(401, "wrong-old-password")
    if len(new) < 6:
        raise HTTPException(400, "weak-password")
    hp = security.hash_password(new)
    db.set_admin(admin["username"], hp["hash"], hp["salt"])
    # A real password is now set → disable the "no password" first-run mode.
    db.set_meta("auth_is_default", "0")
    db.add_event("warn", "password-change", "admin password changed", ip=_client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ settings
@app.get("/api/settings")
async def api_get_settings(request: Request, _: str = Depends(_require_auth)):
    return db.get_settings()


@app.post("/api/settings")
async def api_set_settings(request: Request, _: str = Depends(_require_auth)):
    payload = await request.json()
    allowed = set(config.DEFAULT_SETTINGS.keys())
    updates = {}
    for k, v in payload.items():
        if k not in allowed:
            continue
        if k == "default_fingerprint" and v not in config.VALID_FINGERPRINTS:
            continue
        if k == "default_alpn" and v not in config.VALID_ALPNS:
            continue
        updates[k] = v
    db.set_settings(updates)
    # routing-affecting flags require an Xray reload
    if any(k in updates for k in ("block_ads", "block_iran_sites", "restrict_ips")):
        try:
            xray.write_xray_config()
            xray.restart_xray()
        except Exception:  # noqa: BLE001
            pass
    db.add_event("info", "settings-update", json.dumps(updates, ensure_ascii=False)[:300])
    return {"ok": True, "settings": db.get_settings()}


# ------------------------------------------------------------------ avatar gallery (profile pictures)
GALLERY_BUILTIN = ("g1", "g2", "g3", "g4", "g5", "g6")


def _gallery_upload_dir() -> str:
    d = os.path.join(config.DATA_DIR, "gallery")
    os.makedirs(d, exist_ok=True)
    return d


def _sanitize_avatar_key(key) -> str:
    """Normalize an avatar key. Returns '' for the default (TiTaN logo)."""
    key = (key or "").strip()[:128]
    if not key or key == "titan":
        return ""
    if key.startswith("gallery:"):
        slug = key.split(":", 1)[1]
        return f"gallery:{slug}" if slug in GALLERY_BUILTIN else ""
    if key.startswith("upload:"):
        fname = os.path.basename(key.split(":", 1)[1])
        return f"upload:{fname}" if fname else ""
    return ""


def _resolve_avatar(key) -> dict:
    """Map an avatar key to {key, url}. Default is the TiTaN logo."""
    key = _sanitize_avatar_key(key)
    if key.startswith("gallery:"):
        slug = key.split(":", 1)[1]
        return {"key": key, "url": f"/static/img/gallery/{slug}.svg"}
    if key.startswith("upload:"):
        fname = key.split(":", 1)[1]
        if os.path.exists(os.path.join(_gallery_upload_dir(), fname)):
            return {"key": key, "url": f"/api/gallery-image/{fname}"}
    return {"key": "titan", "url": "/static/img/titan-avatar.svg"}


def _gallery_items() -> list:
    items = [{"id": f"gallery:{s}", "url": f"/static/img/gallery/{s}.svg",
              "name": s, "builtin": True} for s in GALLERY_BUILTIN]
    for fname in sorted(os.listdir(_gallery_upload_dir())):
        if fname.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            items.append({"id": f"upload:{fname}", "url": f"/api/gallery-image/{fname}",
                          "name": fname, "builtin": False})
    return items


@app.get("/api/gallery")
async def api_gallery(_: str = Depends(_require_auth)):
    return {"items": _gallery_items()}


@app.get("/api/gallery-image/{fname}")
async def api_gallery_image(fname: str, _: str = Depends(_require_auth)):
    fname = os.path.basename(fname)
    path = os.path.join(_gallery_upload_dir(), fname)
    if not os.path.exists(path):
        raise HTTPException(404, "not-found")
    media = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
             ".webp": "image/webp"}.get(os.path.splitext(fname)[1].lower(), "image/png")
    return FileResponse(path, media_type=media, headers={"Cache-Control": "no-store"})


@app.post("/api/gallery")
async def api_gallery_upload(request: Request, _: str = Depends(_require_auth)):
    """Upload a picture into the gallery (persisted in the data dir)."""
    form = await request.form()
    file = form.get("file")
    if file is None or not getattr(file, "filename", None):
        raise HTTPException(400, "no-file")
    data = await file.read()
    if len(data) > 4 * 1024 * 1024:
        raise HTTPException(400, "too-large")
    try:
        img = PILImage.open(io.BytesIO(data))
        img = img.convert("RGB")
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "invalid-image")
    img.thumbnail((512, 512))
    fname = f"{secrets.token_hex(8)}.png"
    img.save(os.path.join(_gallery_upload_dir(), fname), "PNG")
    db.add_event("info", "gallery-upload", fname, ip=_client_ip(request))
    return {"ok": True, "item": {"id": f"upload:{fname}", "url": f"/api/gallery-image/{fname}",
                                 "name": fname, "builtin": False}}


@app.delete("/api/gallery/{fname}")
async def api_gallery_delete(fname: str, request: Request, _: str = Depends(_require_auth)):
    fname = os.path.basename(fname)
    path = os.path.join(_gallery_upload_dir(), fname)
    if not os.path.exists(path):
        raise HTTPException(404, "not-found")
    os.remove(path)
    db.add_event("warn", "gallery-delete", fname, ip=_client_ip(request))
    return {"ok": True}


@app.post("/api/admin-avatar")
async def api_set_admin_avatar(request: Request, _: str = Depends(_require_auth)):
    """Set the admin's profile picture (TiTaN logo / gallery image / upload)."""
    payload = await request.json()
    key = _sanitize_avatar_key(payload.get("avatar"))
    if key and not key.startswith(("gallery:", "upload:")):
        raise HTTPException(400, "invalid-avatar")
    if key.startswith("upload:"):
        fname = key.split(":", 1)[1]
        if not os.path.exists(os.path.join(_gallery_upload_dir(), fname)):
            raise HTTPException(400, "invalid-avatar")
    db.set_setting("admin_avatar", key or "titan")
    db.add_event("info", "avatar-set", key or "titan", ip=_client_ip(request))
    return {"ok": True, "avatar": _resolve_avatar(key)}


# ------------------------------------------------------------------ connection diagnostics
@app.get("/api/connection-test")
async def api_connection_test(_: str = Depends(_require_auth)):
    """Self-test that explains why generated configs may not connect."""
    settings = db.get_settings()
    domain = (settings.get("public_domain") or "").strip()
    port = _link_port(settings)
    result = {
        "xray_installed": xray.xray_available(),
        "xray_running": xray.xray_running(),
        "config_exists": os.path.exists(config.XRAY_CONFIG_PATH),
        "domain": domain,
        "port": port,
        "public_domain_configured": bool(domain),
    }

    # are the local Xray inbound ports actually accepting connections?
    internal = {}
    for name, p in (
        ("vless-ws", config.XRAY_VLESS_WS_PORT),
        ("vmess-ws", config.XRAY_VMESS_WS_PORT),
        ("trojan-ws", config.XRAY_TROJAN_WS_PORT),
        ("xhttp", config.XRAY_XHTTP_PORT),
    ):
        internal[name] = await _tcp_latency("127.0.0.1", p, timeout=1.5) is not None
    result["internal_ports_open"] = internal

    # validate the generated Xray config (only if binary present)
    result["config_valid"] = None
    if xray.xray_available() and result["config_exists"]:
        try:
            proc = await asyncio.create_subprocess_exec(
                config.XRAY_BIN, "run", "-test", "-c", config.XRAY_CONFIG_PATH,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _out, _err = await proc.communicate()
            result["config_valid"] = proc.returncode == 0
        except Exception as e:  # noqa: BLE001
            result["config_valid"] = False
            result["config_error"] = str(e)[:200]

    # reach the public domain + WS path (only when a domain is configured)
    public = {"checked": False}
    if domain:
        public["checked"] = True
        try:
            async with httpx.AsyncClient(timeout=6, follow_redirects=True, verify=True) as client:
                r = await client.get(f"https://{domain}:{port}/health")
                public["panel_http_status"] = r.status_code
                r2 = await client.get(f"https://{domain}:{port}/vl-ws")
                public["ws_status"] = r2.status_code
                public["ws_path_routed"] = r2.status_code not in (404, 502, 503)
        except Exception as e:  # noqa: BLE001
            public["error"] = str(e)[:200]
    result["public"] = public
    return result


# ------------------------------------------------------------------ users api
@app.get("/api/users")
async def api_list_users(_: str = Depends(_require_auth)):
    return {"users": [ _serialize_user(u) for u in db.list_users() ]}


@app.post("/api/users")
async def api_create_user(request: Request, _: str = Depends(_require_auth)):
    payload = await request.json()
    settings = db.get_settings()
    uid = secrets.token_hex(8)
    protocol = payload.get("protocol", "vless")
    if protocol not in ("vless", "vmess", "trojan", "shadowsocks"):
        raise HTTPException(400, "invalid-protocol")
    transport, security = _normalize_protocol_fields(
        protocol,
        payload.get("transport") or settings.get("default_transport", "ws"),
        payload.get("security", "tls"),
    )
    fingerprint = payload.get("fingerprint") or settings.get("default_fingerprint", "chrome")
    if fingerprint not in config.VALID_FINGERPRINTS:
        fingerprint = "chrome"
    alpn = payload.get("alpn") if payload.get("alpn") is not None else settings.get("default_alpn", "http/1.1")
    if alpn not in config.VALID_ALPNS:
        alpn = "http/1.1"
    data = {
        "uid": uid,
        "uuid": str(uuid_lib.uuid4()),
        "name": (payload.get("name") or "User").strip()[:64],
        "note": (payload.get("note") or "")[:200],
        "protocol": protocol,
        "transport": transport,
        "security": security,
        "fingerprint": fingerprint,
        "alpn": alpn,
        "public_key": payload.get("public_key", ""),
        "short_id": payload.get("short_id", ""),
        "spider_x": payload.get("spider_x", ""),
        "max_devices": int(payload.get("max_devices") or 0),
        "allowed_ips": payload.get("allowed_ips") or [],
        "quota_bytes": int(float(payload.get("quota_gb") or 0) * 1024 ** 3),
        "expire_at": _expire_from_days(payload.get("expire_days")),
        "max_requests": int(payload.get("max_requests") or 0),
        "node_id": int(payload.get("node_id") or 1),
        "avatar": _sanitize_avatar_key(payload.get("avatar")),
    }
    user = db.create_user(data)
    _reload_xray()
    db.add_event("info", "user-create", f"{user['name']} ({protocol})", ip=_client_ip(request))
    return {"ok": True, "user": _serialize_user(user, with_links=True, request=request)}


@app.get("/api/users/{uid}")
async def api_get_user(uid: str, request: Request, _: str = Depends(_require_auth)):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    return _serialize_user(user, with_links=True, request=request)


@app.patch("/api/users/{uid}")
async def api_update_user(uid: str, request: Request, _: str = Depends(_require_auth)):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    payload = await request.json()
    fields = {}
    for k in ("name", "note", "enabled", "protocol", "transport", "security",
              "fingerprint", "alpn", "public_key", "short_id", "spider_x",
              "max_devices", "allowed_ips", "max_requests", "node_id"):
        if k in payload:
            fields[k] = payload[k]
    if "avatar" in payload:
        fields["avatar"] = _sanitize_avatar_key(payload.get("avatar"))
    proto = fields.get("protocol", user.get("protocol", "vless"))
    if "transport" in fields or "security" in fields:
        t, s = _normalize_protocol_fields(
            proto,
            fields.get("transport", user.get("transport", "ws")),
            fields.get("security", user.get("security", "tls")),
        )
        fields["transport"], fields["security"] = t, s
    if "fingerprint" in fields and fields["fingerprint"] not in config.VALID_FINGERPRINTS:
        fields["fingerprint"] = "chrome"
    if "alpn" in fields and fields["alpn"] not in config.VALID_ALPNS:
        fields["alpn"] = "http/1.1"
    if "quota_gb" in payload:
        fields["quota_bytes"] = int(float(payload["quota_gb"] or 0) * 1024 ** 3)
    if "expire_days" in payload:
        fields["expire_at"] = _expire_from_days(payload.get("expire_days"))
    updated = db.update_user(uid, fields)
    _reload_xray()
    db.add_event("info", "user-update", f"{uid}", ip=_client_ip(request))
    return {"ok": True, "user": _serialize_user(updated, with_links=True, request=request)}


@app.delete("/api/users/{uid}")
async def api_delete_user(uid: str, request: Request, _: str = Depends(_require_auth)):
    if not db.delete_user(uid):
        raise HTTPException(404, "not-found")
    state.ACTIVE.pop(uid, None)
    _reload_xray()
    db.add_event("warn", "user-delete", f"{uid}", ip=_client_ip(request))
    return {"ok": True}


@app.post("/api/users/{uid}/reset")
async def api_reset_user(uid: str, _: str = Depends(_require_auth)):
    if not db.get_user(uid):
        raise HTTPException(404, "not-found")
    db.reset_user_usage(uid)
    return {"ok": True}


@app.post("/api/users/{uid}/regenerate")
async def api_regenerate(uid: str, request: Request, _: str = Depends(_require_auth)):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    db.update_user(uid, {"uuid": str(uuid_lib.uuid4())})
    state.ACTIVE.pop(uid, None)
    _reload_xray()
    db.add_event("warn", "uuid-rotate", f"{uid}", ip=_client_ip(request))
    return {"ok": True, "user": _serialize_user(db.get_user(uid), with_links=True, request=request)}


@app.post("/api/users/{uid}/toggle")
async def api_toggle(uid: str, request: Request, _: str = Depends(_require_auth)):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    new_state = not bool(user["enabled"])
    db.update_user(uid, {"enabled": new_state})
    _reload_xray()
    db.add_event("info", "user-toggle", f"{uid} -> {new_state}", ip=_client_ip(request))
    return {"ok": True, "enabled": new_state}


@app.get("/api/users/{uid}/links")
async def api_user_links(uid: str, request: Request, _: str = Depends(_require_auth)):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    return _serialize_user(user, with_links=True, request=request)


@app.get("/api/users/{uid}/qr")
async def api_user_qr(uid: str, request: Request, _: str = Depends(_require_auth)):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    settings = db.get_settings()
    link = build_links(_public_host(request), _link_port(settings), user, settings)["main"]
    img = qrcode.make(link, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


def _expire_from_days(days) -> float | None:
    d = int(days or 0)
    return (time.time() + d * 86400) if d > 0 else None


_SERVED_TRANSPORTS = {
    "vless": {"ws", "xhttp", "grpc"},
    "vmess": {"ws", "xhttp", "grpc"},
    "trojan": {"ws"},
    "shadowsocks": set(),
}


def _normalize_protocol_fields(protocol: str, transport, security) -> tuple[str, str]:
    """Coerce transport/security to values the server can actually serve."""
    t = (transport or "ws").lower()
    s = (security or "tls").lower()
    allowed = _SERVED_TRANSPORTS.get(protocol, {"ws"})
    if t not in allowed:
        t = "ws" if "ws" in allowed else next(iter(allowed), "ws")
    if s not in ("tls", "none", "reality"):
        s = "tls"
    return t, s


def _reload_xray():
    try:
        xray.write_xray_config()
        xray.restart_xray()
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ nodes api
@app.get("/api/nodes")
async def api_list_nodes(_: str = Depends(_require_auth)):
    nodes = []
    for n in db.list_nodes():
        nodes.append(_serialize_node(n, await _node_status(n)))
    return {"nodes": nodes}


@app.post("/api/nodes")
async def api_create_node(request: Request, _: str = Depends(_require_auth)):
    payload = await request.json()
    name = (payload.get("name") or "").strip()[:64]
    if not name:
        raise HTTPException(400, "name-required")
    address = (payload.get("address") or "").strip()[:200]
    cc = (payload.get("country_code") or "").strip()[:2].upper()
    # auto-detect country/flag when the admin didn't set one but gave an address
    loc = {}
    if not cc and address:
        loc = await asyncio.to_thread(detect_location, address)
    node = db.create_node({
        "name": name,
        "address": address,
        "city": (payload.get("city") or loc.get("city") or "").strip()[:64],
        "country": (payload.get("country") or loc.get("country") or "").strip()[:64],
        "country_code": cc or loc.get("country_code", ""),
        "flag": payload.get("flag") or _flag_for(cc or loc.get("country_code")),
    })
    db.add_event("info", "node-create", name, ip=_client_ip(request))
    return {"ok": True, "node": _serialize_node(node, await _node_status(node))}


@app.patch("/api/nodes/{node_id}")
async def api_update_node(node_id: int, request: Request, _: str = Depends(_require_auth)):
    node = db.get_node(node_id)
    if not node:
        raise HTTPException(404, "not-found")
    payload = await request.json()
    fields = {}
    for k in ("name", "address", "city", "country", "country_code", "flag", "enabled"):
        if k in payload:
            fields[k] = payload[k]
    # auto-detect country/flag if an address is given and none is known
    if "address" in fields and fields.get("address") and not fields.get("country_code") \
            and not fields.get("flag") and not node.get("country_code"):
        loc = await asyncio.to_thread(detect_location, fields["address"])
        if loc:
            fields.setdefault("city", loc["city"])
            fields.setdefault("country", loc["country"])
            fields["country_code"] = loc["country_code"]
            fields["flag"] = loc["flag"]
    if "country_code" in fields and not payload.get("flag"):
        fields["flag"] = _flag_for(fields["country_code"])
    updated = db.update_node(node_id, fields)
    db.add_event("info", "node-update", str(node_id), ip=_client_ip(request))
    return {"ok": True, "node": _serialize_node(updated, await _node_status(updated))}


@app.delete("/api/nodes/{node_id}")
async def api_delete_node(node_id: int, request: Request, _: str = Depends(_require_auth)):
    if not db.delete_node(node_id):
        raise HTTPException(404, "not-found")
    db.add_event("warn", "node-delete", str(node_id), ip=_client_ip(request))
    return {"ok": True}


@app.post("/api/nodes/{node_id}/ping")
async def api_ping_node(node_id: int, _: str = Depends(_require_auth)):
    node = db.get_node(node_id)
    if not node:
        raise HTTPException(404, "not-found")
    _node_status_cache.pop(node_id, None)
    db.touch_node(node_id)
    return {"ok": True, "status": await _node_status(node)}


# ------------------------------------------------------------------ reports
@app.get("/api/reports")
async def api_reports(days: int = 7, _: str = Depends(_require_auth)):
    days = min(max(int(days or 7), 1), 30)
    users = db.list_users()
    totals = {"users": len(users), "active": 0, "expired": 0, "disabled": 0,
              "total_up": 0, "total_down": 0}
    protocols: dict = {}
    for u in users:
        st = _user_status(u)
        if not u["enabled"]:
            totals["disabled"] += 1
        elif st["expired"]:
            totals["expired"] += 1
        else:
            totals["active"] += 1
        totals["total_up"] += u.get("used_up") or 0
        totals["total_down"] += u.get("used_down") or 0
        protocols[u["protocol"]] = protocols.get(u["protocol"], 0) + 1

    top = sorted(users, key=lambda u: (u.get("used_up") or 0) + (u.get("used_down") or 0), reverse=True)[:6]

    day_bucket = int(time.time() // 86400) * 86400
    raw = {r["bucket"]: r for r in db.get_traffic(day_bucket - (days - 1) * 86400)}
    daily = []
    for i in range(days - 1, -1, -1):
        d = day_bucket - i * 86400
        up = down = 0
        for h in range(24):
            row = raw.get(d + h * 3600)
            if row:
                up += row["up"]
                down += row["down"]
        daily.append({"t": d, "up": up, "down": down})

    return {
        "totals": totals,
        "protocols": [{"protocol": k, "count": v} for k, v in protocols.items()],
        "daily": daily,
        "top_users": [
            {"uid": u["uid"], "name": u["name"],
             "used": (u.get("used_up") or 0) + (u.get("used_down") or 0)}
            for u in top
        ],
    }


# ------------------------------------------------------------------ admin info
@app.get("/api/admin-info")
async def api_admin_info(_: str = Depends(_require_auth)):
    admin = db.get_admin()
    last_login = None
    for e in db.list_events(limit=1000):
        if e["action"] == "login":
            last_login = e["ts"]
            break
    return {
        "username": admin["username"] if admin else None,
        "role": "ادمین کل",
        "avatar": _resolve_avatar(db.get_settings().get("admin_avatar")),
        "created_at": admin["created_at"] if admin else None,
        "last_login": last_login,
        "last_login_ip": next(
            (e["ip"] for e in db.list_events(limit=1000) if e["action"] == "login"), ""
        ),
    }


# ------------------------------------------------------------------ subscriptions
@app.get("/sub/{uid}")
async def sub_plain(uid: str, request: Request):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    settings = db.get_settings()
    links = build_links(_public_host(request), _link_port(settings), user, settings)
    combined = [c["link"] for c in links["info"]] + links["all"]
    body = subscription_text(combined)
    headers = _sub_headers(user)
    return Response(content=body, media_type="text/plain", headers=headers)


@app.get("/sub/{uid}/json")
async def sub_json(uid: str, request: Request):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    settings = db.get_settings()
    links = build_links(_public_host(request), _link_port(settings), user, settings)
    st = _user_status(user)
    return JSONResponse({
        "name": user["name"],
        "uid": uid,
        "enabled": st["live_enabled"],
        "protocol": user["protocol"],
        "quota_gb": round((user.get("quota_bytes") or 0) / (1024 ** 3), 3),
        "used_gb": round(st["used"] / (1024 ** 3), 3),
        "days_left": st["days_left"],
        "active_connections": st["active_connections"],
        "links": links["all"],
        "main_link": links["main"],
    }, headers=_sub_headers(user))


@app.get("/sub/{uid}/base64")
async def sub_base64(uid: str, request: Request):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    settings = db.get_settings()
    links = build_links(_public_host(request), _link_port(settings), user, settings)
    combined = [c["link"] for c in links["info"]] + links["all"]
    return PlainTextResponse(subscription_text(combined), headers=_sub_headers(user))


def _sub_headers(user: dict) -> dict:
    used_up = int(user.get("used_up") or 0)
    used_down = int(user.get("used_down") or 0)
    total = int(user.get("quota_bytes") or 0)
    expire = int(user.get("expire_at") or 0)
    info = f"upload={used_up}; download={used_down}; total={total}; expire={expire}"
    return {
        "Content-Type": "text/plain; charset=utf-8",
        "Subscription-Userinfo": info,
        "subscription-userinfo": info,
        "Profile-Update-Interval": "1",
        "profile-update-interval": "1",
        "Profile-Title": "base64:" + base64.b64encode(user["name"].encode()).decode(),
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Powered-By": "TiTaN",
    }


# ------------------------------------------------------------------ public status
@app.get("/api/status/{uid}")
async def api_public_status(uid: str):
    user = db.get_user(uid)
    if not user:
        raise HTTPException(404, "not-found")
    st = _user_status(user)
    return {
        "name": user["name"],
        "enabled": st["live_enabled"],
        "protocol": user["protocol"],
        "quota_gb": round((user.get("quota_bytes") or 0) / (1024 ** 3), 4),
        "used_gb": round(st["used"] / (1024 ** 3), 4),
        "days_left": st["days_left"],
        "active_connections": st["active_connections"],
    }


# ------------------------------------------------------------------ system
@app.get("/health")
async def health():
    return {"status": "ok", "ts": time.time(), "version": APP_VERSION}


@app.get("/api/stats")
async def api_stats(_: str = Depends(_require_auth)):
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(config.DATA_DIR)
    totals = db.get_totals()
    started = float(db.get_meta("created_at") or time.time())
    active_now = state.total_active()
    recent = db.count_recently_seen(60)

    now_bucket = int(time.time() // 3600) * 3600
    raw = {r["bucket"]: r for r in db.get_traffic(now_bucket - 23 * 3600)}
    hourly = []
    for i in range(23, -1, -1):
        b = now_bucket - i * 3600
        row = raw.get(b)
        hourly.append({
            "t": b,
            "up": row["up"] if row else 0,
            "down": row["down"] if row else 0,
        })

    # count events in the last 24h (for the header notification badge)
    day_ago = time.time() - 86400
    events_today = sum(1 for e in db.list_events(limit=1000) if e["ts"] >= day_ago)
    nodes = db.list_nodes()

    return {
        "cpu_percent": cpu,
        "mem_percent": mem.percent,
        "mem_used_mb": round(mem.used / 1048576, 1),
        "mem_total_mb": round(mem.total / 1048576, 1),
        "disk_percent": disk.percent,
        "disk_free_gb": round(disk.free / (1024 ** 3), 1),
        "uptime_seconds": time.time() - started,
        "total_up": totals["up"],
        "total_down": totals["down"],
        "users_count": totals["count"],
        "enabled_count": sum(1 for u in db.list_users() if u["enabled"]),
        "active_connections": active_now,
        "recently_active": recent,
        "nodes_count": len(nodes),
        "events_today": events_today,
        "hourly": hourly,
        "location": describe_colo(bg.LOCATION.get("colo")),
        "xray_installed": xray.xray_available(),
        "xray_running": xray.xray_running(),
        "app_version": APP_VERSION,
    }


@app.get("/api/events")
async def api_events(level: str | None = None, limit: int = 200,
                     _: str = Depends(_require_auth)):
    return {"events": db.list_events(limit=min(limit, 1000), level=level)}


@app.delete("/api/events")
async def api_clear_events(_: str = Depends(_require_auth)):
    db.clear_events()
    return {"ok": True}


@app.get("/api/backup")
async def api_backup_download(_: str = Depends(_require_auth)):
    raw = db.backup_bytes()
    payload = gzip.compress(raw)
    b64 = base64.b64encode(payload).decode()
    return PlainTextResponse(b64, headers={
        "Content-Disposition": f'attachment; filename="titan-backup-{time.strftime("%Y%m%d-%H%M%S")}.db.gz.b64"',
        "Content-Type": "application/octet-stream",
    })


@app.post("/api/backup/restore")
async def api_backup_restore(file: UploadFile, _: str = Depends(_require_auth)):
    content = await file.read()
    try:
        text = content.decode("ascii").strip()
        payload = base64.b64decode(text)
        raw = gzip.decompress(payload)
    except Exception:  # noqa: BLE001
        # maybe it was uploaded as a raw sqlite file
        raw = content
    if not raw.startswith(b"SQLite"):
        raise HTTPException(400, "invalid-backup")
    db.replace_db(raw)
    _reload_xray()
    db.add_event("warn", "restore", "database restored from backup")
    return {"ok": True}


@app.post("/api/restart")
async def api_restart(_: str = Depends(_require_auth)):
    async def _delayed():
        await asyncio.sleep(1.5)
        os._exit(87)

    asyncio.create_task(_delayed())
    return {"ok": True, "restarting": True}


@app.api_route("/dns-query", methods=["GET", "POST", "OPTIONS"])
async def doh_endpoint(request: Request):
    if request.method == "OPTIONS":
        return Response(status_code=204, headers=_cors_headers())
    try:
        if request.method == "POST":
            body = await request.body()
            ct = request.headers.get("content-type", "application/dns-message")
            try:
                r = await doh_client.post(DOH_PRIMARY, content=body, headers={"content-type": ct})
            except Exception:  # noqa: BLE001
                r = await doh_client.post(DOH_SECONDARY, content=body, headers={"content-type": ct})
        else:
            params = dict(request.query_params)
            try:
                r = await doh_client.get(DOH_PRIMARY, params=params)
            except Exception:  # noqa: BLE001
                r = await doh_client.get(DOH_SECONDARY, params=params)
        return Response(
            content=r.content,
            status_code=r.status_code,
            media_type=r.headers.get("content-type", "application/dns-message"),
            headers=_cors_headers(),
        )
    except Exception:  # noqa: BLE001
        return Response(content=b"", status_code=502)


def _cors_headers() -> dict:
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept",
    }


# ------------------------------------------------------------------ entrypoint
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=config.PANEL_PORT,
        log_level="info",
    )
