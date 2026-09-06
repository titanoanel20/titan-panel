"""Build client connection links (vless://, vmess://, trojan://, ss://) and
subscription payloads for a user.

Every generated link must exactly match an inbound that xray.py generates:
  - vless : ws (/vl-ws) · xhttp (/xhttp) · grpc (serviceName "titan")
  - vmess : ws (/vm-ws) · xhttp (/xhttp) · grpc (serviceName "titan")
  - trojan: ws (/tr-ws)
  - ss    : aes-128-gcm
"""
import base64
import json
import time
from urllib.parse import quote

from . import config

SS_METHODS = [
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
]

# transports the panel can actually serve, per protocol
SERVED_TRANSPORTS = {
    "vless": {"ws", "xhttp", "grpc", "tcp", "httpupgrade"},
    "vmess": {"ws", "xhttp", "grpc", "tcp", "httpupgrade"},
    "trojan": {"ws", "tcp"},
    "shadowsocks": set(),
    "hysteria2": set(),
}


def _transport_for(user: dict, settings: dict) -> str:
    """Resolve the transport a user's link should advertise.

    Falls back to a transport the server can actually serve, so a config that
    was created with an unsupported combination never produces a dead link.
    """
    t = (user.get("transport") or settings.get("default_transport", "ws") or "ws").lower()
    proto = user.get("protocol", "vless").lower()
    allowed = SERVED_TRANSPORTS.get(proto, {"ws"})
    return t if t in allowed else ("ws" if "ws" in allowed else next(iter(allowed), "ws"))


def _fragment_params(settings: dict) -> dict:
    """Extra ?params used by v2rayNG's fragment feature when enabled."""
    if not settings.get("fragment_enabled"):
        return {}
    return {
        "fp_len": settings.get("fragment_length", "10-30"),
        "fp_int": settings.get("fragment_interval", "10-20"),
    }


def _host_params(host: str, path: str, sni: str, fp: str, alpn: str,
                 transport: str, settings: dict) -> str:
    parts = [
        f"type={quote(transport, safe='')}",
        f"host={quote(host, safe='')}",
        f"path={quote(path, safe='/')}",
        f"sni={quote(sni, safe='')}",
        f"fp={quote(fp, safe='')}",
    ]
    if alpn:
        parts.append(f"alpn={quote(alpn, safe=',/')}")
    for k, v in _fragment_params(settings).items():
        parts.append(f"{k}={quote(str(v), safe='')}")
    return "&".join(parts)


def _grpc_params(service: str, sni: str, fp: str) -> str:
    return (
        f"type=grpc&serviceName={quote(service, safe='')}&"
        f"sni={quote(sni, safe='')}&fp={quote(fp, safe='')}"
    )


def build_vless_link(host: str, port: int, user: dict, settings: dict) -> str:
    uuid = user["uuid"]
    transport = _transport_for(user, settings)
    security = (user.get("security") or "tls").lower()
    fp = user.get("fingerprint") or settings.get("default_fingerprint", "chrome")
    alpn = user.get("alpn", settings.get("default_alpn", "http/1.1"))
    sni = settings.get("sni_override") or host
    name = quote('TiTaN-' + user['name'] + '-VLESS-' + transport.upper())

    if security == "reality":
        # Reality is only served over raw TCP; public key/short id come from
        # the panel's generated keypair (settings), with per-user overrides.
        pk = quote(user.get("public_key") or settings.get("reality_pub", ""), safe="")
        sid = quote(user.get("short_id") or settings.get("reality_sid", ""), safe="")
        rsni = settings.get("reality_sni") or sni
        sx = quote(user.get("spider_x", "") or rsni, safe="")
        return (
            f"vless://{uuid}@{host}:{port}?encryption=none&security=reality&"
            f"pbk={pk}&sid={sid}&sni={quote(rsni, safe='')}&spx={sx}&fp={fp}&type=tcp&"
            f"headerType=none&flow=xtls-rprx-vision#{name}"
        )

    sec = "tls" if security == "tls" else "none"
    if transport == "grpc":
        return f"vless://{uuid}@{host}:{port}?encryption=none&security={sec}&{_grpc_params(_grpc_service(user), sni, fp)}#{name}"
    if transport in ("ws", "xhttp", "httpupgrade"):
        params = _host_params(host, _path_for("vless", transport), sni, fp, alpn, transport, settings)
        return f"vless://{uuid}@{host}:{port}?encryption=none&security={sec}&{params}#{name}"
    if transport == "tcp":
        # raw TCP: TLS terminated by Xray (or plain). sni/fp/alpn still apply.
        if security == "tls":
            params = f"type=tcp&headerType=none&sni={quote(sni, safe='')}&fp={fp}"
            if alpn:
                params += f"&alpn={quote(alpn, safe=',/')}"
            return f"vless://{uuid}@{host}:{port}?encryption=none&security=tls&{params}#{name}"
        return f"vless://{uuid}@{host}:{port}?encryption=none&security=none&type=tcp&headerType=none#{name}"
    # plain tcp fallback (no such inbound is generated unless explicitly added)
    return f"vless://{uuid}@{host}:{port}?encryption=none&security=none&type=tcp&headerType=none#{name}"


def build_vmess_link(host: str, port: int, user: dict, settings: dict) -> str:
    uuid = user["uuid"]
    transport = _transport_for(user, settings)
    security = (user.get("security") or "tls").lower()
    fp = user.get("fingerprint") or settings.get("default_fingerprint", "chrome")
    alpn = user.get("alpn", settings.get("default_alpn", "http/1.1"))
    sni = settings.get("sni_override") or host

    net = transport if transport in ("ws", "xhttp", "grpc", "httpupgrade") else "tcp"
    vm = {
        "v": "2",
        "ps": "TiTaN-" + user["name"] + "-VMess-" + net.upper(),
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": net,
        "type": "none",
        "host": host,
        "path": _path_for("vmess", transport) if transport == "ws" else "",
        "tls": "tls" if security == "tls" else "none",
        "sni": sni,
        "alpn": alpn,
        "fp": fp,
    }
    if transport == "xhttp":
        vm["path"] = _path_for("vmess", "xhttp")
    if transport == "httpupgrade":
        vm["path"] = _path_for("vmess", "httpupgrade")
    if transport == "grpc":
        vm["path"] = _grpc_service(user)
    b64 = base64.b64encode(json.dumps(vm, separators=(",", ":")).encode()).decode()
    return "vmess://" + b64


def build_trojan_link(host: str, port: int, user: dict, settings: dict) -> str:
    password = user["uuid"]
    transport = _transport_for(user, settings)
    sni = settings.get("sni_override") or host
    alpn = user.get("alpn", settings.get("default_alpn", "http/1.1"))
    fp = user.get("fingerprint") or settings.get("default_fingerprint", "chrome")
    name = quote("TiTaN-" + user["name"] + "-Trojan-" + transport.upper())

    if transport == "tcp":
        # classic Trojan over raw TCP (TLS terminated by Xray)
        return (
            f"trojan://{quote(password, safe='')}@{host}:{port}?"
            f"security=tls&sni={quote(sni, safe='')}&alpn={quote(alpn, safe=',/')}&fp={fp}#{name}"
        )
    return (
        f"trojan://{quote(password, safe='')}@{host}:{port}?"
        f"security=tls&type=ws&host={quote(host, safe='')}&path={quote('/tr-ws', safe='/')}"
        f"&sni={quote(sni, safe='')}&alpn={quote(alpn, safe=',/')}&fp={fp}#{name}"
    )


def build_ss_link(host: str, port: int, user: dict, settings: dict) -> str:
    method = SS_METHODS[0]
    # Derive a stable 16-byte key from the uuid (works for aes-128-gcm).
    key = base64.urlsafe_b64encode(user["uuid"].encode()[:16]).decode().rstrip("=")
    raw = f"{method}:{key}"
    b64 = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    return f"ss://{b64}@{host}:{port}#{quote('TiTaN-' + user['name'] + '-SS')}"


def build_hy2_link(host: str, port: int, user: dict, settings: dict) -> str:
    """Hysteria2 (QUIC/UDP) link. The user's uuid doubles as the auth password."""
    auth = user["uuid"]
    sni = settings.get("sni_override") or host
    name = quote("TiTaN-" + user["name"] + "-Hysteria2")
    params = f"sni={quote(sni, safe='')}&insecure=0&alpn=h3"
    if config.HY2_OBFS:
        params += f"&obfs=salamander&obfs-password={quote(config.HY2_OBFS, safe='')}"
    return f"hysteria2://{quote(auth, safe='')}@{host}:{port}/?{params}#{name}"


def build_links(host: str, port: int, user: dict, settings: dict) -> dict:
    """Return {"main": link, "all": [links], "info": [dummy status links]}."""
    out = {}
    if user["protocol"] == "vless":
        out["vless"] = build_vless_link(host, port, user, settings)
    elif user["protocol"] == "vmess":
        out["vmess"] = build_vmess_link(host, port, user, settings)
    elif user["protocol"] == "trojan":
        out["trojan"] = build_trojan_link(host, port, user, settings)
    elif user["protocol"] == "shadowsocks":
        out["shadowsocks"] = build_ss_link(host, port, user, settings)
    elif user["protocol"] == "hysteria2":
        out["hysteria2"] = build_hy2_link(host, port, user, settings)

    all_links = list(out.values())

    # Info "dummy" links so the client's remark shows live usage/expiry info.
    quota_gb = (user.get("quota_bytes") or 0) / (1024 ** 3)
    used_gb = ((user.get("used_up") or 0) + (user.get("used_down") or 0)) / (1024 ** 3)
    days_left = ""
    if user.get("expire_at"):
        days_left = f"{max(0, int((user['expire_at'] - time.time()) // 86400))}d"
    remark = f"TiTaN {user['name']} | {used_gb:.2f}/{quota_gb:g}GB | {days_left or '∞'}"
    dummy = (
        f"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:10001?"
        f"encryption=none&security=none&type=tcp&headerType=none#{quote(remark)}"
    )
    info = [{"remark": remark, "link": dummy, "kind": "status"}]
    return {"main": all_links[0] if all_links else "", "all": all_links, "info": info}


def subscription_text(links: list[str]) -> str:
    return base64.b64encode("\n".join(links).encode()).decode()


def _path_for(protocol: str, transport: str) -> str:
    if transport == "ws":
        return {"vless": "/vl-ws", "vmess": "/vm-ws", "trojan": "/tr-ws"}.get(protocol, "/ws")
    if transport == "xhttp":
        return "/xhttp"
    if transport == "httpupgrade":
        return "/hup"
    return "/ws"


def _grpc_service(user: dict) -> str:
    return "titan"
