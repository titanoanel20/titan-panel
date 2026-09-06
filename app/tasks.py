"""Background tasks: traffic flush, housekeeping, keep-alive, auto-backup."""
import asyncio
import base64
import gzip
import logging
import os
import time

import httpx

from . import config, db, state, xray

log = logging.getLogger("titan.tasks")

# cached Cloudflare colo for the location widget
LOCATION: dict = {"colo": "?"}


async def _periodic_flush():
    """Every 5s pull Xray deltas and add them to each user's usage."""
    while True:
        try:
            await asyncio.sleep(5)
            deltas = await xray.get_xray_stats()
            if deltas:
                total_up = total_down = 0
                for uid, d in deltas.items():
                    db.add_user_usage(uid, d.get("up", 0), d.get("down", 0))
                    db.touch_last_seen(uid)
                    state.LAST_TRAFFIC[uid] = time.time()
                    total_up += d.get("up", 0)
                    total_down += d.get("down", 0)
                    _check_quota(uid)
                db.add_traffic(int(time.time() // 3600) * 3600, total_up, total_down)
        except asyncio.CancelledError:
            break
        except Exception:  # noqa: BLE001
            await asyncio.sleep(2)


def _check_quota(uid: str):
    """Disable a user once their quota is exceeded."""
    user = db.get_user(uid)
    if not user:
        return
    quota = user["quota_bytes"] or 0
    used = (user["used_up"] or 0) + (user["used_down"] or 0)
    if quota > 0 and used >= quota:
        db.update_user(uid, {"enabled": False})
        db.add_event("warn", "auto-disable", f"quota reached: {uid}", user_id=user["id"])


async def _housekeeping():
    """Disable expired users, heartbeat the local node, run backups."""
    while True:
        try:
            await asyncio.sleep(30)
            now = time.time()
            for u in db.list_users():
                if u["enabled"] and u.get("expire_at") and now >= u["expire_at"]:
                    db.update_user(u["uid"], {"enabled": False})
                    db.add_event("warn", "auto-disable", f"expired: {u['uid']}", user_id=u["id"])
            # keep the local node's "last seen" fresh
            for n in db.list_nodes():
                if n.get("is_local"):
                    db.touch_node(n["id"])
            await _maybe_backup()
        except asyncio.CancelledError:
            break
        except Exception:  # noqa: BLE001
            await asyncio.sleep(5)


async def _keep_alive():
    """Ping the public panel port periodically so serverless/cloud hosts stay warm."""
    await asyncio.sleep(20)
    while True:
        try:
            await asyncio.sleep(300)
            async with httpx.AsyncClient(timeout=5) as client:
                await client.get(f"http://127.0.0.1:{config.PUBLIC_PORT}/health")
        except asyncio.CancelledError:
            break
        except Exception:  # noqa: BLE001
            await asyncio.sleep(5)


async def _refresh_location():
    """Resolve Cloudflare edge colo once at startup and every 12h.
    Also keeps the local node's city/country/flag in sync."""
    from .colo_map import describe_colo

    while True:
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                r = await client.get("https://www.cloudflare.com/cdn-cgi/trace")
                for line in r.text.splitlines():
                    if line.startswith("colo="):
                        LOCATION["colo"] = line.split("=", 1)[1]
                        break
            loc = describe_colo(LOCATION.get("colo"))
            if loc.get("city") and loc.get("city") != "Unknown":
                db.set_local_node_location(
                    loc["city"], loc["country"], "", loc["flag"]
                )
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(12 * 3600)


async def _maybe_backup():
    settings = db.get_settings()
    if not settings.get("backup_enabled"):
        return
    last = float(db.get_meta("backup_last_at") or "0")
    interval = int(settings.get("backup_interval_hours", 24) or 24) * 3600
    if time.time() - last < interval:
        return
    try:
        backup_dir = os.path.join(config.DATA_DIR, "backups")
        os.makedirs(backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        src = config.DB_PATH
        if not os.path.exists(src):
            return
        with open(src, "rb") as f:
            raw = f.read()
        payload = gzip.compress(raw)
        b64 = base64.b64encode(payload).decode()
        path = os.path.join(backup_dir, f"titan-{stamp}.db.gz.b64")
        with open(path, "w", encoding="utf-8") as f:
            f.write(b64)
        db.set_meta("backup_last_at", str(time.time()))
        # keep last 7 backups
        files = sorted(os.listdir(backup_dir))
        for old in files[:-7]:
            try:
                os.remove(os.path.join(backup_dir, old))
            except OSError:
                pass
        db.add_event("info", "backup", f"created {os.path.basename(path)}")
    except Exception as e:  # noqa: BLE001
        log.error("backup failed: %s", e)


def start_background_tasks(app):
    tasks = [
        asyncio.create_task(_periodic_flush()),
        asyncio.create_task(_housekeeping()),
        asyncio.create_task(_keep_alive()),
        asyncio.create_task(_refresh_location()),
    ]
    app.state.titan_tasks = tasks
    return tasks
