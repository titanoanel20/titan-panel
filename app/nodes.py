"""Multi-node coordination.

Two roles share one codebase (see config.ROLE):

- **main**: owns the database and the dashboard. It pushes each user's config
  to the node the user is assigned to, so that node runs Xray for them.
- **node**: runs Xray for the users the main panel pushed to it, and reports
  their traffic usage back to the main panel.

All node <-> main traffic is authenticated with a shared secret
(config.NODE_SECRET) and happens over HTTPS in production.
"""
import hashlib
import json
import logging
import secrets

import httpx

from . import config, db

log = logging.getLogger("titan.nodes")

# fields a node needs to build Xray inbounds for a user
SYNC_FIELDS = (
    "uuid", "name", "enabled", "protocol", "transport", "security",
    "fingerprint", "alpn", "public_key", "short_id", "spider_x",
    "max_devices", "quota_bytes", "expire_at", "max_requests", "avatar",
)


def secret_ok(secret: str) -> bool:
    """Constant-time check of the shared node secret."""
    if not config.NODE_SECRET:
        return False
    return secrets.compare_digest(str(secret or ""), config.NODE_SECRET)


def user_sync_payload(u: dict) -> dict:
    """Trim a user dict down to what a node needs."""
    out = {k: u.get(k) for k in ("uid",) + SYNC_FIELDS}
    out["uid"] = u["uid"]
    return out


def _node_url(node: dict) -> str | None:
    addr = (node.get("address") or "").strip()
    if not addr:
        return None
    if not addr.startswith(("http://", "https://")):
        addr = "https://" + addr
    return addr.rstrip("/")


def _payload_hash(users: list[dict]) -> str:
    canon = json.dumps(
        [{k: u.get(k) for k in ("uid",) + SYNC_FIELDS} for u in users],
        sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256(canon.encode()).hexdigest()


async def sync_node(node: dict, users: list[dict], timeout: float = 8.0) -> bool:
    """Push a node's full user list to it. Returns True on success."""
    url = _node_url(node)
    if not url or not config.NODE_SECRET:
        return False
    payload = {
        "secret": config.NODE_SECRET,
        "users": [user_sync_payload(u) for u in users],
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cl:
            r = await cl.post(f"{url}/api/node/sync", json=payload)
            ok = r.status_code == 200
            if not ok:
                log.warning("node sync failed for %s: HTTP %s", url, r.status_code)
            return ok
    except Exception as e:  # noqa: BLE001
        log.warning("node sync error for %s: %s", url, e)
        return False


async def sync_all() -> dict[str, bool]:
    """Push users to every remote node (main role). Returns {node_name: ok}."""
    results: dict[str, bool] = {}
    if not config.NODE_SECRET:
        return results
    users = db.list_users()
    by_node: dict[int, list] = {}
    for u in users:
        by_node.setdefault(int(u.get("node_id") or 1), []).append(u)
    for node in db.list_nodes():
        if node.get("is_local") or not node.get("enabled"):
            continue
        node_users = sorted(by_node.get(node["id"], []), key=lambda x: x["uid"])
        # skip re-push when nothing changed since the last successful sync
        h = _payload_hash(node_users)
        if db.get_meta(f"node_sync_hash:{node['id']}") == h:
            results[node["name"]] = True
            continue
        if await sync_node(node, node_users):
            db.set_meta(f"node_sync_hash:{node['id']}", h)
            results[node["name"]] = True
        else:
            results[node["name"]] = False
    return results


async def report_usage(usage: dict[str, dict], timeout: float = 8.0) -> bool:
    """Send per-user traffic deltas back to the main panel (node role)."""
    if not config.MAIN_URL or not config.NODE_SECRET or not usage:
        return False
    payload = {"secret": config.NODE_SECRET, "usage": usage}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cl:
            r = await cl.post(f"{config.MAIN_URL}/api/node/usage", json=payload)
            return r.status_code == 200
    except Exception as e:  # noqa: BLE001
        log.warning("usage report failed: %s", e)
        return False
