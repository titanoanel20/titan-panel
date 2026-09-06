"""Multi-node coordination.

Two roles share one codebase (see config.ROLE):

- **main**: owns the database and the dashboard. It pushes each user's config
  to the node the user is assigned to, so that node runs Xray for them.
- **node**: runs Xray for the users the main panel pushed to it, and reports
  their traffic usage back to the main panel.

Authentication is either a shared secret (TITAN_NODE_SECRET, legacy/simple) or
a per-node token issued by the main panel's "Quick node setup" wizard
(TITAN_NODE_TOKEN on the node side). With a token, a node can self-register:
it reports its own public URL to the main panel, so the admin never has to copy
domains around or keep a shared secret in sync.
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


def _matches(a: str, b: str) -> bool:
    return bool(b) and secrets.compare_digest(str(a or ""), str(b))


def secret_valid_for_node(secret: str) -> bool:
    """Node side: accept a sync push from the main panel."""
    if _matches(secret, config.NODE_SECRET):
        return True
    return _matches(secret, config.NODE_TOKEN)


def secret_valid_for_main(secret: str) -> bool:
    """Main side: accept a report/registration from a node."""
    if _matches(secret, config.NODE_SECRET):
        return True
    return db.get_node_by_token(secret) is not None


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


def _sync_secret(node: dict) -> str:
    """Credential the main panel presents when pushing to a node."""
    return node.get("token") or config.NODE_SECRET


def _payload_hash(users: list[dict]) -> str:
    canon = json.dumps(
        [{k: u.get(k) for k in ("uid",) + SYNC_FIELDS} for u in users],
        sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256(canon.encode()).hexdigest()


def _reality_payload() -> dict | None:
    """Reality keypair to hand to nodes so their Reality inbound matches links."""
    priv = db.get_meta("reality_priv")
    if not priv:
        return None
    return {
        "priv": priv,
        "pub": db.get_meta("reality_pub") or "",
        "sid": db.get_meta("reality_sid") or "",
    }


async def sync_node(node: dict, users: list[dict], timeout: float = 8.0) -> bool:
    """Push a node's full user list to it. Returns True on success."""
    url = _node_url(node)
    if not url or not _sync_secret(node):
        return False
    payload = {
        "secret": _sync_secret(node),
        "users": [user_sync_payload(u) for u in users],
        "reality": _reality_payload(),
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
    users = db.list_users()
    by_node: dict[int, list] = {}
    for u in users:
        by_node.setdefault(int(u.get("node_id") or 1), []).append(u)
    for node in db.list_nodes():
        if node.get("is_local") or not node.get("enabled"):
            continue
        if not node.get("token") and not config.NODE_SECRET:
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
    secret = config.NODE_TOKEN or config.NODE_SECRET
    if not config.MAIN_URL or not secret or not usage:
        return False
    payload = {"secret": secret, "usage": usage}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cl:
            r = await cl.post(f"{config.MAIN_URL}/api/node/usage", json=payload)
            return r.status_code == 200
    except Exception as e:  # noqa: BLE001
        log.warning("usage report failed: %s", e)
        return False


async def register(main_url: str, token: str, url: str, timeout: float = 8.0) -> bool:
    """Node side: self-register with the main panel using its token + URL."""
    if not main_url or not token or not url:
        return False
    payload = {"token": token, "url": url}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cl:
            r = await cl.post(f"{main_url}/api/node/register", json=payload)
            return r.status_code == 200
    except Exception as e:  # noqa: BLE001
        log.warning("node register failed: %s", e)
        return False
