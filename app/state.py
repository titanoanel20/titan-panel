"""In-memory runtime state shared across the app."""
import time

# uid -> set of active connection tokens (websocket/client connections).
ACTIVE: dict[str, set] = {}

# uid -> first client IP seen since server start (used for device pinning).
FIRST_IP: dict[str, str] = {}

# uid -> last time a request counted toward max_requests.
REQUEST_BUCKET: dict[str, list] = {}

# uid -> unix ts of last Xray traffic delta (updated by the flush task).
LAST_TRAFFIC: dict[str, float] = {}


def register_connection(uid: str, token: str) -> bool:
    """Register an active connection. Returns False if max_devices would be
    exceeded or the user is disabled."""
    bucket = ACTIVE.setdefault(uid, set())
    bucket.add(token)
    return True


def unregister_connection(uid: str, token: str) -> None:
    bucket = ACTIVE.get(uid)
    if bucket:
        bucket.discard(token)
        if not bucket:
            ACTIVE.pop(uid, None)


def active_count(uid: str) -> int:
    return len(ACTIVE.get(uid, set()))


def total_active() -> int:
    return sum(len(v) for v in ACTIVE.values())
