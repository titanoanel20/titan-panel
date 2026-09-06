"""SQLite persistence layer for TiTaN.

Thread/async safe via a process-wide lock. Uses WAL mode for concurrent reads
while writes are serialized.
"""
import json
import os
import secrets
import sqlite3
import threading
import time
from typing import Any

from . import config

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uid             TEXT UNIQUE NOT NULL,
    uuid            TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL DEFAULT 'User',
    note            TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    protocol        TEXT NOT NULL DEFAULT 'vless',
    transport       TEXT NOT NULL DEFAULT 'ws',
    security        TEXT NOT NULL DEFAULT 'tls',
    fingerprint     TEXT NOT NULL DEFAULT 'chrome',
    alpn            TEXT NOT NULL DEFAULT 'http/1.1',
    public_key      TEXT NOT NULL DEFAULT '',
    short_id        TEXT NOT NULL DEFAULT '',
    spider_x        TEXT NOT NULL DEFAULT '',
    max_devices     INTEGER NOT NULL DEFAULT 0,
    first_device_uid TEXT NOT NULL DEFAULT '',
    allowed_ips     TEXT NOT NULL DEFAULT '',
    quota_bytes     INTEGER NOT NULL DEFAULT 0,
    expire_at       REAL,
    created_at      REAL NOT NULL,
    used_up         INTEGER NOT NULL DEFAULT 0,
    used_down       INTEGER NOT NULL DEFAULT 0,
    request_count   INTEGER NOT NULL DEFAULT 0,
    max_requests    INTEGER NOT NULL DEFAULT 0,
    last_seen       REAL
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    level      TEXT NOT NULL DEFAULT 'info',
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    user_id    INTEGER
);
CREATE TABLE IF NOT EXISTS traffic_hourly (
    bucket INTEGER PRIMARY KEY,
    up     INTEGER NOT NULL DEFAULT 0,
    down   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    address      TEXT NOT NULL DEFAULT '',
    city         TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    country_code TEXT NOT NULL DEFAULT '',
    flag         TEXT NOT NULL DEFAULT '🏳️',
    is_local     INTEGER NOT NULL DEFAULT 0,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL,
    last_seen    REAL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid);
"""


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.executescript(SCHEMA)
        _conn.commit()
        _ensure_bootstrap()
    return _conn


def _ensure_bootstrap():
    """Generate secret key / default settings / migrations on first run."""
    c = _conn
    if not get_meta("secret_key"):
        set_meta("secret_key", secrets.token_hex(32))
    if not get_meta("created_at"):
        set_meta("created_at", str(time.time()))
    if not get_meta("backup_last_at"):
        set_meta("backup_last_at", "0")

    # migration: users.node_id (config -> node association)
    cols = [r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()]
    if "node_id" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN node_id INTEGER NOT NULL DEFAULT 1")
        c.commit()

    # seed the local node (this server) once
    row = c.execute("SELECT id FROM nodes WHERE is_local=1").fetchone()
    if not row:
        c.execute(
            "INSERT INTO nodes(name, address, city, country, country_code, flag, "
            "is_local, enabled, created_at, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("سرور اصلی", "", "—", "—", "", "🌐", 1, 1, time.time(), time.time()),
        )
        c.commit()

    # --- default admin — no registration required. ---------------------------
    # Username: "TiTaN". Password intentionally unset until the admin sets one
    # from Settings → Security. While auth_is_default is "1", login accepts the
    # default username without any password.
    if not get_admin():
        from . import security as _sec
        hp = _sec.hash_password("")
        set_admin("TiTaN", hp["hash"], hp["salt"])
        set_meta("auth_is_default", "1")


def get_meta(key: str) -> str | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None


def set_meta(key: str, value: str):
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        c.commit()


def get_secret_key() -> str:
    key = get_meta("secret_key")
    if not key:
        key = secrets.token_hex(32)
        set_meta("secret_key", key)
    return key


def get_admin() -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM admin WHERE id=1").fetchone()
        return dict(row) if row else None


def set_admin(username: str, password_hash: str, salt: str) -> None:
    with _lock:
        c = _connect()
        c.execute("DELETE FROM admin")
        c.execute(
            "INSERT INTO admin(id, username, password_hash, salt, created_at) "
            "VALUES(1, ?, ?, ?, ?)",
            (username, password_hash, salt, time.time()),
        )
        c.commit()


def get_settings() -> dict:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT key, value FROM settings").fetchall()
    settings = dict(config.DEFAULT_SETTINGS)
    for row in rows:
        try:
            settings[row["key"]] = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            settings[row["key"]] = row["value"]
    return settings


def set_setting(key: str, value: Any) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        c.commit()


def set_settings(mapping: dict) -> None:
    for k, v in mapping.items():
        set_setting(k, v)


def list_users() -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
    return [dict(r) for r in rows]


def get_user(uid: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        return dict(row) if row else None


def get_user_by_uuid(uuid: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM users WHERE uuid=?", (uuid,)).fetchone()
        return dict(row) if row else None


def create_user(data: dict) -> dict:
    with _lock:
        c = _connect()
        cols = [
            "uid", "uuid", "name", "note", "enabled", "protocol", "transport",
            "security", "fingerprint", "alpn", "public_key", "short_id",
            "spider_x", "max_devices", "first_device_uid", "allowed_ips",
            "quota_bytes", "expire_at", "created_at", "max_requests", "node_id",
        ]
        now = time.time()
        values = {
            "uid": data["uid"],
            "uuid": data["uuid"],
            "name": data.get("name", "User")[:64],
            "note": data.get("note", "")[:200],
            "enabled": 1 if data.get("enabled", True) else 0,
            "protocol": data.get("protocol", "vless"),
            "transport": data.get("transport", "ws"),
            "security": data.get("security", "tls"),
            "fingerprint": data.get("fingerprint", "chrome"),
            "alpn": data.get("alpn", "http/1.1"),
            "public_key": data.get("public_key", ""),
            "short_id": data.get("short_id", ""),
            "spider_x": data.get("spider_x", ""),
            "max_devices": int(data.get("max_devices", 0) or 0),
            "first_device_uid": data.get("first_device_uid", ""),
            "allowed_ips": json.dumps(data.get("allowed_ips", []), ensure_ascii=False),
            "quota_bytes": int(data.get("quota_bytes", 0) or 0),
            "expire_at": data.get("expire_at"),
            "created_at": now,
            "max_requests": int(data.get("max_requests", 0) or 0),
            "node_id": int(data.get("node_id", 1) or 1),
        }
        placeholders = ", ".join("?" for _ in cols)
        c.execute(
            f"INSERT INTO users({', '.join(cols)}) VALUES({placeholders})",
            [values[col] for col in cols],
        )
        c.commit()
    return get_user(data["uid"])


def update_user(uid: str, fields: dict) -> dict | None:
    allowed = {
        "name", "note", "enabled", "protocol", "transport", "security",
        "fingerprint", "alpn", "public_key", "short_id", "spider_x",
        "max_devices", "first_device_uid", "quota_bytes", "expire_at",
        "max_requests", "node_id",
    }
    with _lock:
        c = _connect()
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "enabled":
                v = 1 if v else 0
            if k == "allowed_ips":
                v = json.dumps(v, ensure_ascii=False)
            sets.append(f"{k}=?")
            vals.append(v)
        if sets:
            vals.append(uid)
            c.execute(f"UPDATE users SET {', '.join(sets)} WHERE uid=?", vals)
            c.commit()
    return get_user(uid)


def set_user_usage(uid: str, up: int, down: int) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE users SET used_up=?, used_down=? WHERE uid=?", (up, down, uid)
        )
        c.commit()


def add_user_usage(uid: str, up_delta: int, down_delta: int) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE users SET used_up=used_up+?, used_down=used_down+? WHERE uid=?",
            (up_delta, down_delta, uid),
        )
        c.commit()


def reset_user_usage(uid: str) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE users SET used_up=0, used_down=0, request_count=0 WHERE uid=?",
            (uid,),
        )
        c.commit()


def delete_user(uid: str) -> bool:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM users WHERE uid=?", (uid,))
        c.commit()
        return cur.rowcount > 0


def touch_last_seen(uid: str, ts: float | None = None) -> None:
    with _lock:
        c = _connect()
        c.execute("UPDATE users SET last_seen=? WHERE uid=?", (ts or time.time(), uid))
        c.commit()


def count_recently_seen(seconds: int) -> int:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT COUNT(*) AS n FROM users WHERE last_seen IS NOT NULL AND last_seen > ?",
            (time.time() - seconds,),
        ).fetchone()
        return row["n"]


def get_totals() -> dict:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT COALESCE(SUM(used_up),0) AS up, COALESCE(SUM(used_down),0) AS down, "
            "COUNT(*) AS n FROM users"
        ).fetchone()
        return {"up": row["up"], "down": row["down"], "count": row["n"]}


def add_event(level: str, action: str, detail: str = "", ip: str = "", user_id: int | None = None) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO events(ts, level, action, detail, ip, user_id) VALUES(?,?,?,?,?,?)",
            (time.time(), level, action, detail[:400], ip, user_id),
        )
        c.commit()
        # keep only the last 2000 rows
        c.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)"
        )
        c.commit()


def list_events(limit: int = 200, level: str | None = None) -> list[dict]:
    with _lock:
        c = _connect()
        if level:
            rows = c.execute(
                "SELECT * FROM events WHERE level=? ORDER BY id DESC LIMIT ?",
                (level, limit),
            ).fetchall()
        else:
            rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear_events() -> None:
    with _lock:
        c = _connect()
        c.execute("DELETE FROM events")
        c.commit()


# ------------------------------------------------------------------ nodes
def list_nodes() -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT * FROM nodes ORDER BY is_local DESC, id ASC").fetchall()
    return [dict(r) for r in rows]


def get_node(node_id: int) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return dict(row) if row else None


def create_node(data: dict) -> dict:
    with _lock:
        c = _connect()
        cur = c.execute(
            "INSERT INTO nodes(name, address, city, country, country_code, flag, "
            "is_local, enabled, created_at, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                data.get("name", "Node")[:64],
                data.get("address", "")[:200],
                data.get("city", "")[:64],
                data.get("country", "")[:64],
                data.get("country_code", "")[:2],
                data.get("flag", "🏳️"),
                0,
                1 if data.get("enabled", True) else 0,
                time.time(),
                time.time(),
            ),
        )
        c.commit()
        return get_node(cur.lastrowid)


def update_node(node_id: int, fields: dict) -> dict | None:
    allowed = {"name", "address", "city", "country", "country_code", "flag", "enabled"}
    with _lock:
        c = _connect()
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "enabled":
                v = 1 if v else 0
            sets.append(f"{k}=?")
            vals.append(v)
        if sets:
            vals.append(node_id)
            c.execute(f"UPDATE nodes SET {', '.join(sets)} WHERE id=?", vals)
            c.commit()
    return get_node(node_id)


def delete_node(node_id: int) -> bool:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM nodes WHERE id=? AND is_local=0", (node_id,))
        c.commit()
        return cur.rowcount > 0


def touch_node(node_id: int) -> None:
    with _lock:
        c = _connect()
        c.execute("UPDATE nodes SET last_seen=? WHERE id=?", (time.time(), node_id))
        c.commit()


def set_local_node_location(city: str, country: str, country_code: str, flag: str) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE nodes SET city=?, country=?, country_code=?, flag=? WHERE is_local=1",
            (city, country, country_code, flag),
        )
        c.commit()


def backup_bytes() -> bytes:
    """Return a consistent snapshot of the DB file."""
    with _lock:
        c = _connect()
        c.execute("PRAGMA wal_checkpoint(FULL)")
        c.commit()
    with open(config.DB_PATH, "rb") as f:
        return f.read()


def add_traffic(bucket: int, up: int, down: int) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO traffic_hourly(bucket, up, down) VALUES(?,?,?) "
            "ON CONFLICT(bucket) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
            (bucket, up, down),
        )
        c.execute("DELETE FROM traffic_hourly WHERE bucket < ?", (bucket - 168 * 3600,))
        c.commit()


def get_traffic(bucket_from: int) -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute(
            "SELECT bucket, up, down FROM traffic_hourly WHERE bucket >= ? ORDER BY bucket ASC",
            (bucket_from,),
        ).fetchall()
    return [dict(r) for r in rows]


def replace_db(data: bytes) -> bool:
    """Replace the live DB with the given bytes (used by restore)."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                _conn.close()
            except sqlite3.Error:
                pass
            _conn = None
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = config.DB_PATH + ".restore"
        with open(tmp, "wb") as f:
            f.write(data)
        for suffix in ("-wal", "-shm"):
            try:
                os.remove(config.DB_PATH + suffix)
            except OSError:
                pass
        os.replace(tmp, config.DB_PATH)
        _connect()
        return True
