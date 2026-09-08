"""Shared fixtures for the TiTaN test-suite.

Why these fixtures look unusual: the panel keeps state in module globals
(`db._conn`, `state.ACTIVE`, `main._node_status_cache`) and reads
`TITAN_DATA_DIR` once at import. A per-test "fresh app" therefore requires
re-importing *every* `app.*` module; doing it partially leaves half the code
talking to the previous test's SQLite file (observed as a first-run login
failing against a directory that had never been written to).

So the suite runs one bootstrapped app per session and each fixture puts the
two pieces of global state a test cares about - the admin credential and the
login throttle - into a known condition, then restores them.
"""
import os
import pathlib
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO.parent))

#: env vars the fixtures own; each is restored on teardown so a subprocess-started panel
#: can never inherit another test's database
ENV_KEYS = ("TITAN_DATA_DIR", "TITAN_DB_PATH", "TITAN_XRAY_CONFIG")


def compile_all(root):
    return subprocess.run([sys.executable, "-m", "compileall", "-q", "app", "scripts"],
                          cwd=str(root), capture_output=True, text=True)


@pytest.fixture(scope="session")
def repo_root():
    return REPO


@pytest.fixture(scope="session")
def client_hello():
    """Build a genuine TLS ClientHello for a given SNI.

    Hand-written hex is a bad way to test an SNI parser: this returns exactly
    what a client puts on the wire, captured from Python's own OpenSSL before
    any server replies.
    """
    import asyncio
    import ssl

    def _build(sni: str = "www.speedtest.net") -> bytes:
        captured = {}

        async def _run():
            async def stub(reader, writer):
                captured["buf"] = await reader.read(4096)
                writer.close()

            server = await asyncio.start_server(stub, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                _r, _w = await asyncio.open_connection("127.0.0.1", port, ssl=ctx,
                                                       server_hostname=sni)
                await asyncio.sleep(0.2)
            except (ssl.SSLError, ConnectionError, OSError):
                pass
            server.close()
            await server.wait_closed()

        asyncio.run(_run())
        assert captured.get("buf"), "could not capture a ClientHello from this interpreter"
        return captured["buf"]

    return _build


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    """A fully booted panel with its own throwaway database (mock Xray mode)."""
    data = tmp_path_factory.mktemp("titan-data")
    saved = {k: os.environ.get(k) for k in ENV_KEYS}
    os.environ["TITAN_DATA_DIR"] = str(data)
    os.environ["TITAN_DB_PATH"] = str(data / "titan.db")
    os.environ["TITAN_XRAY_CONFIG"] = str(data / "config.json")
    for mod in [m for m in list(sys.modules) if m.startswith("app.")]:
        del sys.modules[mod]
    main = __import__("app.main", fromlist=["app"])
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c
    # TestClient-based tests re-import app modules against these paths; leaving
    # them in os.environ poisons any test that starts a *subprocess* panel (it
    # inherits the environment) - which made live-server tests share one database
    # depending on file order.
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture(scope="session")
def db(client):
    """The panel's own persistence module, for state the API cannot set."""
    from app import db as _db
    return _db


def _clear_throttle(db):
    """The login guard lives in the meta table; tests must start from zero."""
    for key in [k for (k,) in db._connect().execute(
            "SELECT key FROM meta WHERE key LIKE 'login_attempts%'")]:
        db.set_meta(key, '{"count": 0, "locked_until": 0}')


@pytest.fixture()
def first_run(client, db):
    """Panel exactly as a fresh deploy behaves: admin `TiTaN`, no password.

    In this state the login endpoint accepts ANY password, which is why tests
    about credentials must switch to `admin` instead.
    """
    from app import security
    hp = security.hash_password("")
    db.set_admin("TiTaN", hp["hash"], hp["salt"])
    db.set_meta("auth_is_default", "1")
    _clear_throttle(db)
    client.cookies.clear()
    r = client.post("/api/login", json={"username": "TiTaN", "password": ""})
    assert r.status_code == 200, r.text
    yield client
    db.set_meta("auth_is_default", "1")
    _clear_throttle(db)


@pytest.fixture()
def admin(client, db):
    """A real password is set, so authentication is actually enforced.

    The credential is restored to the first-run state afterwards, because
    `change-password` refuses a blank new password and there is no API to unset
    one - the hash has to be written directly.
    """
    from app import security
    pw = "test-" + uuid.uuid4().hex[:10]
    hp = security.hash_password(pw)
    db.set_admin("TiTaN", hp["hash"], hp["salt"])
    db.set_meta("auth_is_default", "0")
    _clear_throttle(db)
    client.cookies.clear()
    r = client.post("/api/login", json={"username": "TiTaN", "password": pw})
    assert r.status_code == 200, r.text
    client._password = pw
    yield client
    empty = security.hash_password("")
    db.set_admin("TiTaN", empty["hash"], empty["salt"])
    db.set_meta("auth_is_default", "1")
    _clear_throttle(db)


@pytest.fixture()
def make_user(admin):
    """Create users through the API and delete them again, keeping tests apart."""
    uids = []

    def _make(**fields):
        fields.setdefault("name", "t-" + uuid.uuid4().hex[:6])
        r = admin.post("/api/users", json=fields, headers={"Origin": "http://testserver"})
        assert r.status_code == 200, r.text
        u = r.json()["user"]
        uids.append(u["uid"])
        return u

    yield _make
    for uid in uids:
        admin.delete(f"/api/users/{uid}")
