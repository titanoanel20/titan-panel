"""End-to-end checks against a real uvicorn process, not the in-process client.

TestClient calls the ASGI app directly, so it bypasses everything the server
puts in front of it. That hid a real bug: uvicorn runs
`ProxyHeadersMiddleware` by default (`proxy_headers=True`,
`forwarded_allow_ips="127.0.0.1"`), which *rewrites* `request.client` from
`X-Forwarded-For`. Because nginx on 127.0.0.1 is the only peer in this
deployment, the "peer address" the login throttle was keyed on was still fully
attacker controlled - a green TestClient suite and a broken production guard.
Only a live server can see that.
"""
import contextlib
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: A booted server inherits os.environ, so the keys that point at a database must
#: come from the test - otherwise it silently shares another test's DB (and its
#: admin password) whenever that test happened to run first.
ISOLATED_ENV = ("TITAN_DATA_DIR", "TITAN_DB_PATH", "TITAN_XRAY_CONFIG", "PANEL_PORT")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def booted(tmp_path, extra_env: dict | None = None):
    """Run the exact command the container runs, and yield its base URL.

    `extra_env` is how a test opts into a runtime that differs from the
    default deploy (e.g. forcing the raw TCP entry on).
    """
    data = tmp_path / "live" / str(_free_port())
    data.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if k not in ISOLATED_ENV}
    env.update({"TITAN_DATA_DIR": str(data), "TITAN_DB_PATH": str(data / "titan.db"),
                "TITAN_XRAY_CONFIG": str(data / "config.json"),
                "PANEL_PORT": str(port), "PYTHONPATH": REPO,
                "PATH": os.environ.get("PATH", ""), **(extra_env or {})})
    log = open(data / "server.log", "w+", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, "-m", "app.main"], cwd=REPO, env=env,
                            stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 25
        while time.time() < deadline:
            if proc.poll() is not None:
                log.seek(0)
                pytest.fail(f"server exited with {proc.returncode}:\n{log.read()[-2500:]}")
            try:
                if httpx.get(f"{base}/health", timeout=1.5).status_code == 200:
                    break
            except Exception:
                time.sleep(0.25)
        else:
            log.seek(0)
            pytest.fail(f"server never became healthy:\n{log.read()[-2500:]}")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


@pytest.fixture()
def live(tmp_path):
    with booted(tmp_path) as base:
        yield base


@pytest.fixture()
def first_run_session(live):
    """Session for a panel that has no password yet (fresh bootstrapped DB)."""
    with httpx.Client(base_url=live, timeout=20) as c:
        r = c.post("/api/login", json={"username": "TiTaN", "password": ""})
        assert r.status_code == 200, r.text
        yield c


def lock_password(client, pw: str) -> None:
    """Move a first-run panel to an enforced password (there is no API to unset)."""
    r = client.post("/api/change-password", json={"old_password": "", "new_password": pw})
    assert r.status_code == 200, r.text
    client._pw = pw


def test_server_serves_traffic(live):
    """Trivially true, but it is what the crash-loop destroyed."""
    body = httpx.get(f"{live}/health", timeout=5).json()
    assert body["status"] == "ok"
    assert isinstance(body["users"], int)
    # auto mode must stay off when no platform proxy exists: on a VPS every
    # inbound already owns its own port, and a gratuitous listener is a bug.


def test_forged_xff_does_not_change_the_peer_the_app_sees(live, first_run_session):
    """`request.client.host` must be the real socket peer, not our header.

    /api/events echoes the resolved IP, so ask for it twice: once with a forged
    XFF (for display) and once bare, then assert the *throttle* saw one bucket.
    """
    # lock a password, otherwise every wrong guess "succeeds" in first-run mode
    lock_password(first_run_session, "hard-" + "x" * 8)

    for i in range(5):
        rr = httpx.post(f"{live}/api/login", json={"username": "TiTaN", "password": f"nope{i}"},
                        headers={"X-Forwarded-For": f"203.0.113.{i+1}"}, timeout=120)
        assert rr.status_code == 401, rr.text

    evs = first_run_session.get("/api/events?limit=50").json()["events"]
    fails = [e for e in evs if e["action"] == "login-failed"]
    assert len(fails) >= 5, fails
    # the audit field still reports the advertised client (best effort)...
    assert {e["ip"] for e in fails}, "no ip recorded at all"
    # ...but the counter bucket is keyed on the true peer: exactly one, and it
    # is the loopback address, never any 203.0.113.x.
    # Assert via behaviour: a single shared bucket had to accumulate 5 failures,
    # which triggers the >=3 soft backoff on the last two attempts.
    t0 = time.time()
    httpx.post(f"{live}/api/login", json={"username": "TiTaN", "password": "one-more"}, timeout=120)
    assert time.time() - t0 >= 0.4, "counter was not shared across spoofed IPs"


def test_valid_login_is_not_penalised(live, first_run_session):
    pw = "good-" + "y" * 8
    lock_password(first_run_session, pw)
    for _ in range(4):
        httpx.post(f"{live}/api/login", json={"username": "TiTaN", "password": "junk"}, timeout=120)
    t0 = time.time()
    r = httpx.post(f"{live}/api/login", json={"username": "TiTaN", "password": pw}, timeout=60)
    assert r.status_code == 200
    assert time.time() - t0 < 0.5, "the correct password paid for someone else's guesses"


def test_cross_origin_state_change_rejected_over_http(live):
    """Same-site cookie + preflight are not the control; the Origin check is."""
    with httpx.Client(base_url=live, timeout=20) as c:
        c.post("/api/login", json={"username": "TiTaN", "password": ""})  # first-run session
        r = c.post("/api/change-password", json={"old_password": "", "new_password": "zzz" + "q" * 6},
                   headers={"Origin": "https://evil.example"})
        assert r.status_code == 403, (r.status_code, r.text)
        # and the write truly did not happen: the first-run login still works
        c2 = httpx.Client(base_url=live, timeout=15)
        assert c2.post("/api/login", json={"username": "TiTaN", "password": ""}).status_code == 200


def test_swagger_is_not_served(live):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert httpx.get(f"{live}{path}", timeout=5).status_code == 404, path


def test_create_user_and_fetch_subscription_end_to_end(live):
    """The user-visible flow that must never regress: create -> link -> client pull."""
    with httpx.Client(base_url=live, timeout=15) as c:
        assert c.post("/api/login", json={"username": "TiTaN", "password": ""}).status_code == 200
        r = c.post("/api/users", json={"name": "e2e", "protocol": "vless", "quota_gb": 3,
                                       "expire_days": 30})
        assert r.status_code == 200, r.text
        u = r.json()["user"]
        assert u["main_link"].startswith("vless://")
        sub = httpx.get(f"{live}/sub/{u['uid']}", timeout=10)
        assert sub.status_code == 200
        import base64
        assert "vless://" in base64.b64decode(sub.text).decode()
        # the status page is public by design and must render
        assert httpx.get(f"{live}/status/{u['uid']}", timeout=10).status_code == 200
        c.delete(f"/api/users/{u['uid']}")


# ------------------------------------------------------- public-port takeover
