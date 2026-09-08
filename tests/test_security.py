"""Security fixes: CSRF guard, login throttle, reduced attack surface.

Everything that involves credentials runs against the `admin` fixture (a real
password is set). With `first_run` the panel accepts ANY password by design, so
a check written against it would pass even if authentication were removed.
"""
import time
import uuid

import pytest

ORIGIN = "http://testserver"


# ------------------------------------------------------------------ CSRF
def test_cross_origin_state_change_is_rejected(admin):
    """A malicious page must not be able to rotate the admin password.

    Auth is a cookie and the mutating endpoints are JSON, so the CORS preflight
    happened to block cross-site form posts. That is luck, not a control: the
    multipart endpoints never need a preflight.
    """
    stolen = "stolen-" + uuid.uuid4().hex[:8]
    r = admin.post("/api/change-password",
                   json={"old_password": admin._password, "new_password": stolen},
                   headers={"Origin": "https://evil.example"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "csrf-origin-rejected"


def test_blocked_csrf_request_changed_nothing(admin, make_user):
    """The rejection must precede the write, not just shape the response."""
    u = make_user(name="victim-probe")
    r = admin.post("/api/login", json={"username": "TiTaN", "password": admin._password})
    assert r.status_code == 200, "the legitimate password stopped working"
    assert admin.get(f"/api/users/{u['uid']}").json()["name"] == "victim-probe"


def test_multipart_endpoint_is_guarded_too(admin):
    """POST /api/gallery takes form data: no preflight, so it must be checked."""
    r = admin.post("/api/gallery",
                   files={"file": ("x.png", b"not-an-image", "image/png")},
                   headers={"Origin": "https://evil.example"})
    assert r.status_code == 403, r.text


def test_referer_only_forgery_is_caught(admin):
    """Some requests carry no Origin, only a Referer - still must be checked."""
    before = admin.get("/api/settings").json()["block_ads"]
    r = admin.post("/api/settings", json={"block_ads": not before},
                   headers={"Referer": "https://evil.example/x"})
    assert r.status_code == 403, r.text
    assert admin.get("/api/settings").json()["block_ads"] == before


def test_same_origin_requests_still_work(admin):
    r = admin.post("/api/users", json={"name": "legit-origin"}, headers={"Origin": ORIGIN})
    assert r.status_code == 200, r.text
    admin.delete(f"/api/users/{r.json()['user']['uid']}")


def test_no_origin_at_all_is_allowed(first_run):
    """v2rayNG, curl and node-to-node calls send no Origin header."""
    assert first_run.get("/api/users").status_code == 200
    assert first_run.get("/api/stats").status_code == 200


def test_read_endpoints_are_not_blocked(admin):
    """A guard that also rejects GET breaks the dashboard."""
    for path in ("/api/me", "/api/settings", "/api/users", "/api/nodes", "/api/events"):
        assert admin.get(path, headers={"Origin": "https://evil.example"}).status_code == 200, path


def test_subscription_routes_are_exempt(admin, make_user):
    """The VPN client that polls /sub/<uid> cannot be expected to send an Origin."""
    u = make_user(name="sub-client")
    assert admin.get(f"/sub/{u['uid']}").status_code == 200


# ------------------------------------------------------ login throttle
def test_forged_xff_does_not_reset_the_budget(admin):
    """The throttle used to be keyed on X-Forwarded-For, which the client sends.

    Ten forged IPs therefore meant ten independent budgets. The counter is now
    keyed on the peer address, so failures accumulate and the response slows
    down on a schedule the test can observe.
    """
    delays = []
    for i in range(6):
        t0 = time.time()
        r = admin.post("/api/login", json={"username": "TiTaN", "password": f"guess-{i}"},
                       headers={"X-Forwarded-For": f"203.0.113.{i+1}"})
        assert r.status_code == 401, r.text
        delays.append(time.time() - t0)
    assert delays[4] > delays[1], f"no progressive backoff: {[round(d, 2) for d in delays]}"
    assert delays[5] > delays[4], f"backoff stopped growing: {[round(d, 2) for d in delays]}"


def test_each_forged_ip_gets_no_fresh_budget(admin):
    """Same idea, asserted on the counter itself rather than on timing."""
    from app import db
    for i in range(4):
        admin.post("/api/login", json={"username": "TiTaN", "password": f"x{i}"},
                   headers={"X-Forwarded-For": f"198.51.100.{i}"})
    keys = [k for (k,) in db._connect().execute(
        "SELECT key FROM meta WHERE key LIKE 'login_attempts%'")]
    assert len(keys) == 1, f"one counter per spoofed IP: {keys}"
    import json
    count = json.loads(db.get_meta(keys[0]))["count"]
    assert count >= 4, f"counter did not accumulate: {count}"


def test_successful_login_is_never_delayed(admin):
    for _ in range(3):
        admin.post("/api/login", json={"username": "TiTaN", "password": "nope"})
    t0 = time.time()
    r = admin.post("/api/login", json={"username": "TiTaN", "password": admin._password})
    assert r.status_code == 200
    assert time.time() - t0 < 0.5, "a valid login must not pay the penalty"


def test_attempted_username_is_sanitized_for_the_audit_log(admin):
    """The failed-login username is rendered into the dashboard log table."""
    marker = "</td><img src=x onerror=alert(1)>" + uuid.uuid4().hex[:6]
    admin.post("/api/login", json={"username": marker, "password": "x"})
    events = admin.get("/api/events?limit=50").json()["events"]
    row = next((e for e in events if e["action"] == "login-failed"), None)
    assert row is not None, "the failed attempt was not recorded at all"
    assert "<" not in row["detail"] and ">" not in row["detail"], row["detail"]


# ------------------------------------------------------ surface reduction
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_schema_is_not_public(first_run, path):
    """Swagger hands anonymous scanners every route and payload shape."""
    assert first_run.get(path).status_code == 404


@pytest.mark.parametrize("path,body", [
    ("/api/node/sync", {"users": []}),
    ("/api/node/usage", {"usage": {}}),
    ("/api/node/register", {"token": "x", "url": "https://x"}),
])
def test_node_endpoints_require_a_credential(first_run, path, body):
    assert first_run.post(path, json=body).status_code == 401


def test_dashboard_api_requires_a_session(admin):
    """A call without the session cookie must be 401, never a 200 or a 500."""
    cookie = admin.cookies.get("titan_session")
    admin.cookies.clear()
    try:
        for path in ("/api/users", "/api/settings", "/api/stats", "/api/nodes", "/api/events"):
            assert admin.get(path).status_code == 401, path
    finally:
        admin.cookies.set("titan_session", cookie or "")


def test_logout_clears_the_session(admin):
    admin.post("/api/logout")
    assert admin.get("/api/users").status_code == 401


def test_session_cookie_flags(first_run):
    """HttpOnly and SameSite guard the only credential the panel issues."""
    r = first_run.post("/api/login", json={"username": "TiTaN", "password": ""})
    header = r.headers.get("set-cookie", "")
    assert "titan_session=" in header, header
    assert "httponly" in header.lower(), header
    assert "samesite" in header.lower(), header
    assert "path=/" in header.lower(), header


def test_first_run_state_is_reported_to_the_ui(first_run):
    """/api/me must expose `default_auth` so the dashboard can warn about it."""
    me = first_run.get("/api/me").json()
    assert me["logged_in"] is True
    assert me["default_auth"] is True


def test_locked_state_is_reported(admin):
    me = admin.get("/api/me").json()
    assert me["default_auth"] is False
