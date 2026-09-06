#!/usr/bin/env python3
"""Quick end-to-end smoke test against a running TiTaN instance (mock mode)."""
import sys
import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

def main():
    c = httpx.Client(timeout=10, follow_redirects=False)
    # health
    assert c.get(f"{BASE}/health").json()["status"] == "ok"
    # setup status — registration is disabled; the default admin always exists
    st = c.get(f"{BASE}/api/setup-status").json()
    print("needs_setup:", st["needs_setup"])
    assert st["needs_setup"] is False

    # log in with the default admin ("TiTaN", no password until one is set)
    r = c.post(f"{BASE}/api/login", json={"username": "TiTaN", "password": ""})
    assert r.status_code == 200, r.text
    c.cookies.set("titan_session", r.cookies.get("titan_session"))
    print("logged in (default admin)")

    # create a user
    r = c.post(f"{BASE}/api/users", json={"name": "Test", "protocol": "vless", "quota_gb": 5, "expire_days": 30})
    assert r.status_code == 200, r.text
    uid = r.json()["user"]["uid"]
    print("user created:", uid)

    # list users
    users = c.get(f"{BASE}/api/users").json()["users"]
    assert any(u["uid"] == uid for u in users)

    # links
    links = c.get(f"{BASE}/api/users/{uid}/links").json()
    assert links["main_link"].startswith("vless://"), links["main_link"]
    print("main link ok")

    # subscription
    sub = c.get(f"{BASE}/sub/{uid}")
    assert sub.status_code == 200
    print("subscription ok, bytes:", len(sub.content))

    # stats
    s = c.get(f"{BASE}/api/stats").json()
    print("stats ok, users:", s["users_count"], "hourly buckets:", len(s["hourly"]))

    print("✅ SMOKE TEST PASSED")

if __name__ == "__main__":
    main()
