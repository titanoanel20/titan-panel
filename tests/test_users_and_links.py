"""User CRUD, quota/expiry math and per-protocol link generation.

Background: `db.update_user()` filtered writes through an allowlist that did
not contain `allowed_ips`, so PATCH returned 200 with the value silently
dropped - the admin believed an IP pin was configured when nothing enforced it.
"""
import base64

import pytest

PROTO_LINK_PREFIX = {
    "vless": "vless://",
    "vmess": "vmess://",
    "trojan": "trojan://",
    "shadowsocks": "ss://",
    "hysteria2": "hysteria2://",
    "wireguard": "wireguard://",
}


@pytest.mark.parametrize("proto,prefix", sorted(PROTO_LINK_PREFIX.items()))
def test_every_advertised_protocol_produces_a_working_link(admin, proto, prefix):
    """A protocol listed in config.VALID_PROTOCOLS must yield a dialable link."""
    r = admin.post("/api/users", json={"name": f"p-{proto}", "protocol": proto},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    u = r.json()["user"]
    assert u["main_link"], f"{proto} produced an empty link"
    assert u["main_link"].startswith(prefix), u["main_link"][:40]
    admin.delete(f"/api/users/{u['uid']}")


def test_link_carries_transport_path_and_sni(admin):
    u = admin.post("/api/users", json={"name": "ws-user", "protocol": "vless",
                                       "transport": "ws", "security": "tls"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    link = u["main_link"]
    assert "path=/vl-ws" in link, link
    assert "sni=" in link and "security=tls" in link
    admin.delete(f"/api/users/{u['uid']}")


def test_grpc_link_uses_the_service_name_the_server_serves(admin):
    u = admin.post("/api/users", json={"name": "grpc-user", "protocol": "vless",
                                       "transport": "grpc"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    assert "type=grpc" in u["main_link"], u["main_link"]
    assert "serviceName=titan" in u["main_link"], u["main_link"]
    admin.delete(f"/api/users/{u['uid']}")


def test_unsupported_transport_is_downgraded_not_dropped(admin):
    """Trojan has no gRPC inbound; a link advertising one is a dead config."""
    u = admin.post("/api/users", json={"name": "bad-combo", "protocol": "trojan",
                                       "transport": "grpc"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    assert u["transport"] in ("ws", "tcp"), u["transport"]
    assert "type=grpc" not in u["main_link"]
    admin.delete(f"/api/users/{u['uid']}")


def test_uuid_rotation_does_not_touch_other_users(admin):
    a = admin.post("/api/users", json={"name": "rotate-me", "protocol": "trojan"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    b = admin.post("/api/users", json={"name": "keep-me", "protocol": "trojan"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    old_a, old_b = a["uuid"], b["uuid"]
    admin.post(f"/api/users/{a['uid']}/regenerate")
    assert admin.get(f"/api/users/{a['uid']}").json()["uuid"] != old_a
    assert admin.get(f"/api/users/{b['uid']}").json()["uuid"] == old_b
    for uid in (a["uid"], b["uid"]):
        admin.delete(f"/api/users/{uid}")


# ------------------------------------------------------------- quota / expiry
def test_quota_and_expiry_math(admin):
    u = admin.post("/api/users", json={"name": "quota", "quota_gb": 2.5, "expire_days": 7},
                   headers={"Origin": "http://testserver"}).json()["user"]
    assert u["quota_bytes"] == int(2.5 * 1024 ** 3), u["quota_bytes"]
    assert u["expire_at"] and 6 <= u["status"]["days_left"] <= 7, u["status"]
    admin.delete(f"/api/users/{u['uid']}")


def test_zero_quota_means_unlimited(admin):
    u = admin.post("/api/users", json={"name": "unlimited"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    assert u["quota_bytes"] == 0
    assert u["status"]["quota_exceeded"] is False and u["status"]["days_left"] is None
    admin.delete(f"/api/users/{u['uid']}")


def test_allowed_ips_persists(admin):
    """The bug: validated by the handler, dropped by the UPDATE allowlist."""
    u = admin.post("/api/users", json={"name": "pinned"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    r = admin.patch(f"/api/users/{u['uid']}",
                    json={"allowed_ips": ["5.5.5.5", "6.6.6.6"], "max_devices": 2},
                    headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    got = r.json()["user"]
    assert got["allowed_ips"] == ["5.5.5.5", "6.6.6.6"], got["allowed_ips"]
    assert got["max_devices"] == 2
    # it must survive a re-read from SQLite, not just live in the response
    assert admin.get(f"/api/users/{u['uid']}").json()["allowed_ips"] == ["5.5.5.5", "6.6.6.6"]
    admin.delete(f"/api/users/{u['uid']}")


def test_unknown_fields_cannot_be_written(admin):
    """A PATCH must never let a client add arbitrary columns."""
    u = admin.post("/api/users", json={"name": "inject"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    r = admin.patch(f"/api/users/{u['uid']}",
                    json={"password_hash": "x", "is_admin": 1, "name": "renamed"},
                   headers={"Origin": "http://testserver"})
    body = r.json()["user"]
    assert body["name"] == "renamed"
    assert "password_hash" not in body and "is_admin" not in body
    admin.delete(f"/api/users/{u['uid']}")


def test_disabled_user_is_marked_inactive(admin):
    u = admin.post("/api/users", json={"name": "off"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    admin.post(f"/api/users/{u['uid']}/toggle")
    got = admin.get(f"/api/users/{u['uid']}").json()
    assert got["enabled"] == 0 and got["status"]["live_enabled"] is False
    admin.delete(f"/api/users/{u['uid']}")


# ------------------------------------------------------------- subscription
def test_subscription_is_readable_without_login(client, admin, make_user):
    """VPN clients poll this; it is public by design. Lock the contract."""
    u = make_user(name="sub-me", quota_gb=1)
    r = client.get(f"/sub/{u['uid']}")
    assert r.status_code == 200
    links = base64.b64decode(r.text).decode().splitlines()
    assert links, "empty subscription"
    assert any(l.startswith("vless://") for l in links), links[:1]
    assert "subscription-userinfo" in r.headers


def test_public_status_endpoint_leaks_no_secrets(client, admin, make_user):
    u = make_user(name="public-view")
    r = client.get(f"/api/status/{u['uid']}")
    assert r.status_code == 200
    body = r.text
    assert "vless://" not in body and u["uuid"] not in body, body[:200]


def test_unknown_uid_is_404_not_500(client, admin):
    assert admin.get("/sub/does-not-exist").status_code == 404
    assert admin.get("/api/status/does-not-exist").status_code == 404
    assert admin.patch("/api/users/does-not-exist", json={"name": "x"}).status_code == 404
    assert admin.get("/api/users/does-not-exist").status_code == 404
    assert admin.delete("/api/users/does-not-exist").status_code == 404


def test_qr_png(admin):
    u = admin.post("/api/users", json={"name": "qr"},
                   headers={"Origin": "http://testserver"}).json()["user"]
    r = admin.get(f"/api/users/{u['uid']}/qr")
    assert r.status_code == 200 and r.content[:4] == b"\x89PNG"
    admin.delete(f"/api/users/{u['uid']}")
