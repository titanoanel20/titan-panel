"""Pinning the Reality keypair, so a Railway redeploy cannot kill every client.

Why this exists: on Railway without a Volume the container filesystem (and with
it `titan.db`) is thrown away on each deploy. The panel then regenerates the
Reality keypair while every link the admin already published still carries the
old `pbk` -- every Reality client starts timing out at once, which looks exactly
like operator blocking. Pinning a key (env or UI) makes the keypair survive.
"""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app import reality


def _new_keypair() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    enc = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")  # noqa: E731
    return enc(priv.private_bytes_raw()), enc(priv.public_key().public_bytes_raw())


# ------------------------------------------------------------------ parsing
def test_public_key_is_derived_without_the_xray_binary():
    priv, expected = _new_keypair()
    assert reality.public_for(priv) == expected


def test_padded_input_is_accepted_too():
    priv, expected = _new_keypair()
    padded = base64.urlsafe_b64encode(base64.urlsafe_b64decode(priv + "=")).decode()
    assert reality.public_for(padded) == expected


@pytest.mark.parametrize("bad", [
    "", "   ", "not base64 at all !!!", "YWJj",                  # 3 bytes
    base64.urlsafe_b64encode(b"\x00" * 31).decode().rstrip("="),  # too short
    base64.urlsafe_b64encode(b"\x00" * 33).decode().rstrip("="),  # too long
])
def test_junk_key_is_rejected_as_a_client_error(bad):
    with pytest.raises(reality.BadKey):
        reality.public_for(bad)


# ------------------------------------------------------------------ storage
@pytest.fixture()
def pristine_reality(db):
    """Restore every piece of Reality state a test may touch.

    `meta.value` is NOT NULL, so "this key did not exist yet" cannot be undone
    with `set_meta(key, None)` - the missing rows are deleted again instead.
    """
    metas = ("reality_priv", "reality_pub", "reality_sid", "reality_priv_source")
    keys = ("reality_pub", "reality_sid", "reality_sni", "reality_dest")
    before_meta = {k: db.get_meta(k) for k in metas}
    before_set = {k: db.get_settings().get(k) for k in keys}
    yield
    c = db._connect()
    for k, v in before_meta.items():
        if v is None:
            c.execute("DELETE FROM meta WHERE key=?", (k,))
        else:
            db.set_meta(k, v)
    c.commit()
    for k, v in before_set.items():
        db.set_setting(k, v)


def test_pinning_writes_the_public_key_everywhere_links_read_it(admin, db, pristine_reality):
    priv, pub = _new_keypair()
    r = admin.post("/api/reality/key", json={"private_key": priv, "sni": "www.speedtest.net"},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pub"] == pub
    assert body["pinned"] is True
    assert "private_key" not in body and priv not in r.text     # never echo the secret
    assert db.get_settings()["reality_pub"] == pub              # link builder input
    assert db.get_meta("reality_pub") == pub                    # xray inbound input
    assert db.get_settings()["reality_sni"] == "www.speedtest.net"
    assert reality.key_source() == "pinned"


def test_a_pinned_key_changes_the_generated_links(admin, db, pristine_reality):
    """The whole point: links carry the pbk the inbound actually answers to."""
    priv, pub = _new_keypair()
    assert admin.post("/api/reality/key", json={"private_key": priv},
                      headers={"Origin": "http://testserver"}).status_code == 200
    r = admin.post("/api/users", json={"name": "pinned-check", "protocol": "vless",
                                       "transport": "tcp", "security": "reality", "quota_gb": 1},
                   headers={"Origin": "http://testserver"})
    uid = r.json()["user"]["uid"]
    try:
        link = r.json()["user"]["main_link"]
        assert f"pbk={pub}" in link, link
        assert "security=reality" in link and "flow=xtls-rprx-vision" in link
    finally:
        admin.delete(f"/api/users/{uid}")


def test_the_private_key_never_reaches_the_audit_log(admin, db, pristine_reality):
    priv, _pub = _new_keypair()
    admin.post("/api/reality/key", json={"private_key": priv},
               headers={"Origin": "http://testserver"})
    admin.post("/api/reality/key", json={"private_key": "garbage!!"},
               headers={"Origin": "http://testserver"})
    events = admin.get("/api/events?limit=50").json()["events"]
    assert any(e["action"] == "reality-key-pinned" for e in events), events[:3]
    blob = str(events)
    assert priv not in blob, "key material leaked into the event log"
    assert "garbage!!" not in blob, "rejected input echoed verbatim"


def test_bad_key_is_400_and_changes_nothing(admin, db, pristine_reality):
    before = db.get_settings()["reality_pub"]
    r = admin.post("/api/reality/key", json={"private_key": "short!"},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 400, r.text
    assert "invalid-private-key" in r.json()["detail"]
    assert db.get_settings()["reality_pub"] == before


def test_pinning_requires_a_credential(client):
    client.cookies.clear()
    r = client.post("/api/reality/key", json={"private_key": "x"})
    assert r.status_code in (307, 401, 403)


# ------------------------------------------------------------------ report
def test_report_says_the_key_is_pinned(admin, db, pristine_reality):
    priv, pub = _new_keypair()
    assert admin.post("/api/reality/key", json={"private_key": priv},
                      headers={"Origin": "http://testserver"}).status_code == 200
    d = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
    assert d["reality"]["key_source"] == "pinned"
    assert d["reality"]["public_key"] == pub      # the public half is meant to be public
    assert priv not in json.dumps(d)               # the private half is not


def test_report_warns_about_the_ephemeral_filesystem(admin, monkeypatch, db, pristine_reality):
    from app import config

    monkeypatch.setattr(config, "IS_RAILWAY", True)
    monkeypatch.delenv("RAILWAY_VOLUME_NAME", raising=False)
    db.set_meta("reality_priv_source", "")          # not pinned
    db.set_meta("reality_priv", "generated-key")     # a key exists, but it is ephemeral
    d = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
    assert any("Volume" in w and "pbk" in w for w in d["warnings"]), d["warnings"]
    monkeypatch.setenv("RAILWAY_VOLUME_NAME", "titan-data")
    d2 = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
    assert not any("Volume" in w for w in d2["warnings"]), d2["warnings"]
