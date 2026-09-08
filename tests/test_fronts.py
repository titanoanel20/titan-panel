"""External-proxy fronts (the 3x-ui ``externalProxy`` equivalent).

A front is an address the client dials instead of the origin - Railway's TCP
proxy, a CDN edge, a mirror. Every configured front must produce its own links
(and its own subscription entries) without touching the primary ones.
"""
import base64

from app import fronts


def test_a_railway_front_is_cleaned_not_rejected():
    row, err = fronts.normalize({
        "remark": "  Railway raw ",
        "host": " https://ROUNDHOUSE.PROXY.RLWY.NET ",
        "port": "15140",
        "forceTls": "same",
        "sni": "www.speedtest.net",
        "fingerprint": "Chrome",
    })
    assert err is None
    assert row["host"] == "roundhouse.proxy.rlwy.net"
    assert row["port"] == 15140 and row["remark"] == "Railway raw"
    assert row["force_tls"] == "same" and row["fingerprint"] == "chrome"


def test_a_front_needs_a_dialable_host_and_port():
    for bad in ({"host": ""}, {"host": "cdn.example"}, {"host": "cdn.example", "port": 0},
                {"host": "cdn.example", "port": 70000}, {"host": "cdn.example", "port": "http"},
                {"host": "cdn.example", "port": 443, "force_tls": "maybe"},
                {"host": "cdn.example", "port": 443, "sni": "not a host"},
                {"host": "cdn.example", "port": 443, "fingerprint": "netscape"},
                {"host": "cdn.example", "port": 443, "alpn": "h2 ; rm -rf"},
                "just a string"):
        assert fronts.normalize(bad)[1], bad


def test_identical_fronts_collapse_and_a_long_list_is_refused():
    rows, err = fronts.normalize_rows([
        {"host": "cdn.example.com", "port": 443},
        {"host": "CDN.EXAMPLE.COM", "port": "443", "remark": "again"},
    ])
    assert err is None and len(rows) == 1
    many = [{"host": f"a{i}.example.com", "port": 443} for i in range(11)]
    assert fronts.normalize_rows(many) == ([], f"too-many-fronts: {fronts.MAX_FRONTS} max")
    assert fronts.normalize_rows(None) == ([], None)


def test_forcing_tls_rewrites_security_and_the_remark():
    user = {"uuid": "u-1", "name": "Ali", "protocol": "vless", "transport": "tcp",
            "security": "reality"}
    settings = {"sni_override": "panel.example.com", "default_fingerprint": "chrome"}
    row = {"remark": "CDN", "host": "cdn.example.com", "port": 2053, "force_tls": "tls",
           "sni": "www.lost.com", "fingerprint": "firefox", "alpn": "h2"}
    u, s, host, port = fronts.with_front(user, row, settings)
    assert (host, port) == ("cdn.example.com", 2053)
    assert u["security"] == "tls" and u["name"] == "Ali · CDN"
    assert s["sni_override"] == "www.lost.com" and s["default_fingerprint"] == "firefox"
    assert user["security"] == "reality" and settings["default_fingerprint"] == "chrome"

    off = dict(row, force_tls="none", sni="", fingerprint="", alpn="")
    u2, _s2, _h, _p = fronts.with_front(user, off, settings)
    assert u2["security"] == "none"


def test_links_are_built_per_front_without_touching_the_primary(monkeypatch):
    """Reality on the origin must become plain TLS behind a front that cannot
    forward a Reality handshake, and its link must carry the front's SNI."""
    from app import main

    user = {"uid": "x1", "uuid": "u-1", "name": "sara", "protocol": "vless", "transport": "tcp",
            "security": "reality", "enabled": True, "node_id": 0}
    settings = {
        "public_domain": "panel.example.com", "public_port": 443, "default_transport": "ws",
        "default_fingerprint": "chrome", "default_alpn": "http/1.1", "sni_override": "",
        "reality_pub": "PUB", "reality_sid": "00", "reality_sni": "www.speedtest.net",
        "external_proxy_rows": [{"remark": "CDN", "host": "cdn.example.com", "port": 8443,
                                 "force_tls": "tls", "sni": "a.example", "fingerprint": "",
                                 "alpn": ""}],
    }
    monkeypatch.setattr(main.db, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "_public_host", lambda request: "panel.example.com")
    monkeypatch.setattr(main, "_user_endpoint", lambda u, request: ("panel.example.com", 443))
    monkeypatch.setattr(main, "_ensure_wg_user", lambda u: u)
    monkeypatch.setattr(main, "_user_is_remote", lambda u: False)

    primary = main.build_links("panel.example.com", 443, user, settings)["all"][0]
    built = main._links_for(user, None)
    front = built["fronts"][0]["links"][0]
    assert "@panel.example.com:443" in primary
    assert "@cdn.example.com:8443?" in front
    assert "security=reality" in primary and "security=tls" in front
    assert "sni=a.example" in front and "sni=www.speedtest.net" in primary
    assert front.split("#")[-1].endswith("%20%C2%B7%20CDN") or "CDN" in front
    assert built["main"] == primary                    # nothing was displaced
    assert built["fronts"][0]["remark"] == "CDN"


def test_no_rows_means_no_fronts_at_all(monkeypatch):
    """The default deployment must not gain a single extra link."""
    from app import main
    user = {"uid": "x0", "uuid": "u-0", "name": "n", "protocol": "vless", "transport": "ws",
            "security": "tls", "enabled": True, "node_id": 0}
    monkeypatch.setattr(main.db, "get_settings", lambda: {"external_proxy_rows": []})
    monkeypatch.setattr(main, "_public_host", lambda request: "panel.example.com")
    monkeypatch.setattr(main, "_user_endpoint", lambda u, request: ("panel.example.com", 443))
    monkeypatch.setattr(main, "_ensure_wg_user", lambda u: u)
    monkeypatch.setattr(main, "_user_is_remote", lambda u: False)
    assert main._links_for(user, None)["fronts"] == []


def test_settings_api_stores_rows_and_rejects_junk(admin):
    good = [{"remark": "Railway", "host": "roundhouse.proxy.rlwy.net", "port": 15140,
             "force_tls": "same"}]
    r = admin.post("/api/settings", json={"external_proxy_rows": good},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    saved = admin.get("/api/settings").json()["external_proxy_rows"]
    assert saved[0]["host"] == "roundhouse.proxy.rlwy.net" and saved[0]["port"] == 15140

    r = admin.post("/api/settings", json={"external_proxy_rows": [{"host": "x", "port": 0}]},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 400 and "external_proxy_rows" in r.text
    # the bad write must not have damaged the good one
    assert admin.get("/api/settings").json()["external_proxy_rows"][0]["port"] == 15140
    admin.post("/api/settings", json={"external_proxy_rows": []}, headers={"Origin": "http://testserver"})


def test_subscription_carries_one_entry_per_front(admin, make_user):
    from app import db
    saved = db.get_settings().get("external_proxy_rows")
    db.set_settings({"external_proxy_rows": [{"remark": "CDN", "host": "cdn.example.com",
                                             "port": 2053, "force_tls": "tls", "sni": "a.example",
                                             "fingerprint": "", "alpn": ""}]})
    try:
        u = make_user(name="front-me", protocol="vless", transport="tcp", security="tls")
        body = admin.get(f"/sub/{u['uid']}").text
        links = base64.b64decode(body + "=" * (-len(body) % 4)).decode().strip().splitlines()
        assert any("@cdn.example.com:2053" in l for l in links), links
        assert sum(1 for l in links if "cdn.example.com" in l) == 1
        payload = admin.get(f"/sub/{u['uid']}/json").json()
        assert payload["fronts"][0]["host"] == "cdn.example.com"
    finally:
        db.set_settings({"external_proxy_rows": saved or []})


def test_network_status_reports_the_fronts(admin):
    from app import db
    saved = db.get_settings().get("external_proxy_rows")
    db.set_settings({"external_proxy_rows": [{"remark": "Mirror", "host": "m.example.com",
                                             "port": 443, "force_tls": "same"}]})
    try:
        data = admin.get("/api/network/status").json()
        assert data["fronts"] == [{"remark": "Mirror", "host": "m.example.com", "port": 443,
                                   "force_tls": "same", "sni": ""}]
    finally:
        db.set_settings({"external_proxy_rows": saved or []})


def test_the_dead_settings_keys_stay_dead():
    """Removed because nothing ever read them; re-adding one without a consumer
    is what this test is here to catch."""
    from app import config
    for key in ("fragment_packets", "notify_new_conn", "reality_enabled", "lang", "theme"):
        assert key not in config.DEFAULT_SETTINGS, key
