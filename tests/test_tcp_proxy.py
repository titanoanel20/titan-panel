"""Railway TCP-proxy support: endpoint discovery, the first-byte demux, and the
links that must point at the shared raw port instead of the HTTPS edge.

Everything here is tested against real bytes (a ClientHello captured from
Python's own TLS stack) rather than hand-written hex, because the SNI parser is
exactly the kind of code where an off-by-one silently routes every Reality
client into the wrong inbound.
"""
import asyncio
import types
from urllib.parse import parse_qs, urlparse

import pytest

from app import config, tcp_proxy


def _upstream(reply: bytes, *, wait_for_eof: bool = False):
    """A stub inbound: records the bytes it received, answers, then hangs up.

    ``wait_for_eof`` is for the large-payload test, where answering only after
    the whole request has arrived is what makes the assertion deterministic.
    """
    seen = {"got": b"", "port": 0}

    async def handler(reader, writer):
        try:
            if wait_for_eof:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    seen["got"] += chunk
            else:
                seen["got"] += await reader.read(4096)
        except (ConnectionError, OSError):
            pass
        try:
            writer.write(reply)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        try:
            writer.close()
        except (ConnectionError, OSError):
            pass

    return seen, handler


# ------------------------------------------------------------------ discovery
def test_railway_env_is_read(monkeypatch):
    monkeypatch.setenv("RAILWAY_TCP_PROXY_DOMAIN", "roundhouse.proxy.rlwy.net")
    monkeypatch.setenv("RAILWAY_TCP_PROXY_PORT", "11105")
    assert tcp_proxy.railway_endpoint() == ("roundhouse.proxy.rlwy.net", 11105)


@pytest.mark.parametrize("domain,port", [
    ("", "11105"),          # Railway has been seen to inject blanks here
    ("roundhouse.proxy.rlwy.net", ""),
    ("roundhouse.proxy.rlwy.net", "not-a-port"),
    ("roundhouse.proxy.rlwy.net", "70000"),
    ("", ""),
])
def test_missing_or_junk_env_means_no_endpoint(monkeypatch, domain, port):
    """A half-configured proxy must produce *no* endpoint, not a dead link."""
    monkeypatch.setenv("RAILWAY_TCP_PROXY_DOMAIN", domain)
    monkeypatch.setenv("RAILWAY_TCP_PROXY_PORT", port)
    assert tcp_proxy.railway_endpoint() is None


def test_settings_override_env(monkeypatch):
    monkeypatch.setenv("RAILWAY_TCP_PROXY_DOMAIN", "railway.proxy.rlwy.net")
    monkeypatch.setenv("RAILWAY_TCP_PROXY_PORT", "15140")
    assert tcp_proxy.endpoint_for({}) == ("railway.proxy.rlwy.net", 15140)
    assert tcp_proxy.endpoint_source({}) == "railway"
    over = {"tcp_proxy_host": "vpn.example.com", "tcp_proxy_port": "2083"}
    assert tcp_proxy.endpoint_for(over) == ("vpn.example.com", 2083)
    assert tcp_proxy.endpoint_source(over) == "settings"
    # an address, a path and a trailing dot all normalise to a bare hostname
    assert tcp_proxy.endpoint_for({"tcp_proxy_host": "https://VPN.example.com:2083/x",
                                   "tcp_proxy_port": 2083}) == ("vpn.example.com", 2083)
    # A half-entered setting (host, no port) is unusable, so the platform value
    # wins instead -- and endpoint_source still says "railway", i.e. the card
    # never claims a setting is in effect that is being ignored.
    assert tcp_proxy.endpoint_for({"tcp_proxy_host": "vpn.example.com"}) == (
        "railway.proxy.rlwy.net", 15140)
    assert tcp_proxy.endpoint_source({"tcp_proxy_host": "vpn.example.com"}) == "railway"
    monkeypatch.delenv("RAILWAY_TCP_PROXY_DOMAIN")
    monkeypatch.delenv("RAILWAY_TCP_PROXY_PORT")
    assert tcp_proxy.endpoint_for({"tcp_proxy_host": "vpn.example.com"}) is None


def test_env_override_for_other_platforms(monkeypatch):
    monkeypatch.delenv("RAILWAY_TCP_PROXY_DOMAIN", raising=False)
    monkeypatch.delenv("RAILWAY_TCP_PROXY_PORT", raising=False)
    monkeypatch.setenv("TITAN_TCP_PROXY_HOST", "raw.edge.render.com")
    monkeypatch.setenv("TITAN_TCP_PROXY_PORT", "17000")
    assert tcp_proxy.endpoint_for({}) == ("raw.edge.render.com", 17000)
    assert tcp_proxy.endpoint_source({}) == "env"


def test_application_port_drives_the_listen_port(monkeypatch):
    """Railway names the port it forwards to; matching it avoids the classic
    mismatch where the proxy targets PORT (nginx) instead of the VPN inbound."""
    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", "25565")
    assert tcp_proxy.railway_application_port() == 25565
    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", "garbage")
    assert tcp_proxy.railway_application_port() is None


def test_config_int_env_survives_garbage(monkeypatch):
    monkeypatch.setenv("TITAN_RAW_ENTRY_PORT", "")
    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", "40000")
    assert config._int_env("TITAN_RAW_ENTRY_PORT", "RAILWAY_TCP_APPLICATION_PORT",
                           default=config.DEFAULT_RAW_ENTRY_PORT) == 40000
    monkeypatch.setenv("RAILWAY_TCP_APPLICATION_PORT", "99999999")
    assert config._int_env("TITAN_RAW_ENTRY_PORT", "RAILWAY_TCP_APPLICATION_PORT",
                           default=config.DEFAULT_RAW_ENTRY_PORT) == config.DEFAULT_RAW_ENTRY_PORT


# ------------------------------------------------------------------ demux
def test_classify_http_before_tls():
    assert tcp_proxy.classify(b"GET /health HTTP/1.1\r\n")[0] == "http"
    assert tcp_proxy.classify(b"POST /api/login HTTP/1.1\r\n")[0] == "http"
    assert tcp_proxy.classify(b"") == ("raw", "")
    assert tcp_proxy.classify(b"\x05\x06random binary")[0] == "raw"


def test_sni_from_a_real_client_hello(client_hello):
    hello = client_hello("www.speedtest.net")
    kind, sni = tcp_proxy.classify(hello)
    assert kind == "tls"
    assert sni == "www.speedtest.net"          # a length-field off-by-one ate a 'w' once
    assert tcp_proxy.extract_sni(hello[:80]) == ""   # header survives, name not present


def test_extract_sni_never_raises_on_junk():
    junk = [b"\x16", b"\x16\x03", b"\x16\x03\x03\xff\xff", b"\x16\x03\x01\x00\x05\x01\x00",
            bytes(range(64)), b"\x16\x03\x03\x00\x0a\x01\x00\x00\x06\x03\x03",
            b"\x16\x03\x03\x7f\xff" + b"\x00" * 40]
    for data in junk:
        assert tcp_proxy.extract_sni(data) == ""


def test_router_sends_unmatched_sni_to_tls_and_known_sni_to_reality():
    routes = tcp_proxy.build_routes(http_target=("127.0.0.1", 1), tls_target=("127.0.0.1", 2),
                                    reality_target=("127.0.0.1", 3), raw_target=("127.0.0.1", 4))
    router = tcp_proxy.RawEntry(routes, reality_snis=("www.speedtest.net",))
    assert router.route_for("tls", "www.speedtest.net")[1] == 3
    assert router.route_for("tls", "other.example")[1] == 2
    assert router.route_for("tls", "")[1] == 2          # split ClientHello, SNI not yet seen
    assert router.route_for("http", "")[1] == 1
    assert router.route_for("raw", "")[1] == 4
    # with no TLS inbound configured, an unknown SNI must still reach Reality
    only_reality = tcp_proxy.RawEntry({"http": ("127.0.0.1", 1), "reality": ("127.0.0.1", 3)},
                                      reality_snis=("s",))
    assert only_reality.route_for("tls", "")[1] == 3


def test_build_routes_falls_back_for_missing_classes():
    routes = tcp_proxy.build_routes(http_target=("h", 1), tls_target=("t", 2))
    assert routes["raw"] == ("t", 2)          # no plain inbound -> share the TLS one
    assert "reality" not in routes


# ------------------------------------------------------------------ end to end
def _run_router_test(payloads, *, reality_sni="www.speedtest.net", wait_for_eof=False,
                   half_close=False):
    """Boot a router with four stub inbounds and return what each received."""
    stubs = {}
    for key, reply in (("http", b"PANEL"), ("tls", b"TLS-INBOUND"),
                       ("reality", b"REALITY-INBOUND"), ("raw", b"PLAIN-INBOUND")):
        seen, handler = _upstream(reply, wait_for_eof=wait_for_eof)
        stubs[key] = seen
        stubs[key + "_srv"] = handler

    async def _run():
        servers = {}
        for key in ("http", "tls", "reality", "raw"):
            servers[key] = await asyncio.start_server(stubs[key + "_srv"], "127.0.0.1", 0)
            stubs[key]["port"] = servers[key].sockets[0].getsockname()[1]
        routes = {k: ("127.0.0.1", stubs[k]["port"]) for k in servers}
        router = tcp_proxy.RawEntry(routes, host="127.0.0.1", port=0,
                                    reality_snis=(reality_sni,), peek_timeout=0.5)
        await router.serve()
        results = []
        for data in payloads:
            reader, writer = await asyncio.open_connection("127.0.0.1", router.bound_port)
            writer.write(data)
            await writer.drain()
            if half_close:
                # A VPN client never does this, but it is the only way to prove
                # the router propagates a half-close instead of deadlocking, and
                # it lets the stub answer after the full payload landed.
                assert writer.can_write_eof()
                writer.write_eof()
            reply = await asyncio.wait_for(reader.read(4096), timeout=5)
            results.append(reply)
            writer.close()
        await asyncio.sleep(0.2)          # let the stubs record the bytes
        for s in servers.values():
            s.close()
        await router.stop()
        return results, router.stats()

    results, stats = asyncio.run(_run())
    return results, stubs, stats


def test_router_forwards_every_class_byte_for_byte(client_hello):
    hello = client_hello("www.speedtest.net")
    other = client_hello("example.com")
    payloads = [b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", hello, other, b"\x01\x02\x03plain"]
    results, stubs, stats = _run_router_test(payloads)

    assert results == [b"PANEL", b"REALITY-INBOUND", b"TLS-INBOUND", b"PLAIN-INBOUND"]
    assert stubs["http"]["got"] == payloads[0]
    # nothing may be dropped or added: Reality's handshake breaks on one stray byte
    assert stubs["reality"]["got"] == hello
    assert stubs["tls"]["got"] == other
    assert stubs["raw"]["got"] == b"\x01\x02\x03plain"
    assert stats["by_kind"] == {"http": 1, "tls": 2, "raw": 1}
    assert stats["connections"] == 4
    assert stats["recent_errors"] == []


def test_router_keeps_streaming_both_directions():
    """A VPN connection is long-lived; the router must not stop after the peek."""
    payload = b"GET /x HTTP/1.1\r\n\r\n" + b"A" * 200000
    results, stubs, _ = _run_router_test([payload], wait_for_eof=True, half_close=True)
    assert results == [b"PANEL"]
    assert len(stubs["http"]["got"]) == len(payload)
    assert stubs["http"]["got"] == payload      # the peeked prefix is re-sent, not swallowed


def test_router_reports_a_dead_upstream_instead_of_crashing(client=None):
    payloads = [b"\x01nope"]

    async def _run():
        router = tcp_proxy.RawEntry({"raw": ("127.0.0.1", 1), "http": ("127.0.0.1", 1),
                                     "tls": ("127.0.0.1", 1)},
                                    host="127.0.0.1", port=0, peek_timeout=0.2)
        await router.serve()
        reader, writer = await asyncio.open_connection("127.0.0.1", router.bound_port)
        writer.write(payloads[0])
        await writer.drain()
        got = await asyncio.wait_for(reader.read(100), timeout=3)
        await router.stop()
        return got, router.stats()

    got, stats = asyncio.run(_run())
    assert got == b""                                   # client is closed, not hung
    assert stats["recent_errors"] and "unreachable" in stats["recent_errors"][0]


# ------------------------------------------------------------------ links
def _settings_with_proxy(**extra):
    return {"tcp_proxy_host": "roundhouse.proxy.rlwy.net", "tcp_proxy_port": 11105,
            "public_domain": "panel.example.com", "public_port": 443,
            "default_transport": "ws", "default_fingerprint": "chrome",
            "default_alpn": "http/1.1", "reality_enabled": True, "reality_sni": "www.speedtest.net",
            **extra}


def test_reality_link_dials_the_proxy_not_the_https_edge():
    from app import links
    settings = _settings_with_proxy()
    host, port = "roundhouse.proxy.rlwy.net", 11105
    user = {"uuid": "u-" * 4 + "1", "name": "Ali", "protocol": "vless",
            "transport": "tcp", "security": "reality", "spider_x": ""}
    link = links.build_vless_link(host, port, user, {**settings, "reality_pub": "PUBKEY",
                                                      "reality_sid": "01234567"})
    assert f"@{host}:{port}?" in link
    assert "security=reality" in link and "type=tcp" in link
    assert "up.railway.app" not in link and ":443" not in link


def test_ws_links_stay_on_the_https_edge(monkeypatch):
    """The proxy port carries raw bytes only; a WebSocket link pointed at it dies."""
    from app import main
    user = {"uid": "x", "name": "sara", "protocol": "vless", "transport": "ws",
            "security": "tls", "enabled": True, "node_id": 0}
    monkeypatch.setattr(main.tcp_proxy, "endpoint_for", lambda s: ("roundhouse.proxy.rlwy.net", 11105))
    with monkeypatch.context() as m:
        m.setattr(main.db, "get_settings", lambda: _settings_with_proxy())
        m.setattr(main, "_public_host", lambda request: "panel.example.com")
        host, port = main._user_endpoint(user, None)
    assert (host, port) == ("panel.example.com", 443)


def test_which_users_may_use_the_shared_raw_port():
    from app import main
    base = {"uid": "x", "name": "n", "enabled": True, "node_id": 0, "transport": "tcp",
            "security": "reality"}
    settings = _settings_with_proxy()
    assert main._raw_linkable({**base}, settings) is True                     # vless+tcp
    assert main._raw_linkable({**base, "protocol": "vmess", "security": "tls"}, settings) is False
    assert main._raw_linkable({**base, "protocol": "trojan", "security": "tls"}, settings) is False
    assert main._raw_linkable({**base, "protocol": "shadowsocks"}, settings) is False
    assert main._raw_linkable({**base, "protocol": "shadowsocks"},
                              _settings_with_proxy(raw_default_inbound="shadowsocks")) is True
    assert main._raw_linkable({**base, "transport": "ws"}, settings) is False


def test_tcp_user_endpoint_actually_moves_to_the_proxy(monkeypatch):
    """The predicate is only useful if _user_endpoint honours it."""
    from app import main
    proxy = ("roundhouse.proxy.rlwy.net", 11105)
    monkeypatch.setattr(main.tcp_proxy, "endpoint_for", lambda s: proxy)
    with monkeypatch.context() as m:
        m.setattr(main.db, "get_settings", lambda: _settings_with_proxy())
        m.setattr(main, "_public_host", lambda request: "panel.example.com")
        reality = {"uid": "x", "name": "n", "protocol": "vless", "transport": "tcp",
                   "security": "reality", "enabled": True, "node_id": 0}
        assert main._user_endpoint(reality, None) == proxy
        vmess = {**reality, "protocol": "vmess", "security": "tls"}
        host, port = main._user_endpoint(vmess, None)
        assert (host, port) == ("panel.example.com", config.XRAY_TCP_VMESS_TLS_PORT)


def test_report_warns_when_railway_has_no_tcp_proxy(monkeypatch):
    from app import main
    monkeypatch.setattr(config, "IS_RAILWAY", True)
    monkeypatch.delenv("RAILWAY_TCP_PROXY_DOMAIN", raising=False)
    monkeypatch.delenv("RAILWAY_TCP_PROXY_PORT", raising=False)
    monkeypatch.delenv("TITAN_TCP_PROXY_HOST", raising=False)
    monkeypatch.delenv("TITAN_TCP_PROXY_PORT", raising=False)
    monkeypatch.setattr(main, "_raw_round_trip", _fake_round_trip)

    report = asyncio.run(main._network_report({}))
    assert report["tcp_proxy"]["endpoint"] == ""
    assert any("TCP proxy" in w for w in report["warnings"])
    assert report["udp"]["note"].lower().count("udp") >= 1


async def _fake_round_trip():
    return {"checked": False, "listening": False, "round_trip_ok": False, "detail": "",
            "upstream": "", "bytes_back": 0}


def test_raw_entry_autostart_decision_is_platform_aware(monkeypatch):
    from app import main
    monkeypatch.setattr(config, "IS_RAILWAY", False)
    assert main._raw_entry_wanted({}) is False                      # VPS: keep 1:1 ports
    assert main._raw_entry_wanted(_settings_with_proxy()) is True   # proxy detected
    assert main._raw_entry_wanted({"raw_entry_mode": "off",
                                   **_settings_with_proxy()}) is False
    monkeypatch.setattr(config, "IS_RAILWAY", True)
    assert main._raw_entry_wanted({"raw_entry_mode": "auto"}) is True
    assert main._raw_entry_wanted({"raw_entry_mode": "off"}) is False


def test_routes_point_at_the_real_inbound_ports(monkeypatch):
    from app import main
    routes = main._raw_entry_routes({"raw_default_inbound": "shadowsocks"})
    assert routes["tls"] == ("127.0.0.1", config.XRAY_TCP_VLESS_TLS_PORT)
    assert routes["reality"] == ("127.0.0.1", config.XRAY_TCP_VLESS_REALITY_PORT)
    assert routes["raw"] == ("127.0.0.1", config.XRAY_SS_PORT)
    assert routes["http"] == ("127.0.0.1", config.PANEL_PORT)
    snis = main._reality_snis({"reality_sni": "WWW.Speedtest.NET"})
    assert snis[0] == "www.speedtest.net"              # normalised, setting first
    assert config.REALITY_SNI.lower() in snis          # the inbound's own name too
    assert len(snis) == len(set(snis))                 # no duplicates


def test_settings_endpoints_are_gated_and_validate_values(admin):
    before = admin.get("/api/settings").json()
    assert "tcp_proxy_host" in before and "raw_entry_mode" in before
    r = admin.post("/api/network/selftest", headers={"Origin": "http://testserver"})
    assert r.status_code in (200, 403, 409)      # 403 = cross-origin guard, not a 500
    try:
        r = admin.post("/api/settings", json={"raw_entry_mode": "banana", "tcp_proxy_port": "99999"},
                       headers={"Origin": "http://testserver"})
        assert r.status_code == 200
        after = r.json()["settings"]
        assert after["raw_entry_mode"] == before.get("raw_entry_mode", "auto")   # junk rejected
        assert after["tcp_proxy_port"] == 0                                       # out of range clamped
    finally:
        admin.post("/api/settings", json={k: before[k] for k in
                   ("tcp_proxy_host", "tcp_proxy_port", "raw_entry_mode", "raw_default_inbound")
                   if k in before}, headers={"Origin": "http://testserver"})


def test_network_status_needs_auth(client):
    client.cookies.clear()
    r = client.get("/api/network/status")
    assert r.status_code in (307, 401, 403)


def test_health_advertises_the_raw_entry(admin):
    r = admin.get("/health")
    assert r.status_code == 200
    assert "raw_tcp" in r.json()


def test_links_never_bake_in_a_host_the_client_cannot_dial(monkeypatch):
    """Opening the panel on 127.0.0.1 (probe, docker -p, the raw port) used to
    write @127.0.0.1 into every link. Railway tells us the real domain, so use
    it; a self-host deploy with no such hint keeps the request host untouched."""
    from app import main
    monkeypatch.setattr(main.db, "get_settings", lambda: {"public_domain": ""})
    Req = types.SimpleNamespace(headers={"host": "127.0.0.1:8123"},
                                url=types.SimpleNamespace(hostname="127.0.0.1"))

    monkeypatch.delenv("RAILWAY_PUBLIC_DOMAIN", raising=False)
    assert main._usable_public_host("127.0.0.1") is False
    assert main._usable_public_host("10.0.0.5") is True       # LAN: the admin's choice
    assert main._usable_public_host("vpn.example.com") is True
    assert main._public_host(Req) == "127.0.0.1"            # no better hint -> unchanged
    monkeypatch.setenv("RAILWAY_PUBLIC_DOMAIN", "titan.up.railway.app")
    assert main._public_host(Req) == "titan.up.railway.app"
    monkeypatch.setattr(main.db, "get_settings", lambda: {"public_domain": "panel.example.com"})
    assert main._public_host(Req) == "panel.example.com"    # explicit setting still wins


def test_the_api_and_subscription_actually_carry_the_proxy_endpoint(admin, db):
    """End to end through the real endpoints a client uses -- not just the builder.

    A link that is right in `links.py` but wrong in `/sub/<uid>` is still a
    broken customer, and the subscription is how most clients are configured.
    """
    import base64

    keys = ("tcp_proxy_host", "tcp_proxy_port", "default_transport", "public_domain")
    saved = {k: db.get_settings().get(k) for k in keys}
    db.set_settings({"tcp_proxy_host": "roundhouse.proxy.rlwy.net", "tcp_proxy_port": 11105,
                     "public_domain": ""})
    try:
        r = admin.post("/api/users", json={"name": "raw-e2e", "protocol": "vless", "transport": "tcp",
                                           "security": "reality", "quota_gb": 1},
                       headers={"Origin": "http://testserver"})
        assert r.status_code == 200, r.text
        uid = r.json()["user"]["uid"]
        try:
            main = r.json()["user"]["main_link"]
            assert "roundhouse.proxy.rlwy.net:11105" in main, main
            assert "security=reality" in main, main
            payload = admin.get(f"/api/users/{uid}/links").json()
            again = (payload.get("user") or payload)["main_link"]   # flat or wrapped
            assert again == main, (again, main)          # stable across requests
            sub = admin.get(f"/sub/{uid}")
            decoded = base64.b64decode(sub.text).decode()
            assert "roundhouse.proxy.rlwy.net:11105" in decoded, decoded[:200]
        finally:
            admin.delete(f"/api/users/{uid}")
    finally:
        db.set_settings(saved)
        assert db.get_settings()["tcp_proxy_host"] == saved["tcp_proxy_host"]


def test_the_status_card_lists_the_raw_entry_and_its_verdict(admin):
    r = admin.get("/api/network/status", headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    d = r.json()
    for key in ("platform", "tcp_proxy", "round_trip", "reality", "udp", "warnings", "protocols"):
        assert key in d, key
    assert d["platform"] in ("railway", "self-host")
    # no proxy is configured in the test deploy, and this is not Railway
    assert d["tcp_proxy"]["endpoint"] == ""
    assert "Hysteria2" in d["udp"]["note"] or "UDP" in d["udp"]["note"]
    assert d["protocols"]["hysteria2_wireguard"].lower().startswith("udp")


# ------------------------------------------------------------------ anti-DPI params
def test_raw_links_carry_the_fragment_settings(admin, db):
    """Fragmenting the ClientHello is the documented Irancell/MCI workaround, so it
    has to be on the *raw* links - that is where the DPI actually breaks the
    handshake. Before this, only WS links carried the knobs."""
    keys = ("tcp_proxy_host", "tcp_proxy_port", "public_domain", "raw_entry_mode",
            "fragment_enabled", "fragment_length", "fragment_interval")
    saved = {k: db.get_settings().get(k) for k in keys}
    db.set_settings({"tcp_proxy_host": "roundhouse.proxy.rlwy.net", "tcp_proxy_port": 11105,
                     "public_domain": "", "raw_entry_mode": "on",
                     "fragment_enabled": True, "fragment_length": "10-100", "fragment_interval": "1-5"})
    try:
        r = admin.post("/api/users", json={"name": "frag", "protocol": "vless", "transport": "tcp",
                                           "security": "reality", "quota_gb": 1},
                       headers={"Origin": "http://testserver"})
        assert r.status_code == 200, r.text
        uid = r.json()["user"]["uid"]
        try:
            main = r.json()["user"]["main_link"]
            q = parse_qs(urlparse(main).query)
            assert q["fp_len"] == ["10-100"], main
            assert q["fp_int"] == ["1-5"], main
            assert "roundhouse.proxy.rlwy.net" in main and "security=reality" in main, main
            assert q["fp"] == ["chrome"], main          # fingerprint untouched by the change
            # the same knobs still reach the WS link, spelled identically
            payload = admin.get(f"/api/users/{uid}/links").text
            assert "fp_len=10-100" in payload and "fp_int=1-5" in payload
        finally:
            admin.delete(f"/api/users/{uid}", headers={"Origin": "http://testserver"})
    finally:
        db.set_settings(saved)


def test_no_fragment_params_when_the_setting_is_off(admin, db):
    """Default behaviour must not change: no magic params in a normal link."""
    keys = ("tcp_proxy_host", "tcp_proxy_port", "public_domain", "raw_entry_mode", "fragment_enabled")
    saved = {k: db.get_settings().get(k) for k in keys}
    db.set_settings({"tcp_proxy_host": "roundhouse.proxy.rlwy.net", "tcp_proxy_port": 11105,
                     "public_domain": "", "raw_entry_mode": "on", "fragment_enabled": False})
    try:
        r = admin.post("/api/users", json={"name": "nofrag", "protocol": "vless", "transport": "tcp",
                                           "security": "reality", "quota_gb": 1},
                       headers={"Origin": "http://testserver"})
        uid = r.json()["user"]["uid"]
        try:
            assert "fp_len" not in r.json()["user"]["main_link"], r.json()["user"]["main_link"]
        finally:
            admin.delete(f"/api/users/{uid}", headers={"Origin": "http://testserver"})
    finally:
        db.set_settings(saved)


def test_report_names_the_dead_http_target(admin, monkeypatch):
    """A raw entry that forwards to a port nobody listens on looks like "blocked by
    the operator" from the client side, so the report has to name the misroute."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    dead_port = free + 1                       # the port right after a bound one: not listening
    stub = types.SimpleNamespace(bound_port=free, server=object(), errors=[],
                                 routes={"http": ("127.0.0.1", dead_port)},
                                 stats=lambda: {"recent_errors": []})
    monkeypatch.setattr(admin.app.state, "raw_entry", stub, raising=False)
    d = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
    hits = [w for w in d["warnings"] if str(dead_port) in w and "PANEL_PORT" in w]
    assert hits, d["warnings"]
    assert d["round_trip"]["checked"] is True and d["round_trip"]["round_trip_ok"] is False


def test_no_reality_users_means_no_dead_handshake_warning(admin, db):
    """The soft note must not read like the hard one: "no reality users" is a to-do,
    "users hold links with no keypair" is an outage."""
    d = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
    assert not any("already hold Reality links" in w for w in d["warnings"]), d["warnings"]


def test_reality_report_matches_what_xray_actually_serves(admin, db):
    """The inbound exists iff a keypair exists and someone uses Reality. The stored
    `reality_enabled` flag is not read by the config generator, so reporting it as
    the serving state makes a working panel look broken."""
    metas = ("reality_priv", "reality_pub")
    saved = {k: db.get_meta(k) for k in metas}
    c = db._connect()
    try:
        db.set_meta("reality_priv", "PRIV")
        db.set_meta("reality_pub", "PUB")
        r = admin.post("/api/users", json={"name": "serving", "protocol": "vless", "transport": "tcp",
                                           "security": "reality", "quota_gb": 1},
                       headers={"Origin": "http://testserver"})
        uid = r.json()["user"]["uid"]
        try:
            d = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
            assert d["reality"]["enabled"] is True, d["reality"]
            assert d["reality"]["reality_users"] >= 1
            assert d["reality"]["keypair"] is True
            assert d["reality"]["reality_enabled_setting"] in (True, False)  # stored flag, unused
        finally:
            admin.delete(f"/api/users/{uid}", headers={"Origin": "http://testserver"})
    finally:
        for k, v in saved.items():
            if v is None:
                c.execute("DELETE FROM meta WHERE key=?", (k,))   # meta.value is NOT NULL
            else:
                db.set_meta(k, v)
        c.commit()


def test_reality_users_without_a_keypair_are_reported_as_dead(admin, db):
    metas = ("reality_priv", "reality_pub")
    saved = {k: db.get_meta(k) for k in metas}
    c = db._connect()
    for k in metas:
        c.execute("DELETE FROM meta WHERE key=?", (k,))
    c.commit()
    r = admin.post("/api/users", json={"name": "orphan", "protocol": "vless", "transport": "tcp",
                                       "security": "reality", "quota_gb": 1},
                   headers={"Origin": "http://testserver"})
    uid = r.json()["user"]["uid"]
    try:
        d = admin.get("/api/network/status", headers={"Origin": "http://testserver"}).json()
        assert d["reality"]["enabled"] is False and d["reality"]["keypair"] is False
        hits = [w for w in d["warnings"] if "already hold Reality links" in w]
        assert hits and hits[0].startswith("1 user"), d["warnings"]
        assert not any("not in use yet" in w for w in d["warnings"]), d["warnings"]
    finally:
        admin.delete(f"/api/users/{uid}", headers={"Origin": "http://testserver"})
        for k, v in saved.items():
            if v is None:
                c.execute("DELETE FROM meta WHERE key=?", (k,))
            else:
                db.set_meta(k, v)
        c.commit()
