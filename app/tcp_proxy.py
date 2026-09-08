"""Railway "TCP Proxy" support: endpoint discovery + a raw-TCP entry multiplexer.

Why this module exists
----------------------
On Railway the only socket that reaches the container is the one behind the
HTTPS edge, so every link the panel generates dials ``<service>.up.railway.app:443``
and rides a WebSocket path through that edge. Mobile operators in Iran filter
exactly that shape of traffic by SNI/domain, which is why the same config can
work on MCI and time out on Irancell (the TCP handshake looks fine to ping, the
TLS handshake never completes).

Railway's TCP Proxy (service Settings -> Networking -> TCP Proxy) forwards *raw*
bytes to one internal port: nothing terminates TLS on the way, so the SNI a
Reality client presents is the SNI the operator's DPI sees. This module resolves
that endpoint (so links can point at it) and runs the small first-byte router
that lets the single forwarded port serve every raw inbound the panel owns.

Hard constraints this design has to live with (all verified against Railway's
own docs as of 2026-09):
  * one TCP proxy per service, i.e. ONE internal port -> hence the router;
  * ``RAILWAY_TCP_PROXY_DOMAIN`` / ``RAILWAY_TCP_PROXY_PORT`` may be empty even
    when a proxy exists (a known Railway hiccup), so explicit settings win;
  * the proxy is TCP only -- no UDP, so Hysteria2/WireGuard can never work here;
  * the proxy does not send PROXY protocol, so the real client IP is not
    available on the raw path (per-user IP pinning stays a VPS-only feature).
"""
import asyncio
import contextlib
import logging
import os
import time

log = logging.getLogger("titan.tcp_proxy")

# Railway-injected variables (docs: Variables Reference).
ENV_DOMAIN = "RAILWAY_TCP_PROXY_DOMAIN"
ENV_PORT = "RAILWAY_TCP_PROXY_PORT"
ENV_APP_PORT = "RAILWAY_TCP_APPLICATION_PORT"
# Operator-provided overrides, for Render/Fly/a VPS in front of a raw TCP proxy.
ENV_OVERRIDE_HOST = "TITAN_TCP_PROXY_HOST"
ENV_OVERRIDE_PORT = "TITAN_TCP_PROXY_PORT"

MAX_PEEK_BYTES = 4096
PEEK_TIMEOUT = 0.75


def _clean_host(value) -> str:
    """Normalise a hostname: strip scheme, path, port and brackets."""
    host = str(value or "").strip()
    if not host:
        return ""
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip()
    if host.startswith("["):  # [::1]:1234
        end = host.find("]")
        if end != -1:
            return host[1:end]
    if ":" in host:
        head, _, tail = host.rpartition(":")
        if tail.isdigit():
            host = head
    return host.strip().strip(".").lower()


def _port(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


# ------------------------------------------------------------------ discovery
def railway_endpoint() -> tuple[str, int] | None:
    """``(host, port)`` from Railway's TCP proxy env vars, or None.

    Empty values are treated as "not configured": Railway is known to inject
    blanks for these two variables even with a proxy attached, and a blank
    would produce a link that dials an empty hostname.
    """
    host = _clean_host(os.environ.get(ENV_DOMAIN))
    port = _port(os.environ.get(ENV_PORT))
    if not host or port is None:
        return None
    return host, port


def railway_application_port() -> int | None:
    """The internal port Railway forwards to, if it tells us.

    The panel listens for raw traffic on exactly this port, which removes the
    classic Railway foot-gun where the proxy's target port and the app's port
    disagree (Railway resolves the target from PORT if you set one yourself).
    """
    return _port(os.environ.get(ENV_APP_PORT))


def endpoint_for(settings: dict | None) -> tuple[str, int] | None:
    """Where a raw-TCP client should dial: panel setting, then env, then Railway.

    Settings win because the panel's UI is the operator's escape hatch when the
    platform metadata is missing or stale.
    """
    settings = settings or {}
    host = _clean_host(settings.get("tcp_proxy_host"))
    port = _port(settings.get("tcp_proxy_port"))
    if host and port is not None:
        return host, port
    env_host = _clean_host(os.environ.get(ENV_OVERRIDE_HOST))
    env_port = _port(os.environ.get(ENV_OVERRIDE_PORT))
    if env_host and env_port is not None:
        return env_host, env_port
    return railway_endpoint()


def endpoint_source(settings: dict | None) -> str:
    """Which layer supplied the endpoint -- shown in the panel's network card."""
    settings = settings or {}
    if _clean_host(settings.get("tcp_proxy_host")) and _port(settings.get("tcp_proxy_port")) is not None:
        return "settings"
    if _clean_host(os.environ.get(ENV_OVERRIDE_HOST)) and _port(os.environ.get(ENV_OVERRIDE_PORT)) is not None:
        return "env"
    if railway_endpoint():
        return "railway"
    return ""


# Public aliases: main.py validates user input with the same parsers, and a
# leading underscore there would be a reach into private module API.
clean_host = _clean_host
parse_port = _port


# ------------------------------------------------------------------ demux core
#: bytes that can legally start a plaintext HTTP request line on ``location /``
HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"PATCH", b"OPTIO", b"DELET", b"CONNE", b"trac")


def extract_sni(buf: bytes) -> str:
    """Server Name from a TLS ClientHello, or "" if it is not parseable.

    Reads only what a ClientHello header promises, never trusts a length field
    to stay inside the buffer, and never raises -- the router must not die on a
    malformed handshake.
    """
    #  record header: type(1) version(2) length(2)
    if len(buf) < 6 or buf[0] != 0x16 or buf[1] != 0x03:
        return ""
    rec_len = int.from_bytes(buf[3:5], "big")
    end = min(len(buf), 5 + rec_len)
    hs = buf[5:end]
    #  handshake header: type(1) length(3)
    if len(hs) < 4 or hs[0] != 0x01:
        return ""
    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + hs_len]
    #  client hello: version(2) random(32)
    i = 2 + 32
    if len(body) < i + 1:
        return ""
    i += body[i] + 1                      # session id
    if len(body) < i + 2:
        return ""
    i += 2 + int.from_bytes(body[i:i + 2], "big")   # cipher suites
    if len(body) < i + 1:
        return ""
    i += 1 + body[i]                      # compression methods
    if len(body) < i + 2:
        return ""
    ext_end = i + 2 + int.from_bytes(body[i:i + 2], "big")
    i += 2
    while i + 4 <= min(ext_end, len(body)):
        etype = int.from_bytes(body[i:i + 2], "big")
        elen = int.from_bytes(body[i + 2:i + 4], "big")
        data = body[i + 4:i + 4 + elen]
        if etype == 0x0000:               # server_name
            if len(data) < 4:
                return ""
            # ServerNameList: list length(2), then per name: type(1) + length(2) + host
            if int.from_bytes(data[0:2], "big") + 2 > len(data) or data[2] != 0:
                return ""
            name_len = int.from_bytes(data[3:5], "big")
            name = data[5:5 + name_len]
            try:
                return _clean_host(name.decode("ascii"))
            except UnicodeDecodeError:
                return ""
        i += 4 + elen
    return ""


def classify(buf: bytes) -> tuple[str, str]:
    """Route a fresh connection from its first bytes.

    Returns ``(kind, sni)`` where kind is one of ``http`` / ``tls`` / ``raw``.
    ``http`` is matched first because a plaintext request line is unambiguous
    and misrouting it would hand an HTTP client a VPN inbound.
    """
    if not buf:
        return "raw", ""
    if buf.startswith(HTTP_METHODS):
        return "http", ""
    if buf[0] == 0x16 and len(buf) >= 5 and buf[1] == 0x03:
        return "tls", extract_sni(buf)
    return "raw", ""


# ------------------------------------------------------------------ the router
class RawEntry:
    """First-byte router: one public socket, several Xray inbounds.

    ``routes`` maps a classification to an internal ``(host, port)`` pair. The
    buffered peek is prepended to the upstream connection, so Xray sees the
    bytes exactly as the client sent them -- no framing, no PROXY protocol,
    nothing for a Reality handshake to trip over.
    """

    def __init__(self, routes: dict[str, tuple[str, int]], *, host: str = "0.0.0.0",
                 port: int = 0, reality_snis=(), peek_timeout: float = PEEK_TIMEOUT):
        self.routes = dict(routes)
        self.host = host
        self.port = port
        self.reality_snis = {s.lower() for s in reality_snis if s}
        self.peek_timeout = peek_timeout
        self.server: asyncio.Server | None = None
        self.bound_port = 0
        self.started_at = 0.0
        self.counts = {"http": 0, "tls": 0, "raw": 0}
        self.conns = 0
        self.errors: list[str] = []

    # -- lifecycle -------------------------------------------------------
    async def serve(self) -> None:
        self.server = await asyncio.start_server(
            self._handle, host=self.host, port=self.port, reuse_address=True)
        socknames = self.server.sockets or []
        self.bound_port = socknames[0].getsockname()[1] if socknames else self.port
        self.started_at = time.time()
        log.info("raw TCP entry listening on %s:%s -> %s",
                 self.host, self.bound_port,
                 ", ".join(f"{k}={v[1]}" for k, v in sorted(self.routes.items())))

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()
            self.server = None

    # -- helpers ---------------------------------------------------------
    def route_for(self, kind: str, sni: str) -> tuple[str, int] | None:
        if kind == "tls":
            if sni and sni in self.reality_snis:
                return self.routes.get("reality") or self.routes.get("tls")
            # Unknown or absent SNI (a ClientHello split across segments): use the
            # TLS inbound, but Reality is often the only raw inbound on a platform
            # proxy, so fall through to it instead of dropping the client.
            return self.routes.get("tls") or self.routes.get("reality")
        return self.routes.get(kind)

    def _note_error(self, what: str) -> None:
        self.errors.append(what)
        del self.errors[:-10]
        log.warning("raw entry: %s", what)

    async def _peek(self, reader: asyncio.StreamReader) -> bytes:
        """Read up to MAX_PEEK_BYTES, but never block a fast client on SNI.

        A first segment that is clearly not TLS is enough to decide, so the
        timeout only applies while we are still hoping for a full ClientHello.
        """
        buf = b""
        deadline = self.peek_timeout if self.peek_timeout > 0 else 0.001
        loop = asyncio.get_running_loop()
        until = loop.time() + deadline
        while len(buf) < MAX_PEEK_BYTES:
            chunk = b""
            remaining = until - loop.time()
            if remaining > 0:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), remaining)
                except (TimeoutError, asyncio.TimeoutError):
                    break
                except (ConnectionError, OSError):
                    break
            if not chunk:
                break
            buf += chunk
            kind, sni = classify(buf)
            if kind != "tls" or sni:
                break
        return buf

    async def _pump(self, src: asyncio.StreamReader, dst_writer) -> None:
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst_writer.write(data)
                await dst_writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(Exception):
                if dst_writer.can_write_eof():
                    dst_writer.write_eof()
                elif not dst_writer.is_closing():
                    dst_writer.close()

    async def _handle(self, client_reader, client_writer) -> None:
        peer = client_writer.get_extra_info("peername")
        self.conns += 1
        buf = await self._peek(client_reader)
        kind, sni = classify(buf)
        self.counts[kind] = self.counts.get(kind, 0) + 1
        target = self.route_for(kind, sni)
        if target is None:
            self._note_error(f"no route for {kind} (sni={sni or '-'}) from {peer}")
            with contextlib.suppress(Exception):
                client_writer.close()
            return
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(*target)
        except (OSError, ConnectionRefusedError) as exc:
            self._note_error(f"{kind} -> {target[0]}:{target[1]} unreachable: {exc}")
            with contextlib.suppress(Exception):
                client_writer.close()
            return
        if buf:
            upstream_writer.write(buf)
            with contextlib.suppress(Exception):
                await upstream_writer.drain()
        try:
            await asyncio.gather(
                self._pump(client_reader, upstream_writer),
                self._pump(upstream_reader, client_writer),
            )
        finally:
            for writer in (upstream_writer, client_writer):
                with contextlib.suppress(Exception):
                    writer.close()

    # -- reporting -------------------------------------------------------
    def stats(self) -> dict:
        return {
            "listening": self.server is not None,
            "bind": f"{self.host}:{self.bound_port}",
            "routes": {k: f"{v[0]}:{v[1]}" for k, v in sorted(self.routes.items())},
            "reality_sni": sorted(self.reality_snis),
            "connections": self.conns,
            "by_kind": dict(self.counts),
            "uptime": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "recent_errors": list(self.errors[-5:]),
        }


# ------------------------------------------------------------------ glue
def build_routes(*, http_target: tuple[str, int], tls_target: tuple[str, int],
                 reality_target: tuple[str, int] | None = None,
                 raw_target: tuple[str, int] | None = None) -> dict[str, tuple[str, int]]:
    routes = {"http": http_target, "tls": tls_target}
    if reality_target:
        routes["reality"] = reality_target
    if raw_target:
        routes["raw"] = raw_target
    else:
        routes["raw"] = tls_target
    return routes
