"""Runtime configuration derived from environment variables."""
import os

# Directory that holds the SQLite DB and generated Xray config.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("TITAN_DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("TITAN_DB_PATH", os.path.join(DATA_DIR, "titan.db"))
XRAY_CONFIG_PATH = os.environ.get(
    "TITAN_XRAY_CONFIG", "/usr/local/bin/config.json"
)

# Public port of the container (Railway/Render inject PORT). Nginx listens here.
PUBLIC_PORT = int(os.environ.get("PORT", "8000"))

# Ports for the internal services (localhost only).
PANEL_PORT = int(os.environ.get("PANEL_PORT", "10000"))
XRAY_VLESS_WS_PORT = int(os.environ.get("XRAY_VLESS_WS_PORT", "10001"))
XRAY_VMESS_WS_PORT = int(os.environ.get("XRAY_VMESS_WS_PORT", "10002"))
XRAY_TROJAN_WS_PORT = int(os.environ.get("XRAY_TROJAN_WS_PORT", "10003"))
XRAY_XHTTP_PORT = int(os.environ.get("XRAY_XHTTP_PORT", "10004"))
XRAY_GRPC_PORT = int(os.environ.get("XRAY_GRPC_PORT", "10005"))
XRAY_SS_PORT = int(os.environ.get("XRAY_SS_PORT", "10006"))
XRAY_SS_2022_PORT = int(os.environ.get("XRAY_SS_2022_PORT", "10014"))
XRAY_API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))

# ------------------------------------------------------------------ raw TCP
# Raw-TCP inbounds bind on the public interface (they own the socket — no TLS
# termination at the edge). Each protocol × security combo gets its own port.
XRAY_TCP_VLESS_PORT = int(os.environ.get("XRAY_TCP_VLESS_PORT", "10007"))            # none
XRAY_TCP_VLESS_TLS_PORT = int(os.environ.get("XRAY_TCP_VLESS_TLS_PORT", "10008"))    # tls
XRAY_TCP_VLESS_REALITY_PORT = int(os.environ.get("XRAY_TCP_VLESS_REALITY_PORT", "10009"))  # reality
XRAY_TCP_VMESS_PORT = int(os.environ.get("XRAY_TCP_VMESS_PORT", "10010"))            # none
XRAY_TCP_VMESS_TLS_PORT = int(os.environ.get("XRAY_TCP_VMESS_TLS_PORT", "10011"))    # tls
XRAY_TCP_TROJAN_PORT = int(os.environ.get("XRAY_TCP_TROJAN_PORT", "10012"))          # tls

# Xray terminates TLS itself for the TCP-TLS inbounds; point these at a cert.
TLS_CERT_FILE = os.environ.get("TITAN_TLS_CERT", "")
TLS_KEY_FILE = os.environ.get("TITAN_TLS_KEY", "")

# ------------------------------------------------------------------ raw entry
# Railway's TCP Proxy forwards a public host:port to exactly ONE internal port,
# while this panel owns one inbound per protocol/security pair. So the raw
# inbounds are fronted by a first-byte router (see app/tcp_proxy.py) bound here.
#
# RAILWAY_TCP_APPLICATION_PORT names the port Railway actually targets; defaulting
# to it removes the classic mismatch where the proxy points at PORT (which nginx
# owns) and the VPN inbound silently dials into the web server.
def _int_env(*names: str, default: int = 0) -> int:
    """First sane integer among `names`, else `default`.

    config.py is imported before anything can render an error page, so a
    malformed value must not take the whole panel down the way a bare int()
    would.
    """
    for name in names:
        raw = (os.environ.get(name) or "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            continue
        if 1 <= value <= 65535:
            return value
    return default


DEFAULT_RAW_ENTRY_PORT = 10999
RAW_ENTRY_PORT = _int_env("TITAN_RAW_ENTRY_PORT", "RAILWAY_TCP_APPLICATION_PORT",
                          default=DEFAULT_RAW_ENTRY_PORT)
# 0.0.0.0 by default: Railway connects to the container's published interface.
RAW_ENTRY_BIND = os.environ.get("TITAN_RAW_ENTRY_BIND", "0.0.0.0") or "0.0.0.0"
# auto = run the router only where raw ports cannot be published (Railway /
# a detected TCP proxy endpoint). on/off force it.
RAW_ENTRY_MODE = (os.environ.get("TITAN_RAW_ENTRY") or "auto").strip().lower()
# Optional explicit endpoint, for Render/Fly/VPS-in-front-of-a-TCP-proxy setups.
TCP_PROXY_HOST = (os.environ.get("TITAN_TCP_PROXY_HOST") or "").strip()
TCP_PROXY_PORT = _int_env("TITAN_TCP_PROXY_PORT", default=0)
IS_RAILWAY = bool(os.environ.get("RAILWAY_SERVICE_ID") or os.environ.get("RAILWAY_PROJECT_ID"))


# The decision itself (env mode + DB mode + detected endpoint) lives in
# main._raw_entry_wanted, so that a setting changed in the UI is honoured
# without needing a redeploy of the env vars.

# Reality (VLESS) — destination to masquerade as + SNI to present.
REALITY_DEST = os.environ.get("TITAN_REALITY_DEST", "1.1.1.1:443")
REALITY_SNI = os.environ.get("TITAN_REALITY_SNI", "www.microsoft.com")

# ------------------------------------------------------------------ Hysteria2
# Hysteria2 runs over QUIC (UDP). The inbound binds on the public interface and
# terminates TLS itself (needs TITAN_TLS_CERT / TITAN_TLS_KEY).
XRAY_HY2_PORT = int(os.environ.get("XRAY_HY2_PORT", "443"))            # UDP
# Salamander obfuscation password ("" = off). Requires a recent Xray-core.
HY2_OBFS = os.environ.get("TITAN_HY2_OBFS", "")
# HTTP/3 masquerade for unauthenticated probes ("" = off): proxy mode only.
HY2_MASQUERADE_URL = os.environ.get("TITAN_HY2_MASQUERADE_URL", "")

# ------------------------------------------------------------------ HTTPUpgrade
# HTTPUpgrade transport (like XHTTP) — served through nginx on the public port.
XRAY_HTTPUPGRADE_PORT = int(os.environ.get("XRAY_HTTPUPGRADE_PORT", "10013"))

# ------------------------------------------------------------------ Fallback
# Single-port fallback: VLESS(TCP+TLS) + WebSocket paths served on one port.
# 0 = disabled. On a VPS/Docker set it to 443; on Railway pick a TCP-proxied
# port (443 is reserved for the HTTPS edge). Needs TITAN_TLS_CERT/_KEY.
FALLBACK_PORT = int(os.environ.get("TITAN_FALLBACK_PORT", "0") or 0)

# ------------------------------------------------------------------ Shadowsocks 2022
# 2022 methods use a pre-shared key (like WireGuard); the PSK is derived
# deterministically from the user uuid so main and nodes always agree.
SS_METHODS = [
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
]
SS_2022_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
DEFAULT_SS_METHOD = os.environ.get("XRAY_SS_METHOD", "2022-blake3-aes-128-gcm")

# ------------------------------------------------------------------ WireGuard
# Optional userspace WireGuard/AmneziaWG server (VPS/Docker only — needs a TUN
# device + NET_ADMIN). The panel generates keypairs and the client config, and
# manages a userspace WG process. Skipped gracefully when the binary is absent.
WG_PORT = int(os.environ.get("TITAN_WG_PORT", "51820"))            # UDP
WG_SUBNET = os.environ.get("TITAN_WG_SUBNET", "10.200.0.0/24")
WG_BIN = os.environ.get("TITAN_WG_BIN", "/usr/local/bin/amnezia-wg-go")
WG_CONFIG_PATH = os.environ.get(
    "TITAN_WG_CONFIG", "/usr/local/bin/wg0.conf"
)


def tls_ready() -> bool:
    """True when a certificate pair is configured and present on disk."""
    return bool(
        TLS_CERT_FILE and TLS_KEY_FILE
        and os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE)
    )


def fallback_active() -> bool:
    """True when the single-port fallback inbound should be generated."""
    return bool(FALLBACK_PORT) and tls_ready()

# Xray binary location + feature flag (dev mode runs the panel without Xray).
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")

# Where Xray's own stdout/stderr goes (diagnostics).
XRAY_LOG_PATH = os.environ.get("TITAN_XRAY_LOG", os.path.join(DATA_DIR, "xray.log"))

# Session cookie.
SESSION_COOKIE = "titan_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
# Progressive backoff starts after this many failed logins (see api_login);
# the delay, not a hard lock, is the primary defence because a single-container
# deploy shares one counter across every visitor.
LOGIN_SOFT_FAILS = 3
LOGIN_BACKOFF_CAP_SECONDS = 15
# Hard lock only after this many consecutive failures.
LOGIN_MAX_ATTEMPTS = 8
LOGIN_HARD_LOCK_ATTEMPTS = 30
LOGIN_LOCK_SECONDS = 10 * 60  # 10 minutes

# ------------------------------------------------------------------ multi-node
# TITAN_ROLE=main  -> the control panel (dashboard + DB). Syncs users to nodes.
# TITAN_ROLE=node  -> a pure proxy node: runs Xray for the users the main panel
#                     assigns to it and reports their usage back.
ROLE = os.environ.get("TITAN_ROLE", "main").strip().lower() or "main"
IS_NODE = ROLE == "node"

# Shared secret that lets the main panel talk to its nodes (and vice versa).
# Must be identical on every service. If empty, node sync is disabled.
NODE_SECRET = os.environ.get("TITAN_NODE_SECRET", "")

# Per-node credential issued by the main panel's "Quick node setup" wizard.
# When set, the node uses it to authenticate itself (register + usage report)
# and to verify the main panel's sync pushes. Replaces the shared secret.
NODE_TOKEN = os.environ.get("TITAN_NODE_TOKEN", "")

# The node's own public URL (used to self-register with the main panel).
# Auto-derived from Railway's injected RAILWAY_PUBLIC_DOMAIN when available.
def _node_public_url() -> str:
    d = os.environ.get("TITAN_NODE_URL", "").strip()
    if d:
        return d
    d = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
    if not d:
        return ""
    if d.startswith(("http://", "https://")):
        return d
    return "https://" + d


NODE_URL = _node_public_url()

# On a node: the public URL of the main panel, e.g. https://panel.example.com
MAIN_URL = os.environ.get("TITAN_MAIN_URL", "").strip().rstrip("/")

# How often (seconds) the main panel re-pushes users to its nodes.
NODE_SYNC_INTERVAL = int(os.environ.get("TITAN_NODE_SYNC_INTERVAL", "60"))


# Default settings for newly created users / generated links.
DEFAULT_SETTINGS = {
    "lang": "fa",
    "theme": "dark",
    "public_domain": "",
    "public_port": 443,
    # Raw-TCP entry through a platform TCP proxy (Railway). Empty host means
    # "detect from the platform"; the fields only exist to override that.
    "tcp_proxy_host": "",
    "tcp_proxy_port": 0,
    # "" (default) = not configured in the panel, so TITAN_RAW_ENTRY decides;
    # "on"/"off" pin it from the UI. Storing "auto" here instead of "" would
    # shadow the env var, because a non-empty default always wins the `or`.
    "raw_entry_mode": "",
    # Which inbound owns the "everything else" class on the shared raw port.
    # Shadowsocks' first bytes are indistinguishable from plain VLESS, so only
    # one of them can live behind a single platform port.
    "raw_default_inbound": "vless",
    "admin_avatar": "titan",
    "default_transport": "ws",
    "default_fingerprint": "chrome",
    "default_alpn": "http/1.1",
    "sni_override": "",
    "fragment_enabled": False,
    "fragment_packets": "tlshello",
    "fragment_length": "10-30",
    "fragment_interval": "10-20",
    "restrict_ips": True,
    "block_ads": True,
    "block_iran_sites": False,
    "notify_new_conn": False,
    "backup_enabled": True,
    "backup_interval_hours": 24,
    # reality (VLESS) — public values, filled when the keypair is generated
    "reality_pub": "",
    "reality_enabled": False,
    "reality_sid": "",
    "reality_sni": "",
    "reality_dest": "",
}

# Which Xray outbound tags are counted as "blocked" domains (for the routing
# feature). Must match the tag names emitted in xray.py::generate_xray_config.
BLOCKED_TAGS = {"block-ads", "block-iran", "block-adult", "block-custom"}

VALID_FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
VALID_ALPNS = {"http/1.1", "h2,http/1.1", "h3,h2,http/1.1", ""}
VALID_TRANSPORTS = {"ws", "xhttp", "grpc", "tcp", "httpupgrade"}
VALID_SECURITY = {"none", "tls", "reality"}
VALID_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "wireguard"}
