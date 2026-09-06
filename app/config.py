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

# Reality (VLESS) — destination to masquerade as + SNI to present.
REALITY_DEST = os.environ.get("TITAN_REALITY_DEST", "1.1.1.1:443")
REALITY_SNI = os.environ.get("TITAN_REALITY_SNI", "www.microsoft.com")

# Xray binary location + feature flag (dev mode runs the panel without Xray).
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")

# Where Xray's own stdout/stderr goes (diagnostics).
XRAY_LOG_PATH = os.environ.get("TITAN_XRAY_LOG", os.path.join(DATA_DIR, "xray.log"))

# Session cookie.
SESSION_COOKIE = "titan_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
LOGIN_MAX_ATTEMPTS = 8
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
    "reality_sid": "",
    "reality_sni": "",
    "reality_dest": "",
}

# Which Xray outbound tags are counted as "blocked" domains (for the routing
# feature). Must match the tag names emitted in xray.py::generate_xray_config.
BLOCKED_TAGS = {"block-ads", "block-iran", "block-adult", "block-custom"}

VALID_FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
VALID_ALPNS = {"http/1.1", "h2,http/1.1", "h3,h2,http/1.1", ""}
VALID_TRANSPORTS = {"ws", "xhttp", "grpc", "tcp"}
VALID_SECURITY = {"none", "tls", "reality"}
