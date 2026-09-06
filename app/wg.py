"""Optional userspace WireGuard (AmneziaWG) server management.

Xray-core cannot terminate WireGuard as a *server* inbound, so TiTaN manages a
userspace `amnezia-wg-go` process instead (VPS/Docker with NET_ADMIN and
/dev/net/tun — not available on Railway). The panel:

  - generates the server keypair once (X25519 via the `cryptography` package)
    and persists it in the meta table,
  - generates a keypair + overlay IP per WireGuard user (on the main panel),
  - builds the client config (returned as a link / conf download),
  - regenerates the server config locally per node and restarts the process.

Every node runs its own WG server; each node publishes its public key through
/health so the main panel can embed the right key in client configs.
"""
import base64
import ipaddress
import logging
import os
import subprocess

from . import config, db
from . import nodes as nodesync

log = logging.getLogger("titan.wg")

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    _HAS_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAS_CRYPTO = False

_wg_process: subprocess.Popen | None = None


def available() -> bool:
    """True when key generation is possible (cryptography installed)."""
    return _HAS_CRYPTO


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def gen_keypair() -> tuple[str, str]:
    """Return (private, public) WireGuard keys in standard base64."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64(priv_raw), _b64(pub_raw)


def ensure_keys() -> tuple[str, str]:
    """Persist this node's WG server keypair (one per node)."""
    if not _HAS_CRYPTO:
        return "", ""
    priv = db.get_meta("wg_priv")
    if not priv:
        priv, pub = gen_keypair()
        db.set_meta("wg_priv", priv)
        db.set_meta("wg_pub", pub)
    pub = db.get_meta("wg_pub") or ""
    return priv, pub


def server_public_key() -> str:
    if not _HAS_CRYPTO:
        return ""
    ensure_keys()
    return db.get_meta("wg_pub") or ""


def _subnet() -> ipaddress.IPv4Network:
    try:
        return ipaddress.ip_network(config.WG_SUBNET, strict=False)
    except ValueError:
        return ipaddress.ip_network("10.200.0.0/24")


def server_ip() -> str:
    return str(_subnet().network_address + 1)


def allocate_ip() -> str:
    """Next free client IP inside the WG subnet (server keeps the first host)."""
    net = _subnet()
    taken = {u.get("wg_ip") for u in db.list_users() if u.get("wg_ip")}
    ip = net.network_address + 2
    last = net.broadcast_address - 1
    while ip <= last:
        s = str(ip)
        if s not in taken:
            return s
        ip += 1
    return ""


def ensure_user_keys(u: dict) -> dict:
    """Fill in a WireGuard user's keypair + overlay IP (idempotent)."""
    if not _HAS_CRYPTO:
        return u
    fields = {}
    if not u.get("wg_priv") or not u.get("wg_pub"):
        priv, pub = gen_keypair()
        fields["wg_priv"] = priv
        fields["wg_pub"] = pub
    if not u.get("wg_ip"):
        fields["wg_ip"] = allocate_ip()
    if fields:
        db.update_user(u["uid"], fields)
        u = db.get_user(u["uid"])
    return u


def client_conf(u: dict, host: str, port: int, server_pub: str,
                dns: str = "1.1.1.1") -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {u.get('wg_priv') or ''}\n"
        f"Address = {u.get('wg_ip') or ''}/32\n"
        f"DNS = {dns}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {host}:{port}\n"
        "PersistentKeepalive = 25\n"
    )


def server_config(users: list[dict]) -> str:
    """Build the wg-quick-style config for this node's WG server."""
    if not _HAS_CRYPTO:
        return ""
    priv, _ = ensure_keys()
    if not priv:
        return ""
    prefix = _subnet().prefixlen
    lines = [
        "[Interface]",
        f"PrivateKey = {priv}",
        f"ListenPort = {config.WG_PORT}",
        f"Address = {server_ip()}/{prefix}",
        "",
    ]
    for u in users:
        if u.get("enabled") and u.get("wg_pub") and u.get("wg_ip"):
            lines.append("[Peer]")
            lines.append(f"PublicKey = {u['wg_pub']}")
            lines.append(f"AllowedIPs = {u['wg_ip']}/32")
            lines.append("")
    return "\n".join(lines)


def write_server_config(users: list[dict]) -> bool:
    if not _HAS_CRYPTO:
        return False
    content = server_config(users)
    if not content:
        return False
    os.makedirs(os.path.dirname(config.WG_CONFIG_PATH), exist_ok=True)
    tmp = config.WG_CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, config.WG_CONFIG_PATH)
    return True


def wg_users() -> list[dict]:
    """WG users whose traffic this process must serve (same role rules as Xray)."""
    return [u for u in nodesync.local_users()
            if u.get("enabled") and u.get("protocol") == "wireguard"]


def restart() -> None:
    """Regenerate the server config and (re)start amnezia-wg-go."""
    global _wg_process
    if _wg_process and _wg_process.poll() is None:
        _wg_process.terminate()
        try:
            _wg_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _wg_process.kill()
        _wg_process = None
    if not _HAS_CRYPTO:
        return
    if not os.path.exists(config.WG_BIN):
        log.info("WireGuard binary not found (%s) — WG server skipped", config.WG_BIN)
        return
    users = wg_users()
    if not any(u.get("wg_pub") for u in users):
        return  # no peers to serve
    if not write_server_config(users):
        return
    log_path = os.path.join(config.DATA_DIR, "wireguard.log")
    os.makedirs(config.DATA_DIR, exist_ok=True)
    logf = open(log_path, "a", encoding="utf-8")
    _wg_process = subprocess.Popen(
        [config.WG_BIN, "-c", config.WG_CONFIG_PATH],
        stdout=logf,
        stderr=subprocess.STDOUT,
    )
    log.info("WireGuard restarted (pid=%s, peers=%d)", _wg_process.pid, len(users))


def running() -> bool:
    return bool(_wg_process and _wg_process.poll() is None)
