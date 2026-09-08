"""REALITY (VLESS) key management.

REALITY needs a stable x25519 keypair per panel. We generate it once with the
Xray binary (``xray x25519``) and persist it in the database so connection links
stay valid across restarts. The private key lives in `meta` (never exposed to the
frontend); the public key + short id are stored as settings so the link builder
can read them.

Keeping those keys valid across a *redeploy* therefore depends on the database
surviving it - i.e. on a persistent Volume (`/app/data` on Railway). Without one,
every deploy generates a new keypair and previously published `pbk` values die.
"""
import logging
import secrets
import subprocess

from . import config, db

log = logging.getLogger("titan.reality")


def _xray_x25519() -> tuple[str, str] | None:
    """Return (private_key, public_key) from `xray x25519`, or None."""
    try:
        out = subprocess.run(
            [config.XRAY_BIN, "x25519"],
            capture_output=True, text=True, timeout=20,
        )
    except Exception as e:  # noqa: BLE001
        log.warning("xray x25519 failed: %s", e)
        return None
    priv = pub = ""
    for line in (out.stdout or "").splitlines():
        if line.startswith("Private key:"):
            priv = line.split(":", 1)[1].strip()
        elif line.startswith("Public key:"):
            pub = line.split(":", 1)[1].strip()
    if priv and pub:
        return priv, pub
    return None


def ensure_reality_keys() -> dict | None:
    """Return {priv, pub, sid, sni, dest} for the panel, generating once.

    Returns None when no Xray binary is available (dev/mock mode) and no keys
    have been generated yet — Reality inbounds are then skipped.
    """
    priv = db.get_meta("reality_priv")
    if priv:
        return {
            "priv": priv,
            "pub": db.get_meta("reality_pub") or "",
            "sid": db.get_meta("reality_sid") or "",
            "sni": config.REALITY_SNI,
            "dest": config.REALITY_DEST,
        }
    keys = _xray_x25519()
    if not keys:
        return None
    priv, pub = keys
    sid = secrets.token_hex(4)
    db.set_meta("reality_priv", priv)
    db.set_meta("reality_pub", pub)
    db.set_meta("reality_sid", sid)
    # public values → settings, so get_settings() carries them to link builder
    db.set_setting("reality_pub", pub)
    db.set_setting("reality_sid", sid)
    db.set_setting("reality_sni", config.REALITY_SNI)
    db.set_setting("reality_dest", config.REALITY_DEST)
    log.info("Reality keypair generated (sni=%s dest=%s)", config.REALITY_SNI, config.REALITY_DEST)
    return {"priv": priv, "pub": pub, "sid": sid, "sni": config.REALITY_SNI, "dest": config.REALITY_DEST}


def apply_reality_config(data: dict) -> None:
    """Node side: accept the main panel's reality keypair + short id."""
    if not data or not data.get("priv"):
        return
    db.set_meta("reality_priv", data["priv"])
    db.set_meta("reality_pub", data.get("pub", ""))
    db.set_meta("reality_sid", data.get("sid", ""))
    db.set_setting("reality_pub", data.get("pub", ""))
    db.set_setting("reality_sid", data.get("sid", ""))
    db.set_setting("reality_sni", config.REALITY_SNI)
    db.set_setting("reality_dest", config.REALITY_DEST)
