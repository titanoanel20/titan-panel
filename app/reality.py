"""REALITY (VLESS) key management for the raw-TCP transport.

REALITY needs a stable x25519 keypair per panel. We generate it once with the
Xray binary (``xray x25519``) and persist it in the database so connection
links stay valid across restarts. The private key lives in `meta` (never
exposed to the frontend); the public key + short id are stored as settings so
the link builder can read them.
"""
import base64
import logging
import os
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



#: env var the admin can set to freeze the keypair (see DEPLOY.md: without a
#: Railway Volume the SQLite file - and with it reality_priv - is wiped on every
#: redeploy, which silently invalidates every Reality client at once).
ENV_PRIV = "TITAN_REALITY_PRIV"


class BadKey(ValueError):
    """The operator pasted something that is not an x25519 private key."""


def _b64raw(value: str) -> bytes:
    """Decode Xray's unpadded urlsafe base64 (its `x25519` output format)."""
    value = (value or "").strip().replace("\n", "").replace(" ", "")
    if not value:
        raise BadKey("empty key")
    pad = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + pad)
    except Exception as exc:  # noqa: BLE001 - binascii raises a plain ValueError
        raise BadKey(f"not base64url: {exc}") from exc
    if len(raw) != 32:
        raise BadKey(f"expected 32 raw key bytes, got {len(raw)}")
    return raw


def encode_pub(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def public_for(private_b64: str) -> str:
    """Xray's public key for a pinned private key, without needing the binary.

    `cryptography` is already a dependency (used for password hashing), so the
    panel can validate a pasted key and derive the matching `pbk` clients need.
    """
    from cryptography.exceptions import InvalidKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    raw = _b64raw(private_b64)
    try:
        priv = X25519PrivateKey.from_private_bytes(raw)
    except InvalidKey as exc:
        raise BadKey(f"not a valid x25519 private key: {exc}") from exc
    return encode_pub(priv.public_key().public_bytes_raw())


def set_private_key(private_b64: str, *, sid: str = "", sni: str = "", dest: str = "") -> dict:
    """Pin a keypair (the same path the node side uses) after validating it."""
    pub = public_for(private_b64)          # raises BadKey before anything is written
    # store exactly what Xray expects: the operator's own base64url string
    db.set_meta("reality_priv", (private_b64 or "").strip())
    db.set_meta("reality_priv_source", "pinned")
    db.set_meta("reality_pub", pub)
    if sid:
        db.set_meta("reality_sid", sid)
    sid = db.get_meta("reality_sid") or secrets.token_hex(4)
    db.set_meta("reality_sid", sid)
    db.set_setting("reality_pub", pub)
    db.set_setting("reality_sid", sid)
    db.set_setting("reality_sni", sni or config.REALITY_SNI)
    db.set_setting("reality_dest", dest or config.REALITY_DEST)
    log.info("Reality keypair pinned from operator input (pub=%s sni=%s)", pub, db.get_settings()["reality_sni"])
    return {"pub": pub, "sid": sid, "sni": db.get_settings()["reality_sni"],
            "dest": db.get_settings()["reality_dest"], "pinned": True}


def key_source() -> str:
    """Where the current private key came from - reported in the UI, never the key.

    "generated" is the fragile state on an ephemeral filesystem: it lives only as
    long as the SQLite file does.
    """
    if db.get_meta("reality_priv_source") == "pinned":
        return "pinned"
    return "generated" if db.get_meta("reality_priv") else "none"



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
    pinned = (os.environ.get(ENV_PRIV) or "").strip()
    if pinned:
        # A pinned key survives every redeploy on an ephemeral filesystem, which
        # is the difference between "Reality works" and "all my clients timed out
        # since this morning". Bad input is logged, not fatal: the panel must
        # still boot so the admin can read why.
        try:
            return set_private_key(pinned)
        except BadKey as exc:
            log.error("%s is not usable (%s) - falling back to generating one", ENV_PRIV, exc)
    keys = _xray_x25519()
    if not keys:
        return None
    priv, pub = keys
    sid = secrets.token_hex(4)
    db.set_meta("reality_priv", priv)
    db.set_meta("reality_pub", pub)
    db.set_meta("reality_priv_source", "generated")
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
    db.set_meta("reality_priv_source", "pinned")
    db.set_meta("reality_pub", data.get("pub", ""))
    db.set_meta("reality_sid", data.get("sid", ""))
    db.set_setting("reality_pub", data.get("pub", ""))
    db.set_setting("reality_sid", data.get("sid", ""))
    db.set_setting("reality_sni", config.REALITY_SNI)
    db.set_setting("reality_dest", config.REALITY_DEST)
