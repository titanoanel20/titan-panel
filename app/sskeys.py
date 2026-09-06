"""Shadowsocks key derivation shared by the link builder and the Xray config.

PSKs are derived deterministically from the user uuid (never from the local
secret key) so the main panel and every node always agree on the same key.
"""
import base64
import hashlib

from . import config


def psk_bytes(uuid: str, method: str) -> bytes:
    """Raw PSK bytes for a user (16 bytes for 128-bit methods, 32 otherwise)."""
    if method in config.SS_2022_METHODS:
        keylen = 16 if "128" in method else 32
        return hashlib.sha256(f"titan-ss:{uuid}".encode()).digest()[:keylen]
    # legacy AEAD: key derived from the uuid string itself
    return uuid.encode()[:16]


def psk_link(uuid: str, method: str) -> str:
    """PSK as it appears in a client link (base64url, no padding)."""
    return base64.urlsafe_b64encode(psk_bytes(uuid, method)).decode().rstrip("=")


def psk_inbound(uuid: str, method: str) -> str:
    """PSK as it appears in the Xray inbound `password` (standard base64)."""
    if method in config.SS_2022_METHODS:
        return base64.b64encode(psk_bytes(uuid, method)).decode()
    # legacy: Xray accepts the same url-safe key used in the link
    return psk_link(uuid, method)


def server_psk(method: str) -> str:
    """Server-side PSK for the 2022 inbound (fixed, per-method)."""
    return base64.b64encode(hashlib.sha256(f"titan-ss-server:{method}".encode()).digest()[:16]).decode()
