"""Best-effort geolocation for node addresses (hostname/IP -> country).

Used to fill a node's city/country/country_code/flag automatically so every
server shows the flag of the country it is hosted in, without manual entry.
"""
import ipaddress
import re
import socket

import httpx

_IP_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city"


def flag_from_code(code: str) -> str:
    """Regional-indicator emoji from a 2-letter ISO country code."""
    code = (code or "").upper().strip()
    if len(code) == 2 and code.isalpha():
        return "".join(chr(0x1F1E6 + (ord(c) - ord("A"))) for c in code)
    return "🏳️"


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def detect_location(address: str, timeout: float = 3.0) -> dict:
    """Resolve a node address to {city, country, country_code, flag}.

    Returns {} on any failure (no network, private IP, unknown host, …) so the
    caller can fall back to whatever the admin typed.
    """
    host = (address or "").strip()
    if not host:
        return {}
    # strip scheme, path/query, port and any userinfo
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", host)
    host = host.split("/", 1)[0].rsplit("@", 1)[-1]
    host = re.sub(r":\d+$", "", host)
    host = host.strip().strip("[]")
    if not host:
        return {}
    try:
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            ip = host
        else:
            ip = socket.gethostbyname(host)
        if _is_private(ip) or ip in ("0.0.0.0", "255.255.255.255"):
            return {}
        r = httpx.get(_IP_API.format(ip=ip), timeout=timeout)
        d = r.json()
        if d.get("status") != "success":
            return {}
        cc = (d.get("countryCode") or "").strip().upper()[:2]
        return {
            "city": (d.get("city") or "").strip()[:64],
            "country": (d.get("country") or "").strip()[:64],
            "country_code": cc,
            "flag": flag_from_code(cc),
        }
    except Exception:  # noqa: BLE001 — best-effort only
        return {}
