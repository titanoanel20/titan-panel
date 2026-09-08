"""External-proxy fronts — the 3x-ui ``stream.externalProxy`` equivalent.

A *front* is an address the client dials that is not the origin: a Railway TCP
proxy, a Cloudflare CDN worker, a mirror node. Every front produces its own set
of links for every user (same uuid, same inbound, different ``host:port`` and —
optionally — a forced security/SNI/fingerprint), which is exactly how 3x-ui
renders "one inbound, many share links" and how the Railway guide expects you to
hand out ``shuttle.proxy.rlwy.net:15140`` next to the domain-based link.

The panel keeps its own defaults: with no rows configured nothing changes, and
``main._user_endpoint`` still decides where the *primary* links point. Fronts are
purely additive.
"""
from __future__ import annotations

import re

MAX_FRONTS = 10
FORCED = ("same", "tls", "none")
_FINGERPRINTS = ("", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random")
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-_]{0,251}[a-zA-Z0-9])?$")


def _clean_host(value) -> str:
    host = str(value or "").strip().lower()
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", host)   # scheme, if pasted in
    host = host.split("/", 1)[0].strip().strip("[]")
    return host


def normalize(row: dict | None) -> tuple[dict | None, str | None]:
    """Validate one front row. Returns ``(row, None)`` or ``(None, error)``."""
    if not isinstance(row, dict):
        return None, "row-not-object"
    host = _clean_host(row.get("host"))
    remark = str(row.get("remark") or "").strip()[:64]
    force_tls = str(row.get("force_tls") or "same").strip().lower()
    if force_tls not in FORCED:
        return None, f"invalid-force-tls: {force_tls}"
    if not host:
        return None, "missing-host"
    if not _HOST_RE.match(host):
        return None, "invalid-host"
    try:
        port = int(row.get("port") or 0)
    except (TypeError, ValueError):
        return None, "invalid-port"
    if not 1 <= port <= 65535:
        return None, "invalid-port"
    sni = str(row.get("sni") or "").strip()[:253]
    if sni and not _HOST_RE.match(sni.lower()):
        return None, "invalid-sni"
    fp = str(row.get("fingerprint") or "").strip().lower()
    if fp not in _FINGERPRINTS:
        return None, f"invalid-fingerprint: {fp}"
    alpn = str(row.get("alpn") or "").strip()[:64]
    if alpn and not re.fullmatch(r"[A-Za-z0-9/,_\-]{1,64}", alpn):
        return None, "invalid-alpn"
    return {
        "remark": remark or host,
        "host": host,
        "port": port,
        "force_tls": force_tls,
        "sni": sni,
        "fingerprint": fp,
        "alpn": alpn,
    }, None


def normalize_rows(rows) -> tuple[list[dict], str | None]:
    """Validate the whole list. Returns ``(clean_rows, None)`` or ``([], error)``."""
    if rows in (None, "", []):
        return [], None
    if not isinstance(rows, list):
        return [], "rows-must-be-a-list"
    if len(rows) > MAX_FRONTS:
        return [], f"too-many-fronts: {MAX_FRONTS} max"
    out: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for row in rows:
        clean, err = normalize(row)
        if err:
            return [], err
        key = (clean["host"], clean["port"])
        if key in seen:                      # two identical fronts = two identical links
            continue
        seen.add(key)
        out.append(clean)
    return out, None


def rows(settings: dict | None) -> list[dict]:
    """Configured fronts, repaired in place if the stored JSON drifted."""
    stored = (settings or {}).get("external_proxy_rows") or []
    out: list[dict] = []
    for row in stored:
        if isinstance(row, dict) and set(row) <= {"remark", "host", "port", "force_tls", "sni",
                                                 "fingerprint", "alpn", "forceTls", "dest"}:
            candidate = dict(row)
            candidate.setdefault("force_tls", candidate.pop("forceTls", "same"))
            candidate["host"] = candidate.get("host") or candidate.pop("dest", "")
            clean, _err = normalize(candidate)
            if clean:
                out.append(clean)
    return out


def with_front(user: dict, front: dict, settings: dict) -> tuple[dict, dict, str, int]:
    """Return ``(user, settings, host, port)`` as they must be for one front.

    The user copy carries the front in its remark so every link builder — which
    all name the link from ``user["name"]`` — tags the fragment automatically.
    """
    u = dict(user)
    s = dict(settings)
    label = front.get("remark") or front["host"]
    u["name"] = f"{user.get('name', '')} · {label}"
    force = front.get("force_tls", "same")
    if force == "tls":
        u["security"] = "tls"                 # reality/plain both become plain TLS
    elif force == "none":
        u["security"] = "none"
    if front.get("sni"):
        s["sni_override"] = front["sni"]
    if front.get("fingerprint"):
        s["default_fingerprint"] = front["fingerprint"]
    if front.get("alpn"):
        s["default_alpn"] = front["alpn"]
    return u, s, front["host"], int(front["port"])
