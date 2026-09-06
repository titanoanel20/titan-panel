"""Generate the Xray-core config.json from the user database and manage the
Xray process. Reads live traffic stats from the Xray API."""
import asyncio
import json
import logging
import os
import re
import subprocess

from . import config, db

log = logging.getLogger("titan.xray")

_previous_stats: dict[str, dict] = {}
_xray_process: subprocess.Popen | None = None
_stats_lock = asyncio.Lock()


def xray_available() -> bool:
    return os.path.exists(config.XRAY_BIN)


def xray_running() -> bool:
    """True when the Xray process we spawned is still alive."""
    return bool(_xray_process and _xray_process.poll() is None)


# ----------------------------------------------------------------- routing rules
def _blocked_rules(settings: dict) -> list:
    """Build Xray routing rules for the domain-blocking feature."""
    rules = []
    if settings.get("block_ads"):
        rules.append({
            "type": "field",
            "domain": ["geosite:category-ads-all"],
            "outboundTag": "block-ads",
        })
    if settings.get("block_iran_sites"):
        rules.append({
            "type": "field",
            "domain": ["geosite:category-iran"],
            "outboundTag": "block-iran",
        })
    if settings.get("restrict_ips"):
        # Block connecting to private/LAN ranges (anti-abuse).
        rules.append({
            "type": "field",
            "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
            "outboundTag": "block",
        })
    return rules


def _xray_users() -> list[dict]:
    """Users whose traffic this process must proxy.

    On the main panel only users assigned to the *local* node are proxied here;
    every other user is proxied by their remote node. On a node, every user in
    the (synced) database is proxied locally.
    """
    users = db.list_users()
    if config.IS_NODE:
        return users
    local_ids = {n["id"] for n in db.list_nodes() if n.get("is_local")}
    return [u for u in users if int(u.get("node_id") or 1) in local_ids]


def generate_xray_config() -> dict:
    """Build the full Xray config dict. Persisted to disk by write_xray_config."""
    users = _xray_users()
    settings = db.get_settings()

    def mk_client(u):
        c = {"id": u["uuid"], "email": u["uid"]}
        if u.get("password"):
            c["password"] = u["password"]
        return c

    vless_clients = [mk_client(u) for u in users if u["enabled"] and u["protocol"] == "vless"]
    vmess_clients = [mk_client(u) for u in users if u["enabled"] and u["protocol"] == "vmess"]
    trojan_clients = [
        {"password": u["uuid"], "email": u["uid"]}
        for u in users if u["enabled"] and u["protocol"] == "trojan"
    ]
    # Shadowsocks users share the ss inbound via method+password pairs.
    ss_users = [u for u in users if u["enabled"] and u["protocol"] == "shadowsocks"]

    outbounds = [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
        {"protocol": "blackhole", "tag": "block-ads"},
        {"protocol": "blackhole", "tag": "block-iran"},
        {"protocol": "blackhole", "tag": "block-adult"},
        {"protocol": "blackhole", "tag": "block-custom"},
    ]

    routing_rules = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
    ]
    routing_rules.extend(_blocked_rules(settings))

    inbounds = [
        {
            "listen": "127.0.0.1",
            "port": config.XRAY_API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
            "tag": "api",
        },
    ]

    if vless_clients:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_VLESS_WS_PORT,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/vl-ws"}},
            "tag": "in-vless-ws",
        })
    if vmess_clients:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_VMESS_WS_PORT,
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm-ws"}},
            "tag": "in-vmess-ws",
        })
    if trojan_clients:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_TROJAN_WS_PORT,
            "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/tr-ws"}},
            "tag": "in-trojan-ws",
        })

    # XHTTP inbound shared by VLESS + VMess users.
    xhttp_vless = [c for c in vless_clients]
    xhttp_vmess = [c for c in vmess_clients]
    if xhttp_vless:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_XHTTP_PORT,
            "protocol": "vless",
            "settings": {"clients": xhttp_vless, "decryption": "none"},
            "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xhttp"}},
            "tag": "in-vless-xhttp",
        })
    if xhttp_vmess:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_XHTTP_PORT,
            "protocol": "vmess",
            "settings": {"clients": xhttp_vmess},
            "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xhttp"}},
            "tag": "in-vmess-xhttp",
        })

    # gRPC inbound shared by VLESS + VMess users.
    grpc_vless = [c for c in vless_clients]
    grpc_vmess = [c for c in vmess_clients]
    if grpc_vless:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_GRPC_PORT,
            "protocol": "vless",
            "settings": {"clients": grpc_vless, "decryption": "none"},
            "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "titan"}},
            "tag": "in-vless-grpc",
        })
    if grpc_vmess:
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_GRPC_PORT,
            "protocol": "vmess",
            "settings": {"clients": grpc_vmess},
            "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "titan"}},
            "tag": "in-vmess-grpc",
        })

    # Shadowsocks inbound.
    if ss_users:
        ss_clients = []
        for u in ss_users:
            key = __import__("base64").urlsafe_b64encode(u["uuid"].encode()[:16]).decode().rstrip("=")
            ss_clients.append({"email": u["uid"], "method": "aes-128-gcm", "password": key})
        inbounds.append({
            "listen": "127.0.0.1",
            "port": config.XRAY_SS_PORT if hasattr(config, "XRAY_SS_PORT") else 10006,
            "protocol": "shadowsocks",
            "settings": {"clients": ss_clients, "network": "tcp,udp"},
            "tag": "in-ss",
        })

    # ---------------- raw TCP inbounds (plain / TLS / Reality) ----------------
    tcp_users = [u for u in users if u.get("transport") == "tcp"]
    vless_tcp_plain = [mk_client(u) for u in tcp_users
                       if u["protocol"] == "vless" and (u.get("security") or "none") == "none"]
    vless_tcp_tls = [mk_client(u) for u in tcp_users
                     if u["protocol"] == "vless" and (u.get("security") or "") == "tls"]
    vless_tcp_reality = [mk_client(u) for u in tcp_users
                         if u["protocol"] == "vless" and (u.get("security") or "") == "reality"]
    vmess_tcp_plain = [mk_client(u) for u in tcp_users
                       if u["protocol"] == "vmess" and (u.get("security") or "none") == "none"]
    vmess_tcp_tls = [mk_client(u) for u in tcp_users
                     if u["protocol"] == "vmess" and (u.get("security") or "") == "tls"]
    trojan_tcp = [{"password": u["uuid"], "email": u["uid"]} for u in tcp_users
                  if u["protocol"] == "trojan"]

    if vless_tcp_plain:
        inbounds.append({
            "listen": "0.0.0.0", "port": config.XRAY_TCP_VLESS_PORT, "protocol": "vless",
            "settings": {"clients": vless_tcp_plain, "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "none"},
            "tag": "in-vless-tcp",
        })
    if vmess_tcp_plain:
        inbounds.append({
            "listen": "0.0.0.0", "port": config.XRAY_TCP_VMESS_PORT, "protocol": "vmess",
            "settings": {"clients": vmess_tcp_plain},
            "streamSettings": {"network": "tcp", "security": "none"},
            "tag": "in-vmess-tcp",
        })

    # TLS over raw TCP — needs a certificate Xray can present.
    tls_ok = (
        config.TLS_CERT_FILE and config.TLS_KEY_FILE
        and os.path.exists(config.TLS_CERT_FILE) and os.path.exists(config.TLS_KEY_FILE)
    )
    if (vless_tcp_tls or vmess_tcp_tls or trojan_tcp) and not tls_ok:
        log.warning("TCP-TLS users exist but no certificate is configured "
                    "(TITAN_TLS_CERT / TITAN_TLS_KEY) — TLS inbounds skipped")
    if tls_ok:
        tls_settings = {
            "certificates": [{
                "certificateFile": config.TLS_CERT_FILE,
                "keyFile": config.TLS_KEY_FILE,
            }],
            "alpn": ["h2", "http/1.1"],
        }
        if vless_tcp_tls:
            inbounds.append({
                "listen": "0.0.0.0", "port": config.XRAY_TCP_VLESS_TLS_PORT, "protocol": "vless",
                "settings": {"clients": vless_tcp_tls, "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
                "tag": "in-vless-tcp-tls",
            })
        if vmess_tcp_tls:
            inbounds.append({
                "listen": "0.0.0.0", "port": config.XRAY_TCP_VMESS_TLS_PORT, "protocol": "vmess",
                "settings": {"clients": vmess_tcp_tls},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
                "tag": "in-vmess-tcp-tls",
            })
        if trojan_tcp:
            inbounds.append({
                "listen": "0.0.0.0", "port": config.XRAY_TCP_TROJAN_PORT, "protocol": "trojan",
                "settings": {"clients": trojan_tcp},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
                "tag": "in-trojan-tcp",
            })

    if vless_tcp_reality:
        priv = db.get_meta("reality_priv")
        sid = db.get_meta("reality_sid") or ""
        if priv:
            inbounds.append({
                "listen": "0.0.0.0", "port": config.XRAY_TCP_VLESS_REALITY_PORT, "protocol": "vless",
                "settings": {"clients": vless_tcp_reality, "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                    "show": False,
                    "dest": config.REALITY_DEST,
                    "xver": 0,
                    "serverNames": [config.REALITY_SNI],
                    "privateKey": priv,
                    "shortIds": [sid],
                }},
                "tag": "in-vless-reality",
            })
        else:
            log.warning("Reality users exist but no private key is available — "
                        "Reality inbound skipped")

    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                "https+local://1.1.1.1/dns-query",
                "https+local://8.8.8.8/dns-query",
                "1.1.1.1",
                "8.8.8.8",
                "localhost",
            ],
            "queryStrategy": "UseIPv4",
        },
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": routing_rules},
    }


def write_xray_config() -> dict:
    cfg = generate_xray_config()
    os.makedirs(os.path.dirname(config.XRAY_CONFIG_PATH), exist_ok=True)
    tmp = config.XRAY_CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, config.XRAY_CONFIG_PATH)
    return cfg


def restart_xray():
    global _xray_process
    if _xray_process and _xray_process.poll() is None:
        _xray_process.terminate()
        try:
            _xray_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _xray_process.kill()
    if xray_available():
        os.makedirs(os.path.dirname(config.XRAY_LOG_PATH), exist_ok=True)
        logf = open(config.XRAY_LOG_PATH, "a", encoding="utf-8")
        _xray_process = subprocess.Popen(
            [config.XRAY_BIN, "run", "-c", config.XRAY_CONFIG_PATH],
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
        log.info("Xray restarted (pid=%s)", _xray_process.pid)
    else:
        log.warning("Xray binary not found — running in dev/mock mode.")


async def get_xray_stats() -> dict:
    """Query the Xray stats API and return per-uid traffic deltas since the
    previous call. Uses the JSON output format."""
    global _previous_stats
    if not xray_available():
        return {}
    async with _stats_lock:
        try:
            proc = await asyncio.create_subprocess_exec(
                config.XRAY_BIN, "api", "statsquery",
                f"--server=127.0.0.1:{config.XRAY_API_PORT}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await proc.communicate()
            out = stdout.decode("utf-8", errors="ignore")
            if not out.strip():
                return {}
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                matches = re.findall(r'name:\s*"([^"]+)"\s*value:\s*(\d+)', out)
                if not matches:
                    return {}
                data = {"stat": [{"name": m[0], "value": int(m[1])} for m in matches]}

            current: dict[str, dict] = {}
            for item in data.get("stat", []):
                name = item.get("name")
                value = item.get("value")
                if not name or value is None:
                    continue
                parts = name.split(">>>")
                if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                    uid, direction, val = parts[1], parts[3], int(value)
                    current.setdefault(uid, {"up": 0, "down": 0})
                    if direction == "uplink":
                        current[uid]["up"] += val
                    elif direction == "downlink":
                        current[uid]["down"] += val

            deltas: dict[str, dict] = {}
            for uid, s in current.items():
                prev = _previous_stats.get(uid, {"up": 0, "down": 0})
                up = s["up"] - prev["up"]
                down = s["down"] - prev["down"]
                if up < 0:
                    up = s["up"]
                if down < 0:
                    down = s["down"]
                if up > 0 or down > 0:
                    deltas[uid] = {"up": up, "down": down}
            _previous_stats = current
            return deltas
        except Exception as e:  # noqa: BLE001
            log.error("Error querying Xray stats: %s", e)
            return {}
