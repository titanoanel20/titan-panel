#!/bin/bash
# Container start: nginx takes the platform's public port and forwards the panel
# to $PANEL_PORT. The routing is derived here, once, and printed - because
# "Application failed to respond" on Railway is nearly always a port mismatch,
# and it used to fail silently.
set -e

PORT="${PORT:-8000}"
PANEL_PORT="${PANEL_PORT:-10000}"
RAW_ENTRY_PORT="${TITAN_RAW_ENTRY_PORT:-${RAILWAY_TCP_APPLICATION_PORT:-10999}}"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/nginx.conf}"   # the image copies it there

if [ "$PANEL_PORT" = "$PORT" ]; then
  # nginx is about to own $PORT, so the panel cannot also bind it: shift the
  # panel and keep nginx pointed at the new number, instead of crash-looping on
  # "address already in use".
  PANEL_PORT=$((PORT + 1))
  echo "[entrypoint] PORT=$PORT was also PANEL_PORT -> panel moved to $PANEL_PORT"
fi
export PANEL_PORT

# Public listen port, and the panel upstream. The upstream is matched by its
# marker comment so the WS/xhttp/grpc proxies keep their own ports.
sed -i -E "s/listen [0-9]+;|listen NGINX_PORT;/listen ${PORT};/g" "$NGINX_CONF"
sed -i -E "s@(proxy_pass http://127\.0\.0\.1:)[0-9]+;([[:space:]]*#[[:space:]]*titan-panel-upstream)@\1${PANEL_PORT};\2@g" "$NGINX_CONF"

if command -v nginx >/dev/null 2>&1; then
  nginx -t
  nginx -s stop 2>/dev/null || true
  nginx
  echo "[entrypoint] nginx: ${PORT} -> panel 127.0.0.1:${PANEL_PORT}"
else
  # No nginx in this image (a different builder, a stripped start command): nothing
  # would answer $PORT, so the panel serves it directly instead of a hidden 10000.
  export PANEL_PORT="$PORT"
  echo "[entrypoint] no nginx found - the panel itself will serve PORT=${PORT}"
fi

echo "[entrypoint] routing: PORT=${PORT} PANEL_PORT=${PANEL_PORT} RAW_ENTRY_PORT=${RAW_ENTRY_PORT} (raw-tcp=${TITAN_RAW_ENTRY:-auto})"
echo "[entrypoint] storage: TITAN_DATA_DIR=${TITAN_DATA_DIR:-/app/data} (a Volume must be mounted here)"

exec python3 -m app.main
