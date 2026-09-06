#!/bin/bash
set -e

# Public port (Railway/Render inject PORT; default 8000)
PORT="${PORT:-8000}"
export PANEL_PORT="${PANEL_PORT:-10000}"

# Patch nginx listen port
sed -i -E "s/listen [0-9]+;|listen NGINX_PORT;/listen ${PORT};/g" /etc/nginx/nginx.conf

# (Re)start nginx
nginx -s stop 2>/dev/null || true
nginx

# Run the panel in foreground
exec python3 -m app.main
