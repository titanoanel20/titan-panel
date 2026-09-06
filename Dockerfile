FROM alpine:3.20

# Runtime dependencies
RUN apk add --no-cache python3 py3-pip nginx curl unzip jq bash tzdata

# Build dependencies for Pillow / psutil
RUN apk add --no-cache --virtual .build-deps \
    gcc musl-dev python3-dev zlib-dev jpeg-dev freetype-dev linux-headers

WORKDIR /app
COPY requirements.txt .

RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt \
    && apk del .build-deps

# Install Xray-core (latest)
RUN curl -fsSL -o xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" \
    && unzip xray.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm xray.zip

# Optional userspace WireGuard server (AmneziaWG). Runs only on VPS/Docker with
# NET_ADMIN + /dev/net/tun; the panel skips it gracefully when absent.
RUN curl -fsSL -o /usr/local/bin/amnezia-wg-go "https://github.com/amnezia-vpn/amnezia-wg-go/releases/latest/download/amnezia-wg-go-linux-amd64" \
    && chmod +x /usr/local/bin/amnezia-wg-go \
    || echo "amnezia-wg-go download skipped (WireGuard will be disabled)"

COPY . /app
COPY nginx.conf /etc/nginx/nginx.conf

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

CMD ["/app/entrypoint.sh"]
