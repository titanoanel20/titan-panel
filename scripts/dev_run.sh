#!/bin/bash
# Local development server (no Xray needed — runs in mock mode).
set -e
cd "$(dirname "$0")/.."
pip install -r requirements.txt >/dev/null 2>&1 || true
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --reload
