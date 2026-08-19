#!/usr/bin/env bash
# NucleiAI one-click launcher for Linux/macOS
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "  NucleiAI - AI-Enhanced Vulnerability Platform"
echo "============================================"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found. Install Python 3.11+ first."
  exit 1
fi

if ! python3 -c "import fastapi, httpx, yaml, bs4, lxml" >/dev/null 2>&1; then
  echo "[*] Installing dependencies..."
  python3 -m pip install -r requirements.txt
fi

echo "[*] Checking environment..."
python3 run.py check

echo "[*] Starting vulnerable test target on 127.0.0.1:9999..."
python3 test-target/vuln_server.py 9999 &
TARGET_PID=$!
trap "kill $TARGET_PID 2>/dev/null || true" EXIT

echo "[*] Starting web panel at http://127.0.0.1:8080"
python3 run.py
