#!/usr/bin/env bash
set -e

echo "====================================================================="
echo "  CRISP 2.2 - Cyber Risk Intelligence & Security Posture Platform"
echo "  Local Linux/macOS Development Launcher"
echo "====================================================================="
echo ""

# 1. Verify Node.js
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js is not installed or not in PATH."
    echo "Please install Node.js 20 or later from https://nodejs.org/"
    exit 1
fi
echo "[*] Detected Node.js: $(node -v)"

# 2. Check Python
if command -v python3 &> /dev/null; then
    echo "[*] Detected Python: $(python3 --version)"
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    echo "[*] Detected Python: $(python --version)"
    PYTHON_CMD="python"
else
    echo "[!] Warning: Python not detected. Background analytics require Python 3.10+."
    PYTHON_CMD=""
fi

# 3. Check and Install Node Dependencies
if [ ! -d "node_modules" ]; then
    echo "[*] Installing Node.js dependencies (first-time setup)..."
    npm install
fi

# 4. Ensure .env exists
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "[*] Creating .env from .env.example template..."
    cp .env.example .env
fi

# 5. Verify WASM binary presence in public folder
if [ ! -f "public/sql-wasm.wasm" ] && [ -f "node_modules/sql.js/dist/sql-wasm.wasm" ]; then
    echo "[*] Copying WebAssembly binary to public folder..."
    cp node_modules/sql.js/dist/sql-wasm.wasm public/sql-wasm.wasm
    cp node_modules/sql.js/dist/sql-wasm-browser.wasm public/sql-wasm-browser.wasm
fi

# 6. Initialize SQLite Database Schema if missing
if [ -n "$PYTHON_CMD" ] && [ ! -f "data/crisp.db" ]; then
    echo "[*] Initializing SQLite database tables..."
    $PYTHON_CMD scripts/migrate.py
fi

echo ""
echo "====================================================================="
echo "  Starting CRISP Full-Stack Server on http://localhost:3000"
echo "  Press Ctrl+C to stop the server."
echo "====================================================================="
echo ""

exec npm run dev
