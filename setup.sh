#!/usr/bin/env bash
# ============================================================================
# LONLY Quickstart & Automated Environment Setup Script
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_PATH="${HOME}/pentest_env"

echo "========================================================================"
echo "  LONLY v2 — Automated Setup & Environment Initialization"
echo "========================================================================"

# 1. Create virtualenv if it doesn't exist
if [ ! -d "$VENV_PATH" ]; then
    echo "[+] Creating Python virtual environment at $VENV_PATH..."
    python3 -m venv "$VENV_PATH"
fi

PYTHON="${VENV_PATH}/bin/python"
PIP="${VENV_PATH}/bin/pip"

# 2. Install/Update Python dependencies
echo "[+] Installing Python dependencies from requirements.txt..."
"$PIP" install --upgrade pip
"$PIP" install -r requirements.txt

# 3. Pull required Ollama model
echo "[+] Verifying Ollama model (gemma3:4b)..."
if command -v ollama >/dev/null 2>&1; then
    ollama pull gemma3:4b || true
else
    echo "[-] Warning: 'ollama' binary not in PATH. Please install from https://ollama.ai"
fi

# 4. Ingest knowledge base for RAG
echo "[+] Initializing RAG ChromaDB knowledge base..."
"$PYTHON" ingest_knowledge.py

# 5. Run Doctor health check
echo "[+] Running LONLY System Health Check..."
"$PYTHON" core/doctor.py

echo "========================================================================"
echo "  Setup Complete! Launch LONLY with:"
echo "    make run"
echo "  or:"
echo "    source ~/pentest_env/bin/activate && python pentest_agent.py"
echo "========================================================================"
