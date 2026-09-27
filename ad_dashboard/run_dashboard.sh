#!/usr/bin/env bash
# ==============================================================================
# Launch Threat Hunting Dashboard & Central API Receiver
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="${SCRIPT_DIR}/../ad_server"

echo "[*] Launching Active Directory Integrity Dashboard & API Receiver..."
echo "[*] Streamlit UI: http://localhost:8501"
echo "[*] Agent API Receiver: http://localhost:8000/api/ad_triage"

streamlit run "${SERVER_DIR}/app.py" --server.port 8501 --server.address 0.0.0.0
