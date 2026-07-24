#!/usr/bin/env bash
# =============================================================================
# SMP V7 — Launcher
# © mrQhere
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}  Security Management Platform — V7${RESET}"
echo -e "  Local-first · Zero-cloud · Encrypted at rest\n"

# ── Venv check ────────────────────────────────────────────────────────────────
if [[ ! -d "$SCRIPT_DIR/venv" ]]; then
    echo -e "${RED}  No virtual environment found.${RESET}"
    echo -e "  Run ${BOLD}./setup.sh${RESET} first to install dependencies.\n"
    exit 1
fi

source "$SCRIPT_DIR/venv/bin/activate"

# ── SQLCipher check ───────────────────────────────────────────────────────────
if ! python3 -c "from pysqlcipher3 import dbapi2" 2>/dev/null; then
    echo -e "${RED}  FATAL: pysqlcipher3 is not installed.${RESET}"
    echo -e "  SMP requires SQLCipher for encrypted-at-rest storage.\n"
    echo -e "  Fix:"
    echo -e "    ${BOLD}sudo apt install libsqlcipher-dev libsqlcipher0${RESET}"
    echo -e "    ${BOLD}pip install pysqlcipher3${RESET}\n"
    exit 1
fi

# ── Launch ────────────────────────────────────────────────────────────────────
echo -e "${GREEN}  Starting SMP V7...${RESET}"
export PYTHONPATH="$SCRIPT_DIR"
exec python3 "$SCRIPT_DIR/main.py" "$@"
