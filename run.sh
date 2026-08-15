#!/usr/bin/env bash
# =============================================================================
# SMP — Launcher
# © mrQhere
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD} Security Management Platform${RESET}"
echo -e " Local-first · Zero-cloud · Encrypted at rest\n"

# ── Venv check ────────────────────────────────────────────────────────────────
if [[ ! -d "$SCRIPT_DIR/venv" ]]; then
 echo -e "${RED} No virtual environment found.${RESET}"
 echo -e " Run ${BOLD}./setup.sh${RESET} first to install dependencies.\n"
 exit 1
fi

source "$SCRIPT_DIR/venv/bin/activate"

# ── SQLCipher check ───────────────────────────────────────────────────────────
if ! python3 -c "from pysqlcipher3 import dbapi2" 2>/dev/null; then
 echo -e "${RED} FATAL: pysqlcipher3 is not installed.${RESET}"
 echo -e " SMP requires SQLCipher for encrypted-at-rest storage.\n"
 echo -e " Fix (Ubuntu 24.04+): sudo apt install libsqlcipher-dev libsqlcipher0t64"
 echo -e " Fix (Ubuntu 22.04): sudo apt install libsqlcipher-dev libsqlcipher0"
 echo -e " Then: pip install pysqlcipher3\n"
 exit 1
fi

# ── Qt / xcb display check ───────────────────────────────────────────────────
# Qt 6.5+ requires libxcb-cursor0 for the xcb platform plugin.
# Auto-install silently — runs on every ./run.sh until the package is present.
if ! dpkg-query -W -f='${Status}' libxcb-cursor0 2>/dev/null | grep -q "install ok installed"; then
 echo -e "${YELLOW} ⚠ libxcb-cursor0 missing — auto-installing (Qt 6.5+ requirement)...${RESET}"
 if sudo apt-get install -y -qq libxcb-cursor0 libxcb-cursor-dev 2>/dev/null; then
 echo -e "${GREEN} ✔ libxcb-cursor0 installed successfully${RESET}"
 else
 echo -e "${YELLOW} ⚠ Auto-install failed. Run manually:${RESET}"
 echo -e " ${BOLD}sudo apt-get install libxcb-cursor0${RESET}"
 echo -e " Continuing in headless API mode to avoid crash...\n"
 # Force headless to prevent Qt core dump
 export HEADLESS_FORCED=1
 fi
fi

# ── Headless / no-display fallback ───────────────────────────────────────────
# If there is no graphical display (SSH session, server, CI), automatically
# switch to API-only mode instead of crashing.
HEADLESS=false
[[ "${HEADLESS_FORCED:-0}" == "1" ]] && HEADLESS=true
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
 HEADLESS=true
fi

# Also detect if the user already passed --api explicitly
for arg in "$@"; do
 [[ "$arg" == "--api" || "$arg" == "--headless" ]] && HEADLESS=true
done

if $HEADLESS; then
 echo -e "${YELLOW} ⚠ No display detected — starting in API-only mode (headless)${RESET}"
 echo -e " Dashboard: ${BOLD}http://localhost:8000/api/v6/docs${RESET}\n"
export PYTHONPATH="$SCRIPT_DIR"
 # Strip any existing --api to avoid duplicates, then force it
 FILTERED_ARGS=()
 for arg in "$@"; do
 [[ "$arg" != "--api" && "$arg" != "--headless" ]] && FILTERED_ARGS+=("$arg")
 done
 exec python3 "$SCRIPT_DIR/main.py" --api "${FILTERED_ARGS[@]}"
fi

# ── GUI launch ────────────────────────────────────────────────────────────────
echo -e "${GREEN} Starting SMP...${RESET}"
export PYTHONPATH="$SCRIPT_DIR"
exec python3 "$SCRIPT_DIR/main.py" "$@"
