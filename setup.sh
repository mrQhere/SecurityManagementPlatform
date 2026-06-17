#!/usr/bin/env bash
# ============================================================
#  Security Management Platform – Linux/Ubuntu Setup Script
# ============================================================
# Usage:  bash setup.sh
# Tested: Ubuntu 20.04 / 22.04 / 24.04
# ============================================================
set -e

PYTHON_MIN="3.11"
VENV_DIR="venv"
REQUIREMENTS="requirements.txt"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   Security Management Platform – Setup       ║"
echo "  ║   Linux / Ubuntu Installer                   ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Locate Python 3.11+ ────────────────────────────────────────────────────
info "Checking Python version..."
PYTHON=""
for candidate in python3.11 python3.12 python3.13 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    warn "Python 3.11+ not found. Attempting to install via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
    PYTHON="python3.11"
fi
success "Using Python: $PYTHON ($($PYTHON --version))"

# ── 2. Create virtual environment ────────────────────────────────────────────
info "Creating virtual environment in ./$VENV_DIR ..."
if [ ! -d "$VENV_DIR" ]; then
    $PYTHON -m venv "$VENV_DIR"
fi
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"
success "Virtual environment ready."

# ── 3. Upgrade pip ───────────────────────────────────────────────────────────
info "Upgrading pip..."
$VENV_PIP install --quiet --upgrade pip

# ── 4. Install Python dependencies ───────────────────────────────────────────
info "Installing Python requirements (this may take a minute)..."
$VENV_PIP install --quiet -r "$REQUIREMENTS"
$VENV_PIP install --quiet PySide6
success "Python packages installed."

# ── 5. System tools via apt ───────────────────────────────────────────────────
info "Installing system scanning tools via apt..."
APT_TOOLS=("nmap" "nikto" "whatweb")
MISSING_APT=()

for tool in "${APT_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_APT+=("$tool")
    else
        success "$tool already installed."
    fi
done

if [ ${#MISSING_APT[@]} -gt 0 ]; then
    info "Installing: ${MISSING_APT[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING_APT[@]}" && success "apt tools installed." \
        || warn "Some apt tools failed. Install manually: sudo apt install ${MISSING_APT[*]}"
fi

# ── 6. Go-based tools (nuclei, subfinder, httpx, ffuf) ───────────────────────
info "Checking Go-based tools..."
GO_TOOLS=(
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "ffuf:github.com/ffuf/ffuf/v2@latest"
)

if command -v go &>/dev/null; then
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"
    for entry in "${GO_TOOLS[@]}"; do
        bin="${entry%%:*}"
        pkg="${entry##*:}"
        if command -v "$bin" &>/dev/null; then
            success "$bin already installed."
        else
            info "Installing $bin via go install..."
            go install "$pkg" && success "$bin installed." \
                || warn "Failed to install $bin. Try: go install $pkg"
        fi
    done
else
    warn "Go not found. The following tools need Go to install:"
    for entry in "${GO_TOOLS[@]}"; do
        bin="${entry%%:*}"; pkg="${entry##*:}"
        echo "      → $bin  :  go install $pkg"
    done
    warn "Install Go from https://go.dev/dl/ and re-run this script."
fi

# ── 7. Nuclei templates update ───────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && success "Nuclei templates updated." \
        || warn "Nuclei template update failed (non-critical)."
fi

# ── 8. OWASP ZAP (manual – too large for auto-install) ───────────────────────
if ! command -v zaproxy &>/dev/null; then
    warn "OWASP ZAP not detected. ZAP is OPTIONAL."
    echo "      Download from: https://www.zaproxy.org/download/"
    echo "      Then set zap_enabled=true in config/settings.json"
fi

# ── 9. Create run script ──────────────────────────────────────────────────────
cat > run.sh << 'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$DIR"
exec "$DIR/venv/bin/python" "$DIR/main.py" "$@"
EOF
chmod +x run.sh
success "Created run.sh"

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  Setup Complete!                             ║"
echo "  ║  Run the app:  bash run.sh                   ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
