#!/usr/bin/env bash
# =============================================================================
# SMP V7 — Setup Script
# Local-first security platform installer
# © mrQhere
# =============================================================================
set -euo pipefail

SCRIPT_START=$(date +%s)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
mkdir -p "$BIN_DIR"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────

elapsed() {
    local now; now=$(date +%s)
    echo "$((now - SCRIPT_START))s"
}

step() {
    echo -e "\n${CYAN}${BOLD}[$(elapsed)] ══ $* ══${RESET}"
}

ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
fail() { echo -e "${RED}  ✘ $*${RESET}"; }

# ── ASCII progress bar ─────────────────────────────────────────────────────
# Usage: progress_bar <current> <total> [label]
progress_bar() {
    local cur=$1 total=$2 label="${3:-}"
    local width=40
    local filled=$(( cur * width / total ))
    local empty=$(( width - filled ))
    local bar=""
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty;  i++ )); do bar+="░"; done
    local pct=$(( cur * 100 / total ))
    # \r to overwrite the same line
    printf "\r  ${CYAN}[%s] %3d%%${RESET}  %s  %s" "$bar" "$pct" "$label" "      "
}

finish_bar() { echo; }  # newline after progress bar

# ── Download prebuilt binary from GitHub Releases ────────────────────────────
# Usage: download_binary <name> <url_amd64> <url_arm64>
# Extracts the binary named <name> from a .zip or .tar.gz archive.
# Returns 0 on success, 1 on failure.
ARCH="$(uname -m)"
is_arm64() { [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; }

download_binary() {
    local name="$1" url_amd64="$2" url_arm64="$3"
    local url; is_arm64 && url="$url_arm64" || url="$url_amd64"

    local tmp; tmp="$(mktemp -d)"
    local archive="$tmp/archive"

    echo -n "    Downloading $name... "
    if ! curl -fsSL --retry 3 --retry-delay 2 -o "$archive" "$url" 2>/dev/null; then
        warn "download failed for $name"
        rm -rf "$tmp"; return 1
    fi

    # Extract
    if [[ "$url" == *.zip ]]; then
        unzip -q "$archive" -d "$tmp" 2>/dev/null || { rm -rf "$tmp"; return 1; }
    else
        tar -xzf "$archive" -C "$tmp" 2>/dev/null || { rm -rf "$tmp"; return 1; }
    fi

    # Find the binary (case-insensitive name match inside archive)
    local binary_path
    binary_path=$(find "$tmp" -type f -name "${name,,}" | head -1)
    if [[ -z "$binary_path" ]]; then
        # Some tools use the full lowercase name
        binary_path=$(find "$tmp" -type f -iname "$name" | head -1)
    fi

    if [[ -n "$binary_path" ]]; then
        install -m 0755 "$binary_path" "$BIN_DIR/$name"
        ok "$name → bin/$name"
        rm -rf "$tmp"; return 0
    else
        warn "binary '$name' not found in archive"
        rm -rf "$tmp"; return 1
    fi
}

# ── Check if a tool is already available ─────────────────────────────────────
have() { command -v "$1" &>/dev/null || [[ -x "$BIN_DIR/$1" ]]; }

# =============================================================================
echo -e "\n${BOLD}╔══════════════════════════════════════════════╗"
echo    "║  SMP — Installer                             ║"
echo    "║  Local-first. Zero-cloud. Encrypted at rest. ║"
echo -e "╚══════════════════════════════════════════════╝${RESET}"

# =============================================================================
# STEP 1 — Python (skip if already present)
# =============================================================================
step "1/7  Python"
if have python3; then
    ok "python3 already installed ($(python3 --version 2>&1))"
else
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip python3-venv python3-dev
    ok "python3 installed"
fi

# =============================================================================
# STEP 2 — Go (skip if already present)
# =============================================================================
step "2/7  Go"
if have go; then
    ok "go already installed ($(go version 2>&1 | awk '{print $3}'))"
else
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go || {
        warn "apt go failed — downloading prebuilt Go tarball"
        GO_VER="1.22.5"
        GOARCH="amd64"; is_arm64 && GOARCH="arm64"
        curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" | sudo tar -C /usr/local -xz
        export PATH="$PATH:/usr/local/go/bin"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    }
    ok "go installed"
fi

# =============================================================================
# STEP 3 — OS packages (parallel, skip-if-installed)
# =============================================================================
step "3/7  OS Packages (apt)"

# ── Refresh apt cache first so apt-cache show queries are accurate ────────────
# apt-cache operates only on the LOCAL index. On a fresh clone or after a
# long gap the index may not list packages that exist in the repo. We update
# unconditionally here (takes ~2s) before any probing.
echo "  Refreshing apt package index..."
sudo apt-get update -qq

# ── Detect correct SQLCipher runtime library name ─────────────────────────────
# Ubuntu 24.04+ (Noble) renamed libsqlcipher0 → libsqlcipher0t64 as part of
# the 64-bit time_t transition. Probe both names after the index is current.
SQLCIPHER_RT=""
SQLCIPHER_BUILD_FROM_SOURCE=false
if apt-cache show libsqlcipher0t64 &>/dev/null 2>&1; then
    SQLCIPHER_RT="libsqlcipher0t64"
    ok "SQLCipher runtime: libsqlcipher0t64 (Ubuntu 24.04+)"
elif apt-cache show libsqlcipher0 &>/dev/null 2>&1; then
    SQLCIPHER_RT="libsqlcipher0"
    ok "SQLCipher runtime: libsqlcipher0 (Ubuntu 22.04 / Debian)"
else
    warn "libsqlcipher0 / libsqlcipher0t64 not found in apt — will build SQLCipher from source."
    SQLCIPHER_BUILD_FROM_SOURCE=true
fi

OS_TOOLS=(nmap nikto whatweb traceroute masscan ruby ruby-dev build-essential
          perl git libsqlcipher-dev openssl libssl-dev
          libxcb-cursor0 libxcb-cursor-dev)
[[ -n "$SQLCIPHER_RT" ]] && OS_TOOLS+=("$SQLCIPHER_RT")

MISSING_APT=()
for t in "${OS_TOOLS[@]}"; do
    if ! dpkg -s "$t" &>/dev/null 2>&1; then
        MISSING_APT+=("$t")
    fi
done

if [[ ${#MISSING_APT[@]} -eq 0 ]]; then
    ok "All OS packages already installed"
else
    echo "  Installing: ${MISSING_APT[*]}"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_APT[@]}"
    ok "OS packages installed"
fi

# ── SQLCipher source build (last resort) ─────────────────────────────────────
if $SQLCIPHER_BUILD_FROM_SOURCE; then
    # Check if already built from a previous run
    if ldconfig -p 2>/dev/null | grep -q 'libsqlcipher'; then
        ok "SQLCipher already present via ldconfig (previous source build)"
        SQLCIPHER_BUILD_FROM_SOURCE=false
    else
        echo "  Building SQLCipher from source (one-time, ~2 min)..."
        _SC_TMP=$(mktemp -d)
        if git clone --depth=1 https://github.com/sqlcipher/sqlcipher.git "$_SC_TMP" 2>/dev/null; then
            pushd "$_SC_TMP" > /dev/null
            ./configure \
                --enable-tempstore=yes \
                CFLAGS="-DSQLITE_HAS_CODEC" \
                LDFLAGS="-lcrypto" \
                --prefix=/usr/local \
                &>/dev/null
            make -j"$(nproc)" &>/dev/null
            sudo make install &>/dev/null
            sudo ldconfig
            popd > /dev/null
            rm -rf "$_SC_TMP"
            ok "SQLCipher built and installed from source"
        else
            rm -rf "$_SC_TMP"
            warn "SQLCipher source build failed (no git/network). pysqlcipher3 may fail."
            warn "Try manually: sudo apt install libsqlcipher-dev libsqlcipher0t64"
        fi
    fi
fi

# =============================================================================
# STEP 4 — Python virtual environment & dependencies
# =============================================================================
step "4/7  Python venv & dependencies"

if [[ ! -d "$SCRIPT_DIR/venv" ]]; then
    python3 -m venv "$SCRIPT_DIR/venv"
    ok "venv created"
else
    ok "venv already exists"
fi

# shellcheck disable=SC1091
source "$SCRIPT_DIR/venv/bin/activate"
pip install --upgrade pip --quiet

echo "  Installing Python requirements..."
total_pkgs=$(wc -l < "$SCRIPT_DIR/requirements.txt")
current=0

# Install in one shot (pip shows its own progress) — but show line count
pip install -r "$SCRIPT_DIR/requirements.txt" --quiet &
PIP_PID=$!

# Show a spinner while pip works
spinner=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
i=0
while kill -0 $PIP_PID 2>/dev/null; do
    printf "\r  %s  Installing %d packages..." "${spinner[$((i % ${#spinner[@]}))]}" "$total_pkgs"
    i=$((i+1)); sleep 0.15
done
printf "\r                                              \r"
wait $PIP_PID
ok "Python dependencies installed ($total_pkgs packages)"

# pysqlcipher3 — hard requirement
if ! python3 -c "from pysqlcipher3 import dbapi2" 2>/dev/null; then
    echo "  Installing pysqlcipher3 (SQLCipher hard requirement)..."
    pip install pysqlcipher3 --quiet && ok "pysqlcipher3 installed" || {
        fail "pysqlcipher3 installation failed."
        echo "  Ensure libsqlcipher-dev is installed, then re-run: pip install pysqlcipher3"
        exit 1
    }
else
    ok "pysqlcipher3 already available"
fi

# =============================================================================
# STEP 5 — ProjectDiscovery & Go security tools (prebuilt binaries, parallel)
# =============================================================================
step "5/7  Go Security Tools (prebuilt binaries)"

export PATH="$PATH:$(go env GOPATH)/bin:$BIN_DIR"
grep -q 'GOPATH.*bin' ~/.bashrc || echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

declare -A TOOLS_AMD64=(
    [nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip"
    [subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip"
    [httpx]="https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip"
    [katana]="https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip"
    [dnsx]="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip"
    [ffuf]="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz"
    [gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v7.0/gitleaks_8.21.2_linux_x64.tar.gz"
    [dalfox]="https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz"
)

declare -A TOOLS_ARM64=(
    [nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_arm64.zip"
    [subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_arm64.zip"
    [httpx]="https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_arm64.zip"
    [katana]="https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_arm64.zip"
    [dnsx]="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip"
    [ffuf]="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz"
    [gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v7.0/gitleaks_8.21.2_linux_arm64.tar.gz"
    [dalfox]="https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_arm64.tar.gz"
)

GO_FALLBACKS=(
    "nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "katana    github.com/projectdiscovery/katana/cmd/katana@latest"
    "dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "ffuf      github.com/ffuf/ffuf/v2@latest"
    "gitleaks  github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest"
    "dalfox    github.com/hahwul/dalfox/v2@latest"
)

tool_names=("nuclei" "subfinder" "httpx" "katana" "dnsx" "ffuf" "gitleaks" "dalfox")
total_go=${#tool_names[@]}
done_go=0

for name in "${tool_names[@]}"; do
    if have "$name"; then
        ok "$name already available"
        done_go=$((done_go+1))
        progress_bar $done_go $total_go "Go tools"
        continue
    fi

    # Try prebuilt binary first
    if is_arm64; then url="${TOOLS_ARM64[$name]:-}"; else url="${TOOLS_AMD64[$name]:-}"; fi

    if [[ -n "${url:-}" ]] && download_binary "$name" "${TOOLS_AMD64[$name]}" "${TOOLS_ARM64[$name]}"; then
        done_go=$((done_go+1))
        progress_bar $done_go $total_go "Go tools"
        continue
    fi

    # Fallback: go install from source
    warn "$name: prebuilt download failed — building from source (slow)"
    for entry in "${GO_FALLBACKS[@]}"; do
        n="${entry%% *}"; pkg="${entry#* }"
        if [[ "$n" == "$name" ]] && have go; then
            go install -v "$pkg" 2>/dev/null && ok "$name installed via go install" || fail "$name: source build also failed"
        fi
    done
    done_go=$((done_go+1))
    progress_bar $done_go $total_go "Go tools"
done
finish_bar

# =============================================================================
# STEP 6 — WPScan (gem → pip → Docker → stub)
# =============================================================================
step "6/7  WPScan"

if have wpscan; then
    ok "wpscan already available"
elif gem install wpscan --no-user-install 2>/dev/null && have wpscan; then
    ok "wpscan installed via gem"
elif pip install wpscanpy --quiet 2>/dev/null && python3 -c "import wpscanpy" 2>/dev/null; then
    # Create a thin wrapper so 'wpscan' resolves as a command
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_PY_WRAPPER'
#!/usr/bin/env bash
exec python3 -m wpscanpy "$@"
WPSCAN_PY_WRAPPER
    chmod +x "$BIN_DIR/wpscan"
    ok "wpscan installed via pip (wpscanpy)"
elif have docker; then
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_WRAPPER'
#!/usr/bin/env bash
# WPScan Docker wrapper — created by SMP setup
exec docker run --rm --network=host wpscanteam/wpscan "$@"
WPSCAN_WRAPPER
    chmod +x "$BIN_DIR/wpscan"
    ok "wpscan Docker wrapper created at bin/wpscan"
    echo "  Note: first run will pull the wpscanteam/wpscan image (~50 MB)"
else
    # All methods failed — create a stub that explains what to do
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_STUB'
#!/usr/bin/env bash
echo ""
echo "  ⚠  WPScan is not installed."
echo "  Install one of the following and re-run setup.sh:"
echo "    gem:    sudo gem install wpscan"
echo "    pip:    pip install wpscanpy"
echo "    docker: docker pull wpscanteam/wpscan"
echo ""
exit 1
WPSCAN_STUB
    chmod +x "$BIN_DIR/wpscan"
    warn "WPScan: gem/pip/docker all unavailable. A stub was created at bin/wpscan."
    warn "WordPress scans will be skipped. Install Ruby, pip wpscanpy, or Docker to enable."
fi

# =============================================================================
# STEP 7 — Finalize
# =============================================================================
step "7/7  Finalizing"

chmod +x "$SCRIPT_DIR/run.sh"

# Ensure bin/ scripts are all executable
find "$BIN_DIR" -type f -exec chmod +x {} \; 2>/dev/null || true

TOTAL=$(elapsed)
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗"
echo    "║  ✔  SMP Setup Complete                       ║"
printf  "║  ⏱  Total time: %-28s ║\n" "$TOTAL"
echo    "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  ▶  Ready. Launch SMP:"
echo "      ./run.sh"
echo ""
