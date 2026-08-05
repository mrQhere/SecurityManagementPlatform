#!/usr/bin/env bash
# =============================================================================
# SMP V7 — Setup Script
# Local-first security platform installer
# =============================================================================
set -euo pipefail

SCRIPT_START=$(date +%s)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
LOG_FILE="$SCRIPT_DIR/setup.log"
mkdir -p "$BIN_DIR"

# Clear previous log
> "$LOG_FILE"

# ── Colours & UI ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { printf "\r\033[K${GREEN}✔${RESET} %s\n" "$*"; }
warn() { printf "\r\033[K${YELLOW}⚠${RESET} %s\n" "$*"; }
fail() { printf "\r\033[K${RED}✘${RESET} %s\n" "$*"; }
info() { printf "\r\033[K${CYAN}ℹ${RESET} %s\n" "$*"; }

spin() {
    local msg="$1"
    shift
    local pid
    
    # Run the command in the background, appending all output to the log file
    "$@" >> "$LOG_FILE" 2>&1 &
    pid=$!

    local spinner=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r\033[K${CYAN}%s${RESET} %s" "${spinner[$((i % ${#spinner[@]}))]}" "$msg"
        i=$((i+1))
        sleep 0.1
    done

    wait $pid
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        ok "$msg"
    else
        fail "$msg (Check setup.log for details)"
        return $exit_code
    fi
}

ARCH="$(uname -m)"
is_arm64() { [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; }

download_binary() {
    local name="$1" url_amd64="$2" url_arm64="$3"
    local url; is_arm64 && url="$url_arm64" || url="$url_amd64"

    local tmp; tmp="$(mktemp -d)"
    local archive="$tmp/archive"

    if ! curl -fsSL --retry 3 --retry-delay 2 -o "$archive" "$url" >> "$LOG_FILE" 2>&1; then
        rm -rf "$tmp"; return 1
    fi

    if [[ "$url" == *.zip ]]; then
        unzip -q "$archive" -d "$tmp" >> "$LOG_FILE" 2>&1 || { rm -rf "$tmp"; return 1; }
    else
        tar -xzf "$archive" -C "$tmp" >> "$LOG_FILE" 2>&1 || { rm -rf "$tmp"; return 1; }
    fi

    local binary_path
    binary_path=$(find "$tmp" -type f -name "${name,,}" | head -1)
    if [[ -z "$binary_path" ]]; then
        binary_path=$(find "$tmp" -type f -iname "$name" | head -1)
    fi

    if [[ -n "$binary_path" ]]; then
        install -m 0755 "$binary_path" "$BIN_DIR/$name"
        rm -rf "$tmp"; return 0
    else
        rm -rf "$tmp"; return 1
    fi
}

have() { command -v "$1" &>/dev/null || [[ -x "$BIN_DIR/$1" ]]; }

# =============================================================================
echo -e "\n${BOLD}Security Management Platform Installer${RESET}"
echo -e "Logs saved to ${CYAN}$LOG_FILE${RESET}\n"

# Ensure sudo credentials are cached upfront so background spinners don't fail silently
echo -e "  ${CYAN}ℹ Asking for administrative privileges (sudo) to install packages...${RESET}"
sudo -v
# Keep-alive: update existing sudo time stamp until script has finished
while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &

# ── Python ──
if have python3; then
    ok "Python 3 installed ($(python3 --version 2>&1))"
else
    spin "Installing Python 3" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip python3-venv python3-dev
fi

# ── Go ──
if have go; then
    ok "Go installed ($(go version 2>&1 | awk '{print $3}'))"
else
    if ! spin "Installing Go via apt" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go; then
        warn "apt go failed — downloading prebuilt Go tarball"
        GO_VER="1.22.5"
        GOARCH="amd64"; is_arm64 && GOARCH="arm64"
        curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" | sudo tar -C /usr/local -xz >> "$LOG_FILE" 2>&1
        export PATH="$PATH:/usr/local/go/bin"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        ok "Go installed via tarball"
    fi
fi

# ── OS Packages (apt) ──
spin "Refreshing apt package index" sudo apt-get update -qq

SQLCIPHER_RT=""
SQLCIPHER_BUILD_FROM_SOURCE=false
if apt-cache show libsqlcipher0t64 >> "$LOG_FILE" 2>&1; then
    SQLCIPHER_RT="libsqlcipher0t64"
elif apt-cache show libsqlcipher0 >> "$LOG_FILE" 2>&1; then
    SQLCIPHER_RT="libsqlcipher0"
else
    warn "libsqlcipher0 not found in apt — will build SQLCipher from source."
    SQLCIPHER_BUILD_FROM_SOURCE=true
fi

OS_TOOLS=(nmap nikto whatweb traceroute masscan ruby ruby-dev build-essential
          perl git libsqlcipher-dev openssl libssl-dev
          libxcb-cursor0 libxcb-cursor-dev pipx clamav clamav-daemon)
[[ -n "$SQLCIPHER_RT" ]] && OS_TOOLS+=("$SQLCIPHER_RT")

MISSING_APT=()
for t in "${OS_TOOLS[@]}"; do
    if ! dpkg -s "$t" >> "$LOG_FILE" 2>&1; then
        MISSING_APT+=("$t")
    fi
done

if [[ ${#MISSING_APT[@]} -eq 0 ]]; then
    ok "OS packages already installed"
else
    if ! spin "Installing missing OS packages" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_APT[@]}"; then
        warn "Some OS packages failed to fetch. Retrying with --fix-missing..."
        sudo DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing -qq >> "$LOG_FILE" 2>&1 || true
        # Force a true return so the spinner shows a checkmark even if 1 package (e.g. masscan) drops
        spin "Installing OS packages (--fix-missing)" bash -c "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing ${MISSING_APT[*]} || true"
        warn "Proceeding despite some missing OS packages (mirror network issue)."
    fi
fi

# ── SQLCipher Source Build ──
if $SQLCIPHER_BUILD_FROM_SOURCE; then
    if ldconfig -p 2>/dev/null | grep -q 'libsqlcipher'; then
        ok "SQLCipher already present via ldconfig"
        SQLCIPHER_BUILD_FROM_SOURCE=false
    else
        _SC_TMP=$(mktemp -d)
        if spin "Cloning SQLCipher" git clone --depth=1 https://github.com/sqlcipher/sqlcipher.git "$_SC_TMP"; then
            pushd "$_SC_TMP" > /dev/null
            spin "Configuring SQLCipher" ./configure CFLAGS="-DSQLITE_HAS_CODEC" LDFLAGS="-lcrypto" --prefix=/usr/local
            spin "Compiling SQLCipher" make -j"$(nproc)"
            spin "Installing SQLCipher" sudo make install
            sudo ldconfig
            popd > /dev/null
            rm -rf "$_SC_TMP"
        else
            rm -rf "$_SC_TMP"
            warn "SQLCipher source build failed (no git/network). pysqlcipher3 may fail."
        fi
    fi
fi

# ── Python venv & dependencies ──
if [[ ! -d "$SCRIPT_DIR/venv" ]]; then
    spin "Creating Python virtual environment" python3 -m venv "$SCRIPT_DIR/venv"
else
    ok "Virtual environment exists"
fi

source "$SCRIPT_DIR/venv/bin/activate"
spin "Upgrading pip" pip install --upgrade pip

total_pkgs=$(wc -l < "$SCRIPT_DIR/requirements.txt")
spin "Installing Python dependencies ($total_pkgs packages)" pip install -r "$SCRIPT_DIR/requirements.txt"

if ! python3 -c "from pysqlcipher3 import dbapi2" >> "$LOG_FILE" 2>&1; then
    if ! spin "Installing pysqlcipher3" pip install pysqlcipher3; then
        fail "pysqlcipher3 installation failed. Ensure libsqlcipher-dev is installed."
        exit 1
    fi
else
    ok "pysqlcipher3 installed"
fi

# ── Go Security Tools ──
export PATH="$PATH:$(go env GOPATH)/bin:$BIN_DIR"
grep -q 'GOPATH.*bin' ~/.bashrc || echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

declare -A TOOLS_AMD64=(
    [nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip"
    [subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip"
    [httpx]="https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip"
    [katana]="https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip"
    [dnsx]="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip"
    [ffuf]="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz"
    [gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v9.0.3/gitleaks_8.21.2_linux_x64.tar.gz"
    [dalfox]="https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz"
)

declare -A TOOLS_ARM64=(
    [nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_arm64.zip"
    [subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_arm64.zip"
    [httpx]="https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_arm64.zip"
    [katana]="https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_arm64.zip"
    [dnsx]="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip"
    [ffuf]="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz"
    [gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v9.0.3/gitleaks_8.21.2_linux_arm64.tar.gz"
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

for name in "${tool_names[@]}"; do
    if have "$name"; then
        ok "$name installed"
        continue
    fi

    if is_arm64; then url="${TOOLS_ARM64[$name]:-}"; else url="${TOOLS_AMD64[$name]:-}"; fi

    if [[ -n "${url:-}" ]] && spin "Downloading $name" download_binary "$name" "${TOOLS_AMD64[$name]}" "${TOOLS_ARM64[$name]}"; then
        continue
    fi

    # Fallback
    built=false
    for entry in "${GO_FALLBACKS[@]}"; do
        n="${entry%% *}"; pkg="${entry#* }"
        if [[ "$n" == "$name" ]] && have go; then
            if spin "Building $name from source" go install -v "$pkg"; then
                built=true
            fi
        fi
    done
    if ! $built; then
        warn "$name download and build failed"
    fi
done

# ── Prowler & CrackMapExec (via pipx) ──
spin "Installing CrackMapExec" pipx install crackmapexec >> "$LOG_FILE" 2>&1 || true
spin "Installing Prowler" pipx install prowler >> "$LOG_FILE" 2>&1 || true

# ── Trivy (Aqua Security) ──
if have trivy; then
    ok "Trivy installed"
else
    if spin "Downloading Trivy" curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BIN_DIR" v0.49.1 >> "$LOG_FILE" 2>&1; then
        :
    else
        warn "Failed to install Trivy"
    fi
fi

# ── WPScan ──
if have wpscan; then
    ok "wpscan installed"
elif gem install wpscan --no-user-install >> "$LOG_FILE" 2>&1 && have wpscan; then
    ok "wpscan installed via gem"
elif pip install wpscanpy >> "$LOG_FILE" 2>&1 && python3 -c "import wpscanpy" >> "$LOG_FILE" 2>&1; then
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_PY_WRAPPER'
#!/usr/bin/env bash
exec python3 -m wpscanpy "$@"
WPSCAN_PY_WRAPPER
    chmod +x "$BIN_DIR/wpscan"
    ok "wpscan installed via pip"
elif have docker; then
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_WRAPPER'
#!/usr/bin/env bash
exec docker run --rm --network=host wpscanteam/wpscan "$@"
WPSCAN_WRAPPER
    chmod +x "$BIN_DIR/wpscan"
    ok "wpscan Docker wrapper created"
else
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_STUB'
#!/usr/bin/env bash
echo "  ⚠  WPScan is not installed."
echo "  Install one of the following and re-run setup.sh:"
echo "    gem:    sudo gem install wpscan"
echo "    pip:    pip install wpscanpy"
echo "    docker: docker pull wpscanteam/wpscan"
exit 1
WPSCAN_STUB
    chmod +x "$BIN_DIR/wpscan"
    warn "WPScan not installed. WordPress scans disabled."
fi

chmod +x "$SCRIPT_DIR/run.sh"
find "$BIN_DIR" -type f -exec chmod +x {} \; 2>/dev/null || true

now=$(date +%s)
echo -e "\n${GREEN}✔ Setup complete in $((now - SCRIPT_START))s${RESET}"
echo -e "  ▶ Launch with: ./run.sh\n"
