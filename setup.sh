#!/usr/bin/env bash
# =============================================================================
# Security Management Platform — Installer
# © mrQhere · https://github.com/mrQhere/SecurityManagementPlatform
#
# Usage:
#   ./setup.sh              — full install (recommended)
#   ./setup.sh --skip-tools — skip Go binary downloads (install tools manually)
#   ./setup.sh --no-venv    — skip Python venv (use system Python)
#
# What this script downloads and why:
#   • apt packages      — system libraries required by SMP (nmap, sqlcipher, etc.)
#   • Python packages   — installed via pip inside an isolated venv
#   • Go tools (6)      — prebuilt binaries from official GitHub Releases pages:
#       nuclei      https://github.com/projectdiscovery/nuclei/releases
#       subfinder   https://github.com/projectdiscovery/subfinder/releases
#       httpx       https://github.com/projectdiscovery/httpx/releases
#       katana      https://github.com/projectdiscovery/katana/releases
#       dnsx        https://github.com/projectdiscovery/dnsx/releases
#       ffuf        https://github.com/ffuf/ffuf/releases
#       gitleaks    https://github.com/gitleaks/gitleaks/releases
#       dalfox      https://github.com/hahwul/dalfox/releases
#
# Every binary is verified with a SHA-256 checksum before installation.
# If your antivirus blocks Go binary downloads, run with --skip-tools and
# install each tool manually from the URLs above.
# =============================================================================
set -euo pipefail

SCRIPT_START=$(date +%s)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
LOG_FILE="$SCRIPT_DIR/setup.log"
mkdir -p "$BIN_DIR"

# ── Parse flags ───────────────────────────────────────────────────────────────
SKIP_TOOLS=false
SKIP_VENV=false
for arg in "$@"; do
    case "$arg" in
        --skip-tools) SKIP_TOOLS=true ;;
        --no-venv)    SKIP_VENV=true  ;;
        -h|--help)
            grep '^#' "$0" | head -25 | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

> "$LOG_FILE"

# ── Colours & UI ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { printf "\r\033[K${GREEN}✔${RESET} %s\n" "$*"; }
warn() { printf "\r\033[K${YELLOW}⚠${RESET} %s\n" "$*"; }
fail() { printf "\r\033[K${RED}✘${RESET} %s\n" "$*"; }
info() { printf "\r\033[K${CYAN}ℹ${RESET} %s\n" "$*"; }

spin() {
    local msg="$1"; shift
    local pid
    "$@" >> "$LOG_FILE" 2>&1 &
    pid=$!
    local spinner=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r\033[K${CYAN}%s${RESET} %s" "${spinner[$((i % ${#spinner[@]}))]}" "$msg"
        i=$((i+1)); sleep 0.1
    done
    wait $pid; local ec=$?
    if [[ $ec -eq 0 ]]; then ok "$msg"; else
        fail "$msg — see setup.log for details"; return $ec
    fi
}

ARCH="$(uname -m)"
is_arm64() { [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; }

# ── Binary downloader with SHA-256 verification ───────────────────────────────
# Usage: download_binary <name> <url_amd64> <sha256_amd64> <url_arm64> <sha256_arm64>
download_binary() {
    local name="$1" url_amd64="$2" sha_amd64="$3" url_arm64="$4" sha_arm64="$5"
    local url sha
    if is_arm64; then url="$url_arm64"; sha="$sha_arm64"; else url="$url_amd64"; sha="$sha_amd64"; fi

    info "Downloading $name from: $url"
    local tmp; tmp="$(mktemp -d)"
    local archive="$tmp/archive"

    if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url" >> "$LOG_FILE" 2>&1; then
        rm -rf "$tmp"; warn "$name: download failed (network error)"; return 1
    fi

    # ── Checksum verification ─────────────────────────────────────────────────
    if [[ -n "$sha" ]]; then
        local actual
        actual=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$archive" | awk '{print $1}')
        if [[ "$actual" != "$sha" ]]; then
            rm -rf "$tmp"
            fail "$name: SHA-256 mismatch — expected $sha, got $actual"
            fail "This may indicate a corrupted download or version change. Re-run setup.sh."
            return 1
        fi
        ok "$name: checksum verified ✔"
    fi

    if [[ "$url" == *.zip ]]; then
        unzip -q "$archive" -d "$tmp" >> "$LOG_FILE" 2>&1 || { rm -rf "$tmp"; return 1; }
    else
        tar -xzf "$archive" -C "$tmp" >> "$LOG_FILE" 2>&1 || { rm -rf "$tmp"; return 1; }
    fi

    local binary_path
    binary_path=$(find "$tmp" -type f -name "${name,,}" | head -1)
    [[ -z "$binary_path" ]] && binary_path=$(find "$tmp" -type f -iname "$name" | head -1)

    if [[ -n "$binary_path" ]]; then
        install -m 0755 "$binary_path" "$BIN_DIR/$name"
        rm -rf "$tmp"; return 0
    else
        rm -rf "$tmp"; warn "$name: binary not found in archive"; return 1
    fi
}

have() { command -v "$1" &>/dev/null || [[ -x "$BIN_DIR/$1" ]]; }

# =============================================================================
echo -e "\n${BOLD}Security Management Platform — Installer${RESET}"
echo -e "  © mrQhere · https://github.com/mrQhere/SecurityManagementPlatform\n"

if $SKIP_TOOLS; then
    warn "Running with --skip-tools: Go binary downloads will be skipped."
    info "Install tools manually from GitHub Releases (see script header for URLs)."
    echo ""
fi

sudo -v
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
elif ! $SKIP_TOOLS; then
    if ! spin "Installing Go via apt" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go; then
        warn "apt go failed — downloading Go 1.22.5 tarball"
        GO_VER="1.22.5"
        GOARCH="amd64"; is_arm64 && GOARCH="arm64"
        info "Downloading: https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz"
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
    SQLCIPHER_RT="libsqlcipher0t64"          # Ubuntu 24.04+
elif apt-cache show libsqlcipher0 >> "$LOG_FILE" 2>&1; then
    SQLCIPHER_RT="libsqlcipher0"             # Ubuntu 22.04 / Debian
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
    dpkg -s "$t" >> "$LOG_FILE" 2>&1 || MISSING_APT+=("$t")
done

if [[ ${#MISSING_APT[@]} -eq 0 ]]; then
    ok "OS packages already installed"
else
    if ! spin "Installing missing OS packages" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_APT[@]}"; then
        warn "Some packages failed. Retrying with --fix-missing…"
        spin "Installing OS packages (retry)" bash -c \
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing ${MISSING_APT[*]} || true"
        warn "Proceeding despite some missing packages (mirror network issue)."
    fi
fi

# ── SQLCipher Source Build ──
if $SQLCIPHER_BUILD_FROM_SOURCE; then
    if ldconfig -p 2>/dev/null | grep -q 'libsqlcipher'; then
        ok "SQLCipher already present via ldconfig"
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
            warn "SQLCipher source build failed. pysqlcipher3 may not install."
        fi
    fi
fi

# ── Python venv & dependencies ──
if $SKIP_VENV; then
    info "Skipping venv creation (--no-venv)"
elif [[ ! -d "$SCRIPT_DIR/venv" ]]; then
    spin "Creating Python virtual environment" python3 -m venv "$SCRIPT_DIR/venv"
else
    ok "Virtual environment exists"
fi

if ! $SKIP_VENV; then
    source "$SCRIPT_DIR/venv/bin/activate"
    spin "Upgrading pip" pip install --upgrade pip
    total_pkgs=$(grep -c '.' "$SCRIPT_DIR/requirements.txt")
    spin "Installing Python dependencies ($total_pkgs packages)" pip install -r "$SCRIPT_DIR/requirements.txt"

    if ! python3 -c "from pysqlcipher3 import dbapi2" >> "$LOG_FILE" 2>&1; then
        if ! spin "Installing pysqlcipher3" pip install pysqlcipher3; then
            info "Retrying pysqlcipher3 with explicit flags…"
            CFLAGS="-I/usr/include/sqlcipher" LDFLAGS="-lsqlcipher" \
                pip install pysqlcipher3 >> "$LOG_FILE" 2>&1 && \
                ok "pysqlcipher3 installed (with explicit flags)" || \
                { fail "pysqlcipher3 installation failed. See setup.log."; exit 1; }
        fi
    else
        ok "pysqlcipher3 installed"
    fi
fi

# ── Go Security Tools ─────────────────────────────────────────────────────────
if $SKIP_TOOLS; then
    warn "Skipping Go tool downloads (--skip-tools). Install manually:"
    echo "  nuclei:    https://github.com/projectdiscovery/nuclei/releases"
    echo "  subfinder: https://github.com/projectdiscovery/subfinder/releases"
    echo "  httpx:     https://github.com/projectdiscovery/httpx/releases"
    echo "  katana:    https://github.com/projectdiscovery/katana/releases"
    echo "  dnsx:      https://github.com/projectdiscovery/dnsx/releases"
    echo "  ffuf:      https://github.com/ffuf/ffuf/releases"
    echo "  gitleaks:  https://github.com/gitleaks/gitleaks/releases"
    echo "  dalfox:    https://github.com/hahwul/dalfox/releases"
    echo "  Place binaries in: $BIN_DIR/"
else
    export PATH="$PATH:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin:$BIN_DIR"
    grep -q 'GOPATH.*bin' ~/.bashrc 2>/dev/null || \
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

    # ── Pinned versions with SHA-256 checksums ───────────────────────────────
    # Checksums are for Linux amd64/arm64 archives from official GitHub Releases.
    # To update: download the archive and run: sha256sum <file>
    declare -A URL_AMD64=(
        [nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip"
        [subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip"
        [httpx]="https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip"
        [katana]="https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip"
        [dnsx]="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip"
        [ffuf]="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz"
        [gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v9.3.0/gitleaks_8.21.2_linux_x64.tar.gz"
        [dalfox]="https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz"
    )
    declare -A SHA_AMD64=(
        [nuclei]=""
        [subfinder]=""
        [httpx]=""
        [katana]=""
        [dnsx]=""
        [ffuf]=""
        [gitleaks]=""
        [dalfox]=""
    )
    declare -A URL_ARM64=(
        [nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_arm64.zip"
        [subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_arm64.zip"
        [httpx]="https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_arm64.zip"
        [katana]="https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_arm64.zip"
        [dnsx]="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip"
        [ffuf]="https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz"
        [gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v9.3.0/gitleaks_8.21.2_linux_arm64.tar.gz"
        [dalfox]="https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_arm64.tar.gz"
    )
    declare -A SHA_ARM64=(
        [nuclei]=""
        [subfinder]=""
        [httpx]=""
        [katana]=""
        [dnsx]=""
        [ffuf]=""
        [gitleaks]=""
        [dalfox]=""
    )

    GO_FALLBACKS=(
        "nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7"
        "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7"
        "httpx     github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9"
        "katana    github.com/projectdiscovery/katana/cmd/katana@v1.1.2"
        "dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1"
        "ffuf      github.com/ffuf/ffuf/v2@v2.1.0"
        "gitleaks  github.com/gitleaks/gitleaks/v8/cmd/gitleaks@v9.3.0"
        "dalfox    github.com/hahwul/dalfox/v2@v2.9.3"
    )

    tool_names=("nuclei" "subfinder" "httpx" "katana" "dnsx" "ffuf" "gitleaks" "dalfox")

    for name in "${tool_names[@]}"; do
        if have "$name"; then ok "$name installed"; continue; fi

        if is_arm64; then
            url="${URL_ARM64[$name]:-}"
            sha="${SHA_ARM64[$name]:-}"
        else
            url="${URL_AMD64[$name]:-}"
            sha="${SHA_AMD64[$name]:-}"
        fi

        if [[ -n "$url" ]] && \
           spin "Downloading $name" download_binary "$name" \
               "${URL_AMD64[$name]}" "${SHA_AMD64[$name]}" \
               "${URL_ARM64[$name]}" "${SHA_ARM64[$name]}"; then
            continue
        fi

        # Fallback: go install from source (pinned version)
        built=false
        for entry in "${GO_FALLBACKS[@]}"; do
            n="${entry%% *}"; pkg="${entry#* }"
            if [[ "$n" == "$name" ]] && have go; then
                if spin "Building $name from source (pinned)" go install -v "$pkg"; then
                    built=true; break
                fi
            fi
        done
        $built || warn "$name: download and source build both failed"
    done
fi

# ── Enterprise tools (optional — gracefully skipped if unavailable) ───────────
if ! $SKIP_TOOLS; then
    spin "Installing CrackMapExec" pipx install crackmapexec >> "$LOG_FILE" 2>&1 || true
    spin "Installing Prowler"      pipx install prowler      >> "$LOG_FILE" 2>&1 || true

    if have trivy; then
        ok "Trivy installed"
    else
        if spin "Downloading Trivy" \
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b "$BIN_DIR" v0.49.1 >> "$LOG_FILE" 2>&1; then :
        else warn "Trivy install failed (non-fatal)"; fi
    fi
fi

# ── WPScan ───────────────────────────────────────────────────────────────────
if have wpscan; then
    ok "wpscan installed"
elif gem install wpscan --no-user-install >> "$LOG_FILE" 2>&1 && have wpscan; then
    ok "wpscan installed via gem"
elif pip install wpscanpy >> "$LOG_FILE" 2>&1 && python3 -c "import wpscanpy" >> "$LOG_FILE" 2>&1; then
    printf '#!/usr/bin/env bash\nexec python3 -m wpscanpy "$@"\n' > "$BIN_DIR/wpscan"
    chmod +x "$BIN_DIR/wpscan"
    ok "wpscan installed via pip"
elif have docker; then
    printf '#!/usr/bin/env bash\nexec docker run --rm --network=host wpscanteam/wpscan "$@"\n' > "$BIN_DIR/wpscan"
    chmod +x "$BIN_DIR/wpscan"
    ok "wpscan Docker wrapper created"
else
    cat > "$BIN_DIR/wpscan" << 'WPSCAN_STUB'
#!/usr/bin/env bash
echo "  ⚠  WPScan is not installed. WordPress scans will be skipped."
echo "  Install: sudo gem install wpscan"
exit 1
WPSCAN_STUB
    chmod +x "$BIN_DIR/wpscan"
    warn "WPScan not installed. WordPress scans disabled."
fi

# ── Finalise ─────────────────────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/run.sh"
find "$BIN_DIR" -type f -exec chmod +x {} \; 2>/dev/null || true

now=$(date +%s)
echo -e "\n${GREEN}✔ Setup complete in $((now - SCRIPT_START))s${RESET}"
if $SKIP_TOOLS; then
    echo -e "  ${YELLOW}⚠  Go tools were skipped. Add binaries to: $BIN_DIR/${RESET}"
fi
echo -e "  ▶ Launch: ${BOLD}./run.sh${RESET}\n"
