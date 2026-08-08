#!/usr/bin/env bash
# =============================================================================
# Security Management Platform — Installer
# © mrQhere · https://github.com/mrQhere/SecurityManagementPlatform
#
# Supported Linux distributions:
#   Ubuntu 20.04 / 22.04 / 24.04   Debian 11 / 12
#   Fedora 39+                      RHEL / Rocky / AlmaLinux 8+
#   Arch Linux / Manjaro            openSUSE Tumbleweed / Leap 15
#   Kali Linux                      Parrot OS
#
# Supported macOS: 12 Monterey+  (via Homebrew)
#
# Usage:
#   ./setup.sh              — full install (recommended)
#   ./setup.sh --skip-tools — skip Go binary downloads (AV-restricted envs)
#   ./setup.sh --no-venv    — use system Python instead of venv
#
# Go tool versions pinned (from official GitHub Releases):
#   nuclei    v3.3.9    projectdiscovery/nuclei
#   subfinder v2.7.0    projectdiscovery/subfinder
#   httpx     v1.7.0    projectdiscovery/httpx
#   katana    v1.1.2    projectdiscovery/katana
#   dnsx      v1.2.1    projectdiscovery/dnsx
#   ffuf      v2.1.0    ffuf/ffuf
#   gitleaks  v8.30.1   gitleaks/gitleaks
#   dalfox    v2.10.0   hahwul/dalfox
# =============================================================================
set -euo pipefail

SCRIPT_START=$(date +%s)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
LOG_FILE="$SCRIPT_DIR/setup.log"
mkdir -p "$BIN_DIR"

# ── Flags ──────────────────────────────────────────────────────────────────────
SKIP_TOOLS=false
SKIP_VENV=false
for arg in "$@"; do
    case "$arg" in
        --skip-tools) SKIP_TOOLS=true ;;
        --no-venv)    SKIP_VENV=true  ;;
        -h|--help)    grep '^#' "$0" | head -30 | sed 's/^# \?//'; exit 0 ;;
    esac
done

> "$LOG_FILE"

# ── UI ─────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { printf "\r\033[K${GREEN}✔${RESET} %s\n" "$*"; }
warn() { printf "\r\033[K${YELLOW}⚠${RESET} %s\n" "$*"; }
fail() { printf "\r\033[K${RED}✘${RESET} %s\n" "$*"; exit 1; }
info() { printf "\r\033[K${CYAN}ℹ${RESET} %s\n" "$*"; }

spin() {
    local msg="$1"; shift
    local pid; "$@" >> "$LOG_FILE" 2>&1 & pid=$!
    local sp=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏") i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r\033[K${CYAN}%s${RESET} %s" "${sp[$((i%10))]}" "$msg"
        ((i++)) || true; sleep 0.1
    done
    wait $pid && { ok "$msg"; return 0; } || { warn "$msg — see setup.log"; return 1; }
}

ARCH="$(uname -m)"
OS="$(uname -s)"
is_arm() { [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; }
have()   { command -v "$1" &>/dev/null || [[ -x "$BIN_DIR/$1" ]]; }

# ── Distro detection ──────────────────────────────────────────────────────────
DISTRO=""
PKG_MGR=""
if [[ "$OS" == "Darwin" ]]; then
    DISTRO="macos"
    PKG_MGR="brew"
elif [[ -f /etc/os-release ]]; then
    source /etc/os-release
    ID_LOWER="${ID,,}"
    case "$ID_LOWER" in
        ubuntu|debian|kali|parrot|linuxmint|pop)
            DISTRO="debian"; PKG_MGR="apt" ;;
        fedora)
            DISTRO="fedora"; PKG_MGR="dnf" ;;
        rhel|centos|rocky|alma|ol)
            DISTRO="rhel"; PKG_MGR="dnf" ;;
        arch|manjaro|endeavouros|garuda)
            DISTRO="arch"; PKG_MGR="pacman" ;;
        opensuse*|suse*)
            DISTRO="opensuse"; PKG_MGR="zypper" ;;
        *)
            warn "Unknown distro '$ID' — attempting apt fallback"
            DISTRO="debian"; PKG_MGR="apt" ;;
    esac
else
    warn "Cannot detect distro — assuming Debian/Ubuntu"
    DISTRO="debian"; PKG_MGR="apt"
fi

echo -e "\n${BOLD}Security Management Platform — Installer${RESET}"
echo -e "  © mrQhere · https://github.com/mrQhere/SecurityManagementPlatform"
echo -e "  Detected: ${BOLD}$OS / $DISTRO${RESET} (arch: $ARCH, pkg: $PKG_MGR)\n"
$SKIP_TOOLS && warn "--skip-tools: Go binary downloads will be skipped"

# ── Package manager helpers ───────────────────────────────────────────────────
pkg_update() {
    case "$PKG_MGR" in
        apt)
            local retries=5
            while (( retries > 0 )); do
                if sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; then return 0; fi
                sleep 5
                ((retries--))
            done
            return 1
            ;;
        dnf)    sudo dnf makecache -q ;;
        pacman) sudo pacman -Sy --noconfirm ;;
        zypper) sudo zypper refresh -q ;;
        brew)   brew update -q ;;
    esac
}

pkg_install() {
    case "$PKG_MGR" in
        apt)
            local retries=5
            while (( retries > 0 )); do
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"; then return 0; fi
                sleep 5
                ((retries--))
            done
            return 1
            ;;
        dnf)    sudo dnf install -y -q "$@" ;;
        pacman) sudo pacman -S --noconfirm --needed "$@" ;;
        zypper) sudo zypper install -y -q "$@" ;;
        brew)   brew install -q "$@" ;;
    esac
}

# Map package names per distro
get_pkg() {
    # get_pkg <canonical> → prints distro-specific package name
    local pkg="$1"
    case "$pkg" in
        python3)
            case "$DISTRO" in arch) echo "python";; *) echo "python3";; esac ;;
        python3-pip)
            case "$DISTRO" in
                arch) echo "python-pip";;
                rhel|fedora) echo "python3-pip";;
                *) echo "python3-pip";;
            esac ;;
        python3-venv)
            case "$DISTRO" in
                arch|rhel|fedora) echo "";;  # included in python package
                *) echo "python3-venv";;
            esac ;;
        python3-dev)
            case "$DISTRO" in
                debian) echo "python3-dev";;
                rhel|fedora) echo "python3-devel";;
                arch) echo "";;  # included
                opensuse) echo "python3-devel";;
            esac ;;
        libsqlcipher-dev)
            case "$DISTRO" in
                debian) echo "libsqlcipher-dev";;
                rhel|fedora) echo "sqlcipher-devel";;
                arch) echo "sqlcipher";;
                opensuse) echo "sqlcipher-devel";;
                macos) echo "sqlcipher";;
            esac ;;
        libsqlcipher0)
            case "$DISTRO" in
                debian)
                    if apt-cache show libsqlcipher1 &>/dev/null; then
                        echo "libsqlcipher1"
                    elif apt-cache show libsqlcipher0t64 &>/dev/null; then
                        echo "libsqlcipher0t64"
                    else
                        echo "libsqlcipher0"
                    fi ;;
                rhel|fedora) echo "sqlcipher";;
                arch) echo "";;  # covered by sqlcipher above
                opensuse) echo "libsqlcipher0";;
            esac ;;
        build-essential)
            case "$DISTRO" in
                debian) echo "build-essential";;
                rhel|fedora) echo "@development-tools";;
                arch) echo "base-devel";;
                opensuse) echo "gcc make";;
            esac ;;
        nmap) echo "nmap" ;;
        nikto)
            case "$DISTRO" in
                arch) echo "nikto";;
                rhel) echo "";;  # manual install on RHEL
                *) echo "nikto";;
            esac ;;
        ruby)
            case "$DISTRO" in
                rhel|fedora) echo "ruby ruby-devel";;
                arch) echo "ruby";;
                *) echo "ruby ruby-dev";;
            esac ;;
        whatweb)
            case "$DISTRO" in
                debian) echo "whatweb";;
                *) echo "";;  # install via gem below
            esac ;;
        perl) echo "perl" ;;
        git)  echo "git"  ;;
        *) echo "$pkg" ;;
    esac
}

# ── sudo keepalive ─────────────────────────────────────────────────────────────
if [[ "$OS" != "Darwin" ]]; then
    sudo -v
    while true; do sudo -n true; sleep 60; kill -0 "$$" 2>/dev/null || exit; done &
fi

# ── System packages ────────────────────────────────────────────────────────────
if ! spin "Updating package index" pkg_update; then
    [[ "$PKG_MGR" == "apt" ]] && fail "apt update failed. If this is a fresh VM, check your AV/firewall network exceptions for archive.ubuntu.com and github.com."
    exit 1
fi

CANONICAL_PKGS=(python3 python3-pip python3-venv python3-dev
                libsqlcipher-dev libsqlcipher0 build-essential
                nmap nikto ruby perl git)

PKGS_TO_INSTALL=()
for cpkg in "${CANONICAL_PKGS[@]}"; do
    dpkg_name="$(get_pkg "$cpkg")"
    [[ -z "$dpkg_name" ]] && continue
    # Check each word in multi-word package specs
    for name in $dpkg_name; do
        [[ "$name" == @* ]] && { PKGS_TO_INSTALL+=("$name"); continue; }
        case "$PKG_MGR" in
            apt)    dpkg -s "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
            dnf)    rpm -q "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
            pacman) pacman -Q "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
            zypper) rpm -q "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
            brew)   brew list "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
        esac
    done
done

if [[ ${#PKGS_TO_INSTALL[@]} -gt 0 ]]; then
    if ! spin "Installing system packages" pkg_install "${PKGS_TO_INSTALL[@]}"; then
        [[ "$PKG_MGR" == "apt" ]] && fail "apt install failed. If this is a fresh VM, check your AV/firewall network exceptions for archive.ubuntu.com and github.com."
        exit 1
    fi
else
    ok "System packages already installed"
fi

# ── Kali / Parrot extra tools (already ship many tools) ───────────────────────
if [[ "${ID_LOWER:-}" == "kali" || "${ID_LOWER:-}" == "parrot" ]]; then
    info "Kali/Parrot detected — many tools pre-installed, skipping duplicates"
fi

# ── SQLCipher source build fallback ───────────────────────────────────────────
if ! python3 -c "import ctypes; ctypes.cdll.LoadLibrary('libsqlcipher.so.0')" &>/dev/null && \
   ! ldconfig -p 2>/dev/null | grep -q 'libsqlcipher'; then
    if [[ "$DISTRO" == "arch" ]]; then
        spin "Installing sqlcipher via pacman" sudo pacman -S --noconfirm --needed sqlcipher
    else
        _sc_tmp=$(mktemp -d)
        if spin "Building SQLCipher from source" bash -c "
            git clone --depth=1 https://github.com/sqlcipher/sqlcipher.git '$_sc_tmp' &&
            cd '$_sc_tmp' &&
            ./configure CFLAGS='-DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2 -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown' LDFLAGS='-lcrypto' --prefix=/usr/local &&
            make -j\$(nproc) && sudo make install && sudo ldconfig"; then
            ok "SQLCipher built from source"
        else
            warn "SQLCipher source build failed — pysqlcipher3 may not install"
        fi
        rm -rf "$_sc_tmp"
    fi
fi

# ── Go ─────────────────────────────────────────────────────────────────────────
if ! $SKIP_TOOLS; then
    if have go; then
        ok "Go installed ($(go version 2>&1 | awk '{print $3}'))"
    else
        GO_VER="1.22.6"
        GOARCH="amd64"; is_arm && GOARCH="arm64"
        case "$DISTRO" in
            debian|rhel|fedora|opensuse)
                spin "Installing Go via package manager" pkg_install golang || true ;;
        esac
        if ! have go; then
            info "Downloading Go $GO_VER from go.dev"
            curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" \
                | sudo tar -C /usr/local -xz >> "$LOG_FILE" 2>&1
            export PATH="$PATH:/usr/local/go/bin"
            grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null || \
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            ok "Go $GO_VER installed"
        fi
    fi
fi

# ── Python venv & dependencies ─────────────────────────────────────────────────
if ! $SKIP_VENV; then
    if [[ ! -f "$SCRIPT_DIR/venv/bin/activate" ]]; then
        rm -rf "$SCRIPT_DIR/venv"
        spin "Creating Python virtual environment" python3 -m venv "$SCRIPT_DIR/venv"
    else
        ok "Virtual environment exists"
    fi

    source "$SCRIPT_DIR/venv/bin/activate"
    spin "Upgrading pip" pip install --upgrade pip

    # pysqlcipher3 before the rest so other deps don't pull in a broken version
    if ! python3 -c "from pysqlcipher3 import dbapi2" &>/dev/null; then
        spin "Installing pysqlcipher3" pip install pysqlcipher3 || \
        spin "pysqlcipher3 (with explicit flags)" bash -c \
            "CFLAGS='-I/usr/include/sqlcipher' LDFLAGS='-lsqlcipher' pip install pysqlcipher3" || \
        fail "pysqlcipher3 failed — see setup.log. SMP cannot start without SQLCipher."
    else
        ok "pysqlcipher3 installed"
    fi

    if spin "Installing Python dependencies" \
        pip install -r "$SCRIPT_DIR/requirements.txt"
    then
        ok "Dependencies installed"
        
        # Install playwright browsers if playwright is in requirements
        if grep -q "playwright" "$SCRIPT_DIR/requirements.txt"; then
            spin "Installing Playwright browser binaries" \
                playwright install chromium
            ok "Playwright binaries installed"
        fi
    fi
fi

# ── Go Security Tools ──────────────────────────────────────────────────────────
if $SKIP_TOOLS; then
    warn "Skipping Go tool downloads (--skip-tools). Install manually:"
    cat <<'EOF'
  nuclei:    https://github.com/projectdiscovery/nuclei/releases/tag/v3.3.9
  subfinder: https://github.com/projectdiscovery/subfinder/releases/tag/v2.7.0
  httpx:     https://github.com/projectdiscovery/httpx/releases/tag/v1.7.0
  katana:    https://github.com/projectdiscovery/katana/releases/tag/v1.1.2
  dnsx:      https://github.com/projectdiscovery/dnsx/releases/tag/v1.2.1
  ffuf:      https://github.com/ffuf/ffuf/releases/tag/v2.1.0
  gitleaks:  https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
  dalfox:    https://github.com/hahwul/dalfox/releases/tag/v2.10.0
  Place binaries in: bin/
EOF
else
    export PATH="$PATH:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin:$BIN_DIR"

    # ── download_binary <name> <url_amd64> <url_arm64> ──────────────────────
    download_binary() {
        local name="$1" url_amd="$2" url_arm="$3"
        local url; is_arm && url="$url_arm" || url="$url_amd"
        info "Downloading $name from: $url"
        local tmp; tmp="$(mktemp -d)"
        local archive="$tmp/archive"
        if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url" >> "$LOG_FILE" 2>&1; then
            rm -rf "$tmp"; warn "$name: download failed"; return 1
        fi
        [[ "$url" == *.zip ]] && \
            unzip -q "$archive" -d "$tmp" >> "$LOG_FILE" 2>&1 || \
            tar -xzf "$archive" -C "$tmp" >> "$LOG_FILE" 2>&1
        local bin; bin=$(find "$tmp" -type f -name "${name,,}" 2>/dev/null | head -1)
        [[ -z "$bin" ]] && bin=$(find "$tmp" -type f -iname "$name" 2>/dev/null | head -1)
        if [[ -n "$bin" ]]; then
            install -m 0755 "$bin" "$BIN_DIR/$name"
            rm -rf "$tmp"; return 0
        fi
        rm -rf "$tmp"; warn "$name: binary not found in archive"; return 1
    }

    # ── Pinned versions (update these when new releases ship) ────────────────
    # Format: name | url_amd64 | url_arm64
    declare -A T_AMD T_ARM T_GO
    BASE_PD="https://github.com/projectdiscovery"
    BASE_FF="https://github.com/ffuf/ffuf/releases/download"
    BASE_GL="https://github.com/gitleaks/gitleaks/releases/download"
    BASE_DX="https://github.com/hahwul/dalfox/releases/download"

    T_AMD[nuclei]="$BASE_PD/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip"
    T_ARM[nuclei]="$BASE_PD/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_arm64.zip"
    T_GO[nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9"

    T_AMD[subfinder]="$BASE_PD/subfinder/releases/download/v2.7.0/subfinder_2.7.0_linux_amd64.zip"
    T_ARM[subfinder]="$BASE_PD/subfinder/releases/download/v2.7.0/subfinder_2.7.0_linux_arm64.zip"
    T_GO[subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.7.0"

    T_AMD[httpx]="$BASE_PD/httpx/releases/download/v1.7.0/httpx_1.7.0_linux_amd64.zip"
    T_ARM[httpx]="$BASE_PD/httpx/releases/download/v1.7.0/httpx_1.7.0_linux_arm64.zip"
    T_GO[httpx]="github.com/projectdiscovery/httpx/cmd/httpx@v1.7.0"

    T_AMD[katana]="$BASE_PD/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip"
    T_ARM[katana]="$BASE_PD/katana/releases/download/v1.1.2/katana_1.1.2_linux_arm64.zip"
    T_GO[katana]="github.com/projectdiscovery/katana/cmd/katana@v1.1.2"

    T_AMD[dnsx]="$BASE_PD/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip"
    T_ARM[dnsx]="$BASE_PD/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip"
    T_GO[dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1"

    T_AMD[ffuf]="$BASE_FF/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz"
    T_ARM[ffuf]="$BASE_FF/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz"
    T_GO[ffuf]="github.com/ffuf/ffuf/v2@v2.1.0"

    T_AMD[gitleaks]="$BASE_GL/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
    T_ARM[gitleaks]="$BASE_GL/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz"
    T_GO[gitleaks]="github.com/gitleaks/gitleaks/v8/cmd/gitleaks@v8.30.1"

    T_AMD[dalfox]="$BASE_DX/v2.10.0/dalfox_2.10.0_linux_amd64.tar.gz"
    T_ARM[dalfox]="$BASE_DX/v2.10.0/dalfox_2.10.0_linux_arm64.tar.gz"
    T_GO[dalfox]="github.com/hahwul/dalfox/v2@v2.10.0"

    for name in nuclei subfinder httpx katana dnsx ffuf gitleaks dalfox; do
        if have "$name"; then ok "$name installed"; continue; fi
        if spin "Downloading $name" \
           download_binary "$name" "${T_AMD[$name]}" "${T_ARM[$name]}"; then
            continue
        fi
        # Fallback: go install (pinned)
        if have go && spin "Building $name from source" \
           go install -v "${T_GO[$name]}" >> "$LOG_FILE" 2>&1; then
            continue
        fi
        warn "$name: download and source build failed — scan will be skipped"
    done

    # ── Optional enterprise tools ─────────────────────────────────────────────
    have trivy || \
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b "$BIN_DIR" v0.55.0 >> "$LOG_FILE" 2>&1 && ok "Trivy installed" || true

    have prowler    || pip install prowler    -q >> "$LOG_FILE" 2>&1 && ok "Prowler installed"    || true
    have nxc 2>/dev/null || pip install netexec -q >> "$LOG_FILE" 2>&1 || true
fi

# ── WPScan ─────────────────────────────────────────────────────────────────────
if ! have wpscan; then
    if sudo gem install wpscan --no-user-install >> "$LOG_FILE" 2>&1 && have wpscan; then
        ok "wpscan installed via gem"
    elif have docker; then
        printf '#!/usr/bin/env bash\nexec docker run --rm --network=host wpscanteam/wpscan "$@"\n' \
            > "$BIN_DIR/wpscan" && chmod +x "$BIN_DIR/wpscan"
        ok "wpscan Docker wrapper created"
    else
        printf '#!/usr/bin/env bash\necho "WPScan not installed. Run: sudo gem install wpscan"\nexit 1\n' \
            > "$BIN_DIR/wpscan" && chmod +x "$BIN_DIR/wpscan"
        warn "WPScan stub created. WordPress scans disabled."
    fi
else
    ok "wpscan installed"
fi

# ── Finalise ───────────────────────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/run.sh"
find "$BIN_DIR" -type f -exec chmod +x {} \; 2>/dev/null || true

now=$(date +%s)
echo -e "\n${GREEN}${BOLD}✔ Setup complete in $((now - SCRIPT_START))s${RESET}"
$SKIP_TOOLS && warn "Go tools were skipped. Add binaries to: $BIN_DIR/"
echo -e "  ▶ Launch GUI:  ${BOLD}./run.sh${RESET}"
echo -e "  ▶ Launch API:  ${BOLD}python main.py --api${RESET}\n"
