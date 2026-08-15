#!/usr/bin/env bash
# =============================================================================
# Security Management Platform — Installer
# © mrQhere · https://github.com/mrQhere/SecurityManagementPlatform
#
# Supported Linux distributions:
# Ubuntu 20.04 / 22.04 / 24.04 Debian 11 / 12
# Fedora 39+ RHEL / Rocky / AlmaLinux 8+
# Arch Linux / Manjaro openSUSE Tumbleweed / Leap 15
# Kali Linux Parrot OS
#
# Supported macOS: 12 Monterey+ (via Homebrew)
#
# Usage:
# ./setup.sh — full install (recommended)
# ./setup.sh --skip-tools — skip Go binary downloads (AV-restricted envs)
# ./setup.sh --no-venv — use system Python instead of venv
#
# Go tool versions pinned (from official GitHub Releases):
# nuclei v3.3.9 projectdiscovery/nuclei
# subfinder v2.7.0 projectdiscovery/subfinder
# httpx v1.7.0 projectdiscovery/httpx
# katana v1.1.2 projectdiscovery/katana
# dnsx v1.2.1 projectdiscovery/dnsx
# ffuf v2.1.0 ffuf/ffuf
# gitleaks v8.30.1 gitleaks/gitleaks
# dalfox v2.10.0 hahwul/dalfox
# race-the-web v1.0.3 The-Z-Labs/race-the-web
#
# Node.js tools pinned:
# ppmap v1.0.0
# wscat v5.2.1
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
 --no-venv) SKIP_VENV=true ;;
 -h|--help) grep '^#' "$0" | head -30 | sed 's/^# \?//'; exit 0 ;;
 esac
done

> "$LOG_FILE"

# ── UI ─────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'
ok() { printf "\r\033[K${GREEN}✔${RESET} %s\n" "$*"; }
warn() { printf "\r\033[K${YELLOW}⚠${RESET} %s\n" "$*"; }
fail() { printf "\r\033[K${RED}✘${RESET} %s\n" "$*"; exit 1; }
info() { printf "\r\033[K${CYAN}ℹ${RESET} %s\n" "$*"; }

spin() {
  local msg="$1"; shift
  (
    local sp=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏") i=0
    while true; do
      printf "\r\033[K${CYAN}%s${RESET} %s" "${sp[$((i%10))]}" "$msg"
      ((i++)) || true; sleep 0.1
    done
  ) & local spin_pid=$!

  if "$@" >> "$LOG_FILE" 2>&1; then
    kill $spin_pid 2>/dev/null; wait $spin_pid 2>/dev/null || true
    ok "$msg"
    return 0
  else
    kill $spin_pid 2>/dev/null; wait $spin_pid 2>/dev/null || true
    warn "$msg — see setup.log"
    return 1
  fi
}

# ── Source Code Extractor & Structured Error Reporting ─────────────────────────
extract_func_source() {
  local func_name="$1"
  local script_path="${BASH_SOURCE[0]:-$0}"
  if [[ -f "$script_path" ]]; then
    awk -v fn="$func_name" '
      $0 ~ "^[ \t]*" fn "[ \t]*\\(\\)[ \t]*\\{" { inside=1 }
      inside { printf "  \033[2m%4d\033[0m │ %s\n", NR, $0 }
      inside && $0 ~ "^[ \t]*\\}" { inside=0; exit }
    ' "$script_path"
  fi
}

report_error_with_code() {
  local code="$1"
  local func_name="$2"
  local step_name="$3"
  local root_cause="${4:-Unspecified runtime fault}"
  local remediation="${5:-Review setup.log and rerun ./setup.sh}"
  local exit_code="${6:-1}"

  echo -e "\n${RED}${BOLD}══════════════════════════════════════════════════════════════════════════════════${RESET}"
  echo -e "${RED}${BOLD} [CRITICAL INSTALLER FAILURE] ${code} — ${step_name}${RESET}"
  echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════════════════════════${RESET}"
  echo -e " ${BOLD}Failed Function:${RESET}  ${CYAN}${func_name}()${RESET} (Exit Status: ${exit_code})"
  echo -e " ${BOLD}Failure Stage:${RESET}    ${step_name}"
  echo -e " ${BOLD}Root Cause:${RESET}       ${root_cause}"
  echo -e ""
  echo -e " ${BOLD}Failed Source Code Context in setup.sh:${RESET}"
  echo -e "${DIM} ──────────────────────────────────────────────────────────────────────────────────${RESET}"
  extract_func_source "$func_name"
  echo -e "${DIM} ──────────────────────────────────────────────────────────────────────────────────${RESET}"

  if [[ -f "$LOG_FILE" && -s "$LOG_FILE" ]]; then
    echo -e " ${BOLD}Recent Log Output (${LOG_FILE}):${RESET}"
    echo -e "${DIM} ──────────────────────────────────────────────────────────────────────────────────${RESET}"
    tail -n 8 "$LOG_FILE" | sed 's/^/   /'
    echo -e "${DIM} ──────────────────────────────────────────────────────────────────────────────────${RESET}"
  fi

  echo -e ""
  echo -e " ${GREEN}${BOLD}Actionable Remediation:${RESET}"
  echo -e "   ${remediation}"
  echo -e ""
  echo -e " ${CYAN}${BOLD}Diagnostics & Troubleshooting:${RESET}"
  echo -e "   • Run self-healing:   ${BOLD}python3 tools/troubleshoot.py --fix${RESET}"
  echo -e "   • Look up error code: ${BOLD}python3 tools/troubleshoot.py --lookup ${code}${RESET}"
  echo -e "   • Consult taxonomy:   ${BOLD}ERROR_CODES.md (${code})${RESET}"
  echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════════════════════════${RESET}\n"

  exit "$exit_code"
}

run_troubleshooter() {
  local reason="$1"
  echo -e "\n${YELLOW}${BOLD}⚠ Issue detected during '${reason}' — Launching SMP Self-Healing Engine...${RESET}"
  
  local healed=false

  # 1. Release stale package locks (if apt)
  if [[ "${PKG_MGR:-}" == "apt" ]]; then
    if sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
      info "Waiting for background package manager process to release lock..."
      sleep 4
      if sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
        warn "Attempting automated release of stale dpkg locks..."
        sudo killall apt apt-get dpkg 2>/dev/null || true
        sleep 2
        sudo dpkg --configure -a >> "$LOG_FILE" 2>&1 || true
        healed=true
      fi
    fi
  fi

  # 2. Run Python troubleshoot --fix if python is available
  if have python3 && [[ -f "$SCRIPT_DIR/tools/troubleshoot.py" ]]; then
    info "Executing python3 tools/troubleshoot.py --fix..."
    python3 "$SCRIPT_DIR/tools/troubleshoot.py" --fix >> "$LOG_FILE" 2>&1 || true
    healed=true
  fi

  # 3. Clean temporary locks
  rm -f /tmp/smp_*.lock 2>/dev/null || true
  rm -f "${HOME}/.smp_runtime.lock" 2>/dev/null || true

  if $healed; then
    ok "Self-healing actions applied — retrying '${reason}'..."
  fi
}

# ── Pre-Flight Network Route Verification ──────────────────────────────────────
verify_network_routes() {
  info "Running pre-flight network route & repository mirror verification..."
  local endpoints=(
    "https://github.com"
    "https://raw.githubusercontent.com"
    "https://pypi.org"
    "https://go.dev"
  )
  local failed_endpoints=()

  for ep in "${endpoints[@]}"; do
    local host; host="$(echo "$ep" | sed -e 's|^[^/]*//||' -e 's|/.*$||')"
    if have curl; then
      if ! curl -fsSI --connect-timeout 4 --max-time 8 "$ep" >/dev/null 2>&1; then
        failed_endpoints+=("$host")
      fi
    elif have wget; then
      if ! wget --spider --timeout=4 -q "$ep"; then
        failed_endpoints+=("$host")
      fi
    elif have python3; then
      if ! python3 -c "import urllib.request; urllib.request.urlopen('$ep', timeout=4)" >/dev/null 2>&1; then
        failed_endpoints+=("$host")
      fi
    fi
  done

  if [[ ${#failed_endpoints[@]} -gt 0 ]]; then
    warn "Network route check failed for: ${failed_endpoints[*]}"
    run_troubleshooter "Network Route Connectivity"
    
    # Retry verification after running troubleshooter
    local retry_failed=()
    for ep in "${endpoints[@]}"; do
      local host; host="$(echo "$ep" | sed -e 's|^[^/]*//||' -e 's|/.*$||')"
      if have curl; then
        if ! curl -fsSI --connect-timeout 4 --max-time 8 "$ep" >/dev/null 2>&1; then
          retry_failed+=("$host")
        fi
      fi
    done

    if [[ ${#retry_failed[@]} -gt 0 ]]; then
      if $SKIP_TOOLS; then
        warn "Outbound route to ${retry_failed[*]} is unreachable, but continuing due to --skip-tools"
      else
        report_error_with_code \
          "SMP-9001" \
          "verify_network_routes" \
          "Pre-Flight Network Route Verification" \
          "Outbound HTTPS connectivity to ${retry_failed[*]} failed. Firewall/proxy rules or DNS resolution may be blocking outbound traffic." \
          "1. Check your internet connection.\n   2. If behind a proxy, configure: export https_proxy=http://proxy:port\n   3. To skip Go binary downloads in restricted environments, run:\n      ./setup.sh --skip-tools" \
          1
      fi
    else
      ok "Network routes verified after self-healing"
    fi
  else
    ok "Network routes & repository mirrors verified"
  fi
}

ARCH="$(uname -m)"
OS="$(uname -s)"
is_arm() { [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; }
have() { command -v "$1" &>/dev/null || [[ -x "$BIN_DIR/$1" ]]; }

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
echo -e " © mrQhere · https://github.com/mrQhere/SecurityManagementPlatform"
echo -e " Detected: ${BOLD}$OS / $DISTRO${RESET} (arch: $ARCH, pkg: $PKG_MGR)\n"
$SKIP_TOOLS && warn "--skip-tools: Go binary downloads will be skipped"

# ── Pre-Flight Connectivity Checks ─────────────────────────────────────────────
verify_network_routes

# ── Package manager helpers ───────────────────────────────────────────────────
pkg_update() {
  case "$PKG_MGR" in
    apt)
      # Cleanup broken Trivy repo list from previous faulty installations
      sudo rm -f /etc/apt/sources.list.d/trivy.list 2>/dev/null || true
      
      local retries=5
      while (( retries > 0 )); do
        if sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; then return 0; fi
        sleep 3
        ((retries--))
      done
      
      # Run automated troubleshooter on update failure
      run_troubleshooter "Package Index Update"
      if sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; then return 0; fi
      
      report_error_with_code \
        "SMP-9002" \
        "pkg_update" \
        "System Package Index Update ($PKG_MGR)" \
        "Failed to update system package cache. DPKG lock contention or unreachable repository mirror." \
        "1. Check if another package manager process is running: sudo fuser /var/lib/dpkg/lock\n   2. Release locks: sudo killall apt apt-get dpkg && sudo dpkg --configure -a\n   3. Run 'python3 tools/troubleshoot.py --fix'" \
        1
      ;;
    dnf) sudo dnf makecache -q ;;
    pacman) sudo pacman -Sy --noconfirm ;;
    zypper) sudo zypper refresh -q ;;
    brew) brew update -q ;;
  esac
}

pkg_install() {
  case "$PKG_MGR" in
    apt)
      local retries=5
      while (( retries > 0 )); do
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"; then return 0; fi
        sleep 3
        ((retries--))
      done
      
      # Run automated troubleshooter on install failure
      run_troubleshooter "System Package Installation"
      if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"; then return 0; fi
      
      report_error_with_code \
        "SMP-9002" \
        "pkg_install" \
        "System Package Installation ($*)" \
        "Failed to install system packages. Package manager lock held or repository dependencies broken." \
        "1. Fix broken dependencies: sudo apt-get install -f\n   2. Run 'python3 tools/troubleshoot.py --fix'\n   3. Manually install required packages: sudo apt-get install -y $*" \
        1
      ;;
    dnf) sudo dnf install -y -q "$@" ;;
    pacman) sudo pacman -S --noconfirm --needed "$@" ;;
    zypper) sudo zypper install -y -q "$@" ;;
    brew) brew install -q "$@" ;;
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
 arch|rhel|fedora) echo "";; # included in python package
 *) echo "python3-venv";;
 esac ;;
 python3-dev)
 case "$DISTRO" in
 debian) echo "python3-dev";;
 rhel|fedora) echo "python3-devel";;
 arch) echo "";; # included
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
 arch) echo "";; # covered by sqlcipher above
 opensuse) echo "libsqlcipher0";;
 esac ;;
 build-essential)
 case "$DISTRO" in
 debian) echo "build-essential";;
 rhel|fedora) echo "@development-tools";;
 arch) echo "base-devel";;
 opensuse) echo "gcc make";;
 esac ;;
 cargo) echo "cargo" ;;
 nmap) echo "nmap" ;;
 nikto)
 case "$DISTRO" in
 arch) echo "nikto";;
 rhel) echo "";; # manual install on RHEL
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
 *) echo "";; # install via gem below
 esac ;;
 perl) echo "perl" ;;
 git) echo "git" ;;
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
 libsqlcipher-dev libsqlcipher0 build-essential cargo
 nmap nikto ruby perl git nodejs npm)

PKGS_TO_INSTALL=()
for cpkg in "${CANONICAL_PKGS[@]}"; do
 dpkg_name="$(get_pkg "$cpkg")"
 [[ -z "$dpkg_name" ]] && continue
 # Check each word in multi-word package specs
 for name in $dpkg_name; do
 [[ "$name" == @* ]] && { PKGS_TO_INSTALL+=("$name"); continue; }
 case "$PKG_MGR" in
 apt) dpkg -s "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
 dnf) rpm -q "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
 pacman) pacman -Q "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
 zypper) rpm -q "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
 brew) brew list "$name" &>/dev/null || PKGS_TO_INSTALL+=("$name") ;;
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
 GO_OS="linux"
 [[ "$OS" == "Darwin" ]] && GO_OS="darwin"
 case "$DISTRO" in
 debian|rhel|fedora|opensuse)
 spin "Installing Go via package manager" pkg_install golang || true ;;
 macos)
 brew install go || true ;;
 esac
 if ! have go; then
 info "Downloading Go $GO_VER from go.dev ($GO_OS/$GOARCH)"
 curl -fsSL "https://go.dev/dl/go${GO_VER}.${GO_OS}-${GOARCH}.tar.gz" \
 | sudo tar -C /usr/local -xz >> "$LOG_FILE" 2>&1
 export PATH="$PATH:/usr/local/go/bin"
 PROFILE_FILE="${HOME}/.bashrc"
 [[ "$OS" == "Darwin" ]] && PROFILE_FILE="${HOME}/.zprofile"
 grep -q '/usr/local/go/bin' "$PROFILE_FILE" 2>/dev/null || \
 echo 'export PATH=$PATH:/usr/local/go/bin' >> "$PROFILE_FILE"
 ok "Go $GO_VER installed"
 fi
 fi
fi

# ── Python venv & dependencies ─────────────────────────────────────────────────
setup_python_env() {
  if [[ ! -f "$SCRIPT_DIR/venv/bin/activate" ]]; then
    rm -rf "$SCRIPT_DIR/venv"
    if ! spin "Creating Python virtual environment" python3 -m venv "$SCRIPT_DIR/venv"; then
      run_troubleshooter "Python Virtualenv Creation"
      if ! spin "Creating Python virtual environment (retry)" python3 -m venv "$SCRIPT_DIR/venv"; then
        report_error_with_code \
          "SMP-9005" \
          "setup_python_env" \
          "Python Virtual Environment Initialization" \
          "python3 -m venv failed to create a virtual environment in $SCRIPT_DIR/venv." \
          "1. Install venv support: sudo apt install python3-venv python3-dev\n   2. Or run setup without virtual environment: ./setup.sh --no-venv" \
          1
      fi
    fi
  else
    ok "Virtual environment exists"
  fi

  source "$SCRIPT_DIR/venv/bin/activate"
  spin "Upgrading pip" pip install --upgrade pip || true
}

install_sqlcipher_binding() {
  if ! python3 -c "from pysqlcipher3 import dbapi2" &>/dev/null; then
    if ! spin "Installing pysqlcipher3" pip install pysqlcipher3; then
      if ! spin "pysqlcipher3 (with explicit flags)" bash -c \
         "CFLAGS='-I/usr/include/sqlcipher' LDFLAGS='-lsqlcipher' pip install pysqlcipher3"; then
        run_troubleshooter "pysqlcipher3 SQLCipher Binding Installation"
        if ! spin "pysqlcipher3 (post-healing attempt)" pip install pysqlcipher3; then
          report_error_with_code \
            "SMP-3001" \
            "install_sqlcipher_binding" \
            "pysqlcipher3 SQLCipher Database Driver Installation" \
            "Failed to compile and link pysqlcipher3 Python binding against SQLCipher C libraries." \
            "1. Install SQLCipher C headers: sudo apt install libsqlcipher-dev build-essential\n   2. Run 'python3 tools/troubleshoot.py --fix'\n   3. Consult ERROR_CODES.md (SMP-3001)" \
            1
        fi
      fi
    fi
    ok "pysqlcipher3 installed"
  else
    ok "pysqlcipher3 installed"
  fi
}

install_python_dependencies() {
  if ! spin "Installing Python dependencies" pip install -r "$SCRIPT_DIR/requirements.txt"; then
    run_troubleshooter "Python Dependencies Installation"
    if ! spin "Installing Python dependencies (retry)" pip install -r "$SCRIPT_DIR/requirements.txt"; then
      report_error_with_code \
        "SMP-9005" \
        "install_python_dependencies" \
        "Python Dependencies Installation (requirements.txt)" \
        "pip failed to resolve or install one or more required packages from requirements.txt." \
        "1. Check network connectivity to pypi.org\n   2. Check setup.log for the specific failed dependency\n   3. Run 'python3 tools/troubleshoot.py --fix'" \
        1
    fi
  fi
  ok "Dependencies installed"

  # Install playwright browser if present
  if grep -q "playwright" "$SCRIPT_DIR/requirements.txt"; then
    spin "Installing Playwright browser binaries" playwright install chromium || true
    ok "Playwright binaries installed"
  fi
}

if ! $SKIP_VENV; then
  setup_python_env
  install_sqlcipher_binding
  install_python_dependencies
fi

# ── Go Security Tools ──────────────────────────────────────────────────────────
if $SKIP_TOOLS; then
  warn "Skipping Go tool downloads (--skip-tools). Install manually:"
  cat <<'EOF'
  nuclei: https://github.com/projectdiscovery/nuclei/releases/tag/v3.3.9
  subfinder: https://github.com/projectdiscovery/subfinder/releases/tag/v2.7.0
  httpx: https://github.com/projectdiscovery/httpx/releases/tag/v1.7.0
  katana: https://github.com/projectdiscovery/katana/releases/tag/v1.1.2
  dnsx: https://github.com/projectdiscovery/dnsx/releases/tag/v1.2.1
  ffuf: https://github.com/ffuf/ffuf/releases/tag/v2.1.0
  gitleaks: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
  dalfox: https://github.com/hahwul/dalfox/releases/tag/v2.10.0
  Place binaries in: bin/
EOF
else
  export PATH="$PATH:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin:$BIN_DIR"

  # ── download_binary <name> <url_amd64> <url_arm64> ──────────────────────
  download_binary() {
    local name="$1" url_amd="$2" url_arm="$3"
    local url expected_sha
    if is_arm; then
      url="$url_arm"
      expected_sha="${T_SHA_ARM[$name]}"
    else
      url="$url_amd"
      expected_sha="${T_SHA_AMD[$name]}"
    fi
    info "Downloading $name from: $url"
    local tmp; tmp="$(mktemp -d)"
    local archive="$tmp/archive"
    if ! curl -fL --retry 3 --retry-delay 2 -o "$archive" "$url" >> "$LOG_FILE" 2>&1; then
      run_troubleshooter "Downloading $name"
      if ! curl -fL --retry 2 --retry-delay 3 -o "$archive" "$url" >> "$LOG_FILE" 2>&1; then
        rm -rf "$tmp"
        warn "$name: download failed"
        return 1
      fi
    fi

    # Cryptographic SHA-256 Verification
    if [[ -n "$expected_sha" ]]; then
      if ! echo "$expected_sha $archive" | sha256sum -c - >/dev/null 2>&1; then
        warn "$name: SHA-256 mismatch! Supply-chain attack or corrupted download."
        rm -rf "$tmp"
        return 1
      fi
    fi

    if [[ "$url" == *.zip ]]; then
      unzip -q "$archive" -d "$tmp" >> "$LOG_FILE" 2>&1
    elif [[ "$url" == *.tar.gz || "$url" == *.tgz ]]; then
      tar -xzf "$archive" -C "$tmp" >> "$LOG_FILE" 2>&1
    else
      cp "$archive" "$tmp/${name,,}"
    fi
    local bin; bin=$(find "$tmp" -type f -name "${name,,}" 2>/dev/null | head -1)
    [[ -z "$bin" ]] && bin=$(find "$tmp" -type f -iname "$name" 2>/dev/null | head -1)
    if [[ -n "$bin" ]]; then
      install -m 0755 "$bin" "$BIN_DIR/$name"
      rm -rf "$tmp"
      return 0
    fi
    rm -rf "$tmp"
    warn "$name: binary not found in archive"
    return 1
  }

 # ── Pinned versions (update these when new releases ship) ────────────────
 # Format: URL arrays keyed by tool name, separate AMD64 / ARM64 / macOS entries
 declare -A T_AMD T_ARM T_MAC_AMD T_MAC_ARM T_GO T_SHA_AMD T_SHA_ARM
 BASE_PD="https://github.com/projectdiscovery"
 BASE_FF="https://github.com/ffuf/ffuf/releases/download"
 BASE_GL="https://github.com/gitleaks/gitleaks/releases/download"
 BASE_DX="https://github.com/hahwul/dalfox/releases/download"

 # nuclei
 T_AMD[nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip"
 T_ARM[nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_arm64.zip"
 T_MAC_AMD[nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_macos_amd64.zip"
 T_MAC_ARM[nuclei]="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_macos_arm64.zip"
 T_GO[nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9"

 # subfinder
 T_AMD[subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_amd64.zip"
 T_ARM[subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_arm64.zip"
 T_MAC_AMD[subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_macos_amd64.zip"
 T_MAC_ARM[subfinder]="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_macos_arm64.zip"
 T_GO[subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.8"

 # httpx
 T_AMD[httpx]="$BASE_PD/httpx/releases/download/v1.7.0/httpx_1.7.0_linux_amd64.zip"
 T_ARM[httpx]="$BASE_PD/httpx/releases/download/v1.7.0/httpx_1.7.0_linux_arm64.zip"
 T_MAC_AMD[httpx]="$BASE_PD/httpx/releases/download/v1.7.0/httpx_1.7.0_macos_amd64.zip"
 T_MAC_ARM[httpx]="$BASE_PD/httpx/releases/download/v1.7.0/httpx_1.7.0_macos_arm64.zip"
 T_GO[httpx]="github.com/projectdiscovery/httpx/cmd/httpx@v1.7.0"

 # katana
 T_AMD[katana]="$BASE_PD/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip"
 T_ARM[katana]="$BASE_PD/katana/releases/download/v1.1.2/katana_1.1.2_linux_arm64.zip"
 T_MAC_AMD[katana]="$BASE_PD/katana/releases/download/v1.1.2/katana_1.1.2_macos_amd64.zip"
 T_MAC_ARM[katana]="$BASE_PD/katana/releases/download/v1.1.2/katana_1.1.2_macos_arm64.zip"
 T_GO[katana]="github.com/projectdiscovery/katana/cmd/katana@v1.1.2"

 # dnsx
 T_AMD[dnsx]="$BASE_PD/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip"
 T_ARM[dnsx]="$BASE_PD/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip"
 T_MAC_AMD[dnsx]="$BASE_PD/dnsx/releases/download/v1.2.1/dnsx_1.2.1_macos_amd64.zip"
 T_MAC_ARM[dnsx]="$BASE_PD/dnsx/releases/download/v1.2.1/dnsx_1.2.1_macos_arm64.zip"
 T_GO[dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1"

 # ffuf
 T_AMD[ffuf]="$BASE_FF/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz"
 T_ARM[ffuf]="$BASE_FF/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz"
 T_MAC_AMD[ffuf]="$BASE_FF/v2.1.0/ffuf_2.1.0_macos_amd64.tar.gz"
 T_MAC_ARM[ffuf]="$BASE_FF/v2.1.0/ffuf_2.1.0_macos_arm64.tar.gz"
 T_GO[ffuf]="github.com/ffuf/ffuf/v2@v2.1.0"

 # gitleaks — note: official releases use 'linux_x64' / 'darwin_x64'
 T_AMD[gitleaks]="$BASE_GL/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
 T_ARM[gitleaks]="$BASE_GL/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz"
 T_MAC_AMD[gitleaks]="$BASE_GL/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz"
 T_MAC_ARM[gitleaks]="$BASE_GL/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz"
 T_GO[gitleaks]="github.com/gitleaks/gitleaks/v8/cmd/gitleaks@v8.30.1"

 # dalfox
 T_AMD[dalfox]="$BASE_DX/v2.10.0/dalfox_2.10.0_linux_amd64.tar.gz"
 T_ARM[dalfox]="$BASE_DX/v2.10.0/dalfox_2.10.0_linux_arm64.tar.gz"
 T_MAC_AMD[dalfox]="$BASE_DX/v2.10.0/dalfox_2.10.0_darwin_amd64.tar.gz"
 T_MAC_ARM[dalfox]="$BASE_DX/v2.10.0/dalfox_2.10.0_darwin_arm64.tar.gz"
 T_GO[dalfox]="github.com/hahwul/dalfox/v2@v2.10.0"

 # race-the-web (Linux only; macOS falls through to go install)
 T_AMD[race-the-web]="https://github.com/TheHackerDev/race-the-web/releases/download/2.0.1/race-the-web_2.0.1_lin64.bin"
 T_ARM[race-the-web]="https://github.com/TheHackerDev/race-the-web/releases/download/2.0.1/race-the-web_2.0.1_lin64.bin"
 T_GO[race-the-web]="github.com/TheHackerDev/race-the-web@v2.0.1"

 # Select the right URL based on OS
 _bin_url() {
 local name="$1"
 if [[ "$OS" == "Darwin" ]]; then
 is_arm && echo "${T_MAC_ARM[$name]:-}" || echo "${T_MAC_AMD[$name]:-}"
 else
 is_arm && echo "${T_ARM[$name]:-}" || echo "${T_AMD[$name]:-}"
 fi
 }

 for name in nuclei subfinder httpx katana dnsx ffuf gitleaks dalfox race-the-web; do
 if have "$name"; then ok "$name installed"; continue; fi
 url="$(_bin_url "$name")"
 if [[ -n "$url" ]] && spin "Downloading $name" \
 download_binary "$name" "$url" "$url"; then
 continue
 fi
 # Fallback: go install (pinned)
 if have go && spin "Building $name from source" \
 go install -v "${T_GO[$name]}" >> "$LOG_FILE" 2>&1; then
 continue
 fi
 warn "$name: download and source build failed — scan will be skipped"
 done

 # Pre-cache Nuclei Templates
 if have nuclei; then
 spin "Fetching Nuclei Templates" nuclei -update-templates -duc -ni || true
 fi

 # ── Optional tools ─────────────────────────────────────────────
 if ! have trivy; then
 spin "Installing Trivy" curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BIN_DIR" >> "$LOG_FILE" 2>&1 || warn "Trivy: installation failed"
 fi
 
 if have trivy; then
 spin "Fetching Trivy Vulnerability Database" trivy image --download-db-only --no-progress || true
 fi

 have prowler || spin "Installing Prowler" pip install prowler -q || true
 have nxc 2>/dev/null || spin "Installing NetExec" pip install git+https://github.com/Pennyw0rth/NetExec.git -q || true
 
 # ── V9.5 Expansion Tools ────────────────────────────────────────────────
 spin "Installing Expansion Python Tools" pip install wafw00f semgrep checkov sslyze cloudsplaining kube-hunter droopescan git-dumper -q || true
 
 if ! have hakrawler; then
 spin "Installing Hakrawler" go install github.com/hakluke/hakrawler@latest >> "$LOG_FILE" 2>&1 || true
 fi
 if ! have gau; then
 spin "Installing Gau" go install github.com/lc/gau/v2/cmd/gau@latest >> "$LOG_FILE" 2>&1 || true
 fi
 if ! have naabu; then
 spin "Installing Naabu" go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest >> "$LOG_FILE" 2>&1 || true
 fi
 if ! have trufflehog; then
 spin "Installing TruffleHog" curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$BIN_DIR" >> "$LOG_FILE" 2>&1 || true
 fi

 # ── V9.5 Faraday/DefectDojo Additions ──────────────────────────────────
 spin "Installing Faraday/Dojo Inspired Python Tools" pip install bandit detect-secrets routersploit impacket -q || true
 if ! have osv-scanner; then
 spin "Installing OSV-Scanner" go install github.com/google/osv-scanner/cmd/osv-scanner@v1 >> "$LOG_FILE" 2>&1 || true
 fi
 if ! have kube-bench; then
 spin "Installing Kube-Bench" go install github.com/aquasecurity/kube-bench@latest >> "$LOG_FILE" 2>&1 || true
 fi

 # ── Node.js Vulnerability Tools ──────────────────────────────────────────
 if have npm; then
 spin "Installing wscat (WebSocket tool)" sudo npm install -g wscat@5.2.1 || true
 
 # ppmap installation
 if ! have ppmap; then
 if have go; then
 _ppmap_tmp=$(mktemp -d)
 if spin "Installing ppmap (Prototype Pollution)" bash -c "
 git clone https://github.com/kleiton0x00/ppmap.git '$_ppmap_tmp' &&
 cd '$_ppmap_tmp' &&
 go mod init ppmap &&
 go get github.com/chromedp/chromedp@v0.10.0 &&
 go build -o ppmap ppmap.go &&
 install -m 0755 ppmap '$BIN_DIR/ppmap'"; then
 ok "ppmap installed"
 else
 warn "ppmap installation failed"
 fi
 rm -rf "$_ppmap_tmp"
 else
 warn "ppmap requires Go which is not installed. Skipping."
 fi
 else
 ok "ppmap installed"
 fi
 else
 warn "npm not found. Node.js tools (wscat, ppmap) will be skipped."
 fi
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
echo -e " ▶ Launch GUI: ${BOLD}./run.sh${RESET}"
echo -e " ▶ Launch API: ${BOLD}./run.sh --api${RESET}\n"
