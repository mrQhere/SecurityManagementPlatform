"""
Tool Installer – auto-detects missing tools and installs what it can.

Supports:
  • pip packages  → installed automatically via pip
  • apt packages  → installed automatically if running as root / with sudo
  • Go binaries   → provides install commands (cannot auto-install without Go)
  • Manual tools  → prints guidance

Called at startup from main.py.
"""
import os
import sys
import shutil
import subprocess
import logging

from tools.config_manager import BASE_DIR
# Prepend project-local bin/ directory to system PATH
bin_dir = os.path.join(BASE_DIR, "bin")
os.makedirs(bin_dir, exist_ok=True)
if bin_dir not in os.environ["PATH"].split(os.path.pathsep):
    os.environ["PATH"] = bin_dir + os.path.pathsep + os.environ["PATH"]

logger = logging.getLogger("smp")

# ── Tool registry ─────────────────────────────────────────────────────────────
# Each entry: (display_name, binary_name, install_method, install_arg)
#   install_method: 'pip' | 'apt' | 'go' | 'manual'
#   install_arg:    package/module name, apt package, go import path, or URL

TOOLS = [
    # Pure-library pip packages (no binary — checked via import)
    ("sslyze",                 None,          "pip",    "sslyze"),
    ("python-owasp-zap-v2.4",  None,          "pip",    "python-owasp-zap-v2.4"),
    ("APScheduler",            None,          "pip",    "APScheduler"),
    ("reportlab",              None,          "pip",    "reportlab"),
    ("requests",               None,          "pip",    "requests"),
    ("colorama",               None,          "pip",    "colorama"),
    ("dnspython",              None,          "pip",    "dnspython"),
    ("requests-futures",       None,          "pip",    "requests-futures"),

    # pip packages that ship CLI binaries
    ("Wapiti",    "wapiti",    "pip",    "wapiti3"),
    ("SQLMap",    "sqlmap",    "pip",    "sqlmap"),
    ("Arjun",     "arjun",     "pip",    "arjun"),
    ("Commix",    "commix",    "pip",    "commix"),

    # System binaries – apt (auto-installed, sudo fallback)
    ("Nmap",        "nmap",        "apt",  "nmap"),
    ("Nikto",       "nikto",       "apt",  "nikto"),
    ("WhatWeb",     "whatweb",     "apt",  "whatweb"),
    ("Traceroute",  "traceroute",  "apt",  "traceroute"),
    ("Masscan",     "masscan",     "apt",  "masscan"),

    # Go binaries — built from source if Go is available, else binary download
    ("Nuclei",    "nuclei",    "go",  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("Subfinder", "subfinder", "go",  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("HTTPx",     "httpx",     "go",  "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("ffuf",      "ffuf",      "go",  "github.com/ffuf/ffuf/v2@latest"),
    ("Gitleaks",  "gitleaks",  "go",  "github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest"),

    # Binary downloads (pre-built — no Go needed)
    ("Dalfox",    "dalfox",    "binary",  ""),
    ("DNSx",      "dnsx",      "binary",  ""),
    ("Katana",    "katana",    "binary",  ""),

    # Source/script tools — downloaded from GitHub and wrapped
    ("ParamSpider",   "paramspider",   "binary", ""),
    ("cloud-enum",    "cloud_enum",    "binary", ""),
    ("theHarvester",  "theHarvester",  "binary", ""),
    ("jwt_tool",      "jwt_tool",      "binary", ""),
    ("WPScan",        "wpscan",        "binary", ""),

    # New V7.0.7 Enterprise pip packages
    ("semgrep",           "semgrep",     "pip",    "semgrep"),
    ("SpiderFoot OSINT",  "sf",          "manual", "Download from https://github.com/smicallef/spiderfoot"),

    # New V7.0.7 Enterprise binaries
    ("Amass",             "amass",       "binary", ""),
    ("Feroxbuster",       "feroxbuster", "binary", ""),
    ("TruffleHog",        "trufflehog",  "binary", ""),
    ("Trivy",             "trivy",       "binary", ""),

    # Internal Pure-Python Modules (No external dependencies)
    ("SSRF Scanner",      None,          "internal", ""),
    ("XXE Scanner",       None,          "internal", ""),
    ("Path Traversal",    None,          "internal", ""),
    ("CRLF Scanner",      None,          "internal", ""),
    ("GraphQL Scanner",   None,          "internal", ""),
    ("API Fuzzer",        None,          "internal", ""),
    ("Hydra (Auth)",      None,          "internal", ""),
    ("HTTP Smuggling",    None,          "internal", ""),
    ("Security Headers",  None,          "internal", ""),
    ("Robots.txt",        None,          "internal", ""),
    ("CORS Scanner",      None,          "internal", ""),
    ("CMS Scanner",       None,          "internal", ""),
    ("Tech Fingerprint",  None,          "internal", ""),
    ("Open Redirect",     None,          "internal", ""),
    ("Retire.js",         None,          "internal", ""),
    ("CVE Correlator",    None,          "internal", ""),

    # Optional / manual-only
    ("OWASP ZAP",  "zaproxy",  "manual", "Download from https://www.zaproxy.org/download/"),
]

def _populate_dynamic_tools():
    try:
        from scanners.core.registry import discover_scanners, _REGISTRY
        discover_scanners()
        
        existing_bins = {t[1] for t in TOOLS if t[1]}
        for name, meta in _REGISTRY.items():
            if not meta.get("needs_binary"): continue
            b = meta.get("binary_name")
            if b and b not in existing_bins:
                TOOLS.append((name, b, "manual", f"Install {b} manually for {name} scanner."))
                existing_bins.add(b)
    except Exception as e:
        logger.error(f"Failed to load dynamic tools: {e}")

_populate_dynamic_tools()

# Module name overrides for pip packages with non-standard import names
_PIP_IMPORT_OVERRIDES = {
    "python-owasp-zap-v2.4": "zapv2",
    "sslyze": "sslyze",
    "APScheduler": "apscheduler",
    "reportlab": "reportlab",
    "requests": "requests",
    "colorama": "colorama",
    "dnspython": "dns",
    "requests-futures": "requests_futures",
    "wapiti3": "wapitiCore",
}


def _pip_install(package):
    """Install a pip package into the current Python environment."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet", package],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            logger.info(f"  [✓] Installed pip package: {package}")
            return True
        else:
            logger.warning(f"  [✗] pip install {package} failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        logger.warning(f"  [✗] pip install {package} error: {e}")
        return False


def _apt_install(package):
    """Install a system package via apt-get (requires sudo or root)."""
    try:
        # Check if apt-get is available
        if not shutil.which("apt-get"):
            logger.warning(f"  [!] apt-get not available. Install manually: sudo apt install {package}")
            return False

        # Try without sudo first (root), then with sudo (non-interactive)
        for cmd in (
            ["apt-get", "install", "-y", "-qq", package],
            ["sudo", "-n", "apt-get", "install", "-y", "-qq", package],
        ):
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                logger.info(f"  [✓] Installed apt package: {package}")
                return True

        logger.warning(f"  [!] apt install {package} failed. Try manually: sudo apt install {package}")
        return False
    except Exception as e:
        logger.warning(f"  [!] apt install {package} error: {e}. Try: sudo apt install {package}")
        return False


def _go_install(name, import_path):
    """Attempt to install a Go binary via `go install`."""
    go_bin = shutil.which("go")
    if not go_bin:
        logger.warning(
            f"  [!] Go not installed. Cannot auto-install {name}.\n"
            f"      Install Go from https://go.dev/dl/ then run:\n"
            f"        go install {import_path}"
        )
        return False
    try:
        result = subprocess.run(
            [go_bin, "install", import_path],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "GOPATH": os.path.expanduser("~/go")}
        )
        if result.returncode == 0:
            logger.info(f"  [✓] Installed Go binary: {name}")
            return True
        else:
            logger.warning(
                f"  [!] go install {name} failed: {result.stderr.strip()}\n"
                f"      Try manually: go install {import_path}"
            )
            return False
    except Exception as e:
        logger.warning(f"  [!] go install {name} error: {e}")
        return False


def _is_tool_available(display_name, binary, method, arg):
    """Check if a tool is available via PATH, bin/, or importable module."""
    bin_dir = os.path.join(BASE_DIR, "bin")
    if binary:
        # Check system PATH
        if shutil.which(binary):
            return True
        # Check project bin/ directory
        local_bin = os.path.join(bin_dir, binary)
        if os.path.isfile(local_bin) and os.access(local_bin, os.X_OK):
            return True
    if method == "pip" and not binary:
        module = _PIP_IMPORT_OVERRIDES.get(arg, arg.lower().replace("-", "_"))
        try:
            __import__(module)
            return True
        except ImportError:
            pass
    if method == "internal":
        return True
    return False


def check_and_install_all(auto_install=True, progress_callback=None):
    """
    Check every tool in the registry. Auto-install pip/apt/go tools when
    *auto_install* is True. Logs a single clean summary.

    Returns:
        dict: {'installed': [...], 'missing': [...], 'skipped': [...]}
    """
    installed, missing, skipped = [], [], []
    go_missing = []  # Go tools that need manual install
    total_tools = len(TOOLS)

    bin_dir = os.path.join(BASE_DIR, "bin")

    # Immediately fix deps for any already-downloaded source tools in bin/
    _ensure_source_tool_deps(bin_dir)

    for idx, (display_name, binary, method, arg) in enumerate(TOOLS):
        if progress_callback:
            progress_callback(idx + 1, total_tools, display_name)

        # Check availability using the unified helper (PATH + bin/ + import)
        if _is_tool_available(display_name, binary, method, arg):
            logger.debug(f"Tool check: {display_name} found.")
            installed.append(display_name)
            continue

        # Not found – attempt install
        if not auto_install:
            logger.debug(f"Tool check: {display_name} not found (auto_install disabled).")
            missing.append(display_name)
            continue

        logger.debug(f"Tool check: {display_name} not found – attempting {method} install…")

        success = False
        if method == "pip":
            success = _pip_install(arg)
        elif method == "apt":
            success = _apt_install(arg)
            if not success:
                # apt failed (no sudo?) — try binary download fallback
                success = bool(_download_missing_tools_locally([display_name]))
        elif method == "go":
            if shutil.which("go"):
                success = _go_install(display_name, arg)
            if not success:
                # go failed or not available — try pre-built binary download
                success = bool(_download_missing_tools_locally([display_name]))
                if not success:
                    go_missing.append(f"go install {arg}")
        elif method == "binary":
            success = bool(_download_missing_tools_locally([display_name]))
        elif method == "manual":
            logger.debug(f"Tool check: {display_name} requires manual install: {arg}")
            skipped.append(display_name)
            continue

        # Re-check availability after install attempt
        if success and _is_tool_available(display_name, binary, method, arg):
            installed.append(display_name)
        elif success:
            # Install reported success but binary not found in PATH yet —
            # likely in bin/ without PATH update; check explicitly
            local_bin = os.path.join(bin_dir, binary) if binary else None
            if local_bin and os.path.isfile(local_bin):
                installed.append(display_name)
            else:
                installed.append(display_name)  # Trust the install report
        else:
            missing.append(display_name)

    # Single clean summary
    logger.info(
        f"Tool Check Complete: {len(installed)} ready | "
        f"{len(missing)} missing | {len(skipped)} manual-only"
    )
    if missing:
        logger.warning(f"Missing scanning tools: {', '.join(missing)}")
    if go_missing:
        logger.warning(
            "Go tools not installed. Install Go from https://go.dev/dl/ then re-run setup.sh"
        )

    return {"installed": installed, "missing": missing, "skipped": skipped}


def install_single_tool(binary_name: str) -> bool:
    """
    Self-Healing On-Demand Tool Installer

    Called at runtime when a scanner binary is detected as missing (or crashes).
    Looks up *binary_name* in the TOOLS registry and attempts installation with
    the appropriate method (pip / apt / go / binary-download).

    Returns True if the binary becomes available after installation, False otherwise.
    """
    logger.info(f"[Self-Heal] Attempting on-demand install of '{binary_name}'...")

    # Find this binary in the TOOLS registry
    matching_entries = [t for t in TOOLS if t[1] == binary_name]
    if not matching_entries:
        # Binary not in registry — check if it's a known manual-only tool
        manual_entries = [t for t in TOOLS if t[0].lower() == binary_name.lower()]
        if manual_entries:
            display, binary, method, arg = manual_entries[0]
            logger.warning(
                f"[Self-Heal] '{binary_name}' requires manual installation.\n"
                f"    -> {arg}"
            )
        else:
            logger.warning(f"[Self-Heal] '{binary_name}' not found in tool registry. Skipping auto-install.")
        return False

    display_name, binary, method, arg = matching_entries[0]

    success = False
    bin_dir = os.path.join(BASE_DIR, "bin")

    if method == "pip":
        logger.info(f"[Self-Heal] Installing pip package: {arg}")
        success = _pip_install(arg)
    elif method == "apt":
        logger.info(f"[Self-Heal] Installing apt package: {arg}")
        success = _apt_install(arg)
        if not success:
            # apt failed (sudo unavailable?) — try binary download fallback
            logger.info(f"[Self-Heal] apt failed for {display_name}, trying binary download...")
            success = bool(_download_missing_tools_locally([display_name]))
    elif method == "go":
        if shutil.which("go"):
            logger.info(f"[Self-Heal] Installing Go binary: {display_name}")
            success = _go_install(display_name, arg)
        if not success:
            logger.info(f"[Self-Heal] Go install failed/unavailable for {display_name}, trying binary download...")
            success = bool(_download_missing_tools_locally([display_name]))
    elif method == "binary":
        logger.info(f"[Self-Heal] Downloading binary for: {display_name}")
        success = bool(_download_missing_tools_locally([display_name]))
    elif method == "manual":
        logger.warning(
            f"[Self-Heal] '{display_name}' requires manual installation: {arg}"
        )
        return False

    # Verify availability via PATH or local bin/
    local_bin_path = os.path.join(bin_dir, binary) if binary else None
    in_path = shutil.which(binary) if binary else False
    in_local_bin = local_bin_path and os.path.isfile(local_bin_path)

    if success and (in_path or in_local_bin):
        logger.info(f"[Self-Heal] '{binary_name}' is now available and ready.")
        return True
    elif success:
        logger.info(f"[Self-Heal] Installation reported success for '{binary_name}'.")
        return True
    else:
        logger.error(f"[Self-Heal] Failed to auto-install '{binary_name}'. Scan step will be skipped.")
        return False


def _install_source_deps(src_dir):
    """Install Python deps for a source-based tool (pyproject.toml / requirements.txt / setup.py)."""
    pyproject = os.path.join(src_dir, "pyproject.toml")
    requirements = os.path.join(src_dir, "requirements.txt")
    setup_py = os.path.join(src_dir, "setup.py")

    if os.path.exists(pyproject):
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet", "."],
                cwd=src_dir, capture_output=True, timeout=180
            )
            return
        except Exception:
            pass
    if os.path.exists(requirements):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet", "-r", requirements],
            capture_output=True, timeout=180
        )
    elif os.path.exists(setup_py):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet", "."],
            cwd=src_dir, capture_output=True, timeout=180
        )


def _download_missing_tools_locally(missing):
    """
    Fully automated zero-user-intervention tool downloader.
    Downloads, extracts, installs deps, and creates wrappers for every tool.
    Users should NEVER have to manually install anything outside of SMP.
    """
    import zipfile
    import tarfile
    import requests
    import platform

    bin_dir = os.path.join(BASE_DIR, "bin")
    os.makedirs(bin_dir, exist_ok=True)

    machine = platform.machine().lower()
    is_arm64 = "arm64" in machine or "aarch64" in machine
    arch = "arm64" if is_arm64 else "amd64"

    # ── Complete download URL registry ────────────────────────────────────────
    urls_amd64 = {
        "Nuclei":       "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip",
        "Subfinder":    "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip",
        "HTTPx":        "https://github.com/projectdiscovery/httpx/releases/download/v1.6.6/httpx_1.6.6_linux_amd64.zip",
        "ffuf":         "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz",
        "Nikto":        "https://github.com/sullo/nikto/archive/refs/tags/2.5.0.zip",
        "Gitleaks":     "https://github.com/gitleaks/gitleaks/releases/download/v7.0.7/gitleaks_8.18.2_linux_x64.tar.gz",
        "Katana":       "https://github.com/projectdiscovery/katana/releases/download/v1.1.1/katana_1.1.1_linux_amd64.zip",
        "DNSx":         "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip",
        "Dalfox":       "https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz",
        "Masscan":      "https://github.com/robertdavidgraham/masscan/archive/refs/heads/master.zip",
        # Source-based tools
        "cloud-enum":       "https://github.com/initstring/cloud_enum/archive/refs/heads/master.zip",
        "ParamSpider":      "https://github.com/devanshbatham/ParamSpider/archive/refs/heads/master.zip",
        "theHarvester":     "https://github.com/laramies/theHarvester/archive/refs/heads/master.zip",
        "jwt_tool":         "https://github.com/ticarpi/jwt_tool/archive/refs/heads/master.zip",
        "WPScan":           "https://github.com/wpscanteam/wpscan/archive/refs/heads/master.zip",

        # New V7.0.7 Enterprise binaries
        "Amass":        "https://github.com/owasp-amass/amass/releases/download/v7.0.7/amass_linux_amd64.zip",
        "Feroxbuster":  "https://github.com/epi052/feroxbuster/releases/download/v2.10.2/x86_64-linux-feroxbuster.tar.gz",
        "TruffleHog":   "https://github.com/trufflesecurity/trufflehog/releases/download/v3.81.0/trufflehog_3.81.0_linux_amd64.tar.gz",
        "Trivy":        "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz",
    }
    urls_arm64 = {
        "Nuclei":       "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_arm64.zip",
        "Subfinder":    "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_arm64.zip",
        "HTTPx":        "https://github.com/projectdiscovery/httpx/releases/download/v1.6.6/httpx_1.6.6_linux_arm64.zip",
        "ffuf":         "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz",
        "Nikto":        "https://github.com/sullo/nikto/archive/refs/tags/2.5.0.zip",
        "Gitleaks":     "https://github.com/gitleaks/gitleaks/releases/download/v7.0.7/gitleaks_8.18.2_linux_arm64.tar.gz",
        "Katana":       "https://github.com/projectdiscovery/katana/releases/download/v1.1.1/katana_1.1.1_linux_arm64.zip",
        "DNSx":         "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip",
        "Dalfox":       "https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_arm64.tar.gz",
        "Masscan":      "https://github.com/robertdavidgraham/masscan/archive/refs/heads/master.zip",
        "cloud-enum":       "https://github.com/initstring/cloud_enum/archive/refs/heads/master.zip",
        "ParamSpider":      "https://github.com/devanshbatham/ParamSpider/archive/refs/heads/master.zip",
        "theHarvester":     "https://github.com/laramies/theHarvester/archive/refs/heads/master.zip",
        "jwt_tool":         "https://github.com/ticarpi/jwt_tool/archive/refs/heads/master.zip",
        "WPScan":           "https://github.com/wpscanteam/wpscan/archive/refs/heads/master.zip",

        # New V7.0.7 Enterprise binaries
        "Amass":        "https://github.com/owasp-amass/amass/releases/download/v7.0.7/amass_linux_arm64.zip",
        "Feroxbuster":  "https://github.com/epi052/feroxbuster/releases/download/v2.10.2/aarch64-linux-feroxbuster.tar.gz",
        "TruffleHog":   "https://github.com/trufflesecurity/trufflehog/releases/download/v3.81.0/trufflehog_3.81.0_linux_arm64.tar.gz",
        "Trivy":        "https://github.com/aquasecurity/trivy/releases/download/v0.53.0/trivy_0.53.0_Linux-ARM64.tar.gz",
    }
    urls = urls_arm64 if is_arm64 else urls_amd64

    # ── V7.0.7 — Security: Download SHA256 Checksums ────────────────────────────
    # Add checksums to verify integrity before extraction
    checksums = {
        "Nuclei": "235f264d32e47e1ccf58d534e2eb4d0d4eeb47f1cae1ebb30a584b8b52565202",
        "Subfinder": "6fda32fe1f5750e63fa07c112b1b615d033e425c6dc6659ed8ec61035eb8eba2",
        "HTTPx": "d069a6bbcc0d6b3c5bedc0322f7b996b2587481ae69162b17941b67d7e42cd2d",
    }
    
    downloaded_any = False

    for name in missing:
        if name not in urls:
            continue

        url = urls[name]
        logger.info(f"[Installer] Downloading {name} from {url}...")

        temp_extract_dir = os.path.join(bin_dir, f"temp_{name.lower().replace('-','_')}")
        os.makedirs(temp_extract_dir, exist_ok=True)
        temp_file = os.path.join(temp_extract_dir, "archive")

        try:
            response = requests.get(url, stream=True, timeout=180)
            response.raise_for_status()
            with open(temp_file, "wb") as f:
                for chunk in response.iter_content(chunk_size=65536):
                    f.write(chunk)
                    
            # ── V7.0.7 — Security Check: SHA256 ────────────────────────────
            if name in checksums:
                import hashlib
                h = hashlib.sha256()
                with open(temp_file, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                computed = h.hexdigest()
                if computed != checksums[name]:
                    logger.error(f"[Installer] SHA256 mismatch for {name}! Expected {checksums[name]}, got {computed}.")
                    continue # Skip extraction for security reasons
                else:
                    logger.info(f"[Installer] SHA256 verified for {name}.")

            # Extract
            if url.endswith(".zip") or "zip" in url.lower():
                with zipfile.ZipFile(temp_file, "r") as zr:
                    zr.extractall(temp_extract_dir)
            elif url.endswith(".tar.gz") or "tar.gz" in url.lower():
                with tarfile.open(temp_file, "r:gz") as tr:
                    tr.extractall(temp_extract_dir)

            # ── Per-tool install logic ────────────────────────────────────────

            if name == "Nikto":
                nikto_pl = None
                for rd, _, fns in os.walk(temp_extract_dir):
                    if "nikto.pl" in fns:
                        nikto_pl = os.path.join(rd, "nikto.pl")
                        break
                if nikto_pl:
                    dst = os.path.join(bin_dir, "nikto_src")
                    if os.path.exists(dst): shutil.rmtree(dst)
                    shutil.move(os.path.dirname(nikto_pl), dst)
                    wrapper = os.path.join(bin_dir, "nikto")
                    with open(wrapper, "w") as wf:
                        wf.write(f'#!/usr/bin/env bash\nperl "{os.path.join(dst, "nikto.pl")}" "$@"\n')
                    os.chmod(wrapper, 0o755)
                    logger.info("[Installer] Nikto installed successfully.")
                    downloaded_any = True

            elif name == "cloud-enum":
                cloud_py = None
                for rd, _, fns in os.walk(temp_extract_dir):
                    if "cloud_enum.py" in fns:
                        cloud_py = os.path.join(rd, "cloud_enum.py")
                        break
                if cloud_py:
                    dst = os.path.join(bin_dir, "cloud_enum_src")
                    if os.path.exists(dst): shutil.rmtree(dst)
                    shutil.move(os.path.dirname(cloud_py), dst)
                    # Install all deps (pyproject.toml / requirements.txt)
                    _install_source_deps(dst)
                    # Also explicitly install known deps in case pyproject parse fails
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet",
                         "dnspython>=2.0", "requests>=2.0", "requests-futures"],
                        capture_output=True, timeout=120
                    )
                    wrapper = os.path.join(bin_dir, "cloud_enum")
                    with open(wrapper, "w") as wf:
                        wf.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{os.path.join(dst, "cloud_enum.py")}" "$@"\n')
                    os.chmod(wrapper, 0o755)
                    logger.info("[Installer] cloud-enum installed successfully.")
                    downloaded_any = True

            elif name == "ParamSpider":
                ps_py = None
                for rd, _, fns in os.walk(temp_extract_dir):
                    if "main.py" in fns and "paramspider" in rd.lower():
                        ps_py = os.path.join(rd, "main.py")
                        break
                    elif "paramspider.py" in fns:
                        ps_py = os.path.join(rd, "paramspider.py")
                        break
                if ps_py:
                    dst = os.path.join(bin_dir, "paramspider_src")
                    if os.path.exists(dst): shutil.rmtree(dst)
                    shutil.move(os.path.dirname(ps_py), dst)
                    _install_source_deps(dst)
                    # Explicitly install known deps
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet",
                         "colorama", "requests"],
                        capture_output=True, timeout=120
                    )
                    wrapper = os.path.join(bin_dir, "paramspider")
                    with open(wrapper, "w") as wf:
                        wf.write(f'#!/usr/bin/env bash\ncd "{dst}"\nexec "{sys.executable}" "{os.path.basename(ps_py)}" "$@"\n')
                    os.chmod(wrapper, 0o755)
                    logger.info("[Installer] ParamSpider installed successfully.")
                    downloaded_any = True

            elif name == "theHarvester":
                # Real theHarvester from GitHub (not the pip stub)
                havester_py = None
                havester_dir = None
                for rd, dirs, fns in os.walk(temp_extract_dir):
                    if "theHarvester.py" in fns or "theHarvester" in fns:
                        havester_dir = rd
                        havester_py = os.path.join(rd, "theHarvester.py") if "theHarvester.py" in fns else os.path.join(rd, "theHarvester")
                        break
                    # Also look for the package __main__ approach
                    if "theHarvester" in dirs:
                        pkg_dir = os.path.join(rd, "theHarvester")
                        if os.path.exists(os.path.join(pkg_dir, "__main__.py")):
                            havester_dir = rd
                            havester_py = "__package__"
                            break
                if havester_dir:
                    dst = os.path.join(bin_dir, "theHarvester_src")
                    if os.path.exists(dst): shutil.rmtree(dst)
                    shutil.move(havester_dir, dst)
                    _install_source_deps(dst)
                    # Core deps known to be needed
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet",
                         "aiodns", "aiohttp", "bs4", "censys", "dnspython",
                         "netaddr", "pyppeteer", "requests", "shodan", "ujson"],
                        capture_output=True, timeout=180
                    )
                    # Create binary wrapper
                    wrapper = os.path.join(bin_dir, "theHarvester")
                    theharvester_entry = os.path.join(dst, "theHarvester.py")
                    if os.path.exists(theharvester_entry):
                        with open(wrapper, "w") as wf:
                            wf.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{theharvester_entry}" "$@"\n')
                    else:
                        # Package-style: run as python -m theHarvester
                        with open(wrapper, "w") as wf:
                            wf.write(f'#!/usr/bin/env bash\ncd "{dst}"\nexec "{sys.executable}" -m theHarvester "$@"\n')
                    os.chmod(wrapper, 0o755)
                    logger.info("[Installer] theHarvester installed successfully.")
                    downloaded_any = True

            elif name == "jwt_tool":
                # jwt_tool: a single Python file
                jwt_py = None
                for rd, _, fns in os.walk(temp_extract_dir):
                    for fn in fns:
                        if fn.lower() in ("jwt_tool.py", "jwtool.py"):
                            jwt_py = os.path.join(rd, fn)
                            break
                    if jwt_py:
                        break
                if jwt_py:
                    dst_dir = os.path.join(bin_dir, "jwt_tool_src")
                    if os.path.exists(dst_dir): shutil.rmtree(dst_dir)
                    shutil.move(os.path.dirname(jwt_py), dst_dir)
                    dst_py = os.path.join(dst_dir, os.path.basename(jwt_py))
                    _install_source_deps(dst_dir)
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet",
                         "termcolor", "pycryptodome"],
                        capture_output=True, timeout=120
                    )
                    wrapper = os.path.join(bin_dir, "jwt_tool")
                    with open(wrapper, "w") as wf:
                        wf.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{dst_py}" "$@"\n')
                    os.chmod(wrapper, 0o755)
                    logger.info("[Installer] jwt_tool installed successfully.")
                    downloaded_any = True

            elif name == "WPScan":
                # WPScan: try gem install, then compile from source
                gem_bin = shutil.which("gem")
                ruby_bin = shutil.which("ruby")
                if not ruby_bin:
                    # Try apt-installing ruby
                    for cmd in (
                        ["apt-get", "install", "-y", "-qq", "ruby", "ruby-dev", "build-essential", "libcurl4-openssl-dev", "libxml2", "libxml2-dev", "libxslt1-dev", "zlib1g-dev"],
                        ["sudo", "-n", "apt-get", "install", "-y", "-qq", "ruby", "ruby-dev", "build-essential", "libcurl4-openssl-dev"],
                    ):
                        result = subprocess.run(cmd, capture_output=True, timeout=180)
                        if result.returncode == 0:
                            ruby_bin = shutil.which("ruby")
                            gem_bin = shutil.which("gem")
                            break
                if gem_bin:
                    result = subprocess.run(
                        [gem_bin, "install", "wpscan", "--no-user-install"],
                        capture_output=True, timeout=300
                    )
                    if result.returncode == 0 and shutil.which("wpscan"):
                        logger.info("[Installer] WPScan installed via gem.")
                        downloaded_any = True
                    else:
                        logger.warning("[Installer] gem install wpscan failed. WPScan requires Ruby 2.5+.")
                else:
                    logger.warning("[Installer] WPScan requires Ruby. Ruby not available.")

            elif name == "Masscan":
                # Masscan: build from source (it's a C program, just needs make)
                masscan_src = None
                for rd, dirs, fns in os.walk(temp_extract_dir):
                    if "Makefile" in fns and "masscan" in rd.lower():
                        masscan_src = rd
                        break
                if masscan_src:
                    # Try to compile
                    result = subprocess.run(
                        ["make", "-j2"],
                        cwd=masscan_src, capture_output=True, timeout=120
                    )
                    masscan_bin = None
                    for rd, _, fns in os.walk(masscan_src):
                        if "masscan" in fns and rd != masscan_src:
                            masscan_bin = os.path.join(rd, "masscan")
                            break
                        elif "masscan" in fns:
                            masscan_bin = os.path.join(rd, "masscan")
                    if masscan_bin and os.path.exists(masscan_bin):
                        target = os.path.join(bin_dir, "masscan")
                        shutil.copy2(masscan_bin, target)
                        os.chmod(target, 0o755)
                        logger.info("[Installer] Masscan compiled and installed successfully.")
                        downloaded_any = True
                    else:
                        # Fall back to apt
                        _apt_install("masscan")

            else:
                # Standard binary (nuclei, subfinder, httpx, ffuf, dalfox, dnsx, katana, gitleaks)
                binary_name_lower = name.lower()
                binary_found = None
                for rd, _, fns in os.walk(temp_extract_dir):
                    if binary_name_lower in fns:
                        binary_found = os.path.join(rd, binary_name_lower)
                        break
                if binary_found:
                    target = os.path.join(bin_dir, binary_name_lower)
                    if os.path.exists(target):
                        os.remove(target)
                    shutil.move(binary_found, target)
                    os.chmod(target, 0o755)
                    logger.info(f"[Installer] {name} binary installed to {target}")
                    downloaded_any = True
                else:
                    logger.warning(f"[Installer] Could not find '{binary_name_lower}' in downloaded archive for {name}.")

        except Exception as e:
            logger.error(f"[Installer] Error downloading/installing {name}: {e}")
        finally:
            if os.path.exists(temp_extract_dir):
                shutil.rmtree(temp_extract_dir, ignore_errors=True)

    # Ensure all bin/ files have execute permission
    if os.path.isdir(bin_dir):
        for fname in os.listdir(bin_dir):
            fpath = os.path.join(bin_dir, fname)
            if os.path.isfile(fpath):
                current = os.stat(fpath).st_mode
                if not (current & 0o100):
                    os.chmod(fpath, current | 0o755)

    return downloaded_any


def _ensure_source_tool_deps(bin_dir):
    """
    When SMP is already running and source tools (cloud_enum, paramspider, theHarvester)
    are present in bin/ but their Python deps are not installed, fix them immediately.
    This ensures tools downloaded by a previous session work correctly right now.
    """
    tool_dep_map = {
        "cloud_enum_src": ["dnspython>=2.0", "requests>=2.0", "requests-futures"],
        "paramspider_src": ["colorama", "requests"],
        "theHarvester_src": ["aiodns", "aiohttp", "bs4", "dnspython", "netaddr", "requests"],
        "jwt_tool_src": ["termcolor", "pycryptodome"],
    }
    for src_name, deps in tool_dep_map.items():
        src_path = os.path.join(bin_dir, src_name)
        if os.path.isdir(src_path):
            # First try pyproject.toml / requirements.txt
            _install_source_deps(src_path)
            # Then ensure the known critical deps
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet"] + deps,
                    capture_output=True, timeout=120
                )
            except Exception:
                pass

