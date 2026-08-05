import os
import json

# Define the base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Prepend project-local bin/ directory to system PATH
bin_dir = os.path.join(BASE_DIR, "bin")
os.makedirs(bin_dir, exist_ok=True)
if bin_dir not in os.environ["PATH"].split(os.path.pathsep):
    os.environ["PATH"] = bin_dir + os.path.pathsep + os.environ["PATH"]

# Folders to initialize
REQUIRED_FOLDERS = [
    os.path.join(BASE_DIR, "database"),
    os.path.join(BASE_DIR, "logs"),
    os.path.join(BASE_DIR, "reports"),
    os.path.join(BASE_DIR, "reports", "html"),
    os.path.join(BASE_DIR, "reports", "pdf"),
    os.path.join(BASE_DIR, "config"),
    os.path.join(BASE_DIR, "cache"),
    os.path.join(BASE_DIR, "database", "backup"),
    os.path.join(BASE_DIR, "scanners"),
    os.path.join(BASE_DIR, "intelligence"),
    os.path.join(BASE_DIR, "ui"),
    os.path.join(BASE_DIR, "tools"),
]

DEFAULT_SETTINGS = {
    # Scanner binary paths
    "nmap_path": "nmap",
    "nuclei_path": "nuclei",
    "nikto_path": "nikto",
    "whatweb_path": "whatweb",
    "subfinder_path": "subfinder",
    "httpx_path": "httpx",
    "ffuf_path": "ffuf",
    "sqlmap_path": "sqlmap",
    "wapiti_path": "wapiti",
    "traceroute_path": "traceroute",
    # OWASP ZAP
    "zap_path": "zaproxy",
    "zap_api_key": "smp-zap-key",
    "zap_host": "127.0.0.1",
    "zap_port": 8090,
    "zap_enabled": False,
    # ffuf wordlist (falls back to built-in mini list if path missing)
    "ffuf_wordlist": "/usr/share/wordlists/dirb/common.txt",
    # SMTP
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_ssl": False,
    "smtp_user": "",
    "smtp_pass": "",
    "smtp_sender": "",
    "smtp_receiver": "",
    # Scheduling
    "scan_schedule_hour": 2,
    "scan_schedule_minute": 0,
    "intel_sync_interval_hours": 1,
    "scanner_timeout_seconds": 180,
    # Database retention
    "backup_retention_days": 30,
    # GitHub Advisory API token (optional — fixes 403 rate-limit errors)
    "github_token": "",
    # Report identity
    "tester_name": "Security Auditor",
    # ── V9.2.3 — Scan Profiles ──────────────────────────────────────────────────
    # Options: "fast", "standard", "full"
    "scan_profile": "standard",
    # ── V9.2.3 — Authenticated Scanning ──────────────────────────────────────────
    # Dict of custom HTTP headers to inject into supported scanners
    # e.g. {"Cookie": "session=abc123", "Authorization": "Bearer eyJ..."}
    "auth_headers": {},
    # ── V9.2.3 — New Scanner Binary Paths ──────────────────────────────────────
    "dalfox_path": "dalfox",
    "arjun_path": "arjun",
    "dnsx_path": "dnsx",
    "katana_path": "katana",
    "commix_path": "commix",
    "jwt_tool_path": "jwt_tool",
    "wpscan_path": "wpscan",
    "wpscan_api_token": "",
    "masscan_path": "masscan",
    "paramspider_path": "paramspider",
    "cloud_enum_path": "cloud_enum",
    # ── V9.2.3 — Proxies & Keys & Features ─────────────────────────────────────
    "http_proxy": "",
    "https_proxy": "",
    "shodan_api_key": "",
    "censys_api_key": "",
    "cloud_enum_keywords": "",
    # ── V9.2.3 — New Security Features ──────────────────────────────────────────
    # MAC Changer — enhanced: show result in dashboard
    "mac_changer_enabled": True,
    "mac_display_result": True,   # Show changed MAC in dashboard status bar
    # Session timeout (auto-lock after idle)
    "session_timeout_minutes": 15,
    # Rate limiting for scanners (requests per minute per target)
    "rate_limit_rpm": 120,
    # SLA breach threshold — findings unfixed longer than this are escalated
    "sla_breach_days": 30,
    # GreyNoise Community API key (optional — free tier works without key)
    "greynoise_api_key": "",
    # RSA license public key path (V6 license format)
    "rsa_license_public_key_path": "",
    # System resource check thresholds (pre-scan)
    "sys_cpu_warn_pct": 80,
    "sys_ram_warn_mb": 500,
    "sys_disk_warn_gb": 1.0,
    # API token expiry (hours)
    "api_token_expiry_hours": 24,
    # SBOM output directory (leave blank for default)
    "sbom_output_dir": "",
    # Port baseline — auto-baseline on first scan
    "port_baseline_enabled": True,
    # Insecure Scans (allow invalid TLS certificates)
    "insecure_scans": False,
}

def init_directories():
    """Create all required project directories if they do not exist."""
    for folder in REQUIRED_FOLDERS:
        os.makedirs(folder, exist_ok=True)

def get_settings_path():
    return os.path.join(BASE_DIR, "config", "settings.json")

def load_settings():
    """Load settings from config/settings.json, creating it with defaults if missing."""
    init_directories()
    path = get_settings_path()
    if not os.path.exists(path):
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            settings = json.load(f)
            # Merge with default settings to ensure all keys exist
            merged = DEFAULT_SETTINGS.copy()
            merged.update(settings)
            return merged
    except Exception:
        return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    """Save settings to config/settings.json."""
    init_directories()
    path = get_settings_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception:
        return False
