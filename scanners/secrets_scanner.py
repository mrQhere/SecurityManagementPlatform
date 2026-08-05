"""
Secrets Scanner V7.0.3
=====================
Real pattern-based secrets detection in HTTP responses, HTML, JS files,
and raw scanner output. Replaces the empty stubs (trufflehog/gitleaks).

Detects:
  - API keys (AWS, GCP, Azure, Stripe, Twilio, SendGrid, etc.)
  - Private keys (RSA, EC, PEM blocks)
  - JWT tokens
  - Database connection strings
  - Generic high-entropy tokens

Fallback chain:
  1. Full regex scan of HTTP responses via requests
  2. Regex scan of already-collected raw output if network fails
"""
import re
import logging
import hashlib
import math
from tools.config_manager import load_settings
verify_tls = not load_settings().get('insecure_scans', False)


logger = logging.getLogger("smp.scan")

# ── Secret patterns ──────────────────────────────────────────────────────────
# (name, regex, severity, entropy_check)
_PATTERNS = [
    # AWS
    ("AWS Access Key ID",     r"AKIA[0-9A-Z]{16}",                               "Critical", False),
    ("AWS Secret Access Key", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]", "Critical", False),

    # GCP
    ("GCP API Key",           r"AIza[0-9A-Za-z\-_]{35}",                         "High",     False),
    ("GCP Service Account",   r'"type":\s*"service_account"',                     "Critical", False),

    # Azure
    ("Azure Storage Key",     r"AccountKey=[A-Za-z0-9+/=]{88}",                  "Critical", False),

    # Private Keys (PEM)
    ("RSA Private Key",       r"-----BEGIN RSA PRIVATE KEY-----",                 "Critical", False),
    ("EC Private Key",        r"-----BEGIN EC PRIVATE KEY-----",                  "Critical", False),
    ("Generic Private Key",   r"-----BEGIN PRIVATE KEY-----",                     "Critical", False),

    # JWT
    ("JWT Token",             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "High", False),

    # Stripe
    ("Stripe Live Key",       r"sk_live_[0-9a-zA-Z]{24,}",                       "Critical", False),
    ("Stripe Pub Key",        r"pk_live_[0-9a-zA-Z]{24,}",                       "Medium",   False),

    # Twilio
    ("Twilio Auth Token",     r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",         "High",     False),

    # SendGrid
    ("SendGrid API Key",      r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",      "High",     False),

    # GitHub
    ("GitHub Token",          r"ghp_[A-Za-z0-9]{36}",                            "High",     False),
    ("GitHub OAuth",          r"gho_[A-Za-z0-9]{36}",                            "High",     False),

    # Database URLs
    ("DB Connection String",  r"(?i)(mysql|postgres|mongodb|redis)://[^\s\"'<>]+", "High",    False),

    # Generic high-entropy strings
    ("High-Entropy Token",    r"(?i)(secret|api_key|apikey|token|password)\s*[=:]\s*['\"]([A-Za-z0-9+/=!@#$%^&*]{20,})['\"]", "Medium", True),
]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    n = len(data)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())


def _scan_text(text: str, source_url: str) -> list:
    """Scan a text blob for secrets. Returns list of finding dicts."""
    findings = []
    seen = set()

    for name, pattern, severity, entropy_check in _PATTERNS:
        try:
            for match in re.finditer(pattern, text):
                matched_val = match.group(0)

                # For entropy-check patterns, verify it's actually high-entropy
                if entropy_check:
                    # Extract the value part (group 2 if available)
                    val = match.group(2) if match.lastindex and match.lastindex >= 2 else matched_val
                    if _shannon_entropy(val) < 3.5:
                        continue  # Too low entropy — likely a placeholder

                # Deduplicate by hash
                key = hashlib.md5(matched_val.encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)

                # Redact part of the secret in the description
                redacted = matched_val[:8] + "..." + matched_val[-4:] if len(matched_val) > 12 else "***"
                findings.append({
                    "severity": severity,
                    "title": f"Exposed Secret Detected: {name}",
                    "description": (
                        f"A potential {name} was found exposed on the target.\n\n"
                        f"Pattern: {name}\n"
                        f"Value (redacted): {redacted}\n"
                        f"Source: {source_url}\n\n"
                        f"Immediate action required: rotate/revoke this credential."
                    ),
                    "tool": "SecretsScanner",
                    "confidence": 80,
                })
        except re.error:
            continue

    return findings


TIMEOUT = 15  # seconds


def run_secrets_scan(url: str) -> list:
    """
    Main scan function. Fetches the URL and scans for exposed secrets.
    
    Returns list of finding dicts.
    Fallback: if network fails, scans any cached HTML/JS already retrieved.
    """
    findings = []

    # Primary: fetch URL and scan response
    try:
        import requests
        session = requests.Session()
        session.headers["User-Agent"] = "SMP-SecretsScanner/6.0"

        # Scan main page
        resp = session.get(url, timeout=TIMEOUT, verify=verify_tls)
        findings += _scan_text(resp.text, url)

        # Also scan common JS paths
        js_paths = ["/static/main.js", "/js/app.js", "/assets/bundle.js", "/js/config.js"]
        for path in js_paths:
            try:
                js_url = url.rstrip("/") + path
                js_resp = session.get(js_url, timeout=5, verify=verify_tls)
                if js_resp.status_code == 200 and "javascript" in js_resp.headers.get("content-type", ""):
                    findings += _scan_text(js_resp.text, js_url)
            except Exception:
                continue

        logger.info(f"[SecretsScanner] Scanned {url}: {len(findings)} potential secrets found")

    except Exception as e:
        logger.warning(f"[SecretsScanner] Network scan failed: {e}. Scanning cached outputs.")
        # Fallback: scan any cached raw outputs
        try:
            from tools.config_manager import BASE_DIR
            raw_dir = os.path.join(BASE_DIR, "database", "raw_outputs")
            if os.path.exists(raw_dir):
                import os
                import gzip
                for fname in os.listdir(raw_dir)[:10]:  # limit to recent 10
                    fpath = os.path.join(raw_dir, fname)
                    try:
                        with gzip.open(fpath, "rt", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        findings += _scan_text(content, f"cached:{fname}")
                    except Exception:
                        continue
        except Exception as e2:
            logger.error(f"[SecretsScanner] Fallback cache scan also failed: {e2}")

    # Deduplicate
    seen_titles = set()
    unique = []
    for f in findings:
        if f["title"] not in seen_titles:
            seen_titles.add(f["title"])
            unique.append(f)

    return unique
