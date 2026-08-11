from scanners.core.registry import register_scanner
"""
Gitleaks Secret Detection Scanner.
1. Probes target for exposed .git directory
2. Clones exposed repo and scans for secrets
3. Probes common secret file paths (.env, credentials.json, etc.)

Does NOT scan SMP's own source directory — that was a critical bug.
"""
import os
import json
import logging
import subprocess
import shutil
import tempfile
import requests
from urllib.parse import urlparse
from tools.db_manager import add_log_entry
from tools.config_manager import load_settings

logger = logging.getLogger("smp.scan")
verify_tls = not load_settings().get("insecure_scans", False)

GITLEAKS_TIMEOUT = 300


@register_scanner(name="Gitleaks", step_name="Running Gitleaks", depends_on=['Shodan'], binary_name="", needs_binary=False, confidence=95)
def run_gitleaks_scan(url):
    """
    Checks target for exposed .git directory, clones and scans it for secrets,
    and probes common secret file paths. Returns list of finding dicts.
    """
    domain = urlparse(url).hostname or url
    logger.info(f"Gitleaks Started: {domain}")
    add_log_entry("INFO", f"Gitleaks Started: {domain}")

    findings = []

    # ── Locate gitleaks binary ─────────────────────────────────────────────
    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        project_bin = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "bin", "gitleaks")
        )
        if os.path.exists(project_bin):
            gitleaks_bin = project_bin

    # ── 1. Probe for exposed .git/config ──────────────────────────────────
    git_config_url = f"{url.rstrip('/')}/.git/config"
    exposed_git = False
    try:
        resp = requests.get(git_config_url, timeout=10, verify=verify_tls, allow_redirects=False)
        if resp.status_code == 200 and ("repositoryformatversion" in resp.text or "[core]" in resp.text):
            exposed_git = True
            findings.append({
                "severity":    "Critical",
                "title":       "Exposed Git Repository (.git directory publicly accessible)",
                "description": (
                    f"The target exposes its Git repository to the internet.\n"
                    f"URL: {git_config_url}\n\n"
                    f"Impact: Full source code, credentials, API keys, DB schemas recoverable.\n\n"
                    f"Remediation:\n"
                    f"  Nginx: location ~ /\\.git {{ deny all; }}\n"
                    f"  Apache: RedirectMatch 404 /\\.git"
                ),
                "template_id": "VULN-GIT-EXPOSURE",
            })
            logger.warning(f"Gitleaks: CRITICAL — Exposed .git at {git_config_url}")
    except Exception as e:
        logger.debug(f"Gitleaks: .git probe: {e}")

    # ── 2. Clone and scan exposed repo ────────────────────────────────────
    if exposed_git and gitleaks_bin:
        tmpdir = tempfile.mkdtemp(prefix="smp_gitleaks_")
        try:
            clone = subprocess.run(
                ["git", "clone", "--depth", "50", url.rstrip("/"), tmpdir],
                capture_output=True, text=True, timeout=60
            )
            if clone.returncode == 0 and os.listdir(tmpdir):
                _scan_directory_for_secrets(gitleaks_bin, tmpdir, url, findings)
        except Exception as e:
            logger.debug(f"Gitleaks: clone attempt: {e}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── 3. Probe common secret file paths ─────────────────────────────────
    secret_paths = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config/database.yml", "/config/secrets.yml",
        "/wp-config.php.bak", "/database.sql", "/dump.sql",
        "/credentials.json", "/service-account.json",
        "/.aws/credentials", "/secrets.json",
    ]
    for path in secret_paths:
        check_url = f"{url.rstrip('/')}{path}"
        try:
            resp = requests.get(check_url, timeout=5, verify=verify_tls, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text) > 10:
                text = resp.text.lower()
                if any(k in text for k in ("password", "secret", "key", "token", "api_key", "database_url", "db_pass")):
                    findings.append({
                        "severity":    "Critical",
                        "title":       f"Sensitive File Exposed: {path}",
                        "description": (
                            f"URL: {check_url}\n"
                            f"HTTP 200 returned for a credential file.\n\n"
                            f"Remediation: Move outside web root or deny access in server config."
                        ),
                        "template_id": "VULN-SECRET-FILE",
                    })
                    logger.warning(f"Gitleaks: Secret file at {check_url}")
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback, logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass

    logger.info(f"Gitleaks Completed: {len(findings)} findings")
    add_log_entry("INFO", f"Gitleaks: {len(findings)} findings")
    return findings


def _scan_directory_for_secrets(gitleaks_bin, directory, url, findings):
    output_json = os.path.join(directory, "_gitleaks.json")
    cmd = [
        gitleaks_bin, "detect",
        "--source", directory,
        "--report-format", "json",
        "--report-path", output_json,
        "--redact", "--no-git",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT)
        if not os.path.exists(output_json):
            return
        with open(output_json, "r", encoding="utf-8") as f:
            leaks = json.load(f)
        for leak in (leaks or [])[:20]:
            findings.append({
                "severity":    "Critical",
                "title":       f"Secret Leaked: {leak.get('RuleID')} in {os.path.basename(leak.get('File', ''))}",
                "description": (
                    f"Source: Cloned from {url}\n"
                    f"Rule: {leak.get('RuleID')}\n"
                    f"File: {leak.get('File')}\n"
                    f"Line: {leak.get('StartLine')}\n"
                    f"Match: {leak.get('Match', '[redacted]')}\n"
                    f"Author: {leak.get('Author', 'N/A')}"
                ),
                "template_id": "VULN-SECRET-LEAK",
            })
        if leaks:
            logger.warning(f"Gitleaks: {len(leaks)} secrets in cloned repo")
    except Exception as e:
        logger.error(f"Gitleaks directory scan: {e}")
