from scanners.core.registry import register_scanner
"""
Dalfox — XSS Parameter Scanner
================================
Dalfox is a powerful open-source XSS scanner using analysis techniques
to identify and verify reflected/stored/DOM XSS vulnerabilities.

Install: go install github.com/hahwul/dalfox/v2/cmd/dalfox@latest
Or:      bin/dalfox (installed by setup.sh)
"""
import subprocess
import json
import logging
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

DALFOX_TIMEOUT = 3600  # 1h — restored from 5min

_SEVERITY_MAP = {
    "G":     "Critical",   # GreatFinding — confirmed exploitable XSS
    "M":     "High",       # Medium confidence
    "I":     "Info",
    "BXSS":  "High",       # Blind XSS
}


@register_scanner(name="Dalfox", step_name="Running Dalfox", depends_on=['Gitleaks'], binary_name="dalfox", needs_binary=True, confidence=90)
def run_dalfox_scan(url):
    """
    Full XSS scan: reflected, DOM, and blind XSS with WAF evasion and parameter mining.
    Returns list of finding dicts, [] if clean, None if binary missing.
    """
    settings = load_settings()
    bin_path = settings.get("dalfox_path", "dalfox")

    logger.info(f"Dalfox Started: {url}")
    add_log_entry("INFO", f"Dalfox Started: XSS scan {url}")

    cmd = [
        bin_path, "url", url,
        "--silence",
        "--no-spinner",
        "--format",      "json",
        "--timeout",     "30",       # per-request timeout (was 10)
        "--delay",       "200",      # 200ms between requests (was 500)
        "--worker",      "20",       # 20 concurrent workers (was default 100, reasonable throttle)
        "--user-agent",  "SMP/9.3.1 (Security Audit)",
        # XSS capabilities
        "--mining-dom",              # mine DOM-based XSS
        "--mining-dict",             # mine using dictionary
        "--deep-domxss",             # deep DOM XSS analysis
        "--remote-payloads", "portswigger,payloadbox",  # external payload sets
        "--waf-evasion",             # WAF evasion techniques
        "--output-all",              # output all finding types
        "--only-poc", "g,m",         # only show confirmed (G) and medium (M) by default
        # Parameter discovery
        "--find-params",             # find additional parameters
        # Follow redirects
        "--follow-redirects",
    ]

    # Blind XSS callback (if configured)
    blind_callback = settings.get("blind_xss_callback", "")
    if blind_callback:
        cmd.extend(["-b", blind_callback])
        logger.info(f"Dalfox: Blind XSS callback configured: {blind_callback}")

    # Auth injection
    cookie = settings.get("scan_cookie", "")
    if cookie:
        cmd.extend(["--cookie", cookie])
    for hname, hval in settings.get("auth_headers", {}).items():
        cmd.extend(["--header", f"{hname}: {hval}"])

    findings = []
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False,
        )
        try:
            stdout, stderr = process.communicate(timeout=DALFOX_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.warning(f"Dalfox Timed Out after {DALFOX_TIMEOUT}s for {url}")
            add_log_entry("WARNING", f"Dalfox Timed Out for {url}")
            return []

        if stderr.strip():
            logger.debug(f"Dalfox stderr: {stderr.strip()[:200]}")

        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data     = json.loads(line)
                ctype    = data.get("type", "I")
                severity = _SEVERITY_MAP.get(ctype, "Medium")
                param    = data.get("param", data.get("parameter", "unknown"))
                payload  = data.get("poc",   data.get("payload", ""))
                evidence = data.get("evidence", "")
                cwe      = data.get("cwe", "CWE-79")
                title    = f"XSS [{ctype}] — Parameter: {param}"
                desc = (
                    f"Type: {ctype} | Severity: {severity}\n"
                    f"Parameter: {param}\n"
                    f"CWE: {cwe}\n"
                    f"Payload: {payload}\n"
                    f"Evidence: {evidence}\n"
                    f"URL: {url}"
                )
                findings.append({
                    "severity":    severity,
                    "title":       title,
                    "description": desc,
                    "template_id": f"DALFOX-XSS-{ctype}-{param.upper()[:20]}",
                    "cve_id":      "",
                })
            except Exception as e:
                logger.debug(f"Dalfox parse error: {e}")

        logger.info(f"Dalfox Completed: {len(findings)} XSS findings")
        add_log_entry("INFO", f"Dalfox: {len(findings)} XSS issues found")
        return findings

    except FileNotFoundError:
        logger.warning(f"Dalfox not found at '{bin_path}'")
        add_log_entry("WARNING", "Dalfox not installed. Skipping XSS scan.")
        return None
    except Exception as e:
        logger.error(f"Dalfox Failed: {e}")
        add_log_entry("ERROR", f"Dalfox Failed: {e}")
        return None
