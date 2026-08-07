from scanners.core.registry import register_scanner
import os
import json
import subprocess
import logging
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

NUCLEI_TIMEOUT = 7200  # 2h — nuclei on complex targets needs full time

@register_scanner(name="Nuclei", step_name="Running Nuclei", depends_on=['Nikto'], binary_name="nuclei", needs_binary=True, confidence=95)
def run_nuclei_scan(url, settings: dict = None):
    """
    Runs a full Nuclei scan against the target URL using all major template categories.
    Returns list of finding dicts, [] if clean, None if binary missing.
    """
    settings = settings or {}
    settings = load_settings()
    nuclei_bin = settings.get("nuclei_path", "nuclei")

    logger.info(f"Nuclei Started: {url}")
    add_log_entry("INFO", f"Nuclei Started: {url}")

    cmd = [
        nuclei_bin, "-u", url,
        "-jsonl",                    # JSON Lines output (one finding per line)
        "-silent",                   # suppress banner/progress to stderr
        "-no-color",                 # no ANSI in output
        "-retries", "2",             # retry failed requests
        "-timeout", "15",            # per-request timeout
        "-rl", "10",                 # rate limit — 10 req/s (safe but fast)
        "-c",  "25",                 # concurrency — 25 parallel templates
        "-bs", "20",                 # bulk size
        "-mhe", "30",                # max host errors before skipping
        "-ss", "template-spray",     # spray mode — better coverage per host
        "-pt", "http,ssl,tcp",       # scan all protocol types
        # Template categories — full coverage
        "-t", "cves/",
        "-t", "vulnerabilities/",
        "-t", "misconfiguration/",
        "-t", "exposures/",
        "-t", "takeovers/",
        "-t", "default-logins/",
        "-t", "technologies/",
        "-t", "network/",
        "-t", "token-spray/",
        "-t", "file/",
        "-t", "fuzzing/",
        "-t", "helpers/",
        "-t", "iot/",
        "-t", "ssl/",
        # Severity — capture everything including info
        "-severity", "critical,high,medium,low,info,unknown",
        # Additional flags
        "-follow-redirects",
        "-system-resolvers",
    ]

    # Inject custom auth headers (authenticated scanning)
    auth_headers = settings.get("auth_headers", {})
    for hname, hval in auth_headers.items():
        cmd.extend(["-H", f"{hname}: {hval}"])

    # Custom cookie
    cookie = settings.get("scan_cookie", "")
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    findings = []
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False
        )
        try:
            stdout, stderr = process.communicate(timeout=NUCLEI_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.error(f"Nuclei Timed Out after {NUCLEI_TIMEOUT}s for {url}")
            add_log_entry("ERROR", f"Nuclei Timed Out for {url}")
            return []

        if process.returncode != 0:
            if stderr and any(k in stderr.lower() for k in ("error", "failed", "invalid", "panic")):
                logger.error(f"Nuclei Failed (exit {process.returncode}): {stderr.strip()[:300]}")
                add_log_entry("ERROR", f"Nuclei Failed: {stderr.strip()[:200]}")
                return None
            else:
                logger.warning(f"Nuclei exited {process.returncode} — parsing output anyway")

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info     = data.get("info", {})
                severity = info.get("severity", "info").capitalize()
                title    = info.get("name", data.get("template-id", "Unknown"))
                desc     = info.get("description", "")

                # Enrich with matcher output, extracted data, CVE info
                matched_at = data.get("matched-at", "")
                extracted  = data.get("extracted-results", [])
                cve_id     = info.get("classification", {}).get("cve-id", [])
                cvss       = info.get("classification", {}).get("cvss-score", "")
                cwe        = info.get("classification", {}).get("cwe-id", [])
                tags       = info.get("tags", [])
                reference  = info.get("reference", [])

                full_desc = desc
                if matched_at:
                    full_desc += f"\n\nMatched At: {matched_at}"
                if extracted:
                    full_desc += f"\nExtracted: {', '.join(str(e) for e in extracted[:5])}"
                if cve_id:
                    full_desc += f"\nCVE: {', '.join(cve_id)}"
                if cvss:
                    full_desc += f"\nCVSS: {cvss}"
                if cwe:
                    full_desc += f"\nCWE: {', '.join(cwe)}"
                if reference:
                    full_desc += f"\nRefs: {', '.join(reference[:3])}"

                findings.append({
                    "severity":    severity,
                    "title":       title,
                    "description": full_desc.strip(),
                    "template_id": data.get("template-id", ""),
                    "cve_id":      cve_id[0] if cve_id else "",
                    "tags":        tags,
                })
            except Exception as e:
                logger.debug(f"Nuclei parse error: {e} — line: {line[:80]}")

        logger.info(f"Nuclei Completed: {len(findings)} findings for {url}")
        add_log_entry("INFO", f"Nuclei Completed: {len(findings)} findings")
        return findings

    except FileNotFoundError:
        logger.error(f"Nuclei not found at '{nuclei_bin}'")
        add_log_entry("ERROR", f"Nuclei not found: '{nuclei_bin}'")
        return None
    except Exception as e:
        logger.error(f"Nuclei Failed: {e}")
        add_log_entry("ERROR", f"Nuclei Failed: {e}")
        return None
