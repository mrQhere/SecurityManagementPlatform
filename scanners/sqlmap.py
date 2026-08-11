from scanners.core.registry import register_scanner
import os
import json
import subprocess
import logging
import tempfile
import urllib.parse
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

SQLMAP_TIMEOUT = 7200  # 2h


@register_scanner(name="SQLMap", step_name="Running SQLMap", depends_on=['Wapiti'], binary_name="sqlmap", needs_binary=True, confidence=95)
def run_sqlmap_scan(url, settings: dict = None):
    """
    Full SQLMap scan: form crawling, high level/risk, technique coverage,
    DB/table enumeration, tamper scripts for WAF bypass.
    Returns list of finding dicts, [] if clean, None if binary missing.
    """
    settings = settings or {}
    settings   = load_settings()
    sqlmap_bin = settings.get("sqlmap_path", "sqlmap")

    logger.info(f"SQLMap Started: {url}")
    add_log_entry("INFO", f"SQLMap Started: {url}")

    findings = []

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            sqlmap_bin,
            "-u", url,
            "--batch",                   # non-interactive
            "--smart",                   # heuristic pre-check (skip non-injectable params)
            "--forms",                   # crawl and test HTML forms
            "--crawl=5",                 # crawl 5 levels deep (was 3)
            "--level=5",                 # max level (test all injection points)
            "--risk=3",                  # max risk (aggressive payloads)
            "--technique=BEUSTQ",        # all techniques: Boolean, Error, Union, Stacked, Time, Query
            "--delay=1",                 # 1s between requests (was 2s)
            "--threads=3",               # 3 concurrent threads
            "--retries=3",               # retry failed requests
            "--timeout=30",              # per-request timeout
            "--output-dir", tmpdir,
            # Enumeration (only if injectable)
            "--dbs",                     # enumerate databases
            "--tables",                  # enumerate tables
            "--banner",                  # grab DB server banner
            "--current-user",            # get current DB user
            "--current-db",              # get current database
            "--is-dba",                  # check if DBA
            "--hostname",                # get server hostname
            # WAF evasion tamper scripts
            "--tamper=space2comment,between,randomcase,charencode,base64encode",
            # Output format
            "--flush-session",           # fresh session per scan
        ]

        # Auth injection
        cookie = settings.get("scan_cookie", "")
        if cookie:
            cmd.extend(["--cookie", cookie])
        for hname, hval in settings.get("auth_headers", {}).items():
            cmd.extend(["-H", f"{hname}: {hval}"])

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, shell=False
            )
            try:
                stdout, stderr = process.communicate(timeout=SQLMAP_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                logger.error(f"SQLMap Timed Out for {url}")
                add_log_entry("ERROR", f"SQLMap Timed Out for {url}")

            # Parse output directory for results
            findings.extend(_parse_sqlmap_output(tmpdir, stdout, url))

        except FileNotFoundError:
            logger.error(f"SQLMap not found at '{sqlmap_bin}'")
            add_log_entry("ERROR", f"SQLMap not found: '{sqlmap_bin}'")
            return None
        except Exception as e:
            logger.error(f"SQLMap Failed: {e}")
            add_log_entry("ERROR", f"SQLMap Failed: {e}")
            return None

    logger.info(f"SQLMap Completed: {len(findings)} findings")
    add_log_entry("INFO", f"SQLMap: {len(findings)} findings")
    return findings


def _parse_sqlmap_output(output_dir, stdout, url):
    """Parse sqlmap output directory and stdout for injection findings."""
    findings = []
    urllib.parse.urlparse(url).hostname or ""

    # Walk output_dir for per-domain log and JSON files
    for root, dirs, files in os.walk(output_dir):
        for fname in files:
            fpath = os.path.join(root, fname)

            if fname == "log":
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().strip()
                    if not content:
                        continue
                    # Extract injection details
                    injected_params = []
                    db_info = []
                    for line in content.splitlines():
                        ll = line.lower()
                        if "parameter:" in ll or "is vulnerable" in ll:
                            injected_params.append(line.strip())
                        if any(k in ll for k in ("current database:", "current user:", "banner:", "is dba:")):
                            db_info.append(line.strip())

                    if injected_params or "sql injection" in content.lower():
                        desc = (
                            f"URL: {url}\n\n"
                            f"SQLMap confirmed SQL injection vulnerabilities.\n\n"
                        )
                        if injected_params:
                            desc += "Vulnerable Parameters:\n" + "\n".join(f"  • {p}" for p in injected_params[:10]) + "\n\n"
                        if db_info:
                            desc += "Database Intelligence:\n" + "\n".join(f"  • {d}" for d in db_info) + "\n\n"
                        desc += f"Full log excerpt:\n{content[:800]}"
                        findings.append({
                            "severity":    "Critical",
                            "title":       "SQL Injection Confirmed (SQLMap)",
                            "description": desc,
                            "template_id": "SQLI-CONFIRMED",
                            "cve_id":      "CWE-89",
                        })
                except Exception as e:
                    logger.debug(f"SQLMap log parse error: {e}")

            elif fname.endswith(".json"):
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict) and data.get("data"):
                        for entry in data["data"][:5]:
                            findings.append({
                                "severity":    "Critical",
                                "title":       f"SQLMap Data Extracted: {fname}",
                                "description": f"SQLMap extracted data from {url}:\n{json.dumps(entry, indent=2)[:500]}",
                                "template_id": "SQLI-DATA-EXTRACT",
                            })
                except Exception as e:
                    from tools.errors import SMPUnclassifiedError
                    import traceback
                    import logging
                    logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                    raise SMPUnclassifiedError(str(e))
                    pass

    # Fallback: check stdout for confirmation
    if not findings and stdout:
        sl = stdout.lower()
        if "is vulnerable" in sl or ("sql injection" in sl and "detected" in sl):
            findings.append({
                "severity":    "Critical",
                "title":       "Possible SQL Injection (SQLMap stdout)",
                "description": f"URL: {url}\n\nSQLMap output indicates injection:\n{stdout[:600]}",
                "template_id": "SQLI-POSSIBLE",
            })

    return findings
