from scanners.core.registry import register_scanner
import os
import json
import subprocess
import tempfile
import logging
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

FFUF_TIMEOUT = 7200  # 2h — large wordlists on slow targets

# Built-in wordlist — used only when no system wordlist is found
_BUILTIN_WORDLIST = [
    "admin", "login", "dashboard", "panel", "wp-admin", "api", "config",
    "backup", "uploads", "static", "assets", "images", "files", "docs",
    "test", "dev", "staging", "phpmyadmin", "db", "database", ".git",
    ".env", "robots.txt", "sitemap.xml", "wp-config.php", "config.php",
    "web.config", "server-status", "server-info", "console", "manager",
    "administrator", "user", "users", "account", "accounts", "register",
    "signup", "signin", "logout", "profile", "settings", "setup",
    "install", "update", "upgrade", "download", "export", "import",
    "cgi-bin", "scripts", "js", "css", "src", "include", "includes",
    "lib", "libs", "vendor", "node_modules", "tmp", "temp", "log", "logs",
    "api/v1", "api/v2", "api/v3", "swagger", "swagger-ui", "openapi",
    ".DS_Store", "Thumbs.db", "/.well-known/", "actuator", "health",
    "metrics", "debug", "trace", "env", "shell", "cmd", "exec",
]

_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 503}

# File extensions to fuzz (appended to each word)
_EXTENSIONS = "php,asp,aspx,jsp,html,htm,json,xml,bak,old,txt,log,sql,zip,tar.gz"


def _get_wordlist(settings):
    custom = settings.get("ffuf_wordlist", "")
    if custom and os.path.isfile(custom):
        return custom, False

    for path in (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ):
        if os.path.isfile(path):
            return path, False

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(_BUILTIN_WORDLIST))
    tmp.close()
    return tmp.name, True


@register_scanner(name="ffuf", step_name="Running ffuf", depends_on=['Nuclei'], binary_name="ffuf", needs_binary=True, confidence=90)
def run_ffuf_scan(url, settings: dict = None):
    """
    Directory/file brute-force + extension fuzzing using ffuf.
    Returns list of finding dicts, [] if clean, None if binary missing.
    """
    settings = settings or {}
    settings  = load_settings()
    bin_path  = settings.get("ffuf_path", "ffuf")
    base_url  = url.rstrip("/") + "/FUZZ"
    wordlist_path, is_temp = _get_wordlist(settings)

    output_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="ffuf_out_", delete=False
    )
    output_path = output_file.name
    output_file.close()

    logger.info(f"ffuf Started: {base_url} | wordlist: {wordlist_path}")
    add_log_entry("INFO", f"ffuf Started: {url}")

    cmd = [
        bin_path,
        "-u",    base_url,
        "-w",    wordlist_path,
        "-o",    output_path,
        "-of",   "json",
        "-s",                       # silent — suppress progress bar
        "-t",    "40",              # 40 concurrent threads (restored from 2)
        "-rate", "50",              # 50 req/s (restored from 2)
        "-mc",   "all",             # match all status codes
        "-fc",   "404",             # filter 404s
        "-fw",   "0",               # filter responses with 0 words (blank pages)
        "-timeout", "10",           # per-request timeout
        "-recursion",               # recursive directory scanning
        "-recursion-depth", "2",    # 2 levels deep
        "-e",    _EXTENSIONS,       # extension fuzzing
        "-se",                      # stop on first error per host
        "-H",    "User-Agent: SMP/9.3.1 (Security Audit)",
        "-H",    "X-Forwarded-For: 127.0.0.1",  # WAF bypass attempt
    ]

    # Auth injection
    cookie = settings.get("scan_cookie", "")
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])
    auth_token = settings.get("auth_headers", {}).get("Authorization", "")
    if auth_token:
        cmd.extend(["-H", f"Authorization: {auth_token}"])

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False
        )
        try:
            stdout, stderr = process.communicate(timeout=FFUF_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.error(f"ffuf Timed Out for {url}")
            add_log_entry("ERROR", f"ffuf Timed Out for {url}")
            if os.path.exists(output_path):
                os.unlink(output_path)
            return []
        finally:
            if is_temp and os.path.exists(wordlist_path):
                os.unlink(wordlist_path)

        raw = ""
        if os.path.exists(output_path):
            try:
                with open(output_path, "r", encoding="utf-8") as fh:
                    raw = fh.read()
            finally:
                os.unlink(output_path)
        else:
            logger.info("ffuf: No output file (0 paths).")
            add_log_entry("INFO", "ffuf: 0 paths found.")
            return []

        return _parse_ffuf_output(raw)

    except FileNotFoundError:
        if is_temp and os.path.exists(wordlist_path):
            os.unlink(wordlist_path)
        if os.path.exists(output_path):
            os.unlink(output_path)
        logger.warning(f"ffuf not found at '{bin_path}'")
        add_log_entry("WARNING", "ffuf not installed. Skipping.")
        return None
    except Exception as e:
        logger.error(f"ffuf Failed: {e}")
        add_log_entry("ERROR", f"ffuf Failed: {e}")
        if os.path.exists(output_path):
            os.unlink(output_path)
        return None


def _severity_for_status(status, path):
    path_l = path.lower()
    if status in (200, 201):
        if any(k in path_l for k in (".env", "config", "backup", ".git", "wp-config", "web.config", "database.yml", ".sql")):
            return "Critical"
        if any(k in path_l for k in ("admin", "panel", "manager", "phpmyadmin", "console", "setup", "install", "actuator", "debug", "trace")):
            return "High"
        if any(k in path_l for k in ("api/v", "swagger", "openapi", ".bak", ".old", ".log")):
            return "Medium"
        return "Low"
    if status in (401, 403):
        return "Low"
    if status == 500:
        return "Medium"
    return "Info"


def _parse_ffuf_output(raw):
    findings = []
    if not raw or not raw.strip():
        logger.info("ffuf: 0 paths discovered.")
        add_log_entry("INFO", "ffuf: 0 paths found.")
        return findings

    try:
        data    = json.loads(raw)
        results = data.get("results", [])

        # SPA false-positive filter: if ≥80% share the same content length, suppress
        lengths = [r.get("length", 0) for r in results if r.get("status", 0) in _INTERESTING_CODES]
        if len(lengths) >= 10:
            from collections import Counter
            most_common_len, most_common_count = Counter(lengths).most_common(1)[0]
            if most_common_count / len(lengths) >= 0.80:
                logger.warning(f"ffuf: SPA false-positive filter triggered (len={most_common_len}, {most_common_count}/{len(lengths)} results). Suppressing common-length results.")
                results = [r for r in results if r.get("length", 0) != most_common_len]

        for r in results:
            status = r.get("status", 0)
            if status not in _INTERESTING_CODES:
                continue
            path      = r.get("input", {}).get("FUZZ", "")
            result_url= r.get("url", "")
            length    = r.get("length", 0)
            words     = r.get("words", 0)
            lines     = r.get("lines", 0)

            severity  = _severity_for_status(status, path)
            title     = f"Path Discovered: /{path} [{status}]"
            desc      = (
                f"URL: {result_url}\n"
                f"Status: {status} | Length: {length} | Words: {words} | Lines: {lines}\n"
                f"Path '/{path}' is accessible and may expose sensitive functionality or data."
            )
            findings.append({
                "severity":    severity,
                "title":       title,
                "description": desc,
                "template_id": f"FFUF-{status}",
            })
    except Exception as e:
        logger.error(f"ffuf parse error: {e}")

    logger.info(f"ffuf Completed: {len(findings)} interesting paths.")
    add_log_entry("INFO", f"ffuf: {len(findings)} paths found.")
    return findings
