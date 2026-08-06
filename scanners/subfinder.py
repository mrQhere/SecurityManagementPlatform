from scanners.core.registry import register_scanner
import json
import subprocess
import logging
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

SUBFINDER_TIMEOUT = 600  # 10 min


def _extract_domain(url):
    import urllib.parse
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urllib.parse.urlparse(url).hostname or url


@register_scanner(name="Subfinder", step_name="Running Subfinder", depends_on=[], binary_name="subfinder", needs_binary=True, confidence=90)
def run_subfinder_scan(url):
    """
    Passive subdomain enumeration using all available sources.
    Returns list of subdomain dicts: [{'host': ..., 'ip': ..., 'source': ...}]
    """
    settings = load_settings()
    bin_path  = settings.get("subfinder_path", "subfinder")
    domain    = _extract_domain(url)

    logger.info(f"Subfinder Started: {domain}")
    add_log_entry("INFO", f"Subfinder Started: {domain}")

    cmd = [
        bin_path,
        "-d", domain,
        "-json",               # JSONL output
        "-silent",             # suppress banner
        "-all",                # use ALL sources (default uses only public ones)
        "-recursive",          # enumerate subdomains of found subdomains
        "-t", "10",            # 10 concurrent goroutines (restored default)
        "-timeout", "30",      # per-source timeout
        "-max-time", "9",      # global time limit (minutes)
        "-oI",                 # include IPs in output
    ]

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False
        )
        try:
            stdout, stderr = process.communicate(timeout=SUBFINDER_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.error(f"Subfinder Timed Out for {domain}")
            add_log_entry("ERROR", f"Subfinder Timed Out for {domain}")
            return []

        if stderr.strip():
            logger.debug(f"Subfinder stderr: {stderr.strip()[:200]}")

        return _parse_subfinder_output(stdout)

    except FileNotFoundError:
        logger.warning(f"Subfinder not found at '{bin_path}'")
        add_log_entry("WARNING", f"Subfinder not installed. Skipping.")
        return None
    except Exception as e:
        logger.error(f"Subfinder Failed: {e}")
        add_log_entry("ERROR", f"Subfinder Failed: {e}")
        return None


def _parse_subfinder_output(raw):
    results = []
    if not raw or not raw.strip():
        logger.info("Subfinder Completed: 0 subdomains found.")
        add_log_entry("INFO", "Subfinder: 0 subdomains found.")
        return results

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append({
                "host":   data.get("host", ""),
                "ip":     data.get("ip", ""),
                "source": data.get("source", "subfinder"),
            })
        except json.JSONDecodeError:
            # Plain text fallback (older subfinder versions)
            if "." in line:
                results.append({"host": line, "ip": "", "source": "subfinder"})

    logger.info(f"Subfinder Completed: {len(results)} subdomains found.")
    add_log_entry("INFO", f"Subfinder: {len(results)} subdomains.")
    return results
