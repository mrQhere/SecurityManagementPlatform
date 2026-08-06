from scanners.core.registry import register_scanner
import json
import subprocess
import logging
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

HTTPX_TIMEOUT = 120


@register_scanner(name="HTTPx", step_name="Running HTTPx", depends_on=[], binary_name="httpx", needs_binary=True, confidence=95)
def run_httpx_scan(url):
    """
    Full HTTP probe using httpx — extracts tech stack, TLS, headers, CDN, JARM,
    response hashing, redirect chains, and favicon hash.
    Returns enriched probe dict + derived findings list.
    """
    settings = load_settings()
    bin_path = settings.get("httpx_path", "httpx")

    logger.info(f"HTTPx Started: {url}")
    add_log_entry("INFO", f"HTTPx Started: {url}")

    cmd = [
        bin_path,
        "-u", url,
        "-json",
        "-silent",
        "-no-color",
        # Probe capabilities
        "-follow-redirects",
        "-max-redirects", "10",
        "-tech-detect",          # technology fingerprinting
        "-title",                # page title
        "-status-code",
        "-content-length",
        "-content-type",
        "-web-server",
        "-ip",                   # resolve IP address
        "-cdn",                  # detect CDN provider
        "-csp",                  # extract CSP header
        "-tls-grab",             # full TLS certificate details
        "-tls-probe",            # TLS probing
        "-jarm",                 # JARM fingerprint (identifies server TLS stack)
        "-hash", "md5,sha256",   # content hashes for change tracking
        "-favicon",              # favicon hash (tech fingerprinting)
        "-response-size-to-read", "102400",  # read up to 100KB of body
        "-probe",                # show probe results
        # Request tuning
        "-t", "5",               # 5 threads (restored from 2)
        "-rl", "5",              # 5 req/s rate limit
        "-timeout", "30",
        "-retries", "2",
        "-random-agent",         # rotate User-Agent
    ]

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False
        )
        try:
            stdout, stderr = process.communicate(timeout=HTTPX_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.error(f"HTTPx Timed Out for {url}")
            add_log_entry("ERROR", f"HTTPx Timed Out for {url}")
            return {}

        if stderr.strip():
            logger.debug(f"HTTPx stderr: {stderr.strip()[:200]}")

        return _parse_httpx_output(stdout, url)

    except FileNotFoundError:
        logger.warning(f"HTTPx not found at '{bin_path}'")
        add_log_entry("WARNING", "HTTPx not installed. Skipping.")
        return None
    except Exception as e:
        logger.error(f"HTTPx Failed: {e}")
        add_log_entry("ERROR", f"HTTPx Failed: {e}")
        return None


def _parse_httpx_output(raw, url):
    if not raw or not raw.strip():
        logger.info("HTTPx: No response.")
        add_log_entry("INFO", "HTTPx: No data returned.")
        return {}

    findings = []
    result   = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        result = {
            "url":            data.get("url", url),
            "status_code":    data.get("status-code") or data.get("status_code", 0),
            "title":          data.get("title", ""),
            "tech":           data.get("tech", []),
            "content_length": data.get("content-length") or data.get("content_length", 0),
            "content_type":   data.get("content-type", ""),
            "webserver":      data.get("webserver", ""),
            "ip":             data.get("host", ""),
            "cdn":            data.get("cdn", False),
            "cdn_name":       data.get("cdn-name", ""),
            "csp":            data.get("csp", ""),
            "tls":            data.get("tls-grab") or data.get("tls", {}),
            "jarm":           data.get("jarm", ""),
            "favicon_hash":   data.get("favicon", {}).get("hash", "") if isinstance(data.get("favicon"), dict) else "",
            "hash_md5":       data.get("hash", {}).get("body-md5", ""),
            "hash_sha256":    data.get("hash", {}).get("body-sha256", ""),
            "redirect_chain": data.get("chain-status-codes", []),
        }

        status = result["status_code"]
        target = result["url"]

        # Derive security findings
        if status == 0:
            findings.append({
                "severity": "High",
                "title": "Host Unreachable",
                "description": f"HTTPx received no response from {target}.",
            })
        elif status >= 500:
            findings.append({
                "severity": "Medium",
                "title": f"HTTP {status} — Server Error",
                "description": f"Server returned HTTP {status} at {target}. Possible misconfiguration or crash.",
            })

        if result.get("webserver"):
            findings.append({
                "severity": "Info",
                "title": f"Web Server Identified: {result['webserver']}",
                "description": (
                    f"Server header exposes: {result['webserver']}. "
                    "Suppress the Server header to reduce fingerprinting surface."
                ),
            })

        if result.get("jarm"):
            findings.append({
                "severity": "Info",
                "title": f"JARM Fingerprint: {result['jarm']}",
                "description": (
                    f"JARM hash identifies the TLS stack in use at {target}. "
                    "Correlate against known-malicious JARM databases."
                ),
            })

        if result.get("cdn"):
            findings.append({
                "severity": "Info",
                "title": f"CDN Detected: {result.get('cdn_name', 'Unknown')}",
                "description": f"Target is behind a CDN ({result.get('cdn_name', '')}). Real origin IP may be discoverable via DNS history.",
            })

        # Flag missing CSP
        if not result.get("csp"):
            findings.append({
                "severity": "Medium",
                "title": "Content-Security-Policy Header Missing",
                "description": f"No CSP header found at {target}. XSS risk is elevated.",
            })

        break  # httpx outputs one JSON per URL

    result["findings"] = findings
    logger.info(f"HTTPx Completed: HTTP {result.get('status_code')} — {len(result.get('tech', []))} tech, {len(findings)} findings")
    add_log_entry("INFO", f"HTTPx Completed: HTTP {result.get('status_code')}, {len(result.get('tech', []))} technologies")
    return result
