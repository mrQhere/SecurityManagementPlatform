# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# Owner: Authorised Personnel Only
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ⚠  CRITICAL NOTICE — Read way.md before ANY changes.                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# =============================================================================
"""
Deep Technology Fingerprinting Scanner.
Performs active banner grabbing and response analysis to accurately identify
technology stack including versions.
"""
import re
import logging
import urllib.parse
try:
    import requests
except ImportError:
    requests = None

from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

TECH_TIMEOUT = 20

# Technology patterns — (header_or_body_regex, tech_name, category)
_TECH_PATTERNS = [
    # Server/Backend from headers
    (r"nginx/([0-9.]+)", "nginx", "Web Server", "Server"),
    (r"Apache/([0-9.]+)", "Apache HTTP Server", "Web Server", "Server"),
    (r"Microsoft-IIS/([0-9.]+)", "Microsoft IIS", "Web Server", "Server"),
    (r"LiteSpeed", "LiteSpeed", "Web Server", "Server"),
    (r"Caddy", "Caddy", "Web Server", "Server"),
    (r"gunicorn/([0-9.]+)", "Gunicorn", "Application Server", "Server"),
    (r"Werkzeug/([0-9.]+)", "Werkzeug (Flask)", "Framework", "X-Powered-By"),
    (r"PHP/([0-9.]+)", "PHP", "Language", "X-Powered-By"),
    (r"ASP\.NET", "ASP.NET", "Framework", "X-Powered-By"),
    (r"Express", "Express.js", "Framework", "X-Powered-By"),
    # Body patterns
    (r"jQuery v?([0-9.]+)", "jQuery", "JavaScript Library", "body"),
    (r"React\.?(?:DOM)?\.version\s*=\s*['\"]([0-9.]+)", "React", "JavaScript Framework", "body"),
    (r"angular(?:\.min)?\.js\?v=([0-9.]+)", "AngularJS", "JavaScript Framework", "body"),
    (r"bootstrap(?:\.min)?\.css\?v=([0-9.]+)", "Bootstrap", "CSS Framework", "body"),
    (r"vue(?:\.min)?\.js.*?@([0-9.]+)", "Vue.js", "JavaScript Framework", "body"),
    (r"next/dist", "Next.js", "Framework", "body"),
    (r"__NUXT__", "Nuxt.js", "Framework", "body"),
    (r"laravel_session", "Laravel", "PHP Framework", "body"),
    (r"django\.contrib", "Django", "Python Framework", "body"),
    (r"csrfmiddlewaretoken", "Django", "Python Framework", "body"),
    (r"Powered by WordPress", "WordPress", "CMS", "body"),
    (r"Drupal\.settings", "Drupal", "CMS", "body"),
]


def run_tech_fingerprint(url):
    """
    Deep technology fingerprinting via response analysis.
    Returns list of technologies as findings, or None on hard failure.
    """
    if not requests:
        logger.error("Tech Fingerprint: 'requests' library not available.")
        return None

    logger.info(f"Tech Fingerprint Started: {url}")
    add_log_entry("INFO", f"Tech Fingerprint Started: {url}")

    findings = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = requests.Session()
    session.headers["User-Agent"] = "SecurityManagementPlatform/2.0 (Security Audit)"

    try:
        try:
            resp = session.get(url, timeout=TECH_TIMEOUT, verify=False, allow_redirects=True)
        except requests.exceptions.SSLError:
            resp = session.get(url.replace("https://", "http://"), timeout=TECH_TIMEOUT,
                               verify=False, allow_redirects=True)

        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:50000]  # Limit body analysis size

        detected = {}

        for pattern, tech_name, category, source in _TECH_PATTERNS:
            search_in = headers_str if source != "body" else body
            if source in ("Server", "X-Powered-By"):
                header_val = resp.headers.get(source, "")
                search_in = header_val

            m = re.search(pattern, search_in, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                key = tech_name
                if key not in detected:
                    detected[key] = {"version": version, "category": category}

        for tech_name, info in detected.items():
            version = info["version"]
            category = info["category"]
            findings.append({
                "severity": "Info",
                "title": f"Technology Detected: {tech_name}" + (f" {version}" if version else ""),
                "description": (
                    f"URL: {url}\n"
                    f"Technology: {tech_name}\n"
                    f"Version: {version if version else 'Unknown'}\n"
                    f"Category: {category}\n\n"
                    f"This technology was detected through deep response analysis. "
                    f"Ensure it is kept up-to-date to avoid known vulnerabilities."
                ),
                "confidence": 80,
            })

        logger.info(f"Tech Fingerprint Completed: {len(detected)} technologies for {url}")
        add_log_entry("INFO", f"Tech Fingerprint Completed: {len(detected)} technologies.")
        return findings

    except requests.exceptions.ConnectionError:
        logger.warning(f"Tech Fingerprint: Could not connect to {url}")
        return []
    except Exception as e:
        logger.error(f"Tech Fingerprint Failed: {e}")
        add_log_entry("ERROR", f"Tech Fingerprint Failed: {e}")
        return None
