# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# Owner: Authorised Personnel Only
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ⚠  CRITICAL NOTICE — Read way.md before ANY changes.                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# =============================================================================
"""
Open Redirect Scanner.
Tests common URL parameters for open redirect vulnerabilities.
"""
import logging
import urllib.parse
try:
    import requests
except ImportError:
    requests = None

from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

REDIRECT_TIMEOUT = 15

# Common redirect parameter names
_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "returnUrl", "return_url", "goto", "destination", "dest", "target",
    "link", "to", "location", "forward", "continue", "callback",
    "redir", "out", "view", "logoutUrl", "login_url",
]

_PAYLOAD = "https://evil.com"


def run_open_redirect_scan(url):
    """
    Test URL parameters for open redirect vulnerabilities.
    Returns list of findings or None on hard failure.
    """
    if not requests:
        logger.error("Open Redirect Scanner: 'requests' library not available.")
        return None

    logger.info(f"Open Redirect Scan Started: {url}")
    add_log_entry("INFO", f"Open Redirect Scan Started: {url}")

    findings = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = requests.Session()
    session.headers["User-Agent"] = "SecurityManagementPlatform/2.0 (Security Audit)"
    session.max_redirects = 3

    vulnerable_params = []

    for param in _REDIRECT_PARAMS:
        test_url = f"{url}?{param}={urllib.parse.quote(_PAYLOAD, safe='')}"
        try:
            resp = session.get(
                test_url,
                timeout=REDIRECT_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            # Check if we ended up at evil.com
            final_url = resp.url
            if "evil.com" in final_url:
                vulnerable_params.append(param)

            # Also check Location header in non-followed redirect
            resp2 = session.get(
                test_url,
                timeout=REDIRECT_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            location = resp2.headers.get("Location", "")
            if "evil.com" in location and param not in vulnerable_params:
                vulnerable_params.append(param)

        except requests.exceptions.TooManyRedirects:
            # If redirect loop, check if evil.com was in the chain
            pass
        except Exception as e:
            logger.debug(f"Open redirect test for param '{param}' failed: {e}")
            continue

    if vulnerable_params:
        findings.append({
            "severity": "High",
            "title": f"Open Redirect Vulnerability — {len(vulnerable_params)} Parameter(s) Affected",
            "description": (
                f"URL: {url}\n"
                f"Vulnerable Parameters: {', '.join(vulnerable_params)}\n"
                f"Payload Used: {_PAYLOAD}\n\n"
                f"Issue: The application redirects users to arbitrary external URLs without validation. "
                f"This can be used for phishing, credential harvesting, and bypassing security controls.\n\n"
                f"Example: {url}?{vulnerable_params[0]}={_PAYLOAD}\n\n"
                f"Recommendation: Validate redirect destinations against a strict whitelist. "
                f"Never use raw user input as a redirect target."
            ),
            "confidence": 88,
        })

    logger.info(f"Open Redirect Scan Completed: {len(findings)} issues for {url}")
    add_log_entry("INFO", f"Open Redirect Scan Completed: {len(findings)} issues.")
    return findings
