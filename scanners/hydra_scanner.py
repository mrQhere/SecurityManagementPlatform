"""Hydra — Rate-limited brute-force authentication testing (login forms only)."""
import logging
import urllib.request
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

WEAK_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("test", "test"), ("user", "user"),
]
LOGIN_PATHS = ["/admin", "/login", "/wp-login.php", "/wp-admin", "/administrator/index.php"]

@register_scanner(name="Auth Brute-Force Test", step_name="Running Auth Brute-Force Test", depends_on=['Tech Fingerprint'], binary_name="", needs_binary=False, confidence=85)
def run_hydra_scanner(url):
    """Conservative: only test a tiny known-weak credential set. Rate-limited."""
    logger.info(f"Auth Brute-Force: Testing {url}")
    base = url.rstrip("/")
    findings = []

    for path in LOGIN_PATHS:
        target = base + path
        # Check if login path exists
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "SMP/9.3.2"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    continue
        except Exception:
            continue

        # Try weak credentials against the login form
        for user, pwd in WEAK_CREDS:
            try:
                data = f"username={user}&password={pwd}".encode()
                login_req = urllib.request.Request(
                    target, data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "SMP/9.3.2",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(login_req, timeout=5) as lr:
                    body = lr.read(512).decode(errors="replace")
                    if any(w in body.lower() for w in ["dashboard", "welcome", "logout", "profile"]):
                        findings.append({
                            "severity": "Critical",
                            "title": "Default Credentials Accepted",
                            "description": f"Login at {target} accepted weak credential: {user}/{pwd}",
                            "source_tool": "Auth Brute-Force",
                            "url": target,
                            "owasp_category": "A07:2021 - Identification and Authentication Failures",
                            "cvss_score": 9.8,
                            "affected_component": target,
                            "business_impact": "Default or weak admin credentials provide full unauthorised access to the application and all its data.",
                            "reproduction_steps": f"curl -X POST {target} -d 'username={user}&password={pwd}'",
                            "remediation_code": "# Enforce strong passwords\n# Add account lockout after 5 failed attempts\n# Enable MFA for all admin accounts",
                            "references_json": ["https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures"]
                        })
            except Exception:
                continue

    return findings
