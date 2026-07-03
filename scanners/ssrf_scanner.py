"""SSRF Scanner — Server-Side Request Forgery parameter testing."""
import logging
import urllib.request
import urllib.parse
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

SSRF_PARAMS = ["url", "redirect", "next", "target", "dest", "destination", "redir", "uri", "path", "continue", "return", "returnTo", "goto", "link", "page", "ref", "view", "load", "fetch", "image", "img", "src"]
SSRF_PAYLOADS = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80", "http://localhost"]

@register_scanner(name="SSRF Scanner", step_name="Running SSRF Scanner", depends_on=['Tech Fingerprint'], binary_name="", needs_binary=False, confidence=85)
def run_ssrf_scan(url):
    logger.info(f"SSRF Scanner: Testing {url}")
    base = url.rstrip("/")
    findings = []
    for param in SSRF_PARAMS:
        for payload in SSRF_PAYLOADS[:1]:  # Conservative — 1 payload per param
            test_url = f"{base}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "SMP/5.4"})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    body = resp.read(512).decode(errors="replace")
                    if any(sig in body for sig in ["ami-id", "instance-id", "169.254", "root:", "localhost"]):
                        findings.append({
                            "severity": "Critical",
                            "title": "SSRF: Server-Side Request Forgery",
                            "description": f"SSRF detected via parameter '{param}'. Server fetched internal resource.",
                            "url": test_url,
                            "owasp_category": "A10:2021 - Server-Side Request Forgery",
                            "affected_component": f"Parameter: {param}",
                            "cvss_score": 9.1,
                            "business_impact": "SSRF allows attackers to pivot to internal services, read cloud metadata (AWS/GCP/Azure credentials), scan internal networks, and in severe cases achieve Remote Code Execution.",
                            "evidence": body[:300],
                            "reproduction_steps": f"curl '{test_url}'",
                            "remediation_code": "# Validate/whitelist URLs before fetching\nimport urllib.parse\nallowed = ['example.com']\nu = urllib.parse.urlparse(user_url)\nassert u.hostname in allowed",
                            "references_json": ["https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_(SSRF)", "https://portswigger.net/web-security/ssrf"]
                        })
            except Exception:
                continue
    return findings
