"""CRLF / Header Injection Scanner."""
import logging
import urllib.request
import urllib.parse
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

CRLF_PAYLOADS = ["%0d%0aX-Injected: crlf", "%0aX-Injected:crlf", "%0d%0aSet-Cookie:crlf=1"]

@register_scanner(name="CRLF Scanner", step_name="Running CRLF Scanner", depends_on=['Tech Fingerprint'], binary_name="", needs_binary=False, confidence=85)
def run_crlf_scan(url):
    logger.info(f"CRLF Scanner: Testing {url}")
    base = url.rstrip("/")
    findings = []
    for payload in CRLF_PAYLOADS:
        try:
            test = f"{base}/{payload}"
            req = urllib.request.Request(test, headers={"User-Agent": "SMP/9.3.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                headers = dict(resp.headers)
                if "X-Injected" in headers or "crlf" in str(headers).lower():
                    findings.append({
                        "severity": "High",
                        "title": "CRLF Injection / Header Injection",
                        "description": "CRLF characters in URL cause HTTP response header injection.",
                        "url": test,
                        "owasp_category": "A03:2021 - Injection",
                        "cvss_score": 6.1,
                        "affected_component": url,
                        "business_impact": "Header injection enables session fixation, XSS via headers, and HTTP response splitting attacks.",
                        "reproduction_steps": f"curl -v '{test}'",
                        "remediation_code": "# Strip \\r\\n from all user-controlled values before using in headers\nvalue = value.replace('\\r','').replace('\\n','')",
                        "references_json": ["https://owasp.org/www-community/attacks/CRLF_Injection", "https://cwe.mitre.org/data/definitions/93.html"]
                    })
        except Exception:
            continue
    return findings
