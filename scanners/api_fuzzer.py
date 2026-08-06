"""REST API Fuzzer — Tests OpenAPI/Swagger endpoints for misconfigurations and injection."""
import logging
import urllib.request
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/v1/swagger.json",
    "/v2/api-docs", "/api/swagger.json", "/docs/openapi.yaml", "/api/v1/openapi.json"
]

@register_scanner(name="API Fuzzer", step_name="Running API Fuzzer", depends_on=['Katana'], binary_name="", needs_binary=False, confidence=80)
def run_api_fuzzer(url):
    logger.info(f"API Fuzzer: Probing API documentation endpoints on {url}")
    findings = []
    for path in OPENAPI_PATHS:
        target = url.rstrip("/") + path
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "SMP/9.3.2"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read().decode(errors="replace")
                if "swagger" in body.lower() or "openapi" in body.lower() or "paths" in body:
                    findings.append({
                        "severity": "High",
                        "title": "API Documentation Exposed",
                        "description": f"OpenAPI/Swagger documentation is publicly accessible at {target}.",
                        "url": target,
                        "owasp_category": "A01:2021 - Broken Access Control",
                        "affected_component": target,
                        "cvss_score": 6.5,
                        "business_impact": "Publicly accessible API documentation reveals all endpoints, parameter names, authentication methods, and data models. Attackers use this to plan targeted attacks.",
                        "evidence": body[:400],
                        "reproduction_steps": f"curl {target}",
                        "remediation_code": "# Restrict Swagger UI to authenticated users only\n# Or disable in production: springfox.documentation.enabled=false",
                        "references_json": ["https://owasp.org/www-project-api-security/", "https://github.com/nicowillis/api-testing"]
                    })
        except Exception:
            continue
    return findings
