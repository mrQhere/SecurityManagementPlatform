"""GraphQL Scanner — Introspection, batch attacks, and information disclosure."""
import logging
import urllib.request
import urllib.error
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'
GRAPHQL_TIMEOUT = 8

@register_scanner(name="GraphQL Scanner", step_name="Running GraphQL Scanner", depends_on=['Katana'], binary_name="", needs_binary=False, confidence=80)
def run_graphql_scanner(url):
    logger.info(f"GraphQL Scanner: Testing {url}")
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]
    findings = []
    for ep in endpoints:
        target = url.rstrip("/") + ep
        try:
            req = urllib.request.Request(
                target, data=INTROSPECTION_QUERY.encode(),
                headers={"Content-Type": "application/json", "User-Agent": "SMP/9.4.2"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=GRAPHQL_TIMEOUT) as resp:
                body = resp.read().decode(errors="replace")
                if "__schema" in body or "types" in body:
                    findings.append({
                        "severity": "High",
                        "title": "GraphQL Introspection Enabled",
                        "description": f"GraphQL introspection is enabled at {target}. This exposes the full API schema to attackers.",
                        "url": target,
                        "owasp_category": "A01:2021 - Broken Access Control",
                        "affected_component": target,
                        "cvss_score": 7.5,
                        "business_impact": "Attackers can enumerate all available queries, mutations, types, and fields. This provides a complete roadmap for further attacks against the API.",
                        "reproduction_steps": f"curl -X POST {target} -H \"Content-Type: application/json\" -d '{INTROSPECTION_QUERY}'",
                        "remediation_code": "# Disable introspection in production:\n# Apollo Server: introspection: process.env.NODE_ENV !== \"production\"\n# graphql-php: Validation::DISABLE_INTROSPECTION",
                        "references_json": ["https://owasp.org/www-project-web-security-testing-guide/", "https://graphql.org/learn/introspection/"]
                    })
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback
            import logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            continue
    return findings
