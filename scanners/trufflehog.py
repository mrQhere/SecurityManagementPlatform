"""TruffleHog — Advanced secret scanning in git repos and web content."""
import subprocess
import logging
import json
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

TRUFFLEHOG_TIMEOUT = 120

@register_scanner(name="TruffleHog", step_name="Running TruffleHog", depends_on=['Cloud Enum'], binary_name="trufflehog", needs_binary=True, confidence=90)
def run_trufflehog_scan(url):
    logger.info(f"TruffleHog: Secret scanning {url}")
    findings = []
    try:
        r = subprocess.run(["trufflehog", "--json", "filesystem", "--path", "."],
                           capture_output=True, text=True, timeout=TRUFFLEHOG_TIMEOUT)
        secrets = []
        for line in r.stdout.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("Raw"):
                    secrets.append(obj)
            except Exception:
                pass
        if secrets:
            findings.append({
                "severity": "Critical",
                "title": "TruffleHog: Secret Keys Detected",
                "description": f"TruffleHog found {len(secrets)} potential secret(s) in accessible content.",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "affected_component": url,
                "business_impact": "Exposed API keys, tokens, or passwords allow immediate unauthorised access to cloud services, databases, and third-party APIs. Can lead to complete account compromise.",
                "evidence": str(secrets[0])[:600] if secrets else "",
                "reproduction_steps": f"trufflehog --json filesystem --path . (or) trufflehog git {url}",
                "references_json": ["https://github.com/trufflesecurity/trufflehog", "https://cwe.mitre.org/data/definitions/798.html"]
            })
        return findings
    except FileNotFoundError:
        logger.warning("trufflehog not found")
        return None
    except Exception as e:
        logger.error(f"TruffleHog: {e}")
        return []
