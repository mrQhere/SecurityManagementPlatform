"""Trivy — Container / Docker image / IaC vulnerability scanner."""
import subprocess
import logging
import json
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

TRIVY_TIMEOUT = 180

@register_scanner(name="Trivy", step_name="Running Trivy", depends_on=['Cloud Enum'], binary_name="trivy", needs_binary=True, confidence=90)
def run_trivy_scan(url):
    logger.info("Trivy: Container/IaC scan")
    findings = []
    try:
        r = subprocess.run(["trivy", "fs", "--format", "json", "--quiet", "."],
                           capture_output=True, text=True, timeout=TRIVY_TIMEOUT)
        data = json.loads(r.stdout or "{}")
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev = v.get("Severity", "Low").capitalize()
                if sev not in ("Critical", "High", "Medium", "Low", "Info"):
                    sev = "Medium"
                
                findings.append({
                    "severity": sev,
                    "title": f"Trivy: {v.get('VulnerabilityID','Unknown')} in {v.get('PkgName','')}",
                    "description": v.get("Description", "Trivy detected a vulnerability in a dependency."),
                    "cve_id": v.get("VulnerabilityID"),
                    "cvss_score": v.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    "affected_component": f"{v.get('PkgName','')} {v.get('InstalledVersion','')}",
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                    "business_impact": "Vulnerable dependencies can be exploited remotely if the service is exposed. Severity determines urgency.",
                    "reproduction_steps": f"trivy image {v.get('PkgName','')} --severity {sev.upper()}",
                    "remediation_code": f"# Update package:\npip install {v.get('PkgName','')}=={v.get('FixedVersion','latest')}",
                    "references_json": v.get("References", [])
                })
        return findings
    except FileNotFoundError:
        logger.warning("trivy not found")
        return None
    except Exception as e:
        logger.error(f"Trivy: {e}")
        return []
