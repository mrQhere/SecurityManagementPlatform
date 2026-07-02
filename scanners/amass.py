"""OWASP Amass — Best-in-class subdomain enumeration + network mapping."""
import subprocess
import logging
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

AMASS_TIMEOUT = 220

@register_scanner(name="Amass", step_name="Running Amass", depends_on=['Subfinder'], binary_name="amass", needs_binary=True, confidence=85)
def run_amass_scan(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    logger.info(f"Amass: Enumerating subdomains for {domain}")
    findings = []
    try:
        r = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "3"],
            capture_output=True, text=True, timeout=AMASS_TIMEOUT
        )
        subs = [l.strip() for l in r.stdout.splitlines() if domain in l]
        if subs:
            findings.append({
                "severity": "Info",
                "title": "Amass: Subdomains Discovered",
                "description": f"Amass passive enumeration found {len(subs)} subdomains.",
                "affected_component": domain,
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "evidence": "\n".join(subs[:30]),
                "business_impact": "Exposed subdomains can reveal internal services, staging environments, or forgotten assets that may have weaker security controls.",
                "reproduction_steps": f"amass enum -passive -d {domain}",
                "references_json": ["https://github.com/owasp-amass/amass", "https://owasp.org/www-project-amass/"]
            })
        return findings
    except FileNotFoundError:
        logger.warning("Amass binary not found")
        return None
    except Exception as e:
        logger.error(f"Amass failed: {e}")
        return []
