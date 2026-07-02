"""SpiderFoot — Automated OSINT aggregation across 200+ data sources."""
import subprocess
import logging
import json
import urllib.parse
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

SPIDERFOOT_TIMEOUT = 180

@register_scanner(name="SpiderFoot OSINT", step_name="Running SpiderFoot OSINT", depends_on=['Subfinder'], binary_name="sf", needs_binary=True, confidence=60)
def run_spiderfoot_scan(url):
    domain = urllib.parse.urlparse(url).hostname or url
    logger.info(f"SpiderFoot: OSINT collection for {domain}")
    findings = []
    try:
        r = subprocess.run(
            ["sf", "-s", domain, "-m", "sfp_dnsresolve,sfp_ssl,sfp_whois,sfp_shodan", "-q", "-o", "JSON"],
            capture_output=True, text=True, timeout=SPIDERFOOT_TIMEOUT
        )
        data = json.loads(r.stdout or "[]")
        for item in data[:20]:
            t = item.get("type", "")
            if "EMAILADDR" in t:
                findings.append({
                    "severity": "Info",
                    "title": "SpiderFoot: Email Address Harvested",
                    "description": f"SpiderFoot OSINT found email: {item.get('data','')}",
                    "affected_component": domain,
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "business_impact": "Exposed email addresses enable spear phishing and credential stuffing attacks targeting staff.",
                    "reproduction_steps": f"sf -s {domain} -m sfp_hunter,sfp_emailformat",
                    "references_json": ["https://www.spiderfoot.net/", "https://owasp.org/"]
                })
        return findings
    except FileNotFoundError:
        logger.warning("SpiderFoot (sf) binary not found")
        return None
    except Exception as e:
        logger.error(f"SpiderFoot: {e}")
        return []
