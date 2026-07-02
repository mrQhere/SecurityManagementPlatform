"""Feroxbuster — Recursive content discovery (fast, async, Rust-based)."""
import subprocess
import logging
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

FEROXBUSTER_TIMEOUT = 180

@register_scanner(name="Feroxbuster", step_name="Running Feroxbuster", depends_on=['Katana'], binary_name="feroxbuster", needs_binary=True, confidence=85)
def run_feroxbuster_scan(url):
    logger.info(f"Feroxbuster: Recursive directory scan on {url}")
    findings = []
    try:
        r = subprocess.run([
            "feroxbuster", "--url", url, "--silent", "--no-recursion",
            "-d", "2", "--timeout", "10", "--threads", "20"
        ], capture_output=True, text=True, timeout=FEROXBUSTER_TIMEOUT)
        
        hits = [l.strip() for l in (r.stdout + r.stderr).splitlines() if "200" in l or "301" in l or "302" in l]
        if hits:
            findings.append({
                "severity": "Medium",
                "title": "Feroxbuster: Hidden Paths Discovered",
                "description": f"Feroxbuster found {len(hits)} accessible paths via recursive brute-force.",
                "owasp_category": "A01:2021 - Broken Access Control",
                "affected_component": url,
                "business_impact": "Hidden admin panels, backup files, or API endpoints may be accessible to unauthorised users.",
                "evidence": "\n".join(hits[:20]),
                "reproduction_steps": f"feroxbuster --url {url} -d 2 --threads 20",
                "references_json": ["https://github.com/epi052/feroxbuster", "https://owasp.org/www-project-web-security-testing-guide/"]
            })
        return findings
    except FileNotFoundError:
        logger.warning("feroxbuster not found")
        return None
    except Exception as e:
        logger.error(f"Feroxbuster: {e}")
        return []
