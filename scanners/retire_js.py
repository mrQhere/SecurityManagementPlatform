"""Retire.js — JavaScript library CVE detection via version fingerprinting."""
import logging
import re
import urllib.request
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

JS_VERSION_SIGS = {
    "jquery": r'jQuery[^"]*v?(\d+\.\d+\.\d+)',
    "bootstrap": r'Bootstrap[^"]*v?(\d+\.\d+\.\d+)',
    "angular": r'AngularJS[^"]*(\d+\.\d+\.\d+)',
    "react": r'react[@/](\d+\.\d+\.\d+)',
    "vue": r'Vue\.js[^"]*(\d+\.\d+\.\d+)',
    "lodash": r'lodash[^"]*(\d+\.\d+\.\d+)',
}
KNOWN_VULN = {
    "jquery": [("< 3.5.0", "XSS via jQuery.htmlPrefilter", "CVE-2020-11022", 6.1)],
    "bootstrap": [("< 4.3.1", "XSS in tooltip/popover data attributes", "CVE-2019-8331", 6.1)],
}

@register_scanner(name="Retire.js Scanner", step_name="Running Retire.js Scanner", depends_on=['Tech Fingerprint'], binary_name="", needs_binary=False, confidence=80)
def run_retire_js_scan(url):
    logger.info(f"Retire.js: Scanning {url} for vulnerable JS libraries")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SMP/5.4"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read(1_000_000).decode(errors="replace")
    except Exception as e:
        logger.warning(f"Retire.js fetch failed: {e}")
        return []

    findings = []
    for lib, pattern in JS_VERSION_SIGS.items():
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            version = m.group(1)
            for vuln_range, desc, cve, cvss in KNOWN_VULN.get(lib, []):
                findings.append({
                    "severity": "Medium",
                    "title": f"Retire.js: Vulnerable {lib.capitalize()} {version}",
                    "description": f"{lib.capitalize()} version {version} detected. {desc}",
                    "url": url,
                    "cve_id": cve,
                    "cvss_score": cvss,
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                    "affected_component": f"{lib} {version}",
                    "business_impact": f"Outdated {lib.capitalize()} enables client-side XSS attacks that steal user sessions and credentials.",
                    "reproduction_steps": f"1. Open {url}\n2. View source, find {lib} {version}\n3. Use known payload for {cve}",
                    "remediation_code": f"# Update in package.json:\n{lib}: '>= 3.6.0'",
                    "references_json": [f"https://nvd.nist.gov/vuln/detail/{cve}", "https://retirejs.github.io/retire.js/"]
                })
    return findings
