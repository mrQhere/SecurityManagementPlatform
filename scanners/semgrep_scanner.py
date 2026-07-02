"""Semgrep — SAST / static analysis on discovered JavaScript and config files."""
import subprocess
import logging
import json
from tools.config_manager import BASE_DIR
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

SEMGREP_TIMEOUT = 180

@register_scanner(name="Semgrep", step_name="Running Semgrep", depends_on=['Cloud Enum'], binary_name="semgrep", needs_binary=True, confidence=90)
def run_semgrep_scan(url):
    logger.info("Semgrep: SAST analysis")
    findings = []
    try:
        r = subprocess.run([
            "semgrep", "--config", "auto", "--json", "--quiet", "."
        ], capture_output=True, text=True, timeout=SEMGREP_TIMEOUT, cwd=BASE_DIR)
        data = json.loads(r.stdout or "{}")
        results = data.get("results", [])
        for res in results[:30]:
            sev_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
            sev = sev_map.get(res.get("severity", "INFO"), "Low")
            findings.append({
                "severity": sev,
                "title": f"Semgrep: {res.get('check_id','Rule Match')}",
                "description": res.get("extra", {}).get("message", "Semgrep rule match detected."),
                "owasp_category": "A03:2021 - Injection",
                "affected_component": res.get("path", ""),
                "evidence": res.get("extra", {}).get("lines", ""),
                "business_impact": "Static analysis finding may indicate insecure coding patterns that could be exploited at runtime.",
                "reproduction_steps": f"semgrep --config {res.get('check_id','')} {res.get('path','')}",
                "references_json": [res.get("extra", {}).get("metadata", {}).get("cwe", "")]
            })
        return findings
    except FileNotFoundError:
        logger.warning("semgrep not found")
        return None
    except Exception as e:
        logger.error(f"Semgrep: {e}")
        return []
