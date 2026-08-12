"""
Semgrep Scanner — SMP V9.4.3
=========================
"""

import logging
import subprocess
from scanners.core.registry import register_scanner
from config.settings import get_setting

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "Semgrep",
    "binary": "semgrep",
    "severity": "High",
    "step_name": "SAST Analysis",
    "confidence": 95,
}

@register_scanner(
    name="Semgrep",
    step_name="SAST Analysis",
    depends_on=['HTTPx'],
    binary_name="semgrep",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "semgrep")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[semgrep] Skipping — requires 'full' profile")
        return []

    cmd = ["semgrep", target_url]
    
    logger.info(f"[semgrep] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[semgrep] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[semgrep] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[semgrep] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "High",
                    "title": "Semgrep Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "semgrep-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[semgrep] Output recorded but no direct vulns parsed.")
        
    return findings
