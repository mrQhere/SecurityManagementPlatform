"""
Tplmap Scanner — SMP V9.4.3
=========================
"""

import logging
import subprocess
from scanners.core.registry import register_scanner
from config.settings import get_setting

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "Tplmap",
    "binary": "tplmap",
    "severity": "Critical",
    "step_name": "SSTI Injection",
    "confidence": 95,
}

@register_scanner(
    name="Tplmap",
    step_name="SSTI Injection",
    depends_on=['Arjun'],
    binary_name="tplmap",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "tplmap")
    
    if get_setting("scan_profile", "standard") not in ["full", "full"] and "full" == "full":
        logger.info(f"[tplmap] Skipping — requires 'full' profile")
        return []

    cmd = ["tplmap", target_url]
    
    logger.info(f"[tplmap] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[tplmap] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[tplmap] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[tplmap] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Critical",
                    "title": "Tplmap Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "tplmap-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[tplmap] Output recorded but no direct vulns parsed.")
        
    return findings
