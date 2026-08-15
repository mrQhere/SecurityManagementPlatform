"""
WafW00f Scanner — SMP V9.4.3
=========================
"""

import logging
import subprocess
from scanners.core.registry import register_scanner
from tools.config_manager import load_settings
def get_setting(key, default=None):
    return load_settings().get(key, default)

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "WafW00f",
    "binary": "wafw00f",
    "severity": "Info",
    "step_name": "WAF Fingerprinting",
    "confidence": 90,
}

@register_scanner(
    name="WafW00f",
    step_name="WAF Fingerprinting",
    depends_on=['HTTPx'],
    binary_name="wafw00f",
    needs_binary=True,
    confidence=90
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "wafw00f")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[wafw00f] Skipping — requires 'full' profile")
        return []

    cmd = ["wafw00f", target_url]
    
    logger.info(f"[wafw00f] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[wafw00f] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[wafw00f] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[wafw00f] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Info",
                    "title": "WafW00f Finding",
                    "description": line.strip()[:200],
                    "confidence": 90,
                    "template_id": "wafw00f-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[wafw00f] Output recorded but no direct vulns parsed.")
        
    return findings
