"""
LFISuite Scanner — SMP V9.4.3
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
    "name": "LFISuite",
    "binary": "lfisuite",
    "severity": "Critical",
    "step_name": "LFI/RFI Exploitation",
    "confidence": 95,
}

@register_scanner(
    name="LFISuite",
    step_name="LFI/RFI Exploitation",
    depends_on=['HTTPx'],
    binary_name="lfisuite",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "lfisuite")
    
    if get_setting("scan_profile", "standard") not in ["full", "full"] and "full" == "full":
        logger.info("[lfisuite] Skipping — requires 'full' profile")
        return []

    cmd = ["lfisuite", target_url]
    
    logger.info(f"[lfisuite] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning("[lfisuite] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("[lfisuite] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[lfisuite] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Critical",
                    "title": "LFISuite Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "lfisuite-001"
                })
                
    if not findings and result.stdout:
        logger.debug("[lfisuite] Output recorded but no direct vulns parsed.")
        
    return findings
