"""
CORScanner Scanner — SMP V9.4.3
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
    "name": "CORScanner",
    "binary": "corscanner",
    "severity": "Medium",
    "step_name": "CORS Misconfig Scan",
    "confidence": 85,
}

@register_scanner(
    name="CORScanner",
    step_name="CORS Misconfig Scan",
    depends_on=['HTTPx'],
    binary_name="corscanner",
    needs_binary=True,
    confidence=85
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "corscanner")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[corscanner] Skipping — requires 'full' profile")
        return []

    cmd = ["corscanner", target_url]
    
    logger.info(f"[corscanner] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[corscanner] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[corscanner] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[corscanner] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Medium",
                    "title": "CORScanner Finding",
                    "description": line.strip()[:200],
                    "confidence": 85,
                    "template_id": "corscanner-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[corscanner] Output recorded but no direct vulns parsed.")
        
    return findings
