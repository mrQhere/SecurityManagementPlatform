"""
Gau Scanner — SMP V9.4.3
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
    "name": "Gau",
    "binary": "gau",
    "severity": "Info",
    "step_name": "URL Extraction",
    "confidence": 95,
}

@register_scanner(
    name="Gau",
    step_name="URL Extraction",
    depends_on=['HTTPx'],
    binary_name="gau",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "gau")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[gau] Skipping — requires 'full' profile")
        return []

    cmd = ["gau", target_url]
    
    logger.info(f"[gau] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[gau] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[gau] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[gau] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Info",
                    "title": "Gau Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "gau-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[gau] Output recorded but no direct vulns parsed.")
        
    return findings
