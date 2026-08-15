"""
CMSeeK Scanner — SMP V9.4.3
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
    "name": "CMSeeK",
    "binary": "cmseek",
    "severity": "High",
    "step_name": "CMS Vulnerability Scan",
    "confidence": 90,
}

@register_scanner(
    name="CMSeeK",
    step_name="CMS Vulnerability Scan",
    depends_on=['WhatWeb'],
    binary_name="cmseek",
    needs_binary=True,
    confidence=90
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "cmseek")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[cmseek] Skipping — requires 'full' profile")
        return []

    cmd = ["cmseek", target_url]
    
    logger.info(f"[cmseek] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[cmseek] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[cmseek] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[cmseek] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "High",
                    "title": "CMSeeK Finding",
                    "description": line.strip()[:200],
                    "confidence": 90,
                    "template_id": "cmseek-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[cmseek] Output recorded but no direct vulns parsed.")
        
    return findings
