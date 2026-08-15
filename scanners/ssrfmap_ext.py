"""
SSRFmapExt Scanner — SMP V9.4.3
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
    "name": "SSRFmapExt",
    "binary": "ssrfmap",
    "severity": "Critical",
    "step_name": "SSRF Exploitation",
    "confidence": 95,
}

@register_scanner(
    name="SSRFmapExt",
    step_name="SSRF Exploitation",
    depends_on=['Arjun'],
    binary_name="ssrfmap",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "ssrfmap")
    
    if get_setting("scan_profile", "standard") not in ["full", "full"] and "full" == "full":
        logger.info(f"[ssrfmap] Skipping — requires 'full' profile")
        return []

    cmd = ["ssrfmap", target_url]
    
    logger.info(f"[ssrfmap] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[ssrfmap] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[ssrfmap] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[ssrfmap] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Critical",
                    "title": "SSRFmapExt Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "ssrfmap-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[ssrfmap] Output recorded but no direct vulns parsed.")
        
    return findings
