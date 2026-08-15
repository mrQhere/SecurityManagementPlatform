"""
SSLyze Scanner — SMP V9.4.3
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
    "name": "SSLyze",
    "binary": "sslyze",
    "severity": "Medium",
    "step_name": "TLS/SSL Cryptographic Analysis",
    "confidence": 95,
}

@register_scanner(
    name="SSLyze",
    step_name="TLS/SSL Cryptographic Analysis",
    depends_on=['HTTPx'],
    binary_name="sslyze",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "sslyze")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[sslyze] Skipping — requires 'full' profile")
        return []

    cmd = ["sslyze", target_url]
    
    logger.info(f"[sslyze] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[sslyze] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[sslyze] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[sslyze] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Medium",
                    "title": "SSLyze Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "sslyze-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[sslyze] Output recorded but no direct vulns parsed.")
        
    return findings
