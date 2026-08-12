"""
Droopescan Scanner — SMP V9.4.3
=========================
"""

import logging
import subprocess
from scanners.core.registry import register_scanner
from config.settings import get_setting

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "Droopescan",
    "binary": "droopescan",
    "severity": "High",
    "step_name": "Drupal/SilverStripe Scan",
    "confidence": 90,
}

@register_scanner(
    name="Droopescan",
    step_name="Drupal/SilverStripe Scan",
    depends_on=['CMS Scanner'],
    binary_name="droopescan",
    needs_binary=True,
    confidence=90
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "droopescan")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[droopescan] Skipping — requires 'full' profile")
        return []

    cmd = ["droopescan", target_url]
    
    logger.info(f"[droopescan] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[droopescan] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[droopescan] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[droopescan] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "High",
                    "title": "Droopescan Finding",
                    "description": line.strip()[:200],
                    "confidence": 90,
                    "template_id": "droopescan-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[droopescan] Output recorded but no direct vulns parsed.")
        
    return findings
