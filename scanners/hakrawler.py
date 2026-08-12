"""
Hakrawler Scanner — SMP V9.4.3
=========================
"""

import logging
import subprocess
from scanners.core.registry import register_scanner
from config.settings import get_setting

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "Hakrawler",
    "binary": "hakrawler",
    "severity": "Info",
    "step_name": "Web Crawling",
    "confidence": 95,
}

@register_scanner(
    name="Hakrawler",
    step_name="Web Crawling",
    depends_on=['HTTPx'],
    binary_name="hakrawler",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "hakrawler")
    
    if get_setting("scan_profile", "standard") not in ["standard", "full"] and "standard" == "full":
        logger.info(f"[hakrawler] Skipping — requires 'full' profile")
        return []

    cmd = ["hakrawler", target_url]
    
    logger.info(f"[hakrawler] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[hakrawler] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[hakrawler] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[hakrawler] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Info",
                    "title": "Hakrawler Finding",
                    "description": line.strip()[:200],
                    "confidence": 95,
                    "template_id": "hakrawler-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[hakrawler] Output recorded but no direct vulns parsed.")
        
    return findings
