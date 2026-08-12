"""
GitDumper Scanner — SMP V9.4.3
=========================
"""

import logging
import subprocess
from scanners.core.registry import register_scanner
from config.settings import get_setting

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "GitDumper",
    "binary": "git-dumper",
    "severity": "High",
    "step_name": "Git Extraction",
    "confidence": 100,
}

@register_scanner(
    name="GitDumper",
    step_name="Git Extraction",
    depends_on=['HTTPx'],
    binary_name="git-dumper",
    needs_binary=True,
    confidence=100
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "git-dumper")
    
    if get_setting("scan_profile", "standard") not in ["full", "full"] and "full" == "full":
        logger.info(f"[git-dumper] Skipping — requires 'full' profile")
        return []

    cmd = ["git-dumper", target_url]
    
    logger.info(f"[git-dumper] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning(f"[git-dumper] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"[git-dumper] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[git-dumper] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "High",
                    "title": "GitDumper Finding",
                    "description": line.strip()[:200],
                    "confidence": 100,
                    "template_id": "git-dumper-001"
                })
                
    if not findings and result.stdout:
        logger.debug(f"[git-dumper] Output recorded but no direct vulns parsed.")
        
    return findings
