"""
KubeHunter Scanner — SMP V9.4.3
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
    "name": "KubeHunter",
    "binary": "kube-hunter",
    "severity": "Critical",
    "step_name": "Kubernetes Audit",
    "confidence": 90,
}

@register_scanner(
    name="KubeHunter",
    step_name="Kubernetes Audit",
    depends_on=['Nmap'],
    binary_name="kube-hunter",
    needs_binary=True,
    confidence=90
)
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "kube-hunter")
    
    if get_setting("scan_profile", "standard") not in ["full", "full"] and "full" == "full":
        logger.info("[kube-hunter] Skipping — requires 'full' profile")
        return []

    cmd = ["kube-hunter", target_url]
    
    logger.info(f"[kube-hunter] Running: {' '.join(cmd)}")
    findings = []
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.warning("[kube-hunter] Binary not found, skipping.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("[kube-hunter] Timed out.")
        return []
    except Exception as e:
        logger.error(f"[kube-hunter] Error: {e}")
        return []

    # Basic generic parser wrapper for integration
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            if "vuln" in line.lower() or "found" in line.lower() or "critical" in line.lower():
                findings.append({
                    "severity": "Critical",
                    "title": "KubeHunter Finding",
                    "description": line.strip()[:200],
                    "confidence": 90,
                    "template_id": "kube-hunter-001"
                })
                
    if not findings and result.stdout:
        logger.debug("[kube-hunter] Output recorded but no direct vulns parsed.")
        
    return findings
