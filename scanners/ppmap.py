import os
import subprocess
import logging
from .core.registry import register_scanner
from tools.config_manager import load_settings

logger = logging.getLogger("smp.scan")

@register_scanner(
    name="Prototype Pollution Scanner",
    step_name="Running Prototype Pollution Scanner",
    depends_on=["Running HTTPx", "Running Subfinder"],
    needs_binary=True,
    binary_name="ppmap"
)
def run_ppmap_scan(url, scan_id=None, settings=None, brain_insights=None):
    """
    Detects Prototype Pollution vulnerabilities using ppmap.
    """
    logger.info(f"Starting ppmap scan for: {url}")
    
    cmd = ["ppmap", "-u", url]
    
    try:
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        
        findings = []
        # ppmap typically prints vulnerability to stdout
        if "VULNERABLE" in process.stdout.upper() or "PROTOTYPE POLLUTION FOUND" in process.stdout.upper():
             findings.append({
                "title": "Prototype Pollution Detected",
                "severity": "High",
                "description": f"Target: {url}\nRaw Output:\n{process.stdout[:500]}",
                "raw": process.stdout
            })
                
        return findings if findings else None
        
    except subprocess.TimeoutExpired:
        logger.warning(f"ppmap timed out for {url}")
        return None
    except Exception as e:
        logger.error(f"ppmap error for {url}: {e}")
        return None
