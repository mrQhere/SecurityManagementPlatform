import os
import subprocess
import logging
from .core.registry import register_scanner
from tools.config_manager import load_settings

logger = logging.getLogger("smp.scan")

@register_scanner(
    name="WebSocket Scanner",
    step_name="Running WebSocket Scanner",
    depends_on=["HTTPx", "Subfinder"],
    needs_binary=True,
    binary_name="wscat"
)
def run_wscat_scan(url, scan_id=None, settings=None, brain_insights=None):
    """
    Checks for open WebSockets.
    """
    logger.info(f"Starting wscat scan for: {url}")
    
    # Try converting http to ws
    ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
    
    cmd = ["wscat", "-c", ws_url, "--connect-timeout", "10"]
    
    try:
        # Just check if we can connect without errors
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        
        findings = []
        if "connected (press CTRL+C to quit)" in process.stdout.lower() or "connected" in process.stdout.lower():
             findings.append({
                "title": "Open WebSocket Discovered",
                "severity": "Info",
                "description": f"WebSocket connection successfully established at {ws_url}",
                "raw": process.stdout
            })
                
        return findings if findings else None
        
    except subprocess.TimeoutExpired:
        logger.warning(f"wscat timed out for {url}")
        return None
    except Exception as e:
        logger.error(f"wscat error for {url}: {e}")
        return None
