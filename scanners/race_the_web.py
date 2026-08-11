import os
import subprocess
import logging
import json
from .core.registry import register_scanner
from tools.config_manager import BASE_DIR, load_settings

logger = logging.getLogger("smp.scan")

@register_scanner(
    name="Race-the-Web Scanner",
    step_name="Running Race-the-Web Scanner",
    depends_on=["Running HTTPx", "Running Subfinder"],
    needs_binary=True,
    binary_name="race-the-web"
)
def run_race_the_web_scan(url, scan_id=None, settings=None, brain_insights=None):
    """
    Detects Time-of-Check to Time-of-Use (TOCTOU) and Race Condition vulnerabilities.
    """
    logger.info(f"Starting Race-the-Web scan for: {url}")
    
    settings = settings or load_settings()
    out_file = os.path.join(BASE_DIR, "logs", f"race_the_web_{scan_id}.json")
    
    cmd = [
        "race-the-web",
        "--url", url,
        "--json", out_file
    ]
    
    try:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        
        findings = []
        if os.path.exists(out_file):
            try:
                with open(out_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            # Only capture true original data without forging
                            if "vulnerable" in data and data["vulnerable"]:
                                findings.append({
                                    "title": "Race Condition Detected",
                                    "severity": "High",
                                    "description": f"Target: {data.get('target', url)}\nDetail: {data.get('detail', '')}",
                                    "raw": data
                                })
            except Exception as e:
                logger.error(f"Failed to parse race-the-web JSON: {e}")
                
        return findings if findings else None
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Race-the-Web timed out for {url}")
        return None
    except Exception as e:
        logger.error(f"Race-the-Web error for {url}: {e}")
        return None
