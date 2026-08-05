"""
ClamAV Scanner — SMP V9.0.2
=========================
Runs ClamAV (clamscan) for malware and YARA static file analysis.
"""

import logging
import subprocess

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "ClamAV",
    "binary": "clamscan",
    "severity": "Critical",
    "step_name": "Running Malware Scan (ClamAV)",
    "confidence": 99,
}

def scan(target_url: str, scan_id: int, settings: dict) -> dict:
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "clamav")

    # For SMP, we scan the local working directory (e.g., downloaded artifacts or code)
    cmd = ["clamscan", "-r", "-i", "."]
    
    logger.info(f"[clamav] Running: {' '.join(cmd)}")
    findings = []
    raw_output = ""

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        raw_output = result.stdout + result.stderr

        for line in raw_output.splitlines():
            if "FOUND" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    file_path = parts[0].strip()
                    malware_name = parts[1].replace("FOUND", "").strip()
                    
                    try:
                        from tools.db_manager import add_finding
                        add_finding(
                            scan_id=scan_id,
                            scanner="ClamAV",
                            severity="Critical",
                            title=f"Malware Detected: {malware_name}",
                            description=f"ClamAV detected malicious signature '{malware_name}' in file: {file_path}",
                            evidence=line,
                            remediation="Quarantine or delete the infected file immediately."
                        )
                        emit_finding(scan_id, "clamav", "Critical", f"Malware: {malware_name}")
                    except Exception as e:
                        logger.debug(f"[clamav] DB write error: {e}")
                    
                    findings.append({"file": file_path, "malware": malware_name})

    except subprocess.TimeoutExpired:
        logger.warning("[clamav] Timed out after 600s")
        raw_output += "\n[TIMEOUT]"
    except Exception as e:
        logger.error(f"[clamav] Error: {e}")
        raw_output = str(e)

    return {
        "success": bool(findings),
        "data": findings,
        "raw_output": raw_output,
    }
