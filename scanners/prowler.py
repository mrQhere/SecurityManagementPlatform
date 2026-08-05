"""
Prowler Scanner — SMP V7.0.1
=========================
Runs Prowler for Cloud Security Posture Management (CSPM).
Requires AWS/Azure credentials configured in the environment.
"""

import logging
import subprocess

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "Prowler",
    "binary": "prowler",
    "severity": "High",
    "step_name": "Running Cloud Security Audit (Prowler)",
    "confidence": 90,
}

def scan(target_url: str, scan_id: int, settings: dict) -> dict:
    from tools.narrative_logger import emit_scanner_start
    emit_scanner_start(scan_id, "prowler")

    cmd = ["prowler", "aws", "--no-banner"]
    
    logger.info(f"[prowler] Running: {' '.join(cmd)}")
    findings = []
    raw_output = ""

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        raw_output = result.stdout + result.stderr

        # Prowler outputs findings; simple regex/parsing could be added here
        if "FAIL" in raw_output:
            try:
                from tools.db_manager import add_finding
                add_finding(
                    scan_id=scan_id,
                    scanner="Prowler",
                    severity="High",
                    title="Cloud Misconfiguration Detected",
                    description="Prowler detected one or more failing checks in the cloud environment.",
                    evidence="Check prowler output for full details.",
                    remediation="Review Prowler HTML/CSV reports and fix IAM/S3 misconfigurations."
                )
            except Exception as e:
                logger.debug(f"[prowler] DB write error: {e}")
            findings.append({"status": "failed_checks"})

    except subprocess.TimeoutExpired:
        logger.warning("[prowler] Timed out after 600s")
        raw_output += "\n[TIMEOUT]"
    except Exception as e:
        logger.error(f"[prowler] Error: {e}")
        raw_output = str(e)

    return {
        "success": bool(findings),
        "data": findings,
        "raw_output": raw_output,
    }
