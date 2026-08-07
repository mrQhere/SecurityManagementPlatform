"""
CrackMapExec Scanner — SMP V9.4.0
=========================
Runs CrackMapExec (CME) / NetExec for Active Directory and internal network pentesting.
"""

import logging
import subprocess

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "CrackMapExec",
    "binary": "cme",
    "severity": "Critical",
    "step_name": "Running Internal AD Recon (CrackMapExec)",
    "confidence": 95,
}

def scan(target_url: str, scan_id: int, settings: dict):
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "crackmapexec")

    # In SMP, we would target IP ranges or specific DCs. For this generic integration,
    # we run an SMB null session probe against the target IP.
    # Note: Target URL must be parsed to an IP/Hostname for CME.
    target = target_url.replace("https://", "").replace("http://", "").split("/")[0]

    cmd = ["cme", "smb", target, "-u", "''", "-p", "''", "--shares"]
    
    logger.info(f"[crackmapexec] Running: {' '.join(cmd)}")
    findings = []
    raw_output = ""

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw_output = result.stdout + result.stderr

        for line in raw_output.splitlines():
            # Basic parsing to look for readable SMB shares over null sessions
            if "READ" in line or "WRITE" in line:
                try:
                    from tools.db_manager import add_finding
                    add_finding(
                        scan_id=scan_id,
                        scanner="CrackMapExec",
                        severity="Critical",
                        title="Null Session / Exposed SMB Share",
                        description="CrackMapExec successfully authenticated using a Null Session and found exposed SMB shares.",
                        evidence=line.strip(),
                        remediation="Disable SMBv1, restrict Null Sessions, and require SMB Signing."
                    )
                    emit_finding(scan_id, "crackmapexec", "Critical", "Exposed SMB Share Found")
                except Exception as e:
                    logger.debug(f"[crackmapexec] DB write error: {e}")
                
                findings.append({"exposed_share": line.strip()})

    except subprocess.TimeoutExpired:
        logger.warning("[crackmapexec] Timed out after 300s")
        raw_output += "\n[TIMEOUT]"
    except Exception as e:
        logger.error(f"[crackmapexec] Error: {e}")
        raw_output = str(e)

    return {
        "success": bool(findings),
        "data": findings,
        "raw_output": raw_output,
    }
