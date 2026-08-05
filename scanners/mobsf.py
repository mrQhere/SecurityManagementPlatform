"""
MobSF Scanner — SMP V7.0.7
=========================
Integrates with the Mobile Security Framework (MobSF) REST API.
"""

import logging
import requests

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "MobSF",
    "binary": "python3",  # Uses Python requests instead of a binary
    "severity": "Medium",
    "step_name": "Running Mobile Application Security Scan (MobSF)",
    "confidence": 85,
    "needs_binary": False,
}

def scan(target_url: str, scan_id: int, settings: dict) -> dict:
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "mobsf")

    mobsf_url = settings.get("mobsf_url", "http://localhost:8000")
    mobsf_api_key = settings.get("mobsf_api_key", "")

    if not mobsf_api_key:
        logger.warning("[mobsf] No MobSF API key provided in settings. Skipping scan.")
        return {"success": False, "data": [], "raw_output": "Missing API Key"}

    headers = {"Authorization": mobsf_api_key}
    findings = []
    
    # In a real workflow, SMP would upload an APK to the API here.
    # For now, we query the MobSF recent scans API to integrate any existing findings.
    try:
        resp = requests.get(f"{mobsf_url}/api/v1/scans", headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for app in data.get("content", []):
                app_name = app.get("APP_NAME", "Unknown")
                score = app.get("SECURITY_SCORE", 100)
                
                if score < 70:
                    try:
                        from tools.db_manager import add_finding
                        add_finding(
                            scan_id=scan_id,
                            scanner="MobSF",
                            severity="High",
                            title=f"Vulnerable Mobile App: {app_name}",
                            description=f"MobSF reported a poor security score of {score}/100 for {app_name}.",
                            evidence=f"App Hash: {app.get('MD5')}",
                            remediation="Review the detailed PDF report in the MobSF dashboard to fix code vulnerabilities."
                        )
                        emit_finding(scan_id, "mobsf", "High", f"Poor Security Score: {app_name}")
                    except Exception as e:
                        logger.debug(f"[mobsf] DB write error: {e}")
                    
                    findings.append({"app": app_name, "score": score})
    except requests.RequestException as e:
        logger.error(f"[mobsf] API Connection Error: {e}")
        return {"success": False, "data": [], "raw_output": str(e)}

    return {
        "success": bool(findings),
        "data": findings,
        "raw_output": "Fetched recent scans from MobSF API.",
    }
