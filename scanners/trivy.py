"""
Trivy Scanner — SMP V9.0.1
=========================
Runs Trivy to scan container images and filesystems for CVEs and misconfigurations.
Uses the V9.0.1 Zero-Friction Plugin Registration.
"""

import logging
import subprocess
import json

logger = logging.getLogger("smp.scan")

PLUGIN_META = {
    "name": "Trivy",
    "binary": "trivy",
    "severity": "High",
    "step_name": "Running Container/FS Scan (Trivy)",
    "confidence": 95,
}

def scan(target_url: str, scan_id: int, settings: dict) -> dict:
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "trivy")

    # In a real environment, target might be an image name or path.
    # For SMP web targets, we fall back to a filesystem scan of the local config/code
    # if it's a localhost/internal URL, otherwise we skip.
    cmd = ["trivy", "fs", ".", "--format", "json"]

    logger.info(f"[trivy] Running: {' '.join(cmd)}")
    findings = []
    raw_output = ""

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw_output = result.stdout + result.stderr

        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                results = data.get("Results", [])
                for res in results:
                    vulnerabilities = res.get("Vulnerabilities", [])
                    for vuln in vulnerabilities:
                        vid = vuln.get("VulnerabilityID", "UNKNOWN")
                        pkg = vuln.get("PkgName", "Unknown")
                        sev = vuln.get("Severity", "Medium").capitalize()
                        
                        try:
                            from tools.db_manager import add_finding
                            add_finding(
                                scan_id=scan_id,
                                scanner="Trivy",
                                severity=sev,
                                title=f"{vid} in {pkg}",
                                description=vuln.get("Description", "No description provided."),
                                evidence=f"Package: {pkg} Version: {vuln.get('InstalledVersion')}",
                                remediation=f"Upgrade {pkg} to a patched version."
                            )
                            if sev in ("High", "Critical"):
                                emit_finding(scan_id, "trivy", sev, f"CVE found: {vid}")
                        except Exception as e:
                            logger.debug(f"[trivy] DB write error: {e}")
                        
                        findings.append({"vuln_id": vid, "package": pkg, "severity": sev})
            except json.JSONDecodeError:
                logger.error("[trivy] Failed to parse Trivy JSON output.")

    except Exception as e:
        logger.error(f"[trivy] Error: {e}")
        raw_output = str(e)

    return {
        "success": len(findings) > 0,
        "data": findings,
        "raw_output": raw_output,
    }
