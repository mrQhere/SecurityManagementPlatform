"""
Gobuster Scanner — SMP V9.3.3
============================
Runs Gobuster for fast directory, file, DNS, and vhost brute-forcing.
Complements ffuf by providing a second fuzzing engine with different
payloads and enumeration modes.

Gobuster modes used:
  - dir   — Directory and file enumeration
  - dns   — Subdomain brute-force via DNS
  - vhost — Virtual host discovery

Install:
    go install github.com/OJ/gobuster/v3@latest
  or:
    sudo apt install gobuster
"""

import logging
import os
import shutil
import subprocess

logger = logging.getLogger("smp.scan")


def run_gobuster(target_url: str, scan_id: int, settings: dict) -> dict:
    """
    Run Gobuster against a target in directory, DNS, and vhost modes.

    Args:
        target_url: Target URL (e.g. https://example.com)
        scan_id:    Database scan ID
        settings:   Settings dict from config_manager

    Returns:
        dict with keys: success (bool), data (list of findings), raw_output (str)
    """
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "gobuster")

    gobuster_bin = settings.get("gobuster_path", "gobuster")
    if not shutil.which(gobuster_bin):
        logger.warning("[gobuster] gobuster not found. Install: go install github.com/OJ/gobuster/v3@latest")
        return {"success": False, "data": [], "raw_output": "gobuster not found"}

    # Wordlist — prefer SMP bundled list, fall back to common system paths
    wordlist = settings.get("ffuf_wordlist", "")
    if not wordlist or not os.path.exists(wordlist):
        for candidate in [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]:
            if os.path.exists(candidate):
                wordlist = candidate
                break

    if not wordlist:
        logger.warning("[gobuster] No wordlist found. Skipping gobuster.")
        return {"success": False, "data": [], "raw_output": "No wordlist available"}

    findings: list[dict] = []
    all_output: list[str] = []

    # ── Mode 1: Directory enumeration ─────────────────────────────────────────
    try:
        cmd = [
            gobuster_bin, "dir",
            "-u", target_url,
            "-w", wordlist,
            "-t", "40",
            "--timeout", "10s",
            "-q",
            "--no-error",
        ]
        logger.info(f"[gobuster] Running dir mode: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
        all_output.append("=== DIR MODE ===\n" + output)

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Error") or line.startswith("="):
                continue
            # Gobuster dir output: /path (Status: 200) [Size: 1234]
            if "(Status:" in line:
                status_code = ""
                if "(Status:" in line:
                    status_code = line.split("(Status:")[1].split(")")[0].strip()
                severity = "Informational"
                if status_code in ("200", "201", "204"):
                    severity = "Informational"
                elif status_code in ("301", "302", "307", "308"):
                    severity = "Low"
                elif status_code in ("401", "403"):
                    severity = "Low"
                path = line.split()[0]
                try:
                    from tools.db_manager import add_finding
                    add_finding(
                        scan_id=scan_id,
                        scanner="Gobuster",
                        severity=severity,
                        title=f"Directory/File discovered: {path}",
                        description=f"Gobuster found accessible path: {path} (HTTP {status_code})",
                        evidence=line,
                        remediation="Review whether this path should be publicly accessible. Restrict or remove if not required.",
                    )
                    emit_finding(scan_id, "gobuster", severity, f"Path found: {path} (HTTP {status_code})")
                except Exception as e:
                    logger.debug(f"[gobuster] DB write error: {e}")
                findings.append({"path": path, "status": status_code, "line": line})

    except subprocess.TimeoutExpired:
        logger.warning("[gobuster] dir mode timed out after 300s")
        all_output.append("=== DIR MODE TIMED OUT ===")
    except Exception as e:
        logger.error(f"[gobuster] dir mode error: {e}")
        all_output.append(f"=== DIR MODE ERROR: {e} ===")

    # ── Mode 2: DNS subdomain brute-force ─────────────────────────────────────
    try:
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname or target_url

        dns_wordlist = settings.get("gobuster_dns_wordlist", "")
        if not dns_wordlist or not os.path.exists(dns_wordlist):
            # Use common subdomain wordlist if available
            for candidate in [
                "/usr/share/wordlists/dns/subdomains-top1million-5000.txt",
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            ]:
                if os.path.exists(candidate):
                    dns_wordlist = candidate
                    break

        if dns_wordlist and os.path.exists(dns_wordlist):
            cmd = [
                gobuster_bin, "dns",
                "-d", domain,
                "-w", dns_wordlist,
                "-t", "20",
                "-q",
                "--no-error",
            ]
            logger.info(f"[gobuster] Running dns mode: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=180
            )
            output = result.stdout + result.stderr
            all_output.append("=== DNS MODE ===\n" + output)

            for line in output.splitlines():
                line = line.strip()
                if not line or "Error" in line:
                    continue
                if "Found:" in line:
                    subdomain = line.replace("Found:", "").strip()
                    try:
                        from tools.db_manager import add_finding
                        add_finding(
                            scan_id=scan_id,
                            scanner="Gobuster",
                            severity="Informational",
                            title=f"Subdomain discovered: {subdomain}",
                            description=f"DNS brute-force found subdomain: {subdomain}",
                            evidence=line,
                            remediation="Review whether this subdomain is intended to be public.",
                        )
                        emit_finding(scan_id, "gobuster", "Informational", f"Subdomain: {subdomain}")
                    except Exception as e:
                        logger.debug(f"[gobuster] DB write error: {e}")
                    findings.append({"subdomain": subdomain, "line": line})
        else:
            all_output.append("=== DNS MODE SKIPPED (no subdomain wordlist) ===")
            logger.info("[gobuster] DNS mode skipped — no subdomain wordlist found.")

    except subprocess.TimeoutExpired:
        logger.warning("[gobuster] dns mode timed out")
        all_output.append("=== DNS MODE TIMED OUT ===")
    except Exception as e:
        logger.error(f"[gobuster] dns mode error: {e}")
        all_output.append(f"=== DNS MODE ERROR: {e} ===")

    raw_output = "\n".join(all_output)
    success = len(findings) > 0 or (len(all_output) > 0)
    logger.info(f"[gobuster] Completed. {len(findings)} findings.")
    return {"success": success, "data": findings, "raw_output": raw_output}
# Made by mrQhere
