"""
Dirb Scanner — SMP V9.3.2
=========================
Runs Dirb for classic web content discovery using dictionary-based scanning.
Provides a third fuzzing engine alongside ffuf and gobuster, using its own
built-in wordlists optimised for older/obscure web paths.

Install:
    sudo apt install dirb
"""

import logging
import os
import re
import shutil
import subprocess

logger = logging.getLogger("smp.scan")


def run_dirb(target_url: str, scan_id: int, settings: dict) -> dict:
    """
    Run Dirb against a target for web content discovery.

    Args:
        target_url: Target URL (e.g. https://example.com)
        scan_id:    Database scan ID
        settings:   Settings dict from config_manager

    Returns:
        dict with keys: success (bool), data (list of urls), raw_output (str)
    """
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "dirb")

    dirb_bin = settings.get("dirb_path", "dirb")
    if not shutil.which(dirb_bin):
        logger.warning("[dirb] dirb not found. Install: sudo apt install dirb")
        return {"success": False, "data": [], "raw_output": "dirb not found"}

    # Dirb uses its own built-in wordlists; optionally override
    wordlist = settings.get("dirb_wordlist", "")

    cmd = [
        dirb_bin,
        target_url,
    ]
    if wordlist and os.path.exists(wordlist):
        cmd.append(wordlist)

    # Flags: -r = non-recursive, -S = silent (only found URLs), -f = fine tuning
    cmd += ["-r", "-S", "-z", "50"]  # -z 50ms delay to be polite

    logger.info(f"[dirb] Running: {' '.join(cmd)}")

    findings: list[dict] = []
    raw_output = ""

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        raw_output = result.stdout + result.stderr

        for line in raw_output.splitlines():
            line = line.strip()
            # Dirb found lines look like: + http://example.com/admin (CODE:200|SIZE:1234)
            if not line.startswith("+") and not line.startswith("==>"):
                continue
            url_match = re.search(r'(https?://[^\s(]+)', line)
            code_match = re.search(r'CODE:(\d+)', line)
            size_match = re.search(r'SIZE:(\d+)', line)

            if not url_match:
                continue

            url = url_match.group(1)
            status = code_match.group(1) if code_match else "?"
            size = size_match.group(1) if size_match else "?"

            severity = "Informational"
            if status in ("200", "201"):
                severity = "Informational"
            elif status in ("301", "302"):
                severity = "Low"
            elif status in ("401", "403"):
                severity = "Low"

            # Flag admin/sensitive paths
            url_lower = url.lower()
            if any(kw in url_lower for kw in ("/admin", "/backup", "/.git", "/.env", "/config", "/secret", "/db", "/phpmyadmin", "/wp-admin")):
                severity = "Medium"

            try:
                from tools.db_manager import add_finding
                add_finding(
                    scan_id=scan_id,
                    scanner="Dirb",
                    severity=severity,
                    title=f"Web path discovered: {url}",
                    description=f"Dirb found accessible path: {url} (HTTP {status}, Size: {size})",
                    evidence=line,
                    remediation="Review this path and restrict access if it should not be publicly accessible.",
                )
                if severity in ("Medium", "High"):
                    emit_finding(scan_id, "dirb", severity, f"Sensitive path: {url}")
            except Exception as e:
                logger.debug(f"[dirb] DB write error: {e}")

            findings.append({"url": url, "status": status, "size": size})

    except subprocess.TimeoutExpired:
        logger.warning("[dirb] Timed out after 300s")
        raw_output += "\n[TIMEOUT]"
    except Exception as e:
        logger.error(f"[dirb] Error: {e}")
        raw_output = str(e)

    logger.info(f"[dirb] Completed. {len(findings)} paths found.")
    return {
        "success": len(findings) > 0 or bool(raw_output),
        "data": findings,
        "raw_output": raw_output,
    }
# Made by mrQhere
