"""
Narrative Logger — SMP V7.0
============================
Translates raw scanner pipeline events into human-readable, step-by-step
walkthrough messages, inspired by the PentestGPT live-console pattern.

Each scanner step emits a narrative line that explains *what* is happening
and *why*. Messages are:
  - Written to  logs/narrative/<scan_id>.log  (persisted per-scan)
  - Sent over the UDP IPC bus so the GUI can display them in real time
  - Accessible via  get_narrative(scan_id)  for the report generator

Usage inside a scanner:
    from tools.narrative_logger import emit, emit_finding, emit_stage
    emit(scan_id, "nmap", "Probing open ports to map the attack surface.")
    emit_finding(scan_id, "nmap", "High", "Port 22 open — SSH service exposed.")
    emit_stage(scan_id, "recon", "active")
"""

import json
import logging
import os
import socket
import time
from datetime import datetime

logger = logging.getLogger("smp.narrative")

# ── Paths ─────────────────────────────────────────────────────────────────────

def _narrative_dir() -> str:
    from tools.config_manager import BASE_DIR
    d = os.path.join(BASE_DIR, "logs", "narrative")
    os.makedirs(d, exist_ok=True)
    return d


def _narrative_path(scan_id: int) -> str:
    return os.path.join(_narrative_dir(), f"scan_{scan_id}.log")


# ── Stage descriptions (what each phase means) ────────────────────────────────

STAGE_DESCRIPTIONS = {
    "recon":    "Passive reconnaissance — gathering intelligence without touching the target.",
    "active":   "Active scanning — probing the target for open ports, services, and vulnerabilities.",
    "exploit":  "Vulnerability analysis — correlating findings against known CVE databases.",
    "report":   "Post-processing — generating risk scores and building the final report.",
}

# ── Scanner narrative templates ───────────────────────────────────────────────

SCANNER_NARRATIVE = {
    "httpx":          "Checking whether the target is alive and collecting initial HTTP metadata.",
    "whatweb":        "Fingerprinting the technology stack — frameworks, CMS, server software.",
    "subfinder":      "Discovering subdomains via passive DNS sources and certificate transparency.",
    "crtsh":          "Querying Certificate Transparency logs for additional subdomains.",
    "hackertarget":   "Performing reverse DNS lookups via HackerTarget.",
    "whois":          "Collecting domain registration and ownership data.",
    "wayback":        "Querying the Wayback Machine for historically exposed URLs and endpoints.",
    "theharvester":   "Running OSINT collection — emails, names, hosts via theHarvester.",
    "traceroute":     "Mapping the network path to the target.",
    "nmap":           "Port and service scanning — identifying open ports and running services.",
    "ssl":            "Analysing TLS configuration — certificate validity, cipher strength.",
    "headers":        "Auditing HTTP security headers — CSP, HSTS, X-Frame-Options, etc.",
    "robots":         "Parsing robots.txt and sitemap — discovering restricted and hidden paths.",
    "cors":           "Testing Cross-Origin Resource Sharing policies for misconfiguration.",
    "cms":            "Detecting CMS platform (WordPress, Drupal, Joomla) and version.",
    "nikto":          "Running Nikto — broad web vulnerability scan against common issues.",
    "nuclei":         "Running Nuclei — template-based vulnerability scan against known CVE patterns.",
    "ffuf":           "Directory and file fuzzing with ffuf — discovering hidden endpoints.",
    "open_redirect":  "Testing URL parameters for open redirect vulnerabilities.",
    "tech_fingerprint": "Deep technology fingerprinting — version detection across all layers.",
    "wapiti":         "OWASP Wapiti scan — testing for injection, XSS, SSRF, and more.",
    "sqlmap":         "Testing for SQL injection vulnerabilities with SQLMap.",
    "shodan":         "Querying Shodan InternetDB for passive internet exposure data.",
    "gitleaks":       "Scanning for exposed secrets and credentials in HTTP responses.",
    "dalfox":         "Parameter-based XSS scan with Dalfox.",
    "arjun":          "Discovering hidden HTTP parameters with Arjun.",
    "dnsx":           "Full DNS enumeration — A, AAAA, MX, TXT, CNAME records.",
    "katana":         "Web crawling with Katana — discovering all reachable endpoints.",
    "commix":         "Testing for OS command injection vulnerabilities.",
    "jwt":            "Analysing JWT tokens for weak secrets and algorithm confusion.",
    "wpscan":         "WordPress-specific vulnerability scan — plugins, themes, users.",
    "masscan":        "High-speed port scan with Masscan — full port range coverage.",
    "paramspider":    "Mining URL parameters from web archives for further testing.",
    "cloud_enum":     "Enumerating cloud assets — S3 buckets, Azure blobs, GCP storage.",
    "zap":            "OWASP ZAP active scan — comprehensive automated web application testing.",
    "gobuster":       "Brute-forcing directories, files, and subdomains with Gobuster (dir + dns modes).",
    "dirb":           "Classic web content discovery with Dirb — scanning for hidden paths and admin panels.",
    "netcat_probe":   "Raw TCP banner grabbing — identifying service versions on open ports found by Nmap.",
    "cve_correlation": "Correlating detected technologies against the CVE intelligence database.",
    "risk_scoring":   "Calculating composite risk score from all findings.",
    "report":         "Generating HTML and PDF reports with full findings and evidence.",
}


# ── Core emit functions ───────────────────────────────────────────────────────

def emit(scan_id: int, scanner: str, message: str, level: str = "INFO") -> None:
    """
    Emit a narrative line for a given scan and scanner.

    Args:
        scan_id:  Database scan ID.
        scanner:  Short scanner key (e.g. 'nmap', 'nuclei').
        message:  Human-readable narrative sentence.
        level:    Log level — INFO, WARNING, FINDING.
    """
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] [{scanner.upper()}] {message}"

    # Write to per-scan narrative log
    try:
        with open(_narrative_path(scan_id), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        logger.debug(f"narrative_logger: file write failed: {e}")

    # Forward over UDP IPC so GUI picks it up in real time
    _ipc_send(scan_id, scanner, message, level)

    logger.debug(f"[Narrative][{scan_id}] {line}")


def emit_stage(scan_id: int, stage: str, status: str = "started") -> None:
    """
    Emit a stage-transition narrative line.

    Args:
        scan_id: Database scan ID.
        stage:   One of 'recon', 'active', 'exploit', 'report'.
        status:  'started' or 'completed'.
    """
    desc = STAGE_DESCRIPTIONS.get(stage, stage)
    if status == "started":
        message = f"Stage started — {desc}"
    else:
        message = f"Stage completed — {desc}"
    emit(scan_id, f"stage:{stage}", message, level="STAGE")


def emit_scanner_start(scan_id: int, scanner: str) -> None:
    """Emit the standard start narrative for a named scanner."""
    description = SCANNER_NARRATIVE.get(scanner.lower(), f"Running {scanner}.")
    emit(scan_id, scanner, description)


def emit_finding(scan_id: int, scanner: str, severity: str, title: str) -> None:
    """
    Emit a narrative entry for a discovered finding.

    Args:
        scan_id:  Database scan ID.
        scanner:  Scanner that found it.
        severity: Critical / High / Medium / Low / Informational.
        title:    Short finding title.
    """
    message = f"[{severity.upper()}] Finding confirmed — {title}"
    emit(scan_id, scanner, message, level="FINDING")


def emit_branch(scan_id: int, trigger_scanner: str, spawned_scanner: str, reason: str) -> None:
    """
    Emit a narrative for a dynamic pipeline branch (stage-feeding decision).

    Args:
        scan_id:         Database scan ID.
        trigger_scanner: Scanner whose output triggered the branch.
        spawned_scanner: Scanner that was dynamically added to the pipeline.
        reason:          Human-readable reason for the branch.
    """
    message = (
        f"Dynamic branch — {trigger_scanner.upper()} result triggered {spawned_scanner.upper()}. "
        f"Reason: {reason}"
    )
    emit(scan_id, "pipeline", message, level="BRANCH")


def get_narrative(scan_id: int) -> list[str]:
    """
    Return all narrative lines for a given scan.

    Args:
        scan_id: Database scan ID.

    Returns:
        List of narrative strings, oldest first.
    """
    path = _narrative_path(scan_id)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except Exception:
        return []


# ── UDP IPC forward ───────────────────────────────────────────────────────────

def _ipc_send(scan_id: int, scanner: str, message: str, level: str) -> None:
    """Send a narrative event to the GUI over the UDP IPC socket."""
    try:
        payload = json.dumps({
            "type": "narrative",
            "data": {
                "scan_id": scan_id,
                "scanner": scanner,
                "message": message,
                "level": level,
                "timestamp": time.time(),
            }
        }).encode("utf-8")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.sendto(payload, ("127.0.0.1", 5005))
        sock.close()
    except Exception:
        pass  # IPC failure is non-fatal; narrative still written to file
# Made by mrQhere
