"""
Netcat Probe Scanner — SMP V9.4.0
================================
Uses netcat (nc) for raw TCP/UDP port probing and banner grabbing.
Complements Nmap by providing direct, low-noise service banner collection
for specific ports without sending SYN/RST noise.

Typical use-cases:
  - Banner grab ports found open by Nmap
  - Probe custom/high ports for running services
  - Detect non-HTTP services (SMTP, FTP, POP3, IMAP, etc.)

Install:
    sudo apt install netcat-openbsd
"""

import logging
import shutil
import socket
import subprocess

logger = logging.getLogger("smp.scan")

# Ports to banner-grab after Nmap (common service ports)
_DEFAULT_PROBE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]


def _tcp_banner(host: str, port: int, timeout: float = 4.0) -> str | None:
    """Grab a banner from a TCP port using raw sockets (no netcat dependency)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send a generic HTTP-like probe for web ports, empty for others
            if port in (80, 8080, 8443, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            else:
                sock.sendall(b"\r\n")
            try:
                data = sock.recv(1024)
                return data.decode("utf-8", errors="replace").strip()
            except Exception:
                return None
    except Exception:
        return None


def _get_open_ports_from_nmap(scan_id: int) -> list[int]:
    """Retrieve open ports already discovered by Nmap from the database."""
    try:
        from tools.db_manager import get_findings_for_scan
        findings = list(get_findings_for_scan(scan_id))
        ports = []
        for f in findings:
            title = f.get("title", "") + " " + f.get("description", "")
            # Parse "Port 22 open", "port 80/tcp", etc.
            import re
            for match in re.findall(r'\bport[s]?\s+(\d+)', title, re.IGNORECASE):
                p = int(match)
                if 1 <= p <= 65535:
                    ports.append(p)
        return list(set(ports)) if ports else _DEFAULT_PROBE_PORTS
    except Exception:
        return _DEFAULT_PROBE_PORTS


def run_scan(target_url: str, scan_id: int = 0):
    """
    Probe open ports for service banners using raw TCP sockets.

    Args:
        target_url: Target URL or hostname
        scan_id:    Database scan ID
        settings:   Settings dict

    Returns:
        dict with keys: success (bool), data (list of banners), raw_output (str)
    """
    from tools.narrative_logger import emit_scanner_start, emit_finding
    emit_scanner_start(scan_id, "netcat_probe")

    try:
        from urllib.parse import urlparse
        host = urlparse(target_url).hostname or target_url
    except Exception:
        host = target_url

    # Use ports already found by Nmap or fall back to defaults
    ports = _get_open_ports_from_nmap(scan_id)
    # Cap at 20 ports to avoid excessive probing time
    ports = ports[:20]

    findings: list[dict] = []
    output_lines: list[str] = []

    logger.info(f"[netcat_probe] Banner grabbing {len(ports)} ports on {host}")

    for port in ports:
        banner = _tcp_banner(host, port)
        if not banner:
            continue

        # Sanitise banner for storage
        banner_clean = banner[:500].replace("\x00", "").strip()
        if not banner_clean:
            continue

        line = f"Port {port}: {banner_clean[:120]}"
        output_lines.append(line)
        logger.info(f"[netcat_probe] {line}")

        severity = "Informational"
        title = f"Service banner on port {port}"

        # Flag potentially interesting banners
        banner_lower = banner_clean.lower()
        if any(kw in banner_lower for kw in ("version", "openssh", "vsftpd", "postfix", "microsoft")):
            severity = "Low"
            title = f"Service version disclosed on port {port}"
        if any(kw in banner_lower for kw in ("220", "login", "welcome", "password", "authentication")):
            severity = "Low"

        try:
            from tools.db_manager import add_finding
            add_finding(
                scan_id=scan_id,
                scanner="Netcat Probe",
                severity=severity,
                title=title,
                description=f"Banner grabbed from {host}:{port}:\n{banner_clean}",
                evidence=banner_clean,
                remediation="Ensure service banners do not expose version information unnecessarily.",
            )
            if severity != "Informational":
                emit_finding(scan_id, "netcat_probe", severity, title)
        except Exception as e:
            logger.debug(f"[netcat_probe] DB write error: {e}")

        findings.append({"port": port, "banner": banner_clean})

    raw_output = "\n".join(output_lines) if output_lines else "No banners collected."
    logger.info(f"[netcat_probe] Completed. {len(findings)} banners grabbed.")
    return {"success": len(findings) > 0, "data": findings, "raw_output": raw_output}
# Made by mrQhere
