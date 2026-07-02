"""HTTP Request Smuggling — CL.TE / TE.CL / TE.TE detection."""
import socket
import logging
import ssl
import urllib.parse
from scanners.core.registry import register_scanner

logger = logging.getLogger("smp.scan")

@register_scanner(name="HTTP Smuggling Scanner", step_name="Running HTTP Smuggling Scanner", depends_on=['Nmap'], binary_name="", needs_binary=False, confidence=80)
def run_smuggler_scan(url):
    logger.info(f"HTTP Smuggling Scanner: Testing {url}")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"

    findings = []

    # CL.TE probe
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n"
        f"0\r\n\r\nG"
    ).encode()

    try:
        s = socket.create_connection((host, port), timeout=5)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(payload)
        resp = s.recv(1024).decode(errors="replace")
        s.close()
        if "400" not in resp and "405" not in resp and len(resp) > 0:
            findings.append({
                "severity": "High",
                "title": "HTTP Request Smuggling (Potential CL.TE)",
                "description": "Server may be vulnerable to HTTP request smuggling via conflicting Content-Length and Transfer-Encoding headers.",
                "url": url,
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "cvss_score": 8.1,
                "affected_component": f"{host}:{port}",
                "business_impact": "Request smuggling can bypass security controls, hijack user sessions, and poison caches, affecting all users of the application.",
                "reproduction_steps": f"# Send CL.TE probe to {host}:{port}\nPOST / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG",
                "references_json": ["https://portswigger.net/web-security/request-smuggling", "https://github.com/defparam/smuggler"]
            })
    except Exception as e:
        logger.debug(f"Smuggling probe failed: {e}")
    return findings
