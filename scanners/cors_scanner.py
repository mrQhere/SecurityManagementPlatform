from scanners.core.registry import register_scanner
"""
CORS Misconfiguration Scanner.
Tests for insecure CORS policies that allow arbitrary origins via OPTIONS and GET.
"""
import logging
import urllib.parse
try:
    import requests
except ImportError:
    requests = None

from tools.db_manager import add_log_entry
from tools.config_manager import load_settings
verify_tls = not load_settings().get('insecure_scans', False)

logger = logging.getLogger("smp.scan")

CORS_TIMEOUT = 20

_BASE_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://target.evil.com",       # trust anchor mismatch
    "http://localhost",              # localhost reflection
    "https://notevil.com.evil.com",  # endsWith bypass
]


@register_scanner(name="CORS", step_name="Running CORS", depends_on=['Robots.txt'], binary_name="", needs_binary=False, confidence=95)
def run_cors_scan(url):
    """Test CORS policy for dangerous misconfigurations. Returns list of findings or None."""
    if not requests:
        logger.error("CORS Scanner: 'requests' library not available.")
        return None

    logger.info(f"CORS Scan Started: {url}")
    add_log_entry("INFO", f"CORS Scan Started: {url}")

    findings = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = requests.Session()
    session.headers["User-Agent"] = "SMP/9.4.2 (Security Audit)"

    # Build origin list, including target-specific subdomain injection
    parsed = urllib.parse.urlparse(url)
    target_domain = parsed.hostname or ""
    test_origins = list(_BASE_ORIGINS)
    if target_domain:
        test_origins.append(f"https://evil.{target_domain}")  # subdomain injection

    try:
        for test_origin in test_origins:
            try:
                resp = session.options(
                    url,
                    headers={
                        "Origin": test_origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization",
                    },
                    timeout=CORS_TIMEOUT,
                    verify=verify_tls,
                    allow_redirects=False,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*" and acac == "true":
                    findings.append({
                        "severity": "Critical",
                        "title": "CORS: Wildcard Origin with Credentials Allowed",
                        "description": (
                            f"URL: {url}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}\n\n"
                            f"Wildcard CORS with credentials allows any origin to make "
                            f"credentialed requests — complete authentication bypass.\n\n"
                            f"Fix: Specify exact trusted origins, never use wildcard with credentials."
                        ),
                        "template_id": "CORS-WILDCARD-CREDS",
                    })
                elif acao == test_origin:
                    severity = "High" if acac == "true" else "Medium"
                    findings.append({
                        "severity": severity,
                        "title": f"CORS: Arbitrary Origin Reflected [{test_origin}]",
                        "description": (
                            f"URL: {url}\n"
                            f"Origin Sent: {test_origin}\n"
                            f"ACAO: {acao} | Credentials: {acac}\n\n"
                            f"The server reflects any submitted Origin. "
                            f"{'With credentials=true, this enables cross-origin session theft.' if acac == 'true' else 'Allows cross-origin data access.'}\n\n"
                            f"Fix: Maintain a server-side whitelist of trusted origins."
                        ),
                        "template_id": "CORS-ORIGIN-REFLECTED",
                    })
                elif acao == "*":
                    findings.append({
                        "severity": "Low",
                        "title": "CORS: Wildcard Origin (*) Configured",
                        "description": (
                            f"URL: {url}\nAccess-Control-Allow-Origin: *\n\n"
                            f"Wildcard CORS allows any domain to make requests. "
                            f"Sensitive endpoints must restrict CORS.\n\n"
                            f"Fix: Restrict to specific trusted origins."
                        ),
                        "template_id": "CORS-WILDCARD",
                    })
                    break  # Only report once

            except requests.exceptions.ConnectionError:
                break
            except Exception as e:
                logger.debug(f"CORS origin {test_origin}: {e}")
                continue

        # GET fallback — for servers that don't respond to OPTIONS
        try:
            get_resp = session.get(
                url,
                headers={"Origin": "https://evil.com"},
                timeout=CORS_TIMEOUT,
                verify=verify_tls,
                allow_redirects=True,
            )
            acao_get = get_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao_get == "https://evil.com" and not any(
                "Arbitrary" in f.get("title", "") for f in findings
            ):
                findings.append({
                    "severity": "High",
                    "title": "CORS: GET Origin Reflected (OPTIONS bypass)",
                    "description": (
                        f"URL: {url}\nTest Origin: https://evil.com\n"
                        f"ACAO on GET: {acao_get}\n\n"
                        f"Server reflects Origin on GET even when OPTIONS is restricted. "
                        f"Cross-origin data theft is possible.\n\n"
                        f"Fix: Validate Origin on all HTTP methods server-side."
                    ),
                    "template_id": "CORS-GET-REFLECTED",
                })
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback, logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass

    except Exception as e:
        logger.error(f"CORS Scan Failed: {e}")
        add_log_entry("ERROR", f"CORS Scan Failed: {e}")
        return None

    logger.info(f"CORS Scan Completed: {len(findings)} issues")
    add_log_entry("INFO", f"CORS: {len(findings)} issues found")
    return findings
