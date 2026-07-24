"""
GreyNoise Community Intelligence Feed V6.5
===========================================
Classifies IPs discovered during scanning as:
  - "noise"       → known benign/internet scanners (Shodan, search engines)
  - "riot"        → known benign infrastructure (AWS, Cloudflare, etc.)
  - "malicious"   → known threat actors
  - "unknown"     → no GreyNoise data

Fallback chain:
  1. GreyNoise Community API (free, no key needed)
  2. Local IP heuristic (RFC1918, localhost, known ranges) if API fails
  3. Return "unknown" — never blocks scan progress

API: https://api.greynoise.io/v3/community/{ip}
"""
import re
import socket
import logging
import ipaddress

logger = logging.getLogger("smp")

_GREYNOISE_API = "https://api.greynoise.io/v3/community/{ip}"
_TIMEOUT       = 5
_CACHE = {}  # Simple in-memory cache per session

try:
    from tools.egress_auditor import egress_auditor
except ImportError:
    egress_auditor = None


def _is_rfc1918(ip: str) -> bool:
    """Check if IP is private/loopback."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _local_heuristic(ip: str) -> dict:
    """
    Fallback heuristic when API is unavailable.
    Returns a partial GreyNoise-style dict.
    """
    if _is_rfc1918(ip):
        return {
            "ip": ip,
            "noise": False,
            "riot": True,
            "classification": "benign",
            "name": "Private/Internal IP",
            "link": "",
            "source": "local-heuristic"
        }
    return {
        "ip": ip,
        "noise": False,
        "riot": False,
        "classification": "unknown",
        "name": "No data",
        "link": "",
        "source": "local-heuristic"
    }


def lookup_ip(ip: str, api_key: str = "") -> dict:
    """
    Look up an IP in GreyNoise Community API.
    
    Returns a dict:
    {
        "ip": str,
        "noise": bool,       — is this a known mass-scanner?
        "riot": bool,        — is this known benign infrastructure?
        "classification": str, — "malicious" | "benign" | "unknown"
        "name": str,         — human-readable context
        "link": str,         — GreyNoise link
        "source": str        — "greynoise-api" | "local-heuristic"
    }
    """
    # Cache check
    if ip in _CACHE:
        return _CACHE[ip]

    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "noise": False, "riot": False, "classification": "unknown",
                "name": "Invalid IP", "link": "", "source": "invalid"}

    # Skip private IPs (don't need API call)
    if _is_rfc1918(ip):
        result = _local_heuristic(ip)
        _CACHE[ip] = result
        return result

    # Primary: GreyNoise Community API
    url = _GREYNOISE_API.format(ip=ip)
    if egress_auditor:
        egress_auditor.record("GreyNoise", url, "IP reputation / wild scanning check")
        from tools.egress_auditor import local_only_mode_active
        if local_only_mode_active():
            result = _local_heuristic(ip)
            _CACHE[ip] = result
            return result
    try:
        import requests
        headers = {"Accept": "application/json"}
        if api_key:
            headers["key"] = api_key

        resp = requests.get(
            url,
            headers=headers,
            timeout=_TIMEOUT
        )

        if resp.status_code == 200:
            data = resp.json()
            result = {
                "ip": ip,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", ""),
                "link": data.get("link", f"https://viz.greynoise.io/ip/{ip}"),
                "source": "greynoise-api"
            }
            _CACHE[ip] = result
            logger.info(f"[GreyNoise] {ip} → {result['classification']} (noise={result['noise']}, riot={result['riot']})")
            return result

        elif resp.status_code == 429:
            logger.warning(f"[GreyNoise] Rate limit hit. Falling back to heuristic for {ip}.")
        elif resp.status_code == 404:
            # IP not in GreyNoise — unknown
            result = {
                "ip": ip, "noise": False, "riot": False,
                "classification": "unknown", "name": "Not in GreyNoise",
                "link": f"https://viz.greynoise.io/ip/{ip}", "source": "greynoise-api"
            }
            _CACHE[ip] = result
            return result

    except Exception as e:
        logger.warning(f"[GreyNoise] API call failed for {ip}: {e}. Using local heuristic.")

    # Fallback: local heuristic
    result = _local_heuristic(ip)
    _CACHE[ip] = result
    return result


def classify_scan_ips(scan_findings: list, api_key: str = "") -> list:
    """
    Enrich a list of findings that contain IP addresses.
    Adds a 'greynoise' key to each finding.
    
    Args:
        scan_findings: List of finding dicts
        api_key: Optional GreyNoise API key
    
    Returns: Enriched findings list
    """
    import re
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    for finding in scan_findings:
        desc = (finding.get("description") or "") + " " + (finding.get("title") or "")
        ips  = set(ip_pattern.findall(desc))
        if not ips:
            continue
        gn_results = {}
        for ip in ips:
            gn_results[ip] = lookup_ip(ip, api_key)
        finding["greynoise"] = gn_results

        # Add note if any IP is known malicious
        malicious_ips = [ip for ip, r in gn_results.items() if r.get("classification") == "malicious"]
        if malicious_ips:
            finding["description"] = (finding.get("description") or "") + (
                f"\n\n[GreyNoise] Known malicious IPs involved: {', '.join(malicious_ips)}"
            )
            # Escalate severity
            if finding.get("severity") in ("Info", "Low"):
                finding["severity"] = "Medium"

    return scan_findings
