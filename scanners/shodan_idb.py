# =============================================================================
import logging
import requests
import socket
from urllib.parse import urlparse
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

def get_ip_from_url(url):
    try:
        domain = urlparse(url).hostname or url
        return socket.gethostbyname(domain)
    except Exception:
        return None

def run_shodan_idb_scan(url):
    """
    Queries Shodan InternetDB (Free, Passive, No Auth) for open ports, cpes, and vulns.
    Returns a list of finding dicts.
    """
    ip = get_ip_from_url(url)
    if not ip:
        logger.warning(f"Shodan IDB: Could not resolve IP for {url}")
        return []

    logger.info(f"Shodan IDB Started: Passive query for {ip}")
    add_log_entry("INFO", f"Shodan IDB Started: Passive query for {ip}")

    findings = []
    api_url = f"https://internetdb.shodan.io/{ip}"

    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            ports = data.get("ports", [])
            cpes = data.get("cpes", [])
            vulns = data.get("vulns", [])
            hostnames = data.get("hostnames", [])
            
            desc = f"IP: {data.get('ip')}\n"
            desc += f"Hostnames: {', '.join(hostnames) if hostnames else 'None'}\n"
            desc += f"Open Ports (Passive): {', '.join(map(str, ports)) if ports else 'None'}\n"
            desc += f"CPEs: {', '.join(cpes) if cpes else 'None'}\n"
            desc += f"Vulnerabilities: {', '.join(vulns) if vulns else 'None'}\n"
            
            severity = "High" if vulns else ("Medium" if ports else "Info")
            title = f"Shodan InternetDB Profiling for {ip}"
            
            findings.append({
                "severity": severity,
                "title": title,
                "description": desc,
                "template_id": "OSINT-SHODAN"
            })
            
            logger.info(f"Shodan IDB Completed: Found {len(ports)} ports and {len(vulns)} vulns.")
            add_log_entry("INFO", f"Shodan IDB Completed: Discovered {len(ports)} ports and {len(vulns)} vulnerabilities.")
        elif response.status_code == 404:
            logger.info(f"Shodan IDB Completed: No data found for {ip}.")
            add_log_entry("INFO", f"Shodan IDB Completed: No data found for {ip}.")
        else:
            logger.warning(f"Shodan IDB API error: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Shodan IDB Failed: {e}")
        
    return findings
