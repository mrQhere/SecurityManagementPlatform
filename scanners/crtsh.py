# =============================================================================
import logging
import requests
from urllib.parse import urlparse
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

def run_crtsh_scan(url):
    """
    Queries crt.sh (Certificate Transparency Logs) for subdomains.
    """
    domain = urlparse(url).hostname or url
    # strip www. if present to get apex domain
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"CRT.sh Started: Enumerating subdomains for {domain}")
    add_log_entry("INFO", f"CRT.sh Started: Enumerating subdomains for {domain}")

    findings = []
    api_url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(api_url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub and not sub.startswith("*"):
                        subdomains.add(sub)
            
            if subdomains:
                subs_list = sorted(list(subdomains))
                desc = f"Discovered {len(subs_list)} subdomains via Certificate Transparency logs:\n\n"
                desc += "\n".join(subs_list[:100])
                if len(subs_list) > 100:
                    desc += f"\n... and {len(subs_list)-100} more."
                    
                findings.append({
                    "severity": "Info",
                    "title": f"CRT.sh Subdomain Discovery: {len(subs_list)} subdomains",
                    "description": desc,
                    "template_id": "OSINT-CRTSH"
                })
            
            logger.info(f"CRT.sh Completed: Found {len(subdomains)} subdomains.")
            add_log_entry("INFO", f"CRT.sh Completed: Discovered {len(subdomains)} subdomains.")
        else:
            logger.warning(f"CRT.sh API error: {response.status_code}")
            
    except Exception as e:
        logger.error(f"CRT.sh Failed: {e}")
        
    return findings
