# =============================================================================
import logging
import requests
from urllib.parse import urlparse
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

def run_hackertarget_scan(url):
    """
    Queries HackerTarget API for Reverse DNS and general host info.
    """
    domain = urlparse(url).hostname or url
    
    logger.info(f"HackerTarget Started: Reverse DNS profiling for {domain}")
    add_log_entry("INFO", f"HackerTarget Started: Reverse DNS profiling for {domain}")

    findings = []
    api_url = f"https://api.hackertarget.com/reversedns/?q={domain}"

    try:
        response = requests.get(api_url, timeout=15)
        if response.status_code == 200:
            text = response.text.strip()
            
            # API returns error message if quota exceeded
            if "error" in text.lower() or "API count exceeded" in text:
                logger.warning("HackerTarget API quota exceeded or error.")
                return findings
                
            lines = text.split("\n")
            desc = f"HackerTarget Reverse DNS returned {len(lines)} records:\n\n"
            desc += text[:1500]
            
            findings.append({
                "severity": "Info",
                "title": "HackerTarget Reverse DNS Mapping",
                "description": desc,
                "template_id": "OSINT-HT"
            })
            
            logger.info(f"HackerTarget Completed: {len(lines)} records found.")
            add_log_entry("INFO", f"HackerTarget Completed: Mapping successful.")
        else:
            logger.warning(f"HackerTarget API error: {response.status_code}")
            
    except Exception as e:
        logger.error(f"HackerTarget Failed: {e}")
        
    return findings
