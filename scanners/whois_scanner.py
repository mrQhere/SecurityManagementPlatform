# =============================================================================
import logging
import subprocess
from urllib.parse import urlparse
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

def run_whois_scan(url):
    """
    Runs local whois command.
    """
    domain = urlparse(url).hostname or url
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"Whois Started: Querying registry for {domain}")
    add_log_entry("INFO", f"Whois Started: Querying registry for {domain}")

    findings = []
    
    try:
        process = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        if process.returncode == 0:
            out = process.stdout.strip()
            
            # Extract basic info
            desc = out[:2000] # Limit length
            if len(out) > 2000:
                desc += "\n... [Truncated for brevity]"
                
            findings.append({
                "severity": "Info",
                "title": "Whois Domain Registry Information",
                "description": desc,
                "template_id": "OSINT-WHOIS"
            })
            logger.info("Whois Completed.")
            add_log_entry("INFO", "Whois Completed.")
        else:
            logger.warning("Whois command failed (perhaps whois is not installed).")
            
    except Exception as e:
        logger.error(f"Whois Failed: {e}")
        
    return findings
