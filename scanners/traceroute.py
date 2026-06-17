# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# =============================================================================
import subprocess
import urllib.parse
import logging
from tools.config_manager import load_settings
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

def extract_host_from_url(url):
    try:
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "http://" + url
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or parsed.path.split("/")[0]
        if not host:
            return url
        return host.strip("/").strip()
    except Exception as e:
        logger.error(f"Failed to parse host from URL {url}: {e}")
        return url

def run_traceroute(url):
    """
    Runs traceroute against the target.
    Returns a list of finding dicts.
    """
    host = extract_host_from_url(url)
    settings = load_settings()
    bin_path = settings.get("traceroute_path", "traceroute")
    
    logger.info(f"Traceroute Started: Tracing path to {host}")
    add_log_entry("INFO", f"Traceroute Started: Tracing path to {host}")
    
    findings = []
    # Using -I for ICMP traceroute (often gets through firewalls better than default UDP)
    cmd = [bin_path, "-I", host]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False
        )
        
        # Traceroute can take a minute if many hops drop
        stdout, stderr = process.communicate(timeout=120)
        
        if stdout.strip():
            findings.append({
                "severity": "Info",
                "title": "Network Path (Traceroute) Discovered",
                "description": f"Traceroute output for {host}:\n\n{stdout.strip()}",
                "template_id": ""
            })
            
        logger.info("Traceroute Completed.")
        add_log_entry("INFO", "Traceroute Completed.")
        return findings
        
    except FileNotFoundError:
        logger.warning(f"Traceroute not installed ('{bin_path}' not found).")
        add_log_entry("WARNING", f"Traceroute not installed. Skipping.")
        return None
    except subprocess.TimeoutExpired:
        process.kill()
        logger.error(f"Traceroute Timed Out for {url}")
        add_log_entry("ERROR", f"Traceroute Timed Out for {url}")
        return None
    except Exception as e:
        logger.error(f"Traceroute Failed: {e}")
        add_log_entry("ERROR", f"Traceroute Failed: {e}")
        return None
