# =============================================================================
import logging
import requests
from urllib.parse import urlparse
from tools.db_manager import add_log_entry

logger = logging.getLogger("smp.scan")

def run_wayback_scan(url):
    """
    Queries Wayback Machine (Archive.org) CDX API for historical endpoints/directories.
    Returns a list of finding dicts.
    """
    domain = urlparse(url).hostname or url
    logger.info(f"Wayback Machine Started: Mapping directories for {domain}")
    add_log_entry("INFO", f"Wayback Machine Started: Mapping directories for {domain}")

    findings = []
    # Collapse by urlkey to avoid thousands of duplicate exact paths, limit to 2000 results
    api_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,mimetype,statuscode&collapse=urlkey&limit=2000"

    try:
        response = requests.get(api_url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:
                # The first row is the header ["original", "mimetype", "statuscode"]
                endpoints = data[1:]
                
                # We specifically look for directories and interesting files
                interesting = []
                all_paths = []
                for row in endpoints:
                    if len(row) >= 1:
                        path = row[0]
                        all_paths.append(path)
                        # Flag interesting extensions or paths
                        path_lower = path.lower()
                        if any(x in path_lower for x in ['.env', 'config.php', 'wp-config', 'backup', '.sql', '.zip', '.tar.gz', 'admin/', 'login', 'api/']):
                            interesting.append(path)
                
                desc = f"Wayback Machine discovered {len(all_paths)} historical endpoints.\n\n"
                
                if interesting:
                    desc += "Highly Interesting/Sensitive Endpoints Discovered:\n"
                    desc += "\n".join(interesting[:50]) # Limit to 50
                    if len(interesting) > 50:
                        desc += f"\n... and {len(interesting)-50} more."
                    desc += "\n\n"
                    severity = "Medium"
                else:
                    severity = "Info"
                    
                desc += "All Discovered Endpoints (Sample):\n"
                desc += "\n".join(all_paths[:100]) # Sample 100 for report
                
                findings.append({
                    "severity": severity,
                    "title": f"Wayback Machine Directory Mapping: {len(all_paths)} paths",
                    "description": desc,
                    "template_id": "OSINT-WAYBACK"
                })
                
            logger.info(f"Wayback Machine Completed: Found {len(data)-1 if len(data) > 0 else 0} historical paths.")
            add_log_entry("INFO", f"Wayback Machine Completed: Discovered {len(data)-1 if len(data) > 0 else 0} paths.")
        else:
            logger.warning(f"Wayback Machine API error: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Wayback Machine Failed: {e}")
        
    return findings
