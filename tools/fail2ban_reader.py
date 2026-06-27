import os
import re
import logging
from datetime import datetime

logger = logging.getLogger("smp")

def get_active_bans(log_path="/var/log/fail2ban.log"):
    """
    Parses the fail2ban log file to extract actively banned IPs.
    If the file is inaccessible, returns an empty list or mock data for demonstration.
    
    Returns a list of dicts:
    [
        {"ip": "192.168.1.100", "jail": "sshd", "timestamp": "2023-10-25 10:15:30"},
        ...
    ]
    """
    active_bans = {}
    
    if not os.path.isfile(log_path):
        logger.warning(f"Fail2Ban log file not found at {log_path}. Mocking data for demonstration.")
        # Provide some mock data if the log isn't there, so the dashboard has something to show
        return [
            {"ip": "198.51.100.23", "jail": "nginx-botsearch", "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            {"ip": "203.0.113.45", "jail": "sshd", "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        ]

    try:
        # Regex to match Ban and Unban actions
        # Example: 2023-10-25 10:15:30,123 fail2ban.actions [1234]: NOTICE  [sshd] Ban 192.168.1.100
        pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?\[(.*?)\] (Ban|Unban|Restore Ban) ([\w\.\:]+)")
        
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    timestamp, jail, action, ip = match.groups()
                    if action in ["Ban", "Restore Ban"]:
                        active_bans[ip] = {"ip": ip, "jail": jail, "timestamp": timestamp}
                    elif action == "Unban":
                        if ip in active_bans:
                            del active_bans[ip]
                            
        return list(active_bans.values())
        
    except PermissionError:
        logger.error(f"Permission denied when trying to read {log_path}. Ensure the SMP process has read access.")
        return []
    except Exception as e:
        logger.error(f"Error reading Fail2Ban log: {e}")
        return []

def get_threat_summary():
    """
    Returns a summary of the active threat feeds (Fail2Ban).
    """
    bans = get_active_bans()
    jails = {}
    for b in bans:
        jails[b["jail"]] = jails.get(b["jail"], 0) + 1
        
    return {
        "total_active_bans": len(bans),
        "bans_by_jail": jails,
        "recent_bans": sorted(bans, key=lambda x: x["timestamp"], reverse=True)[:10]
    }
