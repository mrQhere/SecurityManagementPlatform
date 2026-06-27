import logging

logger = logging.getLogger("smp")

# Mapping of common finding substrings to MITRE ATT&CK techniques
# Format: "substring": "TXXXX - Technique Name"
MITRE_MAPPING = {
    "sql injection": "T1190 - Exploit Public-Facing Application",
    "sqli": "T1190 - Exploit Public-Facing Application",
    "cross-site scripting": "T1190 - Exploit Public-Facing Application",
    "xss": "T1190 - Exploit Public-Facing Application",
    "command injection": "T1190 - Exploit Public-Facing Application",
    "directory traversal": "T1190 - Exploit Public-Facing Application",
    "path traversal": "T1190 - Exploit Public-Facing Application",
    "open redirect": "T1190 - Exploit Public-Facing Application",
    "ssrf": "T1190 - Exploit Public-Facing Application",
    "cve-": "T1190 - Exploit Public-Facing Application",  # Generic CVEs usually fall under this
    
    "brute force": "T1110 - Brute Force",
    "credential stuffing": "T1110 - Brute Force",
    "weak password": "T1110 - Brute Force",
    "default credential": "T1078 - Valid Accounts",
    
    "subdomain": "T1596 - Search Open Technical Databases",
    "dns record": "T1596 - Search Open Technical Databases",
    "open port": "T1595.001 - Active Scanning",
    "directory brute": "T1595.001 - Active Scanning",
    "fuzz": "T1595.001 - Active Scanning",
    
    "api key": "T1552 - Unsecured Credentials",
    "token leaked": "T1552 - Unsecured Credentials",
    "git": "T1552 - Unsecured Credentials",
    "env file": "T1552 - Unsecured Credentials",
    "hardcoded": "T1552 - Unsecured Credentials",
    
    "cors": "T1189 - Drive-by Compromise",
    "csrf": "T1189 - Drive-by Compromise",
    
    "ssl": "T1552.004 - Private Keys",
    "tls": "T1552.004 - Private Keys",
    "certificate": "T1552.004 - Private Keys",
}

def enrich_finding_with_mitre(title):
    """
    Takes a vulnerability title and returns a mapped MITRE ATT&CK ID.
    If no match is found, returns 'Unknown'.
    """
    if not title:
        return "Unknown"
        
    title_lower = title.lower()
    
    for key, mitre_id in MITRE_MAPPING.items():
        if key in title_lower:
            return mitre_id
            
    return "Unknown"
