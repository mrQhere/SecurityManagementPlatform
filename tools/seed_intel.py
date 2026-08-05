#!/usr/bin/env python3
"""
Seed Intelligence (V9 Awakening)
================================
Populates the global_intel.db with a high-fidelity baseline of the world's 
most critical vulnerabilities (Log4Shell, PrintNightmare, Heartbleed, etc.).
This ensures the Neural Engine has immediate context for any new install.
"""
import os
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.brain import process_findings_for_global_intel

def seed_database():
    print("V9 Awakening: Seeding global intelligence database...")
    
    # Simulate high-value findings from across the world
    baseline_intel = [
        {
            "cve_id": "CVE-2021-44228",
            "affected_component": "log4j-core",
            "severity": "Critical",
            "cvss_score": 10.0,
            "epss_score": 0.97,
            "owasp_category": "A06:2021-Vulnerable and Outdated Components"
        },
        {
            "cve_id": "CVE-2021-34527",
            "affected_component": "Windows Print Spooler",
            "severity": "Critical",
            "cvss_score": 8.8,
            "epss_score": 0.92,
            "owasp_category": "A01:2021-Broken Access Control"
        },
        {
            "cve_id": "CVE-2014-0160",
            "affected_component": "OpenSSL 1.0.1",
            "severity": "Critical",
            "cvss_score": 7.5,
            "epss_score": 0.85,
            "owasp_category": "A02:2021-Cryptographic Failures"
        },
        {
            "cve_id": "CVE-2017-0144",
            "affected_component": "SMBv1",
            "severity": "Critical",
            "cvss_score": 8.1,
            "epss_score": 0.96,
            "owasp_category": "A05:2021-Security Misconfiguration"
        },
        {
            "cve_id": "CVE-2022-22965",
            "affected_component": "Spring Framework",
            "severity": "Critical",
            "cvss_score": 9.8,
            "epss_score": 0.94,
            "owasp_category": "A03:2021-Injection"
        },
        {
            "cve_id": "CVE-2019-11043",
            "affected_component": "PHP-FPM",
            "severity": "High",
            "cvss_score": 9.8,
            "epss_score": 0.88,
            "owasp_category": "A03:2021-Injection"
        },
        {
            "cve_id": "CVE-2020-1472",
            "affected_component": "Netlogon",
            "severity": "Critical",
            "cvss_score": 10.0,
            "epss_score": 0.98,
            "owasp_category": "A07:2021-Identification and Authentication Failures"
        }
    ]
    
    # Process them 10 times to give them a high 'observation_count' 
    # so the Brain flags them as "Global Threat Intelligence".
    for _ in range(15):
        process_findings_for_global_intel(baseline_intel)
        
    print("Seeding complete! Intelligence graph populated with baseline heuristics.")

if __name__ == "__main__":
    seed_database()
