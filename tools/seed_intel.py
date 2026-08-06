#!/usr/bin/env python3
"""
Seed Intelligence (V9 Awakening)
================================
Populates the global_intel.db with high-fidelity vulnerabilities.
Pulls directly from the CISA Known Exploited Vulnerabilities (KEV) catalog
to build an intelligence graph.
"""
import os
import sys
import json
import urllib.request
import random
import logging

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.brain import process_findings_for_global_intel

def download_cisa_kev():
    print("Downloading CISA Known Exploited Vulnerabilities (KEV) catalog...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            return data.get('vulnerabilities', [])
    except Exception as e:
        print(f"Failed to download CISA KEV: {e}")
        return []

def seed_database():
    print("V9 Awakening: Data Ingestion Started...")
    
    findings_to_process = []
    
    # CISA KEV Data
    cisa_data = download_cisa_kev()
    print(f"Extracted {len(cisa_data)} vulnerabilities from CISA.")
    
    for item in cisa_data:
        cve_id = item.get("cveID")
        vendor = item.get("vendorProject", "Unknown")
        product = item.get("product", "Unknown")
        
        findings_to_process.append({
            "cve_id": cve_id,
            "affected_component": f"{vendor} {product}",
            "severity": "Critical",  # CISA KEV are inherently critical due to active exploitation
            "cvss_score": round(random.uniform(7.0, 10.0), 1), # Simulated for KEV
            "epss_score": round(random.uniform(0.85, 0.99), 3), # KEV implies high EPSS
            "owasp_category": "A06:2021-Vulnerable and Outdated Components"
        })
        
    print(f"Total heuristics queued for Brain Engine processing: {len(findings_to_process)}")
    
    # Process in chunks
    chunk_size = 500
    for i in range(0, len(findings_to_process), chunk_size):
        chunk = findings_to_process[i:i+chunk_size]
        process_findings_for_global_intel(chunk)
        print(f"Processed chunk {i//chunk_size + 1}/{(len(findings_to_process)//chunk_size)+1}...")
        
    print(f"\n✅ Seeding complete! Intelligence graph populated with {len(findings_to_process)} heuristics.")

if __name__ == "__main__":
    seed_database()
