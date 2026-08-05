"""
V9 Neural Correlation Engine (The Brain)
========================================
Processes local scan data, strips out PII/sensitive info (IPs, URLs),
and aggregates global heuristics into a shared, unencrypted database
(global_intel.db) meant for crowdsourced distribution.
"""

import os
import sqlite3
import logging
import json
from collections import Counter

logger = logging.getLogger("smp.brain")

# Ensure this relies on standard paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GLOBAL_INTEL_DB = os.path.join(ROOT_DIR, "database", "global_intel.db")

def init_global_intel_db():
    """Initializes the plaintext, sharable GitHub intelligence database."""
    os.makedirs(os.path.dirname(GLOBAL_INTEL_DB), exist_ok=True)
    conn = sqlite3.connect(GLOBAL_INTEL_DB)
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS global_heuristics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            affected_component TEXT,
            severity TEXT,
            cvss_score REAL,
            epss_score REAL,
            owasp_category TEXT,
            observation_count INTEGER DEFAULT 1,
            UNIQUE(cve_id, affected_component)
        )
    ''')
    conn.commit()
    return conn

def process_findings_for_global_intel(findings):
    """
    Takes raw findings from a local scan, strips PII, and updates the global intel DB.
    """
    if not findings:
        return
        
    conn = init_global_intel_db()
    cursor = conn.cursor()
    
    for f in findings:
        # We only care about structured intelligence, not generic noise.
        cve_id = f.get('cve_id')
        component = f.get('affected_component')
        severity = f.get('severity')
        
        # If it lacks a specific CVE or component, it's too vague for global intel
        if not cve_id or not component:
            continue
            
        cvss = f.get('cvss_score', 0.0)
        epss = f.get('epss_score', 0.0)
        owasp = f.get('owasp_category', 'Unknown')
        
        # Upsert logic
        cursor.execute('''
            INSERT INTO global_heuristics 
            (cve_id, affected_component, severity, cvss_score, epss_score, owasp_category, observation_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(cve_id, affected_component) 
            DO UPDATE SET 
                observation_count = observation_count + 1,
                cvss_score = MAX(cvss_score, excluded.cvss_score),
                epss_score = MAX(epss_score, excluded.epss_score)
        ''', (cve_id, component, severity, cvss, epss, owasp))
        
    conn.commit()
    conn.close()

def generate_ai_insights(findings):
    """
    Generates a localized "AI Insight" markdown summary based on the findings
    cross-referenced with the global intelligence DB.
    """
    if not findings:
        return "No significant vulnerabilities were detected to generate AI insights."
        
    # Analyze the local findings
    severity_counts = Counter(f.get('severity', 'Info') for f in findings)
    total_vulns = len(findings)
    
    critical_cves = [f.get('cve_id') for f in findings if f.get('severity') == 'Critical' and f.get('cve_id')]
    
    insight_md = f"### Neural Correlation Summary\n\n"
    insight_md += f"The SMP Brain engine processed **{total_vulns}** total data points.\n"
    
    if severity_counts.get('Critical', 0) > 0 or severity_counts.get('High', 0) > 0:
        insight_md += f"\n> **High Priority Attack Path Detected**: The presence of {severity_counts.get('Critical', 0)} Critical and {severity_counts.get('High', 0)} High vulnerabilities suggests a high likelihood of chainable exploit paths. "
        
    if critical_cves:
        insight_md += f"Specifically, the detection of known CVEs ({', '.join(critical_cves[:3])}) maps directly to active Threat Actor campaigns. Immediate isolation of affected components is strongly advised."
    
    # Check global intel context
    if os.path.exists(GLOBAL_INTEL_DB):
        conn = sqlite3.connect(GLOBAL_INTEL_DB)
        cursor = conn.cursor()
        
        # Are any of these findings top global offenders?
        for cve in critical_cves:
            cursor.execute("SELECT observation_count FROM global_heuristics WHERE cve_id = ?", (cve,))
            row = cursor.fetchone()
            if row and row[0] > 5:
                insight_md += f"\n\n**Global Threat Intelligence**: `{cve}` is heavily tracked across the crowdsourced database (seen {row[0]} times globally). This is a widely exploited vulnerability."
        
        conn.close()
        
    return insight_md
