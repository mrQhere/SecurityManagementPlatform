"""
Compliance Mapper V6.0
=======================
Maps SMP finding types and CWE IDs to compliance control references:
  - OWASP Top 10 2021
  - CIS Controls v8
  - ISO 27001:2022 Annex A

Usage:
    from tools.compliance_mapper import map_finding_to_controls
    controls = map_finding_to_controls("SQL Injection", "CWE-89")
    # Returns: {"owasp": "A03:2021", "cis": "CIS 16.1", "iso": "A.8.28"}
"""
import logging
import re

logger = logging.getLogger("smp")

# ── OWASP Top 10 2021 Mapping ────────────────────────────────────────────────
_OWASP_2021 = {
    "A01:2021 - Broken Access Control": [
        "broken access control", "idor", "directory traversal", "path traversal",
        "unauthorized", "privilege escalation", "cwe-22", "cwe-284", "cwe-285",
        "cwe-639", "cwe-918",
    ],
    "A02:2021 - Cryptographic Failures": [
        "ssl", "tls", "weak cipher", "weak encryption", "plaintext", "sensitive data",
        "certificate", "cwe-310", "cwe-311", "cwe-312", "cwe-326", "cwe-327", "cwe-328",
    ],
    "A03:2021 - Injection": [
        "sql injection", "sqli", "command injection", "ldap injection", "xpath injection",
        "nosql injection", "os command", "xxe", "cwe-89", "cwe-77", "cwe-78", "cwe-611",
    ],
    "A04:2021 - Insecure Design": [
        "insecure design", "missing rate limiting", "business logic", "cwe-209", "cwe-656",
    ],
    "A05:2021 - Security Misconfiguration": [
        "misconfiguration", "default credentials", "missing security headers", "cors",
        "open redirect", "directory listing", "debug mode", "cwe-16", "cwe-732",
    ],
    "A06:2021 - Vulnerable and Outdated Components": [
        "outdated", "vulnerable component", "cve-", "known vulnerability", "end of life",
        "retire.js", "cwe-1035", "cwe-937",
    ],
    "A07:2021 - Identification and Authentication Failures": [
        "authentication", "brute force", "weak password", "session", "jwt", "cookie",
        "cwe-287", "cwe-306", "cwe-307", "cwe-521", "cwe-522",
    ],
    "A08:2021 - Software and Data Integrity Failures": [
        "deserialization", "integrity", "supply chain", "ci/cd", "cwe-502", "cwe-345",
    ],
    "A09:2021 - Security Logging and Monitoring Failures": [
        "logging", "monitoring", "audit", "insufficient logging", "cwe-778", "cwe-223",
    ],
    "A10:2021 - Server-Side Request Forgery": [
        "ssrf", "server-side request forgery", "cwe-918",
    ],
}

# ── CIS Controls v8 Mapping ──────────────────────────────────────────────────
_CIS_CONTROLS_V8 = {
    "CIS 1 - Inventory and Control of Enterprise Assets": [
        "asset", "inventory", "unauthorized device",
    ],
    "CIS 2 - Inventory and Control of Software Assets": [
        "software inventory", "unauthorized software", "outdated component",
    ],
    "CIS 3 - Data Protection": [
        "data exposure", "plaintext", "sensitive data", "encryption", "cwe-312",
    ],
    "CIS 4 - Secure Configuration": [
        "misconfiguration", "default credentials", "security headers", "cors", "cwe-16",
    ],
    "CIS 5 - Account Management": [
        "authentication", "weak password", "privilege", "cwe-521", "cwe-522",
    ],
    "CIS 6 - Access Control Management": [
        "access control", "idor", "authorization", "cwe-284", "cwe-285",
    ],
    "CIS 7 - Continuous Vulnerability Management": [
        "cve-", "vulnerability", "patch", "outdated", "retire.js",
    ],
    "CIS 9 - Email and Web Browser Protections": [
        "xss", "phishing", "open redirect", "cwe-79",
    ],
    "CIS 12 - Network Infrastructure Management": [
        "port", "network", "firewall", "traceroute", "dns",
    ],
    "CIS 13 - Network Monitoring and Defense": [
        "ssrf", "injection", "command", "cwe-78", "cwe-918",
    ],
    "CIS 16 - Application Software Security": [
        "sql injection", "xss", "csrf", "jwt", "deserialization", "cwe-89", "cwe-79",
    ],
}

# ── ISO 27001:2022 Annex A Mapping ───────────────────────────────────────────
_ISO_27001_2022 = {
    "A.5.9 - Inventory of Information and other Assets": [
        "asset", "inventory",
    ],
    "A.5.15 - Access Control": [
        "access control", "idor", "authorization", "cwe-284",
    ],
    "A.5.17 - Authentication Information": [
        "authentication", "password", "brute force", "cwe-521",
    ],
    "A.8.7 - Protection against Malware": [
        "malware", "ransomware", "backdoor",
    ],
    "A.8.8 - Management of Technical Vulnerabilities": [
        "cve-", "vulnerability", "patch", "outdated", "retire.js",
    ],
    "A.8.20 - Networks Security": [
        "port", "firewall", "network", "dns", "ssl", "tls",
    ],
    "A.8.23 - Web Filtering": [
        "open redirect", "xss", "phishing",
    ],
    "A.8.24 - Use of Cryptography": [
        "ssl", "tls", "weak cipher", "weak encryption", "certificate", "cwe-310",
    ],
    "A.8.25 - Secure Development Life Cycle": [
        "sql injection", "xss", "csrf", "command injection", "deserialization",
    ],
    "A.8.28 - Secure Coding": [
        "injection", "xss", "sql injection", "cwe-89", "cwe-79", "cwe-78",
    ],
    "A.8.29 - Security Testing in Development and Acceptance": [
        "vulnerability scan", "penetration test",
    ],
}


def _match_controls(title: str, cwe_id: str, control_map: dict) -> list:
    """Match a finding to controls using keyword and CWE matching."""
    title_lower = (title or "").lower()
    cwe_lower = (cwe_id or "").lower()
    matched = []
    for control, keywords in control_map.items():
        for kw in keywords:
            kw = kw.lower()
            if kw in title_lower or kw in cwe_lower:
                matched.append(control)
                break
    return matched


def map_finding_to_controls(title: str, cwe_id: str = "") -> dict:
    """
    Map a finding to compliance controls.
    
    Args:
        title: Finding title/description
        cwe_id: Optional CWE ID (e.g. "CWE-89")
    
    Returns:
        dict with keys: owasp, cis, iso27001 (each a list of matched controls)
    """
    owasp   = _match_controls(title, cwe_id, _OWASP_2021)
    cis     = _match_controls(title, cwe_id, _CIS_CONTROLS_V8)
    iso     = _match_controls(title, cwe_id, _ISO_27001_2022)

    return {
        "owasp":    owasp   or ["Not directly mapped"],
        "cis":      cis     or ["Not directly mapped"],
        "iso27001": iso     or ["Not directly mapped"],
    }


def get_compliance_summary(findings: list) -> dict:
    """
    Get a compliance coverage summary across all findings.
    
    Args:
        findings: List of finding dicts (with 'title' and optionally 'cwe_id')
    
    Returns:
        dict with compliance coverage percentages and top gaps
    """
    owasp_hit = set()
    cis_hit   = set()
    iso_hit   = set()

    for f in findings:
        controls = map_finding_to_controls(
            f.get("title", ""),
            f.get("cwe_id", "")
        )
        owasp_hit.update(controls["owasp"])
        cis_hit.update(controls["cis"])
        iso_hit.update(controls["iso27001"])

    owasp_hit.discard("Not directly mapped")
    cis_hit.discard("Not directly mapped")
    iso_hit.discard("Not directly mapped")

    return {
        "owasp_top10_coverage": round(len(owasp_hit) / len(_OWASP_2021) * 100),
        "cis_controls_coverage": round(len(cis_hit) / len(_CIS_CONTROLS_V8) * 100),
        "iso27001_coverage": round(len(iso_hit) / len(_ISO_27001_2022) * 100),
        "owasp_categories_hit": sorted(owasp_hit),
        "cis_categories_hit": sorted(cis_hit),
        "iso_categories_hit": sorted(iso_hit),
    }
