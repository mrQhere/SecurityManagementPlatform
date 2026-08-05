"""
Compliance Mapper V7
=====================
Maps SMP finding types and CWE IDs to compliance control references:
  - OWASP Top 10 2021
  - CIS Controls v8
  - ISO 27001:2022 Annex A
  - SOC 2 Type II (Trust Services Criteria)
  - PCI-DSS v7.0.4 (Requirements 6, 11)

Usage:
    from tools.compliance_mapper import map_finding_to_controls
    controls = map_finding_to_controls("SQL Injection", "CWE-89")
    # Returns: {"owasp": [...], "cis": [...], "iso27001": [...],
    #            "soc2": [...], "pci_dss": [...]}

Control ID reference format:
  SOC 2  → CC6.1, CC6.6, CC7.2, ...
  PCI-DSS → Req 6.3.1, Req 6.4.1, Req 11.3.1, ...
"""
import logging

logger = logging.getLogger("smp")

# ── OWASP Top 10 2021 ─────────────────────────────────────────────────────────
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

# ── CIS Controls v8 ───────────────────────────────────────────────────────────
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

# ── ISO 27001:2022 Annex A ────────────────────────────────────────────────────
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

# ── SOC 2 Type II (Trust Services Criteria) ───────────────────────────────────
# Source: AICPA Trust Services Criteria (2017 with 2022 points of focus)
_SOC2_TYPE_II = {
    "CC6.1 - Logical and Physical Access Controls": [
        "access control", "idor", "authorization", "unauthorized", "privilege",
        "authentication", "cwe-284", "cwe-285", "cwe-287",
    ],
    "CC6.2 - Prior to Issuing System Credentials": [
        "authentication", "weak password", "brute force", "default credentials",
        "cwe-521", "cwe-307",
    ],
    "CC6.3 - Role-Based Access and Least Privilege": [
        "privilege escalation", "idor", "broken access control", "cwe-284",
    ],
    "CC6.6 - Security Threats from Outside Boundaries": [
        "ssrf", "injection", "xss", "sql injection", "command injection",
        "xxe", "cwe-89", "cwe-79", "cwe-78", "cwe-918",
    ],
    "CC6.7 - Transmission of Data": [
        "ssl", "tls", "weak cipher", "plaintext", "certificate", "cwe-311", "cwe-326",
    ],
    "CC6.8 - Prevention and Detection of Unauthorized Software": [
        "malware", "backdoor", "unauthorized software", "cve-", "vulnerable component",
    ],
    "CC7.1 - Detection of Configuration Changes": [
        "misconfiguration", "default credentials", "cors", "security headers", "cwe-16",
    ],
    "CC7.2 - Monitoring for Anomalies and Threats": [
        "ssrf", "scanning", "reconnaissance", "traceroute", "port", "cwe-918",
    ],
    "CC7.3 - Evaluation of Security Events": [
        "logging", "monitoring", "audit", "insufficient logging", "cwe-778",
    ],
    "CC8.1 - Change Management Process": [
        "outdated", "patch", "cve-", "retire.js", "vulnerable component",
    ],
    "CC9.2 - Vendor and Business Partner Risk": [
        "supply chain", "third party", "dependency", "cwe-1035",
    ],
}

# ── PCI-DSS v7.0.4 ─────────────────────────────────────────────────────────────
# Source: PCI Security Standards Council PCI DSS v7.0.4 (March 2022)
_PCI_DSS_V4 = {
    "Req 6.2.4 - Software Engineering Techniques (Injection Prevention)": [
        "sql injection", "sqli", "command injection", "xxe", "ldap injection",
        "cwe-89", "cwe-77", "cwe-78",
    ],
    "Req 6.3.1 - Security Vulnerabilities Identified and Addressed": [
        "cve-", "outdated", "vulnerable component", "patch", "retire.js",
        "cwe-1035", "cwe-937",
    ],
    "Req 6.3.2 - Inventory of Bespoke and Custom Software": [
        "software inventory", "asset", "sbom", "dependency",
    ],
    "Req 6.4.1 - Web Application Protection (WAF / DAST)": [
        "xss", "csrf", "open redirect", "cors", "injection", "cwe-79", "cwe-352",
    ],
    "Req 6.4.2 - Automated Technical Solution for Web Apps": [
        "xss", "sql injection", "vulnerability scan", "penetration test",
    ],
    "Req 7.2.1 - Access Control Model": [
        "access control", "idor", "authorization", "privilege", "cwe-284",
    ],
    "Req 8.3.2 - Strong Cryptography for Authentication": [
        "authentication", "weak password", "brute force", "cwe-521", "cwe-307",
    ],
    "Req 8.6.1 - Interactive Login Accounts (MFA)": [
        "brute force", "authentication", "jwt", "session", "cwe-307", "cwe-522",
    ],
    "Req 11.3.1 - External Penetration Testing": [
        "penetration test", "vulnerability scan", "open port", "nmap",
    ],
    "Req 11.3.2 - Internal Penetration Testing": [
        "ssrf", "internal", "network", "port", "firewall",
    ],
    "Req 12.3.2 - Targeted Risk Analysis": [
        "risk", "cvss", "epss", "severity", "critical",
    ],
    "Req 4.2.1 - Strong Cryptography in Transit": [
        "ssl", "tls", "weak cipher", "certificate", "plaintext", "cwe-311", "cwe-326",
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
    Map a finding to compliance controls across all frameworks.

    Args:
        title:  Finding title/description
        cwe_id: Optional CWE ID (e.g. "CWE-89")

    Returns:
        dict with keys: owasp, cis, iso27001, soc2, pci_dss
        (each a list of matched control strings, or ["Not directly mapped"])
    """
    return {
        "owasp":    _match_controls(title, cwe_id, _OWASP_2021)   or ["Not directly mapped"],
        "cis":      _match_controls(title, cwe_id, _CIS_CONTROLS_V8) or ["Not directly mapped"],
        "iso27001": _match_controls(title, cwe_id, _ISO_27001_2022)  or ["Not directly mapped"],
        "soc2":     _match_controls(title, cwe_id, _SOC2_TYPE_II)    or ["Not directly mapped"],
        "pci_dss":  _match_controls(title, cwe_id, _PCI_DSS_V4)      or ["Not directly mapped"],
    }


def get_compliance_summary(findings: list) -> dict:
    """
    Get a compliance coverage summary across all findings.

    Args:
        findings: List of finding dicts (with 'title' and optionally 'cwe_id')

    Returns:
        dict with:
          - per-framework coverage percentage
          - per-framework matched control IDs
          - blocking_controls: controls violated in Critical/High findings
            (the ones that matter most for an audit conversation)
    """
    owasp_hit: set = set()
    cis_hit:   set = set()
    iso_hit:   set = set()
    soc2_hit:  set = set()
    pci_hit:   set = set()

    blocking: list = []  # Critical/High findings with their SOC2/PCI control IDs

    for f in findings:
        controls = map_finding_to_controls(
            f.get("title", ""),
            f.get("cwe_id", "")
        )
        owasp_hit.update(controls["owasp"])
        cis_hit.update(controls["cis"])
        iso_hit.update(controls["iso27001"])
        soc2_hit.update(controls["soc2"])
        pci_hit.update(controls["pci_dss"])

        severity = (f.get("severity") or "").lower()
        if severity in ("critical", "high"):
            soc2_blocking  = [c for c in controls["soc2"]    if c != "Not directly mapped"]
            pci_blocking   = [c for c in controls["pci_dss"] if c != "Not directly mapped"]
            if soc2_blocking or pci_blocking:
                blocking.append({
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "soc2":     soc2_blocking,
                    "pci_dss":  pci_blocking,
                })

    for s in (owasp_hit, cis_hit, iso_hit, soc2_hit, pci_hit):
        s.discard("Not directly mapped")

    return {
        "owasp_top10_coverage":  round(len(owasp_hit) / max(len(_OWASP_2021), 1) * 100),
        "cis_controls_coverage": round(len(cis_hit)   / max(len(_CIS_CONTROLS_V8), 1) * 100),
        "iso27001_coverage":     round(len(iso_hit)   / max(len(_ISO_27001_2022), 1) * 100),
        "soc2_coverage":         round(len(soc2_hit)  / max(len(_SOC2_TYPE_II), 1) * 100),
        "pci_dss_coverage":      round(len(pci_hit)   / max(len(_PCI_DSS_V4), 1) * 100),
        # Per-framework matched control IDs
        "owasp_categories_hit":  sorted(owasp_hit),
        "cis_categories_hit":    sorted(cis_hit),
        "iso_categories_hit":    sorted(iso_hit),
        "soc2_controls_hit":     sorted(soc2_hit),
        "pci_dss_controls_hit":  sorted(pci_hit),
        # High/Critical findings that block an audit — the most actionable output
        "audit_blocking_findings": blocking,
    }


def format_compliance_table(summary: dict) -> str:
    """
    Return a compact text table of compliance coverage — useful for report footers.

    Example output:
        Framework        Coverage  Controls Matched
        OWASP Top 10       70%     7/10
        CIS Controls        45%     5/11
        ISO 27001          55%     6/11
        SOC 2 Type II       40%     4/10
        PCI-DSS v7.0.4        50%     6/12
    """
    lines = [
        "Framework          Coverage   Controls Matched",
        "─" * 48,
        f"OWASP Top 10        {summary['owasp_top10_coverage']:>3}%     "
        f"{len(summary['owasp_categories_hit'])}/{len(_OWASP_2021)}",
        f"CIS Controls v8     {summary['cis_controls_coverage']:>3}%     "
        f"{len(summary['cis_categories_hit'])}/{len(_CIS_CONTROLS_V8)}",
        f"ISO 27001:2022      {summary['iso27001_coverage']:>3}%     "
        f"{len(summary['iso_categories_hit'])}/{len(_ISO_27001_2022)}",
        f"SOC 2 Type II       {summary['soc2_coverage']:>3}%     "
        f"{len(summary['soc2_controls_hit'])}/{len(_SOC2_TYPE_II)}",
        f"PCI-DSS v7.0.4        {summary['pci_dss_coverage']:>3}%     "
        f"{len(summary['pci_dss_controls_hit'])}/{len(_PCI_DSS_V4)}",
    ]
    return "\n".join(lines)
