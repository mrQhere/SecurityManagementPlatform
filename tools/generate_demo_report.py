#!/usr/bin/env python3
"""
SMP V9.5 Demo Report Generator
Generates a realistic demonstration VAPT report with synthetic (non-real) findings.

Usage:
    python3 tools/generate_demo_report.py
    python3 tools/generate_demo_report.py --output reports/my_report
    python3 tools/generate_demo_report.py --target 10.10.50.0/24

Outputs:
    <output>.json   — machine-readable report with authenticity hash
    <output>.md     — full professional VAPT report in Markdown
    <output>.pdf    — PDF version (if weasyprint is installed)
"""

import sys
import os
import json
import argparse
import datetime

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.report_generator import ReportGenerator

# ─────────────────────────────────────────────────────────────────────────────
# Demo Data — Realistic but entirely synthetic
# ─────────────────────────────────────────────────────────────────────────────

DEMO_ENGAGEMENT_ID = "ENG-2026-001"
DEMO_TARGET = "10.10.50.0/24"
DEMO_OPERATOR = "mrQhere"
DEMO_INTEL_VERSION = "NVD-2026-08-15"

DEMO_SCANNER_VERSIONS = {
    "nmap": "7.94",
    "nuclei": "3.3.0",
    "nikto": "2.1.6",
    "gobuster": "3.6.0",
    "ffuf": "2.1.0",
    "sqlmap": "1.8.2",
    "dalfox": "2.9.2",
    "ssl_scanner": "SMP-1.3",
    "headers_scanner": "SMP-1.2",
    "jwt_scanner": "SMP-1.1",
}

DEMO_ASSETS = [
    {"asset_value": "10.10.50.10", "asset_type": "ip", "source_scanner": "nmap", "confidence": 1.0},
    {"asset_value": "10.10.50.11", "asset_type": "ip", "source_scanner": "nmap", "confidence": 1.0},
    {"asset_value": "10.10.50.22", "asset_type": "ip", "source_scanner": "nmap", "confidence": 1.0},
    {"asset_value": "webserver.internal", "asset_type": "host", "source_scanner": "nmap", "confidence": 0.95},
    {"asset_value": "api.internal", "asset_type": "host", "source_scanner": "nmap", "confidence": 0.95},
    {"asset_value": "db.internal", "asset_type": "host", "source_scanner": "nmap", "confidence": 0.90},
]

DEMO_SERVICES = [
    {"port": 22, "protocol": "tcp", "state": "open", "product": "OpenSSH", "version": "8.2p1", "service_name": "ssh"},
    {"port": 80, "protocol": "tcp", "state": "open", "product": "Apache httpd", "version": "2.4.51", "service_name": "http"},
    {"port": 443, "protocol": "tcp", "state": "open", "product": "Apache httpd", "version": "2.4.51", "service_name": "https"},
    {"port": 3306, "protocol": "tcp", "state": "open", "product": "MySQL", "version": "8.0.28", "service_name": "mysql"},
    {"port": 8080, "protocol": "tcp", "state": "open", "product": "Jetty", "version": "9.4.43", "service_name": "http-proxy"},
    {"port": 6379, "protocol": "tcp", "state": "open", "product": "Redis", "version": "7.0.5", "service_name": "redis"},
    {"port": 5432, "protocol": "tcp", "state": "open", "product": "PostgreSQL", "version": "14.2", "service_name": "postgresql"},
]

DEMO_FINDINGS = [
    {
        "finding_id": "FND-2026-001",
        "fingerprint": "a1b2c3d4e5f6" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "SQL Injection in Login Endpoint — Authentication Bypass",
        "vulnerability_class": "SQL Injection",
        "cwe_id": "CWE-89",
        "cve_id": [],
        "asset_id": "asset-10-10-50-10",
        "service_id": None,
        "endpoint": "http://webserver.internal/api/v1/login",
        "parameter": "username",
        "severity": "Critical",
        "confidence": 1.0,
        "risk_score": 100.0,
        "evidence": ["EVD-001", "EVD-002"],
        "affected_observations": ["OBS-001", "OBS-002", "OBS-003"],
        "scanner_sources": ["sqlmap", "ffuf"],
        "description": (
            "A classic SQL Injection vulnerability was confirmed in the POST /api/v1/login endpoint. "
            "The `username` parameter is interpolated directly into the SQL query without parameterization "
            "or escaping. Using `' OR '1'='1` an unauthenticated attacker can bypass authentication and "
            "retrieve all user records. Time-based blind injection was also confirmed via `' AND SLEEP(5)--`."
        ),
        "remediation": (
            "1. Replace all dynamic SQL string construction with parameterized queries (prepared statements).\n"
            "2. Apply principle of least privilege to the database account — it should not have SELECT on the users table by default.\n"
            "3. Deploy a WAF rule to detect `OR 1=1`, `SLEEP(`, `UNION SELECT` patterns.\n"
            "4. Rotate all database credentials immediately."
        ),
        "validation": (
            "POST /api/v1/login with body {\"username\": \"' OR '1'='1\", \"password\": \"x\"} "
            "should return HTTP 401 after remediation."
        ),
        "status": "open",
        "provenance": {"kev": False, "epss": 0.45},
        "first_observed_at": "2026-08-15T08:00:00",
        "last_observed_at": "2026-08-15T08:12:00",
        "occurrence_count": 3,
    },
    {
        "finding_id": "FND-2026-002",
        "fingerprint": "b2c3d4e5f6a1" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "CVE-2021-44228 (Log4Shell) — Remote Code Execution via JNDI Lookup",
        "vulnerability_class": "Remote Code Execution",
        "cwe_id": "CWE-917",
        "cve_id": ["CVE-2021-44228"],
        "asset_id": "asset-10-10-50-11",
        "service_id": None,
        "endpoint": "http://api.internal:8080/",
        "parameter": "User-Agent",
        "severity": "Critical",
        "confidence": 0.95,
        "risk_score": 95.0,
        "evidence": ["EVD-003", "EVD-004"],
        "affected_observations": ["OBS-004", "OBS-005"],
        "scanner_sources": ["nuclei"],
        "description": (
            "The Jetty 9.4.43 application on port 8080 incorporates Log4j 2.14.1, which is vulnerable "
            "to CVE-2021-44228 (CVSS 10.0). The `${jndi:ldap://...}` payload in the User-Agent header "
            "triggers an outbound LDAP lookup. In an air-gapped environment this confirms the vulnerable "
            "code path is reachable. Full exploitation would require an attacker-controlled LDAP server."
        ),
        "remediation": (
            "1. Upgrade Log4j to 2.17.1 or later immediately.\n"
            "2. As interim mitigation: set `log4j2.formatMsgNoLookups=true` JVM flag.\n"
            "3. Block outbound LDAP (port 389/636) at the network perimeter.\n"
            "4. Review application logs for historical exploitation attempts."
        ),
        "validation": (
            "Send `User-Agent: ${jndi:ldap://127.0.0.1:9999/test}` after patching and confirm no "
            "outbound LDAP connection is established."
        ),
        "status": "open",
        "provenance": {"kev": True, "epss": 0.97, "cisa_due_date": "2021-12-24"},
        "first_observed_at": "2026-08-15T08:15:00",
        "last_observed_at": "2026-08-15T08:15:30",
        "occurrence_count": 1,
    },
    {
        "finding_id": "FND-2026-003",
        "fingerprint": "c3d4e5f6a1b2" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "Redis Instance Unauthenticated — No Password Set",
        "vulnerability_class": "Authentication Bypass",
        "cwe_id": "CWE-306",
        "cve_id": [],
        "asset_id": "asset-10-10-50-22",
        "service_id": None,
        "endpoint": "10.10.50.22:6379",
        "parameter": None,
        "severity": "High",
        "confidence": 1.0,
        "risk_score": 80.0,
        "evidence": ["EVD-005"],
        "affected_observations": ["OBS-006", "OBS-007"],
        "scanner_sources": ["nmap", "nuclei"],
        "description": (
            "The Redis 7.0.5 instance on port 6379 accepts connections without authentication. "
            "An attacker with network access can read all cached data, write arbitrary keys, and "
            "potentially escalate to RCE via Redis CONFIG SET to write SSH authorized_keys or "
            "cron jobs to the server filesystem."
        ),
        "remediation": (
            "1. Set a strong password: `requirepass <strong_password>` in redis.conf.\n"
            "2. Bind Redis to localhost or a private interface: `bind 127.0.0.1`.\n"
            "3. Disable dangerous commands: `rename-command CONFIG \"\"` in redis.conf.\n"
            "4. Deploy network-level ACLs to restrict access to Redis port."
        ),
        "validation": (
            "After setting requirepass, verify: `redis-cli -h 10.10.50.22 PING` returns "
            "NOAUTH Authentication required."
        ),
        "status": "open",
        "provenance": {"kev": False, "epss": 0.62},
        "first_observed_at": "2026-08-15T08:20:00",
        "last_observed_at": "2026-08-15T08:20:00",
        "occurrence_count": 1,
    },
    {
        "finding_id": "FND-2026-004",
        "fingerprint": "d4e5f6a1b2c3" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "Expired TLS Certificate (Expired 2025-06-01)",
        "vulnerability_class": "TLS / Certificate Issue",
        "cwe_id": "CWE-298",
        "cve_id": [],
        "asset_id": "asset-10-10-50-10",
        "service_id": None,
        "endpoint": "https://webserver.internal:443",
        "parameter": None,
        "severity": "Medium",
        "confidence": 1.0,
        "risk_score": 60.0,
        "evidence": ["EVD-006"],
        "affected_observations": ["OBS-008"],
        "scanner_sources": ["ssl_scanner"],
        "description": (
            "The TLS certificate for webserver.internal expired on 2025-06-01. "
            "Browsers and API clients will display certificate warnings or refuse to connect "
            "(depending on `CURL_CA_BUNDLE` settings). Additionally, the certificate uses a "
            "2048-bit RSA key which, while currently acceptable, is approaching end-of-life "
            "for high-security environments."
        ),
        "remediation": (
            "1. Renew the TLS certificate immediately (Let's Encrypt or internal CA).\n"
            "2. Consider migrating to ECDSA P-256 certificates for improved performance.\n"
            "3. Configure automated certificate renewal (certbot renew --deploy-hook).\n"
            "4. Add certificate expiry monitoring to your alerting stack."
        ),
        "validation": "openssl s_client -connect webserver.internal:443 | openssl x509 -noout -dates should show a future expiry.",
        "status": "open",
        "provenance": {"kev": False, "epss": 0.0},
        "first_observed_at": "2026-08-15T08:25:00",
        "last_observed_at": "2026-08-15T08:25:00",
        "occurrence_count": 1,
    },
    {
        "finding_id": "FND-2026-005",
        "fingerprint": "e5f6a1b2c3d4" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "Missing HTTP Security Headers (CSP, HSTS, X-Frame-Options)",
        "vulnerability_class": "Security Misconfiguration",
        "cwe_id": "CWE-16",
        "cve_id": [],
        "asset_id": "asset-10-10-50-10",
        "service_id": None,
        "endpoint": "http://webserver.internal/",
        "parameter": None,
        "severity": "Medium",
        "confidence": 1.0,
        "risk_score": 60.0,
        "evidence": ["EVD-007"],
        "affected_observations": ["OBS-009", "OBS-010"],
        "scanner_sources": ["headers_scanner"],
        "description": (
            "The web application is missing the following recommended security headers:\n"
            "- Content-Security-Policy (CSP) — absent, allows unrestricted script execution\n"
            "- Strict-Transport-Security (HSTS) — absent, allows protocol downgrade attacks\n"
            "- X-Frame-Options — absent, allows clickjacking via iframe embedding\n"
            "- X-Content-Type-Options — absent, allows MIME-sniffing attacks\n"
            "- Referrer-Policy — absent, leaks sensitive URL parameters to third parties"
        ),
        "remediation": (
            "Add the following headers to the Apache/Nginx configuration:\n"
            "```\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n"
            "X-Frame-Options: DENY\n"
            "X-Content-Type-Options: nosniff\n"
            "Referrer-Policy: strict-origin-when-cross-origin\n"
            "Permissions-Policy: geolocation=(), camera=(), microphone=()\n"
            "```"
        ),
        "validation": "curl -I https://webserver.internal/ should show all headers present.",
        "status": "open",
        "provenance": {"kev": False, "epss": 0.0},
        "first_observed_at": "2026-08-15T08:30:00",
        "last_observed_at": "2026-08-15T08:30:00",
        "occurrence_count": 4,
    },
    {
        "finding_id": "FND-2026-006",
        "fingerprint": "f6a1b2c3d4e5" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "CVE-2022-22965 (Spring4Shell) — Remote Code Execution",
        "vulnerability_class": "Remote Code Execution",
        "cwe_id": "CWE-94",
        "cve_id": ["CVE-2022-22965"],
        "asset_id": "asset-10-10-50-11",
        "service_id": None,
        "endpoint": "http://api.internal:8080/api/",
        "parameter": "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
        "severity": "High",
        "confidence": 0.80,
        "risk_score": 64.0,
        "evidence": ["EVD-008"],
        "affected_observations": ["OBS-011"],
        "scanner_sources": ["nuclei"],
        "description": (
            "The Spring Framework version in use (5.3.15) is likely affected by CVE-2022-22965 "
            "(Spring4Shell, CVSS 9.8). The vulnerability allows a remote attacker to achieve "
            "arbitrary code execution by binding HTTP request parameters to a Java object. "
            "Full exploitation confirmed requires a specific Tomcat deployment configuration. "
            "Confidence set to 80% as the exact Spring version could not be confirmed."
        ),
        "remediation": (
            "1. Upgrade Spring Framework to 5.3.18+ or 5.2.20+.\n"
            "2. Upgrade Spring Boot to 2.6.6+ or 2.5.12+.\n"
            "3. As interim mitigation, add a data binding disallow list for `class.*` parameters.\n"
            "4. Ensure Tomcat is version 9.0.62+ / 8.5.78+."
        ),
        "validation": "Send the CVE-specific PoC payload after patching and verify a non-exploitable response.",
        "status": "open",
        "provenance": {"kev": True, "epss": 0.89, "cisa_due_date": "2022-04-25"},
        "first_observed_at": "2026-08-15T08:35:00",
        "last_observed_at": "2026-08-15T08:35:00",
        "occurrence_count": 1,
    },
    {
        "finding_id": "FND-2026-007",
        "fingerprint": "a7b8c9d0e1f2" * 5,
        "engagement_id": DEMO_ENGAGEMENT_ID,
        "title": "Directory Listing Enabled — Source Code Exposure Risk",
        "vulnerability_class": "Information Disclosure",
        "cwe_id": "CWE-548",
        "cve_id": [],
        "asset_id": "asset-10-10-50-10",
        "service_id": None,
        "endpoint": "http://webserver.internal/uploads/",
        "parameter": None,
        "severity": "Low",
        "confidence": 1.0,
        "risk_score": 30.0,
        "evidence": ["EVD-009"],
        "affected_observations": ["OBS-012"],
        "scanner_sources": ["nikto", "gobuster"],
        "description": (
            "Apache directory listing is enabled for the /uploads/ directory. "
            "This exposes the names and sizes of uploaded files to unauthenticated visitors. "
            "While not directly exploitable, it aids reconnaissance and may expose user data."
        ),
        "remediation": (
            "Disable directory listing in Apache configuration:\n"
            "```\n"
            "<Directory /var/www/html/uploads>\n"
            "    Options -Indexes\n"
            "</Directory>\n"
            "```"
        ),
        "validation": "curl http://webserver.internal/uploads/ should return HTTP 403.",
        "status": "open",
        "provenance": {"kev": False, "epss": 0.0},
        "first_observed_at": "2026-08-15T08:40:00",
        "last_observed_at": "2026-08-15T08:40:00",
        "occurrence_count": 2,
    },
]

DEMO_EVIDENCE_HASHES = [
    "sha256:3d2f1a0b9c8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2",
    "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "sha256:f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9",
    "sha256:4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    "sha256:9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7",
    "sha256:2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "sha256:8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "sha256:d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
    "sha256:1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="SMP V9.5 Demo Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--output", default="reports/demo_report", help="Output path prefix (no extension)")
    parser.add_argument("--target", default=DEMO_TARGET, help="Engagement target (for report header)")
    parser.add_argument("--operator", default=DEMO_OPERATOR, help="Operator name")
    parser.add_argument("--engagement-id", default=DEMO_ENGAGEMENT_ID, help="Engagement ID")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF rendering (Markdown only)")
    return parser.parse_args()


def main():
    args = parse_args()

    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    rg = ReportGenerator(version="V9.5")

    print(f"[SMP V9.5] Generating demo report for engagement: {args.engagement_id}")
    print(f"[SMP V9.5] Target: {args.target}")
    print(f"[SMP V9.5] Operator: {args.operator}")
    print()

    # 1. Generate JSON report
    print("[1/4] Generating JSON report...")
    json_report = rg.generate_json_report(
        engagement_id=args.engagement_id,
        findings=DEMO_FINDINGS,
        evidence_hashes=DEMO_EVIDENCE_HASHES,
        intel_version=DEMO_INTEL_VERSION,
        scanner_versions=DEMO_SCANNER_VERSIONS,
        target=args.target,
        operator=args.operator,
        assets=DEMO_ASSETS,
        services=DEMO_SERVICES,
    )

    json_path = f"{args.output}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2, default=str)
    print(f"    ✅ JSON report → {json_path}")
    print(f"    Authenticity hash: {json_report['authenticity_hash'][:32]}...")

    # 2. Generate Markdown report
    print("[2/4] Generating Markdown report...")
    md_report = rg.generate_markdown_report(
        json_report,
        metadata={
            "client_name": "Demo Client Ltd.",
            "submitted_to": "Security Team",
        },
    )

    md_path = f"{args.output}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_report)
    print(f"    ✅ Markdown report → {md_path}")

    # 3. Generate executive summary
    print("[3/4] Generating executive summary...")
    exec_summary = rg.generate_executive_summary(json_report)
    print()
    print(exec_summary)

    # 4. Optional PDF rendering
    if not args.no_pdf:
        print("[4/4] Attempting PDF render (requires weasyprint)...")
        pdf_path = f"{args.output}.pdf"
        success = rg.render_pdf(md_report, pdf_path)
        if success:
            print(f"    ✅ PDF report → {pdf_path}")
        else:
            print(f"    ℹ️  weasyprint not available — Markdown report saved as {args.output}.md")
    else:
        print("[4/4] Skipping PDF render (--no-pdf)")

    print()
    print(f"[SMP V9.5] Report generation complete.")
    print(f"    Report ID:         {json_report['report_id']}")
    print(f"    Findings:          {json_report['statistics']['total_findings']}")
    print(f"    Risk Rating:       {json_report['statistics']['risk_rating']}")
    print(f"    Authenticity Hash: {json_report['authenticity_hash']}")
    print()
    print(f"To verify report integrity:")
    print(f"    python3 tools/verify_report.py {json_path}")


if __name__ == "__main__":
    main()
