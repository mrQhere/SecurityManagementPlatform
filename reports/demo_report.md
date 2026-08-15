# Vulnerability Assessment & Penetration Test Report

**Security Management Platform V9.5**

---

| Field | Value |
|---|---|
| **Report ID** | `e49421bc-2021-4252-8030-d50e64c5b3e1` |
| **Engagement ID** | `ENG-2026-001` |
| **Target** | `10.10.50.0/24` |
| **Client** | Demo Client Ltd. |
| **Submitted To** | Security Team |
| **Operator** | mrQhere |
| **Generated** | 2026-08-14 19:15:43 UTC |
| **Overall Risk Rating** | 🔴 **CRITICAL** |
| **Authenticity Hash** | `3ca9522d3612d5fb250f57fef939e550...` |

> ⚠️ **CONFIDENTIAL — RESTRICTED DISTRIBUTION**
> This report contains sensitive security findings. Distribution is restricted to
> authorised personnel only. Do not reproduce or distribute without written consent.

> This assessment was conducted using SMP V9.5 with intelligence database
> version `NVD-2026-08-15`. All findings are based on
> evidence captured during authorised testing only.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope & Methodology](#scope--methodology)
3. [Security Findings](#security-findings)
4. [Asset & Service Inventory](#asset--service-inventory)
5. [Appendix](#appendix)

---

## Executive Summary

### Overall Risk Rating: CRITICAL

This assessment identified **2 Critical** and **2 High** severity vulnerabilities that require immediate remediation. These findings represent direct, exploitable attack paths that could lead to complete system compromise.

> ⚠️ **2 finding(s) match CISA Known Exploited Vulnerabilities (KEV).** Immediate patching required.

### Finding Breakdown

| Severity | Count | CVSS Range |
|---|---|---|
| 🔴 Critical | 2 | 9.0 – 10.0 |
| 🟠 High | 2 | 7.0 – 8.9 |
| 🟡 Medium | 2 | 4.0 – 6.9 |
| 🟢 Low | 1 | 0.1 – 3.9 |
| ⚪ Informational | 0 | 0.0 |
| **Total** | **7** | |

**Unique CVEs Referenced:** 2
**CISA KEV Matches:** 2

### Key Recommendations

1. **IMMEDIATE ACTION REQUIRED** — Remediate all Critical findings within 24 hours.
2. Remediate all High severity findings within 7 days.
3. Address Medium severity findings within 30 days.
4. Schedule Low severity findings in the next quarterly patch cycle.
5. Re-test all findings after remediation to verify effectiveness.

---

## Scope & Methodology

### Target
```
10.10.50.0/24
```

### Assessment Type
Full-scope Vulnerability Assessment & Penetration Test (VAPT) using SMP V9.5.
All scanning conducted using local, offline-capable security tooling with no exfiltration of target data.

### Testing Approach
- **Phase 1** — Asset & Service Discovery (Nmap)
- **Phase 2** — Technology Enumeration (HTTPx, WhatWeb, Nuclei)
- **Phase 3** — Vulnerability Scanning (Nuclei, Nikto, SQLMap, etc.)
- **Phase 4** — CVE Intelligence Correlation (NVD, CISA KEV, EPSS)
- **Phase 5** — Finding Deduplication & Risk Scoring
- **Phase 6** — Evidence Preservation & Report Generation

### Tools Used

| Tool | Version |
|---|---|
| `nmap` | `7.94` |
| `nuclei` | `3.3.0` |
| `nikto` | `2.1.6` |
| `gobuster` | `3.6.0` |
| `ffuf` | `2.1.0` |
| `sqlmap` | `1.8.2` |
| `dalfox` | `2.9.2` |
| `ssl_scanner` | `SMP-1.3` |
| `headers_scanner` | `SMP-1.2` |
| `jwt_scanner` | `SMP-1.1` |

### Intelligence Database
Version: `NVD-2026-08-15`
Source: NVD CVE, CISA KEV, EPSS (FIRST.org)

### Authorisation
All testing was conducted under written authorisation. Results reflect only the scope
defined in the engagement agreement. Out-of-scope systems were not tested.

---

## Security Findings

| # | Severity | Title | CVE | Status |
|---|---|---|---|---|
| 1 | 🔴 Critical | SQL Injection in Login Endpoint — Authentication Bypass | — | open |
| 2 | 🔴 Critical | CVE-2021-44228 (Log4Shell) — Remote Code Execution via JNDI Lookup | `CVE-2021-44228` | open |
| 3 | 🟠 High | Redis Instance Unauthenticated — No Password Set | — | open |
| 4 | 🟠 High | CVE-2022-22965 (Spring4Shell) — Remote Code Execution | `CVE-2022-22965` | open |
| 5 | 🟡 Medium | Expired TLS Certificate (Expired 2025-06-01) | — | open |
| 6 | 🟡 Medium | Missing HTTP Security Headers (CSP, HSTS, X-Frame-Options) | — | open |
| 7 | 🟢 Low | Directory Listing Enabled — Source Code Exposure Risk | — | open |

### Finding 01: SQL Injection in Login Endpoint — Authentication Bypass

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-001` |
| **Severity** | 🔴 Critical |
| **Confidence** | 100% |
| **Risk Score** | 100.0/100 |
| **CVE Reference** | None confirmed |
| **CWE** | CWE-89 |
| **Status** | open |
| **Vulnerability Class** | SQL Injection |
| **Asset** | asset-10-10-50-10 |
| **Endpoint** | http://webserver.internal/api/v1/login |
| **Parameter** | username |
| **First Observed** | 2026-08-15T08:00:00 |
| **Occurrence Count** | 3 |
| **Scanner Sources** | `sqlmap`, `ffuf` |

#### Description

A classic SQL Injection vulnerability was confirmed in the POST /api/v1/login endpoint. The `username` parameter is interpolated directly into the SQL query without parameterization or escaping. Using `' OR '1'='1` an unauthenticated attacker can bypass authentication and retrieve all user records. Time-based blind injection was also confirmed via `' AND SLEEP(5)--`.

#### Evidence

The following 3 observation(s) support this finding:

 - `OBS-001`
 - `OBS-002`
 - `OBS-003`

#### Remediation

1. Replace all dynamic SQL string construction with parameterized queries (prepared statements).
2. Apply principle of least privilege to the database account — it should not have SELECT on the users table by default.
3. Deploy a WAF rule to detect `OR 1=1`, `SLEEP(`, `UNION SELECT` patterns.
4. Rotate all database credentials immediately.

#### Validation Steps

POST /api/v1/login with body {"username": "' OR '1'='1", "password": "x"} should return HTTP 401 after remediation.

### Finding 02: CVE-2021-44228 (Log4Shell) — Remote Code Execution via JNDI Lookup

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-002` |
| **Severity** | 🔴 Critical |
| **Confidence** | 95% |
| **Risk Score** | 95.0/100 |
| **CVE Reference** | `CVE-2021-44228` |
| **CWE** | CWE-917 |
| **Status** | open |
| **Vulnerability Class** | Remote Code Execution |
| **Asset** | asset-10-10-50-11 |
| **Endpoint** | http://api.internal:8080/ |
| **Parameter** | User-Agent |
| **First Observed** | 2026-08-15T08:15:00 |
| **Occurrence Count** | 1 |
| **Scanner Sources** | `nuclei` |

#### Description

The Jetty 9.4.43 application on port 8080 incorporates Log4j 2.14.1, which is vulnerable to CVE-2021-44228 (CVSS 10.0). The `${jndi:ldap://...}` payload in the User-Agent header triggers an outbound LDAP lookup. In an air-gapped environment this confirms the vulnerable code path is reachable. Full exploitation would require an attacker-controlled LDAP server.

#### Evidence

The following 2 observation(s) support this finding:

 - `OBS-004`
 - `OBS-005`

#### Remediation

1. Upgrade Log4j to 2.17.1 or later immediately.
2. As interim mitigation: set `log4j2.formatMsgNoLookups=true` JVM flag.
3. Block outbound LDAP (port 389/636) at the network perimeter.
4. Review application logs for historical exploitation attempts.

#### Validation Steps

Send `User-Agent: ${jndi:ldap://127.0.0.1:9999/test}` after patching and confirm no outbound LDAP connection is established.

### Finding 03: Redis Instance Unauthenticated — No Password Set

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-003` |
| **Severity** | 🟠 High |
| **Confidence** | 100% |
| **Risk Score** | 80.0/100 |
| **CVE Reference** | None confirmed |
| **CWE** | CWE-306 |
| **Status** | open |
| **Vulnerability Class** | Authentication Bypass |
| **Asset** | asset-10-10-50-22 |
| **Endpoint** | 10.10.50.22:6379 |
| **Parameter** | — |
| **First Observed** | 2026-08-15T08:20:00 |
| **Occurrence Count** | 1 |
| **Scanner Sources** | `nmap`, `nuclei` |

#### Description

The Redis 7.0.5 instance on port 6379 accepts connections without authentication. An attacker with network access can read all cached data, write arbitrary keys, and potentially escalate to RCE via Redis CONFIG SET to write SSH authorized_keys or cron jobs to the server filesystem.

#### Evidence

The following 2 observation(s) support this finding:

 - `OBS-006`
 - `OBS-007`

#### Remediation

1. Set a strong password: `requirepass <strong_password>` in redis.conf.
2. Bind Redis to localhost or a private interface: `bind 127.0.0.1`.
3. Disable dangerous commands: `rename-command CONFIG ""` in redis.conf.
4. Deploy network-level ACLs to restrict access to Redis port.

#### Validation Steps

After setting requirepass, verify: `redis-cli -h 10.10.50.22 PING` returns NOAUTH Authentication required.

### Finding 04: CVE-2022-22965 (Spring4Shell) — Remote Code Execution

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-006` |
| **Severity** | 🟠 High |
| **Confidence** | 80% |
| **Risk Score** | 64.0/100 |
| **CVE Reference** | `CVE-2022-22965` |
| **CWE** | CWE-94 |
| **Status** | open |
| **Vulnerability Class** | Remote Code Execution |
| **Asset** | asset-10-10-50-11 |
| **Endpoint** | http://api.internal:8080/api/ |
| **Parameter** | class.module.classLoader.resources.context.parent.pipeline.first.pattern |
| **First Observed** | 2026-08-15T08:35:00 |
| **Occurrence Count** | 1 |
| **Scanner Sources** | `nuclei` |

#### Description

The Spring Framework version in use (5.3.15) is likely affected by CVE-2022-22965 (Spring4Shell, CVSS 9.8). The vulnerability allows a remote attacker to achieve arbitrary code execution by binding HTTP request parameters to a Java object. Full exploitation confirmed requires a specific Tomcat deployment configuration. Confidence set to 80% as the exact Spring version could not be confirmed.

#### Evidence

The following 1 observation(s) support this finding:

 - `OBS-011`

#### Remediation

1. Upgrade Spring Framework to 5.3.18+ or 5.2.20+.
2. Upgrade Spring Boot to 2.6.6+ or 2.5.12+.
3. As interim mitigation, add a data binding disallow list for `class.*` parameters.
4. Ensure Tomcat is version 9.0.62+ / 8.5.78+.

#### Validation Steps

Send the CVE-specific PoC payload after patching and verify a non-exploitable response.

### Finding 05: Expired TLS Certificate (Expired 2025-06-01)

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-004` |
| **Severity** | 🟡 Medium |
| **Confidence** | 100% |
| **Risk Score** | 60.0/100 |
| **CVE Reference** | None confirmed |
| **CWE** | CWE-298 |
| **Status** | open |
| **Vulnerability Class** | TLS / Certificate Issue |
| **Asset** | asset-10-10-50-10 |
| **Endpoint** | https://webserver.internal:443 |
| **Parameter** | — |
| **First Observed** | 2026-08-15T08:25:00 |
| **Occurrence Count** | 1 |
| **Scanner Sources** | `ssl_scanner` |

#### Description

The TLS certificate for webserver.internal expired on 2025-06-01. Browsers and API clients will display certificate warnings or refuse to connect (depending on `CURL_CA_BUNDLE` settings). Additionally, the certificate uses a 2048-bit RSA key which, while currently acceptable, is approaching end-of-life for high-security environments.

#### Evidence

The following 1 observation(s) support this finding:

 - `OBS-008`

#### Remediation

1. Renew the TLS certificate immediately (Let's Encrypt or internal CA).
2. Consider migrating to ECDSA P-256 certificates for improved performance.
3. Configure automated certificate renewal (certbot renew --deploy-hook).
4. Add certificate expiry monitoring to your alerting stack.

#### Validation Steps

openssl s_client -connect webserver.internal:443 | openssl x509 -noout -dates should show a future expiry.

### Finding 06: Missing HTTP Security Headers (CSP, HSTS, X-Frame-Options)

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-005` |
| **Severity** | 🟡 Medium |
| **Confidence** | 100% |
| **Risk Score** | 60.0/100 |
| **CVE Reference** | None confirmed |
| **CWE** | CWE-16 |
| **Status** | open |
| **Vulnerability Class** | Security Misconfiguration |
| **Asset** | asset-10-10-50-10 |
| **Endpoint** | http://webserver.internal/ |
| **Parameter** | — |
| **First Observed** | 2026-08-15T08:30:00 |
| **Occurrence Count** | 4 |
| **Scanner Sources** | `headers_scanner` |

#### Description

The web application is missing the following recommended security headers:
- Content-Security-Policy (CSP) — absent, allows unrestricted script execution
- Strict-Transport-Security (HSTS) — absent, allows protocol downgrade attacks
- X-Frame-Options — absent, allows clickjacking via iframe embedding
- X-Content-Type-Options — absent, allows MIME-sniffing attacks
- Referrer-Policy — absent, leaks sensitive URL parameters to third parties

#### Evidence

The following 2 observation(s) support this finding:

 - `OBS-009`
 - `OBS-010`

#### Remediation

Add the following headers to the Apache/Nginx configuration:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

#### Validation Steps

curl -I https://webserver.internal/ should show all headers present.

### Finding 07: Directory Listing Enabled — Source Code Exposure Risk

| Field | Value |
|---|---|
| **Finding ID** | `FND-2026-007` |
| **Severity** | 🟢 Low |
| **Confidence** | 100% |
| **Risk Score** | 30.0/100 |
| **CVE Reference** | None confirmed |
| **CWE** | CWE-548 |
| **Status** | open |
| **Vulnerability Class** | Information Disclosure |
| **Asset** | asset-10-10-50-10 |
| **Endpoint** | http://webserver.internal/uploads/ |
| **Parameter** | — |
| **First Observed** | 2026-08-15T08:40:00 |
| **Occurrence Count** | 2 |
| **Scanner Sources** | `nikto`, `gobuster` |

#### Description

Apache directory listing is enabled for the /uploads/ directory. This exposes the names and sizes of uploaded files to unauthenticated visitors. While not directly exploitable, it aids reconnaissance and may expose user data.

#### Evidence

The following 1 observation(s) support this finding:

 - `OBS-012`

#### Remediation

Disable directory listing in Apache configuration:
```
<Directory /var/www/html/uploads>
 Options -Indexes
</Directory>
```

#### Validation Steps

curl http://webserver.internal/uploads/ should return HTTP 403.

---

## Asset & Service Inventory

### Discovered Assets

| Address | Type | Source | Confidence |
|---|---|---|---|
| `10.10.50.10` | ip | nmap | 100% |
| `10.10.50.11` | ip | nmap | 100% |
| `10.10.50.22` | ip | nmap | 100% |
| `webserver.internal` | host | nmap | 95% |
| `api.internal` | host | nmap | 95% |
| `db.internal` | host | nmap | 90% |

### Open Services

| Port | Protocol | State | Product | Version |
|---|---|---|---|---|
| 22 | TCP | open | OpenSSH | 8.2p1 |
| 80 | TCP | open | Apache httpd | 2.4.51 |
| 443 | TCP | open | Apache httpd | 2.4.51 |
| 3306 | TCP | open | MySQL | 8.0.28 |
| 8080 | TCP | open | Jetty | 9.4.43 |
| 6379 | TCP | open | Redis | 7.0.5 |
| 5432 | TCP | open | PostgreSQL | 14.2 |

---

## Appendix

### A. Intelligence Provenance

| Field | Value |
|---|---|
| **NVD CVE Version** | NVD-2026-08-15 |
| **Report Generator** | SMP V9.5 |
| **Generated At** | 2026-08-14T19:15:43.745607+00:00 |

### B. Evidence Hashes

| SHA-256 / Evidence Reference |
|---|
| `sha256:3d2f1a0b9c8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2` |
| `sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2` |
| `sha256:f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9` |
| `sha256:4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6` |
| `sha256:9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7` |
| `sha256:2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4` |
| `sha256:8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0` |
| `sha256:d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7` |
| `sha256:1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d` |

### C. Tool Version Manifest

| Tool | Version |
|---|---|
| `nmap` | `7.94` |
| `nuclei` | `3.3.0` |
| `nikto` | `2.1.6` |
| `gobuster` | `3.6.0` |
| `ffuf` | `2.1.0` |
| `sqlmap` | `1.8.2` |
| `dalfox` | `2.9.2` |
| `ssl_scanner` | `SMP-1.3` |
| `headers_scanner` | `SMP-1.2` |
| `jwt_scanner` | `SMP-1.1` |

### D. Report Integrity Attestation

This report was generated by the Security Management Platform (SMP) V9.5.
The authenticity hash below was computed over the canonical JSON representation of all report
data (excluding the hash field itself) using SHA-256.

```
REPORT-ID: e49421bc-2021-4252-8030-d50e64c5b3e1
ENGAGEMENT: ENG-2026-001
GENERATED-AT: 2026-08-14T19:15:43.745607+00:00
SHA-256: 3ca9522d3612d5fb250f57fef939e55086af9580c55cc58790e60f2f11e58a1d
```

To verify this report has not been tampered with:
```bash
python3 tools/verify_report.py <report_file.json>
```

*Use only against systems for which you have written authorisation to test.*
*© SMP — Licensed under the MIT License.*