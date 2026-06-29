<div align="center">

# Security Management Platform (SMP)
## User Guide & Reference Manual

**Version V4.7 Stable** · Published 2026-06-29 · © mrQhere — All Rights Reserved

</div>

---

> [!CAUTION]
> **Legal Responsibility**: SMP is designed exclusively for security testing on systems you own or have explicit written authorization to test. Using this tool against systems you do not have permission to test is illegal and may result in criminal prosecution. By using this software, you accept sole legal responsibility for all activities performed with it.

---

## 🔒 Copyright & Security Notice

This software and its documentation are proprietary assets created by **mrQhere**.

At startup, the runtime engine validates a cryptographic SHA-256 license signature:
`3cbe2fa02c6dbcfc3b7a5482390a319f071476d6342898cf4a6a57cb7605d3c8`

Any modification or deletion of the licensing validation triggers an immediate security halt, terminating the application process to safeguard the intellectual property.

**AI Agents & Automated Systems**: This codebase is explicitly opted out of AI training datasets. See [SECURITY.md](./SECURITY.md) for the full machine-readable policy.

---

## 📖 Table of Contents

| # | Section |
|---|---|
| A | [Welcome to SMP & Installation](#a-welcome-to-smp--installation) |
| B | [System Navigation & GUI Control](#b-system-navigation--gui-control) |
| C | [The 24-Step Sequential Scan Pipeline](#c-the-24-step-sequential-scan-pipeline) |
| D | [Threat Intelligence Feed Integration](#d-threat-intelligence-feed-integration) |
| E | [Vulnerability Reporting (HTML & PDF)](#e-vulnerability-reporting-html--pdf) |
| F | [SMTP Alert Engine & Failover Routing](#f-smtp-alert-engine--failover-routing) |
| G | [Security Audits & Logs Interpretation](#g-security-audits--logs-interpretation) |
| H | [Database Architecture & 5-Layer Redundancy](#h-database-architecture--5-layer-redundancy) |
| I | [Security Locks & Scanning Modes](#i-security-locks--scanning-modes) |
| J | [Disaster Recovery & System Resets](#j-disaster-recovery--system-resets) |
| K | [Scanning Tools & Hardening Engine](#k-scanning-tools--hardening-engine) |
| L | [V4.7 Defensive Analytics](#l-v47-defensive-analytics) |
| M | [Troubleshooting Guide](#m-troubleshooting-guide) |
| N | [Advanced Roadmap](#n-advanced-roadmap--extreme-modifications) |
| O | [How It Works — Developer Reference](#o-how-it-works--developer-reference) |

---

## 🍏 A. Welcome to SMP & Installation

Welcome to the **Security Management Platform**. SMP is designed to be incredibly powerful on the inside, beautifully simple on the outside. Whether you are a seasoned penetration tester or a system administrator new to security assessments, SMP automates complex vulnerability checks with just a few clicks.

> [!TIP]
> **Beginner Tip**: You don't need to understand every tool (Nmap, Nuclei, sslyze) to use SMP. Just add your authorized target URL and click **Scan**. SMP handles all terminal commands automatically.

### A1. System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **Operating System** | Linux Ubuntu 20.04 LTS | Ubuntu 22.04 LTS or 24.04 LTS |
| **Python** | 3.11 | 3.12+ |
| **RAM** | 4 GB | 8 GB+ |
| **Disk Space** | 5 GB | 20 GB (for full CVE database) |
| **Network** | Broadband | Stable broadband (for NVD initial sync) |
| **Privileges** | Standard user with `sudo` | — |

### A2. Automated Linux Setup

```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the automated installer (installs Python venv, Go tools, system packages)
bash setup.sh

# Copy the license key (MANDATORY — the app will not start without this)
cp license/license.key config/license.key

# Copy the settings template
cp config/settings.example.json config/settings.json

# Launch SMP
bash run.sh
```

> [!IMPORTANT]
> **First Launch — NVD Database Sync**: On the very first launch, SMP will download the complete NVD CVE database (300,000+ entries going back to 1999). This is a one-time operation that takes **20–60 minutes** depending on your internet connection. NVD enforces a mandatory 6-second delay between API requests. Do not interrupt this process. Subsequent syncs are incremental and complete in under a minute.

### A3. Windows Setup

Run PowerShell as Administrator:
```powershell
.\setup.ps1
```
Or use Command Prompt as Administrator:
```bat
setup.bat
```
Then launch with `run.bat`.

---

## 🚀 First Walkthrough

Complete these four steps before your first scan.

### Step 1: Create Your Master Password

On first launch, you will be greeted by a **Master Password** creation dialog.

- Create a strong password (12+ characters, mix of letters, numbers, symbols).
- **Write it down securely.** SMP uses military-grade AES-256 encryption. If you lose this password, your databases are cryptographically locked forever. There is no recovery option — you must perform a Factory Reset.

### Step 2: Accept the Responsibility Disclaimer

A Legal Responsibility dialog will appear after authentication.
- Read the terms carefully.
- Check the **"I acknowledge"** checkbox to proceed.
- This dialog appears once per installation.

### Step 3: Configure Email Alerts (Recommended)

1. Click the **Settings** tab.
2. Under **SMTP Settings**, enter your Gmail address.
3. Do **not** use your regular Google password. Generate a **16-character App Password** from [Google Account → Security → App Passwords](https://myaccount.google.com/apppasswords).
4. Enter the receiver email and click **Save Settings**.
5. Click **Test Connection** to verify.

### Step 4: Add Your First Target

1. Click the **Targets** tab.
2. Type the URL you are authorized to test (e.g., `https://example.com`).
3. Optionally fill in **Company Name** and **Submitted To** for the PDF report cover page.
4. Click **Add Target**.

You are now ready to scan.

---

## 🖱️ B. System Navigation & GUI Control

SMP features a premium Apple-inspired interface with five main tabs.

### B1. Dashboard Tab

| UI Element | Function |
|---|---|
| **KPI Metric Banners** | Live counts: Monitored Targets, CVE database volume, Active scans, Alert status |
| **Target Risk Summary Table** | All monitored domains with operational status and calculated risk rating |
| **Recent Security Events** | Real-time scrollable log of warnings, scan triggers, and sync events |
| **Refresh Button** | Redraws all dashboard elements from the database |
| **Scan All Targets** | Triggers the full 24-step pipeline for all enabled targets simultaneously |

### B2. Targets Tab

| UI Element | Function |
|---|---|
| **Add New Target** | Input field + Add button for registering a new scan target |
| **Monitored Pipeline Table** | Shows each target: status, last scan date, action buttons (Scan, Report, Toggle, Delete) |
| **Ongoing Scans Feed** | Live output showing which tool is currently running and its progress |
| **Cancel Button** | Gracefully aborts any running scan (works on new and auto-resumed scans) |
| **Smart Resume** | If the app closes mid-scan, restarting automatically resumes from the interrupted step |

### B3. Threat Intel Tab

- **Severity Filters**: Filter the CVE database by Critical, High, Medium, Low.
- **Source Filters**: Filter by NVD, CISA KEV, or GitHub Advisories.
- **CVE Advisory Feed**: Hover over any entry to read its full description.
- **Search**: Full-text search across all 300,000+ CVEs.

### B4. Settings Tab

| Setting Group | Options |
|---|---|
| **Scanner Binary Paths** | Customize where each tool binary is installed |
| **GitHub Token** | Personal access token for higher GitHub API rate limits |
| **SMTP Configuration** | Email server settings for alert dispatch |
| **Report Settings** | Tester name, QA reviewer, report metadata |
| **OWASP ZAP** | Enable/disable optional active ZAP scanning |
| **Danger Zone** | Reset to defaults, clear cache, full factory reset |

### B5. Audit Logs Tab

- **Master Log** (`logs/master.log`): Chronological audit trail of all platform events.
- **Scan Events Log** (`logs/scan.log`): Per-tool scanner output and exit codes.

---

## C. The 24-Step Sequential Scan Pipeline

To prevent DoS triggers and network blocks, all tools run **sequentially** (one at a time). The pipeline is ordered from cheap/fast OSINT tools first, to expensive/active scanners last.

| Step | Tool | Category | What It Finds |
|------|------|----------|----------------|
| 1 | **HTTPx Probe** | Reconnaissance | Confirms target is online; extracts server headers and response metadata |
| 2 | **WhatWeb** | Fingerprinting | Identifies CMS, server software, JavaScript frameworks (e.g., WordPress, Nginx, React) |
| 3 | **Subfinder** | Subdomain Enum | Passive DNS feed queries to discover active subdomains |
| 4 | **theHarvester** | OSINT | Search engine scraping for exposed email addresses and hostnames |
| 5 | **CRT.sh** | Subdomain Enum | Certificate Transparency log queries to find subdomains from TLS certificates |
| 6 | **HackerTarget** | DNS Recon | Reverse DNS lookups, IP range mapping |
| 7 | **Whois** | Registry Recon | Domain registrar, registration dates, contact names |
| 8 | **Wayback Machine** | URL Recon | Historical endpoint discovery from web archive snapshots |
| 9 | **Traceroute** | Network Mapping | UDP path trace to map network hops without root dependency |
| 10 | **Nmap** | Port Scanner | Top-100 port scan with service version detection (`-F -sV -T4`) |
| 11 | **SSL Scanner (sslyze)** | Cryptography | TLS version support, cipher suite audit, Heartbleed, CCS injection, certificate validity |
| 12 | **Security Headers** | Web Audits | Verifies CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 13 | **Robots Scanner** | Path Recon | Parses `robots.txt` and `sitemap.xml` for hidden paths and disallowed directories |
| 14 | **CORS Scanner** | API Audits | Tests wildcard CORS, reflected origin, null origin, and permissive configurations |
| 15 | **CMS Scanner** | Platform Audits | Detects WordPress/Drupal/Joomla themes, plugins, and admin panel exposure |
| 16 | **Nikto** | Web Vulnerability | Legacy CGI, file-based, and configuration vulnerability checks |
| 17 | **Nuclei** | Vulnerabilities | Template-based YAML scanners for 9,000+ CVE and misconfiguration exposures |
| 18 | **ffuf** | Path Fuzzing | Directory and file fuzzing with SPA catch-all false-positive filtering |
| 19 | **Open Redirect** | Web Audits | Tests `?url=`, `?next=`, `?redirect=` and 15+ common redirect parameters |
| 20 | **Tech Fingerprint** | Fingerprinting | Deep response header profiling for additional technology detection |
| 21 | **Wapiti** | Web Vulnerability | Active OWASP injection testing (XSS, SQLi, path traversal, SSRF) |
| 22 | **SQLMap** | Injection Audits | SQL injection detection with `--forms --batch --smart` flags |
| 23 | **Shodan InternetDB** | IoT Profiling | Passive external exposure check using Shodan's Internet database API |
| 24 | **Gitleaks** | Secret Scanning | Checks for exposed `.git/config`, hardcoded API keys, passwords, and tokens |
| ✦ | **CVE Correlation** | Intelligence | Offline: matches detected technologies against the local CVE database |
| ✦ | **Risk Scoring** | Analytics | Calculates a 0–100 weighted risk score using CVSS metrics |
| ✦ | **Report Generation** | Output | Generates VAPT PDF and HTML reports |
| ✦ | **SMTP Alerts** | Notifications | Dispatches email alerts with PDF attachments |

> [!NOTE]
> **OWASP ZAP** is an optional step (disabled by default). When enabled, ZAP requires a separately running Java daemon (`zaproxy`) on port 8090. ZAP is not auto-started by SMP.

---

## D. Threat Intelligence Feed Integration

SMP maintains a **local** vulnerability database synced from four authoritative sources. No data is sent externally during scans.

### D1. Data Sources

| Source | Type | What It Provides |
|---|---|---|
| **NVD (NIST)** | Full CVE Database | 300,000+ CVEs from 1999 to present — no date restriction |
| **CISA KEV** | Active Exploits | Known Exploited Vulnerabilities — prioritized for immediate patching |
| **GitHub Advisories** | Package CVEs | Production-grade advisory records for open-source dependencies |
| **EPSS** | Probability Scores | Exploit Prediction Scoring System — quantifies likelihood of exploitation |

### D2. NVD Sync Behaviour

- **First sync**: Downloads the entire NVD database (300,000+ entries). This is a one-time operation. SMP saves progress automatically so it can resume if interrupted.
- **Incremental sync**: Subsequent syncs fetch only CVEs published in the last 30 days. This completes in under 60 seconds.
- **Rate limiting**: NVD enforces a 6-second inter-request delay. SMP complies automatically.
- **Retry logic**: 5 retry attempts with exponential backoff on API errors (429, 503, timeouts).

### D3. Technology Correlation

After each scan, the Correlation Engine cross-references the target's detected software stack against the CVE database. Matches are inserted into findings as **CVE Correlation** entries, visible in the dashboard and PDF reports.

---

## E. Vulnerability Reporting (HTML & PDF)

Every completed scan generates two report formats:

### E1. Report Structure (6 Sections)

| Section | Content |
|---|---|
| **1 — Cover Page** | Document title ("Vulnerability Assessment Report — System Generated Report"), target metadata, assessment date, tester name, digital verification status |
| **2 — Executive Summary** | Risk narrative, severity count dashboard, historical trend deltas (new/resolved/persisting findings vs. previous scan), strategic action plan |
| **3 — Scope & Methodology** | In-scope asset inventory, excluded assets, testing timeline, framework compliance (OWASP WSTG, NIST SP 800-115, PTES, CVSS v4.0, PCI-DSS v4.0) |
| **4 — Findings Summary Matrix** | Sortable table of all findings: ID, title, tool, severity, CVSS, status |
| **5 — Deep-Dive Technical Findings** | Per-finding pages including: taxonomy mappings (MITRE ATT&CK, CWE, OWASP), technical breakdown, **"How This Was Detected"** explanation, **raw scan result evidence**, remediation blueprint with copy-pasteable code |
| **5B — Hardening Recommendations** | 40+ built-in hardening templates mapped to findings (Nginx, Apache, Linux configs) |
| **6 — Appendices** | Tooling table, post-testing cleanup log, severity glossary, formal attestation & sign-off |

### E2. Digital Verification

Every PDF is SHA-256 hashed at generation time. The hash is embedded in the filename:
```
VAPT_Report_example_com_20260629_a3f1c2d8.pdf
                                  ↑ 8-char SHA-256 prefix
```

You can verify any PDF in the **Settings** tab using the SHASUM Validator.

### E3. HTML Report

A lightweight HTML report is also generated alongside the PDF for email-friendly viewing. It uses a responsive white-theme layout and is fully self-contained (no external dependencies).

---

## F. SMTP Alert Engine & Failover Routing

### F1. Alert Triggers

SMP dispatches email alerts under three conditions:

| Trigger | Severity |
|---|---|
| **Target Offline** | All scanners failed to connect to the target |
| **New Finding** | A new vulnerability not present in the previous scan was detected |
| **Severity Escalation** | An existing finding increased in severity |
| **CVE Match** | A newly synced CVE matches a technology running on an active target |

### F2. Gmail App Password Setup

Standard Gmail accounts require a **16-character App Password** (not your regular password):

1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Select **Mail** and your device.
3. Copy the 16-character code into the `smtp_pass` field in Settings.

### F3. Failover Routing

If the primary SMTP host fails, SMP automatically attempts the backup SMTP relay configured in `smtp_backup_host`. If both fail, the alert is logged and the report is saved locally.

---

## G. Security Audits & Logs Interpretation

| Log File | Purpose |
|---|---|
| `logs/master.log` | Operational audit trail: target changes, backup jobs, user actions |
| `logs/scan.log` | Per-tool command strings, raw output, exit codes |
| `logs/cve.log` | CVE sync progress, API errors, rate limiting events |
| `logs/error.log` | Application crash reports, SQLite write blocks, stack traces |

### G1. Scan Log Markers

| Marker | Meaning |
|---|---|
| `[1/24]` through `[24/24]` | Step number in the pipeline |
| `✅ RECOVERY` | A previously failed step succeeded on retry |
| `Scan Cancelled by User` | User clicked the Cancel button |
| `Resuming Scan from step` | Smart resume activated after interrupted scan |
| `MAC change failed` | Active scanners (Nikto, Nuclei, ffuf, Wapiti, SQLMap) skipped |

---

## H. Database Architecture & 5-Layer Redundancy

### H1. Database Matrix

| Database | Path | Purpose | AES-256 Encrypted |
|---|---|---|---|
| **Primary** | `database/security.db` | Core schema: targets, scans, findings, technologies, baselines | ✅ Yes |
| **Raw Archive** | `backup/active_scans.db` | Full JSON output of every tool per scan | ✅ Yes |
| **Important Findings** | `backup/important_results.db` | High and Critical severity findings only | ✅ Yes |
| **Disaster Recovery** | `backup/full_backup.db` | 1:1 replica of all 8 primary application tables | ✅ Yes |
| **Threat Intel Mirror** | `backup/cve_secondary.db` | Local cache of synced CVE feeds | No (public data) |

### H2. Encryption Mechanism

SMP uses **Fernet symmetric encryption** (AES-128-CBC + HMAC-SHA256) via the `cryptography` library. The master password is hashed with bcrypt (cost factor 12) and the derived key encrypts all database files at shutdown. Databases are decrypted in memory at startup using the verified password.

---

## I. Security Locks & Scanning Modes

### I1. Master Password

SMP encrypts all databases using your master password. If you forget it:
- There is **no recovery option**.
- You must delete the auth file and databases to reset.
- See Section J for reset commands.

> [!CAUTION]
> **Password Loss = Data Loss**: The AES-256 encryption is mathematically unbreakable without the key. Write your password down and store it securely.

### I2. Scanning Modes

When you click **Scan**, a dialog asks for your system's `sudo` password.

| Mode | How to Activate | What Changes |
|---|---|---|
| **Standard Mode** | Leave the password blank and click OK | Passive/network scanners run. Active scanners (Nikto, Nuclei, ffuf, Wapiti, SQLMap) are skipped. |
| **Deep Scan Mode** | Enter your system `sudo` password | (1) MAC address is randomized to a same-vendor random address for anonymization. (2) All 24 active scanners are enabled. (3) Nmap attempts OS fingerprinting. |

### I3. MAC Address Anonymization

In Deep Scan mode, SMP randomizes your network adapter's MAC address before scanning begins. The MAC is changed to a random address with the same vendor prefix (OUI) to avoid triggering vendor-specific network blocks. The original MAC is restored after the scan completes or if the application exits.

---

## J. Disaster Recovery & System Resets

### J1. Reset Master Password

```bash
# Wipes encrypted databases — you will lose scan history
rm -f config/auth.json database/*.db* backup/*.db*
bash run.sh
# Set a new password on the next launch
```

### J2. Full Factory Reset ("The Nuclear Option")

Restores the app to its exact post-clone state:

```bash
rm -rf config/auth.json config/settings.json config/license.key \
       database/* backup/* logs/* cache/* \
       reports/html/* reports/pdf/*

# After reset, restore the license key:
cp license/license.key config/license.key

bash run.sh
```

### J3. Targeted Resets

| What to Reset | Command |
|---|---|
| Settings only | `rm -f config/settings.json && cp config/settings.example.json config/settings.json` |
| Logs & cache | `rm -rf logs/* && rm -f cache/intel_cache.json` |
| Reports only | `rm -rf reports/html/* reports/pdf/*` |
| CVE database | `python3 reset_db.py` |

---

## K. Scanning Tools & Hardening Engine

### K1. theHarvester (OSINT)

- Passive Google, Bing, DuckDuckGo scraping for exposed email addresses and hostnames
- Severity: Info/Medium
- Pipeline Step: 4/24
- No active network connections to target — purely search engine OSINT

### K2. Gitleaks (Secret Scanning)

- Checks if the target exposes `.git/config` to the internet (Critical risk — full source code accessible)
- Scans for hardcoded API keys, passwords, private keys, and OAuth tokens
- Severity: Critical when `.git/` is exposed
- Pipeline Step: 24/24

### K3. SSLyze SSL/TLS Analysis

SMP uses **sslyze 5.x** (Python library — no subprocess required) to perform TLS assessments:

| Check | What It Detects |
|---|---|
| SSL 2.0 / SSL 3.0 | Cryptographically broken protocols (Critical) |
| TLS 1.0 / TLS 1.1 | Deprecated protocols (High/Medium) |
| Heartbleed (CVE-2014-0160) | OpenSSL memory disclosure |
| CCS Injection (CVE-2014-0224) | ChangeCipherSpec injection |
| CRIME Attack | TLS compression enabled |
| Session Renegotiation | Client-initiated DoS risk |
| Certificate Expiry | Warns at 30 days, critical at expiry |
| Certificate Trust Chain | Untrusted or self-signed certificates |

### K4. Automated Hardening Recommendations

After each scan, findings are cross-referenced against `config/hardening_rules.json` (40+ templates). Output includes:

- Nginx configuration changes
- Apache `.htaccess` rules
- Linux shell commands
- All copy-pasteable for immediate use

---

## L. V4.7 Defensive Analytics

The V4.7 release adds five defensive monitoring capabilities:

### L1. Fail2Ban Log Reader

`tools/fail2ban_reader.py` parses local fail2ban logs to provide real-time intelligence on IPs currently banned by your server. Visible in the Dashboard's Recent Events feed.

### L2. MITRE ATT&CK Technique Mapper

`intelligence/mitre_mapper.py` automatically correlates scan findings with MITRE ATT&CK technique IDs. Examples:
- T1190 — Exploit Public-Facing Application (mapped to Nikto/Nuclei findings)
- T1040 — Network Sniffing (mapped to weak TLS cipher findings)

These mappings appear in every VAPT PDF report.

### L3. Historical Scan Trend Analysis

The PDF Executive Summary now includes a delta table comparing the current scan to the previous one:

| Metric | Description |
|---|---|
| New Findings | Vulnerabilities present now but not before |
| Resolved Findings | Vulnerabilities from previous scan that are gone |
| Persisting Findings | Vulnerabilities present in both scans |

### L4. Response Baseline Diffing (Watchdog)

`scanners/watchdog.py` runs every 2 hours in the background:
- Hashes page content to detect defacement
- Monitors open ports for changes
- Checks SSL certificate validity drift
- Sends alerts on anomalies

### L5. Isolated Analytics Database

All threat intelligence feeds are stored in `backup/cve_secondary.db` (separate from the primary operational database) to keep the main database fast for UI queries.

---

## M. Troubleshooting Guide

### Scenario 1: App Won't Start or Configuration is Broken

**Fix (UI method)**: Settings tab → scroll to **Danger Zone** → click **Reset to Default**

**Fix (Terminal)**:
```bash
rm -f config/settings.json
bash run.sh
```

---

### Scenario 2: Forgot Master Password

**Fix**: Delete the auth file and databases, then set a new password:
```bash
rm -f config/auth.json database/*.db* backup/*.db*
bash run.sh
```
> [!WARNING]
> This permanently deletes all scan history. There is no recovery option.

---

### Scenario 3: Tools Missing or Failing

**Fix (UI method)**: Settings tab → click **Check Dependencies & Tools**

**Fix (Terminal)**: Re-run the installer:
```bash
bash setup.sh
```

---

### Scenario 4: CVE Sync Stuck or Database Corrupted

```bash
python3 reset_db.py
```
This safely wipes and rebuilds all database tables while preserving settings and passwords.

---

### Scenario 5: SSLyze Not Working

Ensure sslyze 5.x is installed:
```bash
source venv/bin/activate
pip install "sslyze>=5.2.0"
```
sslyze only runs on HTTPS targets (port 443 or 8443). HTTP-only targets return an empty SSL finding list — this is expected behavior.

---

### Scenario 6: PDF Reports Not Sent by Email

1. Confirm you are using a **16-character Gmail App Password**, not your regular password.
2. Confirm the **Report Email Address** (receiver) is set in Settings.
3. Click **Test Connection** in the SMTP settings section to verify credentials.
4. Check `logs/master.log` for SMTP error messages.

---

### Scenario 7: Active Scanners Skipped (Nikto, Nuclei, etc.)

Active scanners require **Deep Scan mode** (enter your `sudo` password when prompted). If the MAC address change fails (e.g., virtual machine without network control), these tools are automatically skipped. To force-run without MAC change, disable `mac_changer_enabled` in `config/settings.json`:
```json
{ "mac_changer_enabled": false }
```

---

## N. Advanced Roadmap & Extreme Modifications

The following enhancements are planned for future versions or available as advanced developer modifications. Each item is architecturally sound and integration-ready given the existing codebase.

### N1. Local LLM Integration (AI-Driven Remediation)

**Goal**: Integrate a local, offline LLM (e.g., Ollama + Llama 3 / Mistral) that interprets scan findings and generates exact code-level remediation blocks.

**Architecture**:
- Add `tools/llm_engine.py` with an Ollama API client
- After report generation, pipe the findings JSON to the LLM with a structured prompt
- Output: per-finding remediation code blocks embedded in Section 5 of the PDF

**Integration Point**: `tools/report_generator.py` → `_generate_vapt_pdf()` → after `_get_remediation()` call

**Estimated Complexity**: Medium — 2–3 days

---

### N2. Concurrent Scan Count Increase (8–10 Parallel Scans)

**Current Limit**: 3 concurrent scans (`if len(_active_scans) >= 3`)

**Change Required**: `scanners/scan_runner.py` line ~268:
```python
# Current
if len(_active_scans) >= 3:

# Change to
MAX_CONCURRENT_SCANS = int(os.environ.get("SMP_MAX_SCANS", 8))
if len(_active_scans) >= MAX_CONCURRENT_SCANS:
```

**Caveats**: Each scan thread can peak at 2–4 CPU cores during Nmap/Nuclei. On 8-core systems, 8 concurrent scans may cause CPU saturation. The adaptive cooling system (`get_cooling_delay()`) will automatically throttle based on load average.

---

### N3. Multi-Node Distributed Scanning

**Goal**: Distribute scan pipelines across multiple worker machines (agent nodes) for large enterprise environments.

**Architecture**:
- Central SMP coordinator (message broker — Redis or RabbitMQ)
- Worker nodes run individual scanner modules and return results via API
- Coordinator aggregates findings and generates unified reports

**Integration Point**: Replace `_run_scan_sequence()` with a distributed task dispatcher using Celery workers

**Estimated Complexity**: High — 2–3 weeks

---

### N4. Slack / Discord / Teams Push Notifications

**Goal**: Push real-time scan events, critical finding alerts, and CVE matches to team messaging platforms.

**Architecture**:
- Add `tools/webhook_engine.py` with support for Slack Incoming Webhooks, Discord webhooks, and Microsoft Teams connectors
- Hook into `tools/alert_engine.py` alongside SMTP dispatch
- Add webhook URLs to `config/settings.json`

**Estimated Complexity**: Low — 1 day

---

### N5. Compliance Dashboard (PCI-DSS, SOC 2, HIPAA)

**Goal**: Map findings directly to compliance control IDs in the UI and PDF reports.

**Architecture**:
- Add `config/compliance_mappings.json` with control ID → finding type mappings
- Add a "Compliance" tab to the dashboard showing pass/fail by control
- Embed compliance mapping table in PDF Section 3

**Estimated Complexity**: Medium — 3–5 days

---

### N6. REST API Server Mode

**Goal**: Expose SMP functionality over a REST API for integration with CI/CD pipelines, SIEM platforms, and ticketing systems.

**Architecture**:
- Add `api_server.py` using FastAPI with token authentication
- Endpoints: `POST /scans`, `GET /scans/{id}`, `GET /findings`, `GET /reports/{id}`
- Optional: OpenAPI/Swagger documentation

**Integration Point**: Reuse all existing `tools/db_manager.py` functions as API backend

**Estimated Complexity**: Medium — 1 week

---

### N7. Automated Zero-Day Correlation Alerts

**Goal**: Push notifications to Slack/Discord the moment a newly published CVE strictly matches an old scan target's technology stack.

**Architecture**:
- NVD incremental sync already runs every 24 hours
- Extend `intelligence/cve_correlator.py` to re-run correlation for all active targets on each sync
- Trigger webhook notification (N4) + SMTP alert for any new CVE match

**Estimated Complexity**: Low — 1 day (requires N4 or SMTP already configured)

---

### N8. Scheduled Scan Profiles & Time Windows

**Goal**: Allow per-target scan scheduling with time windows (e.g., "only scan on weekends between 2am–6am").

**Architecture**:
- Add `scan_schedule` field to the `targets` table in the database
- Extend `tools/scheduler.py` to respect per-target time windows using APScheduler cron triggers
- Add schedule configuration UI in the Targets tab

**Estimated Complexity**: Low–Medium — 2 days

---

### N9. Evidence Screenshot Capture

**Goal**: Capture browser screenshots of discovered vulnerabilities (e.g., XSS PoC, open redirect landing pages) and embed them in PDF reports.

**Architecture**:
- Add `tools/screenshot_engine.py` using Playwright (headless Chromium)
- After ffuf/CORS/redirect findings, trigger automated screenshot capture
- Embed screenshots in PDF Section 5 finding cards

**Estimated Complexity**: Medium — 3 days

---

## O. How It Works — Developer Reference

This section is a complete architectural deep-dive for developers who want to understand, extend, or contribute to the Security Management Platform.

---

### O1. Application Startup Sequence

```
main.py
  │
  ├─ enforce_license()          ← SHA-256 hash check of config/license.key
  ├─ enforce_single_instance()  ← fcntl.flock() on ~/.smp_runtime.lock
  ├─ OS signal handlers         ← SIGINT/SIGTERM → clean shutdown
  ├─ QApplication init          ← PySide6 Qt6 application with Fusion palette
  ├─ run_password_protection()  ← bcrypt password verification dialog
  ├─ init_directories()         ← Creates logs/, reports/, cache/, backup/
  ├─ setup_logging()            ← 4 rotating log files
  ├─ init_db()                  ← Creates SQLite schema (8 tables)
  ├─ resume_interrupted_scans() ← Restarts any scans that were interrupted
  ├─ check_and_install_all()    ← Background thread: verifies/installs tools
  ├─ start_scheduler()          ← APScheduler: CVE sync + Watchdog
  └─ DashboardWindow().show()   ← Main Qt window
```

---

### O2. Database Schema

The primary database (`database/security.db`) has 8 tables:

| Table | Key Columns | Purpose |
|---|---|---|
| `targets` | id, url, company_name, status | Monitored scan targets |
| `scans` | id, target_id, status, scanner_status, start_time, end_time | Scan run records |
| `findings` | id, scan_id, severity, title, description, source_tool, confidence | Individual vulnerabilities |
| `technologies` | id, scan_id, name, version, category, confidence | Detected tech stack |
| `cves` | id, cve, severity, description, source, cvss_score, published_date | Local CVE database |
| `risk_scores` | id, scan_id, score, rating, breakdown | Calculated risk metrics |
| `alerts` | id, target_id, message, severity, created_at | Platform alert history |
| `log_entries` | id, level, message, created_at | In-DB audit log |

---

### O3. Scan Pipeline Architecture

```
start_scan_for_target(target, sudo_password)
  │
  ├─ _lock: check _active_scans (max 3 concurrent)
  ├─ Check DB for interrupted scan → get resume_scan_id + resume_status
  ├─ _cancel_events[target_id] = threading.Event()
  └─ Thread(_run_scan_sequence, target, resume_scan_id, resume_status, sudo_password)
       │
       ├─ thread_local.sudo_password = sudo_password  ← secure thread-local pass
       ├─ MAC address change (if sudo available)
       │
       ├─ For each of 24 scanner steps:
       │    ├─ _should_run_step()   ← checks cancel event + resume step index
       │    ├─ update_scan_status() ← updates DB ("Running Nmap", etc.)
       │    ├─ run_with_resilience()
       │    │    ├─ Binary availability check (shutil.which)
       │    │    ├─ Dynamic timeout scaling (180s cap, 1.5x on retry)
       │    │    ├─ ResilientPopen: os.setsid() for process group isolation
       │    │    └─ scan_func(url) → result
       │    ├─ _process_*_results() ← save to DB
       │    └─ _log_raw()           ← save raw JSON to backup DB
       │
       ├─ deferred_retry_queue: re-attempt failed steps with 1.5x timeout
       ├─ CVE Correlation (offline matching)
       ├─ Risk Scoring (CVSS-weighted 0–100)
       ├─ generate_scan_reports() → PDF + HTML
       ├─ process_alerts_for_scan() → SMTP dispatch
       └─ backup_all_tables() → 5-layer DB sync
```

---

### O4. Cancellation System

```python
# Cancel event registration (start_scan_for_target):
_cancel_events[target_id] = threading.Event()

# Cancel signal sent by UI:
cancel_scan(target_id)  →  _cancel_events[target_id].set()

# Check at each pipeline step (_should_run_step inside _run_scan_sequence):
if _cancel_events.get(target_id) and _cancel_events[target_id].is_set():
    raise ScanCancelled(f"Scan cancelled at step {step_name}")

# Cleanup always runs (finally block):
_cancel_events.pop(target_id, None)
_active_scans.pop(target_id, None)
_active_urls.discard(url)
```

The `ScanCancelled` exception is caught before the general `Exception` handler, so the scan status is set to "Cancelled" rather than "Failed". Cancel events are now registered for both new scans and auto-resumed scans.

---

### O5. NVD CVE Sync Engine

```
sync_nvd()
  │
  ├─ load_intel_cache()  ← checks nvd_initial_sync_complete flag
  │
  ├─ First-time sync (nvd_initial_sync_complete = False):
  │    └─ _full_sync()
  │         ├─ GET /cves/2.0?resultsPerPage=500&startIndex=0
  │         ├─ Save progress every page to intel_cache.json
  │         ├─ 6.5s sleep between pages (NVD rate limit compliance)
  │         └─ Loop until startIndex >= totalResults
  │
  └─ Subsequent syncs (nvd_initial_sync_complete = True):
       └─ _incremental_sync()
            └─ GET /cves/2.0?pubStartDate=30days_ago&pubEndDate=today
```

**No date restriction**: All CVEs from NVD's full history are downloaded. The previous year < 2015 filter has been removed in V4.7.

---

### O6. PDF Report Generation Pipeline

```
generate_scan_reports(scan_id, target, findings, previous_scan)
  │
  ├─ _build_context()         ← aggregates all data: findings by tool, counts, trends
  ├─ _generate_html_fallback() ← lightweight HTML for email
  └─ _generate_vapt_pdf()
       │
       ├─ _VAPTDoc (SimpleDocTemplate subclass)
       │    └─ _doPage(): stamps CONFIDENTIAL header + SMP footer on every page
       │
       ├─ Section 1: Cover Page
       │    └─ "Vulnerability Assessment Report — System Generated Report"
       │       + generation timestamp + SMP V4.7 attribution
       │
       ├─ Section 2: Executive Summary + Risk Dashboard + Historical Deltas
       ├─ Section 3: Scope, Methodology, Framework Compliance
       ├─ Section 4: Findings Matrix (sortable: Critical → Info)
       ├─ Section 5: Per-finding deep-dive (Taxonomy, Technical, HOW DETECTED, Evidence, Remediation)
       ├─ Section 5B: Hardening Recommendations (40+ templates)
       ├─ Section 6A: Tooling Appendix
       ├─ Section 6B: Post-testing Cleanup Log
       ├─ Section 6C: Severity Glossary
       └─ Section 6D: Formal Attestation
            │
            └─ Post-build: SHA-256 hash → rename file with hash suffix
                           save_report_hash(scan_id, hash) → DB
```

---

### O7. SSLyze Integration (sslyze 5.x)

SMP uses direct attribute access on `result.scan_result` (sslyze 5.x API):

```python
# Protocol checks use snake_case attribute names:
attr_result = getattr(result.scan_result, "ssl_2_0_cipher_suites", None)
inner = getattr(attr_result, "result", None)
accepted = getattr(inner, "accepted_cipher_suites", None)

# Connectivity error detection (5.x compatibility):
conn_err = (
    getattr(result, 'connectivity_error', None) or      # sslyze 5.x
    getattr(result, 'connectivity_error_trace', None)   # sslyze 4.x fallback
)
```

---

### O8. Encryption System

```
On shutdown (on_quit / handle_system_signals):
  encrypt_databases()
    └─ For each DB file:
         ├─ Read raw bytes
         ├─ Fernet(derived_key).encrypt(raw_bytes)
         └─ Write encrypted bytes back to .db file

On startup (after password verification):
  decrypt_databases()
    └─ For each DB file:
         ├─ Fernet(derived_key).decrypt(encrypted_bytes)
         └─ Write plaintext bytes to memory-mapped DB

Key derivation:
  master_password + bcrypt salt → bcrypt hash → base64 → Fernet key
```

---

### O9. Adding a New Scanner Module

To add a new scanner to the pipeline:

1. **Create `scanners/my_scanner.py`** following the pattern:
   ```python
   TIMEOUT = 120  # seconds — will be auto-capped/scaled by run_with_resilience

   def run_my_scan(url):
       """Returns list of finding dicts or None on failure."""
       findings = []
       # ... scan logic ...
       findings.append({
           "severity": "High",
           "title": "Example Finding",
           "description": "Detailed description with evidence",
           "template_id": "MY-001",
           "confidence": 85,
       })
       return findings
   ```

2. **Import in `scan_runner.py`**:
   ```python
   from scanners.my_scanner import run_my_scan
   ```

3. **Add to `_PIPELINE_STEPS`** list at the appropriate position.

4. **Add the step block** in `_run_scan_sequence()`:
   ```python
   if _should_run_step("Running MyScanner", resume_status):
       update_scan_status(scan_id, "Running MyScanner")
       res, success = run_with_resilience(scan_id, "Running MyScanner",
                                          run_my_scan, url, "my_binary_name")
       if success:
           _save_findings(scan_id, res or [], "MyScanner")
       _log_raw(scan_id, "MyScanner", res)
   ```

5. **Update the resume step map** in `_infer_resume_step()`.

---

### O10. Configuration Reference

`config/settings.json` full schema:

| Key | Type | Default | Description |
|---|---|---|---|
| `smtp_host` | string | `smtp.gmail.com` | Primary SMTP server |
| `smtp_port` | int | `587` | SMTP port (587=STARTTLS, 465=SSL) |
| `smtp_user` | string | — | SMTP username / sender email |
| `smtp_pass` | string | — | 16-char App Password (Gmail) |
| `smtp_receiver` | string | — | Alert recipient email address |
| `smtp_backup_host` | string | — | Failover SMTP relay |
| `tester_name` | string | `Security Auditor` | Appears on PDF cover page |
| `qa_reviewer` | string | `QA Manager` | QA reviewer on PDF cover |
| `scan_schedule_hour` | int | `2` | Hour for scheduled scans (24h format) |
| `intel_sync_interval_hours` | int | `24` | CVE sync frequency in hours |
| `mac_changer_enabled` | bool | `true` | Enable MAC randomization for deep scans |
| `scanner_timeout_seconds` | int | `180` | Per-tool timeout cap |
| `zap_enabled` | bool | `false` | Enable OWASP ZAP active scan |
| `zap_host` | string | `127.0.0.1` | ZAP daemon host |
| `zap_port` | int | `8090` | ZAP daemon port |
| `ffuf_wordlist` | string | `/usr/share/wordlists/dirb/common.txt` | Wordlist path for ffuf |
| `github_token` | string | — | GitHub personal access token for advisory sync |

---

*This document is maintained by mrQhere. © 2024–2026 All Rights Reserved.*
*Security Management Platform V4.7 Stable — [https://github.com/mrQhere/SecurityManagementPlatform](https://github.com/mrQhere/SecurityManagementPlatform)*
