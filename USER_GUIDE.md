# Security Management Platform (SMP) — User Guide & Reference Manual

**Author:** mrQhere  
**Version:** V3.1 (Stable Release)  
**Security Status:** Protected under Cryptographic License Signature Verification

---

## 🔒 SECURITY & COPYRIGHT NOTICE

This software and its documentation are proprietary assets created by **mrQhere**. To prevent unauthorized copying, theft, or distribution, the application incorporates a cryptographic hardware/license signature check. 

At startup, the runtime engine validates that the cryptographic hash in `config/license.key` matches the primary owner signature:
`3cbe2fa02c6dbcfc3b7a5482390a319f071476d6342898cf4a6a57cb7605d3c8`

Any modification or deletion of the licensing validation triggers a system security halt, terminating the application process instantly to safeguard the intellectual property.

---

## 📖 Table of Contents
1. [A. Getting Started & Installation](#a-getting-started--installation)
2. [B. System Navigation & GUI Control](#b-system-navigation--gui-control)
3. [C. The 22-Step Sequential Scan Pipeline](#c-the-22-step-sequential-scan-pipeline)
4. [D. Threat Intelligence Feed Integration](#d-threat-intelligence-feed-integration)
5. [E. Vulnerability Reporting (HTML & PDF)](#e-vulnerability-reporting-html--pdf)
6. [F. SMTP Alert Engine & Failover Routing](#f-smtp-alert-engine--failover-routing)
7. [G. Security Audits & Logs Interpretation](#g-security-audits-&-logs-interpretation)
8. [H. Database Backups & Data Portability](#h-database-backups-&-data-portability)
9. [I. Security Locks & Scanner Capabilities](#i-security-locks-&-scanner-capabilities)
10. [J. Disaster Recovery & Complete System Resets](#j-disaster-recovery-&-complete-system-resets)

---

---

## A. Getting Started & Installation

### Prerequisite System Environment
- **Operating System:** Linux/Ubuntu (20.04 LTS or newer)
- **Python Version:** Python 3.11 or newer
- **System Privileges:** Standard user with passwordless `sudo` capability for package installation (nmap, nikto, whatweb, traceroute).

### Automated Setup (Linux)
The platform features a fully automated, non-interactive installation script. Run the following command from the project root:
```bash
bash setup.sh
```
What the installer accomplishes:
1. Checks for local Python 3.11+; installs system Python if missing.
2. Initializes a sandboxed Python Virtual Environment (`./venv`).
3. Installs core python dependencies (`PySide6`, `APScheduler`, `reportlab`, `requests`, `sslyze`, `sqlmap`, `wapiti3`).
4. Installs system packages via `apt` (`nmap`, `nikto`, `whatweb`, `traceroute`).
5. Provision a fuzzer wordlist (automatically creates `/usr/share/wordlists/dirb/common.txt` using sudo, falling back to a local `$PROJECT_ROOT/config/common.txt` if permissions are restricted).
6. Auto-downloads Go language binary compiler (`go1.23.4`) and configures project-local scanner binaries (`nuclei`, `subfinder`, `httpx`, `ffuf`) in `./bin/`.
7. Hardens file permissions (applies `chmod 700` to databases, backups, and settings; `chmod 750` to the binaries folder).

### Launching the Application
Execute the custom startup script to bypass environment paths:
```bash
bash run.sh
```

---

## B. System Navigation & GUI Control

The SMP Console features a premium Apple-inspired high-contrast graphical user interface.

```
┌────────────────────────────────────────────────────────────────────────┐
│  SMP (mrQhere)    │ Dashboard      [ MONITORED ] [ CVE DB ] [ ACTIVE ] │
│  ──────────────── │ ────────────────────────────────────────────────── │
│  ⬤  Dashboard     │  Target Risk Summary            Recent Security    │
│  ⬤  Targets       │  ┌────────────────────────┐    ┌─────────────────┐ │
│  ⬤  Threat Intel  │  │ Target URL  │ Status   │    │ [Time] Msg      │ │
│  ⬤  Settings      │  │ ──────────  │ ──────── │    │ ──────────────  │ │
│  ⬤  Audit Logs    │  │ kniti.live  │ Enabled  │    │ CVE Feed Synced │ │
│                   │  └─────────────┴──────────┘    └─────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Dashboard Tab**:
   - **KPI Metric Banners**: Live count of Monitored Targets, CVE Threat database volume, Active ongoing scans, and Alert dispatch status.
   - **Target Risk Summary Table**: List of monitoed domains with their live operational status and calculated risk classification.
   - **Recent Security Events**: Scrollable widget displaying real-time warning logs, scan triggers, and sync occurrences.
   - **Refresh Button**: Instantly clears memory and hashlib states to redraw the dashboard elements.

2. **Targets Tab**:
   - **Add New Target**: Input a domain/IP (e.g. `https://example.com`) and click "Add Target" to add it to the monitoring pool.
   - **Monitored Pipeline Table**: Shows each target's current status (Enabled/Disabled), last completed scan timestamp, scanning auditor, and action keys (`Scan`, `Report`, `Toggle`, `Delete`).
   - **Ongoing Scans Feed**: Live feedback showing exactly which of the 22 scan pipeline steps is currently executing on active threads.

3. **Threat Intel Tab**:
   - **Filters**: Dropdowns to query the CVE database by severity (Critical, High, Medium, Low) and keyword search.
   - **CVE Advisory Feed**: Tooltips reveal description and product impacts upon hover. Color-coded by severity levels.

4. **Settings Tab**:
   - **Scanner Binary Paths**: Customize executable paths for scanners.
   - **SMTP Configuration**: Specify SMTP host, port, user account, app password (supports toggled password visibility), sender, and receiver. Includes a "Test Connection" worker tool.

5. **Audit Logs Tab**:
   - Tabbed consoles showing Master log, Scan events log, CVE intelligence log, and System Errors log. All logs are prepended in real-time, keeping the latest updates at the very top.

---

## C. The 22-Step Sequential Scan Pipeline

To protect networks from Denial of Service (DoS) triggers, the pipeline runs **sequentially (one tool at a time)**.

| Step | Tool | Category | Output Metric / Inference |
|------|------|----------|---------------------------|
| 1 | **HTTPx Probe** | Reconnaissance | Validates the target is online. Pipeline skips early if down. |
| 2 | **WhatWeb** | Fingerprinting | Identifies underlying server technologies (Apache, WordPress, PHP). |
| 3 | **Subfinder** | Subdomain Enum | Identifies active subdomains via passive query feeds. |
| 4 | **CRT.sh** | Subdomain Enum | Queries Certificate Transparency logs to find subdomains. |
| 5 | **HackerTarget** | DNS Recon | Resolves IP ranges and reverse DNS maps. |
| 6 | **Whois** | Registry Recon | Pulls registrar dates and contact names. |
| 7 | **Wayback Machine**| URL Recon | Searches archive archives to extract historical URL endpoints. |
| 8 | **Traceroute** | Network Mapping | Performs a UDP path trace without root dependencies. |
| 9 | **Nmap** | Port Scanner | Scans top-100 ports (`-F -sV -T4`) for open ports and banners. |
| 10 | **SSL Scanner** | Cryptography | Evaluates TLS configuration vulnerabilities via `sslyze`. |
| 11 | **Security Headers**| Web Audits | Verifies presence of CSP, HSTS, X-Frame-Options, etc. |
| 12 | **Robots Scanner** | Path Recon | Parses `robots.txt` and locates `sitemap.xml` for hidden paths. |
| 13 | **CORS Scanner** | API Audits | Validates origin parameters to check for wildcard CORS. |
| 14 | **CMS Scanner** | Platform Audits | Specifically probes theme/plugin structures on WordPress/Drupal. |
| 15 | **Nikto Web Scan** | Web Vulnerability | Runs CGI and file-based checks (CSV formatted). |
| 16 | **Nuclei** | Vulnerabilities | Runs template-based YAML scanners for CVE exposures. |
| 17 | **ffuf** | Path Fuzzing | Directory fuzzer using wordlist; isolates output via JSON temp file. |
| 18 | **Open Redirect** | Web Audits | Tests parameters (e.g. `?url=`, `?next=`) for open redirection. |
| 19 | **Tech Fingerprint**| Fingerprinting | Performs deep response header profiling. |
| 20 | **Wapiti** | Web Vulnerability | Performs active OWASP injection checks using `wapiti3`. |
| 21 | **SQLMap** | Injection Audits | Tests potential SQL injection points with `--forms --batch --smart`. |
| 22 | **Shodan profile** | IoT profiling | Queries Shodan InternetDB passively to verify external exposures. |

---

## D. Threat Intelligence Feed Integration

The Threat Intelligence engine syncs periodically to compile a local vulnerability database, which maps directly to target technologies:

1. **NVD NIST Feed**:
   - Fetches paginated base records published since 2018. Enforces a 6.5s delay to strictly comply with API request rates. Uses incremental 30-day checks after the first initial sync.
2. **CISA KEV Feed**:
   - Syncs CISA's catalog of Known Exploited Vulnerabilities directly to focus alerts on real-world active exploits.
3. **GitHub Advisories**:
   - Gathers production-grade advisory CVE records using HTTP Link-header pagination.
4. **EPSS scoring**:
   - Enriches entries with Exploit Prediction Scoring System probabilities to help prioritize critical items.

### Technology Correlation
After a scan completes, the Correlation Engine searches the `cves` table for overlaps with the target's detected software names. Any matches are inserted into the `findings` table as a **CVE Correlation** finding, making them visible in the dashboard and reports.

---

## E. Vulnerability Reporting (HTML & PDF)

When a scan finishes, a detailed **15-section report** is compiled:

1. **Cover Page**: Includes target metadata, open ports, and prepared by/tester configuration details.
2. **Executive Summary**: Metrics of findings categorized by severity.
3. **Scope & Authorization**: Authorization statements to demonstrate permission.
4. **Network Reconnaissance**: Hops and route path results.
5. **Open Ports**: Table showing ports, service protocols, and application versions.
6. **SSL/TLS Analysis**: Certificate validity and encryption protocol support.
7. **Detected Technologies**: Full detected tech stack list.
8. **Directory Discovery**: List of accessible fuzz paths found.
9. **Web Vulnerabilities**: Vulnerabilities found during Nikto and Nuclei scans.
10. **Injection Vulnerabilities**: SQL injection vulnerabilities found by SQLMap or Wapiti.
11. **Threat Intel (CVEs)**: Correlated CVE advisories.
12. **Risk Score Metrics**: Displays calculated numeric score (0 to 100) and severity rating.
13. **Hardening Recommendations**: Actionable items mapped to findings.
14. **References & Citations**: Educational URLs to mapping sources.
15. **Historical Timeline**: Charts comparing findings with previous scans.

Reports are saved in `reports/html/` and `reports/pdf/` and are accessible directly from the Targets tab.

---

## F. SMTP Alert Engine & Failover Routing

The alert engine sends email alerts under three circumstances:
1. **Target Offline**: The target goes offline (all tools fail).
2. **Findings Escalation**: A new vulnerability is discovered or an existing one increases in severity.
3. **Correlated CVE**: A newly synced CVE matches a technology running on an active target.

### Setting Up Gmail (App Password Requirement)
Standard Gmail accounts require a 16-character **App Password** for SMTP authentication:
1. Go to **Google Account Settings → Security**.
2. Enable **2-Step Verification**.
3. Click **App Passwords** and generate a key for "Mail".
4. Copy the generated 16-character password and enter it into the Settings tab.

### Failover Relay Routing
To prevent critical alert delivery failure, if the primary SMTP connection (`smtp_host`) fails or times out, the router automatically fails over to the configured backup SMTP relay settings before logging an error.

---

## G. Security Audits & Logs Interpretation

Logs are organized into four dedicated targets:
- **`logs/master.log`**: Standard operational audit trail of target status changes, backup jobs, and user actions.
- **`logs/scan.log`**: Detailed command strings and exit codes of active scanners.
- **`logs/cve.log`**: Intelligence sync errors and API status logs.
- **`logs/error.log`**: Application crash reports, SQLite write blocks, and stack traces.

---

## H. Database Backups & Data Portability

To prevent data corruption, backups use the following protection mechanisms:
- **Write-Ahead Logging (WAL)**: Enabled by default to permit concurrent read and write transactions.
- **Transactional Backoff**: Exponential backoff retry loop resolves locks if writes conflict.
- **Safe WAL Checkpoints**: `PRAGMA wal_checkpoint(TRUNCATE)` is executed before copying the database to ensure all logs are fully committed.
- **Zipped Backups**: Backups are archived directly into a zip file (`backup/archive_container_{timestamp}.zip`).
- **Raw Data Export**: Export SQLite raw data scans directly to a zip file using the GUI.

---

## I. Security Locks & Scanner Capabilities

### Master Password Security Lock
To protect the confidentiality of scanned target URLs, active findings, and custom server settings, the Security Management Platform automatically encrypts all database files on disk using **AES-256 (Fernet)**.
1. **Initial Startup**: On the first launch, the user is required to configure a **Master Password**. This creates an authentication validation token at `config/auth.json`.
2. **Subsequent Launches**: You must input the correct Master Password to unlock the interface and decrypt the database. Failure to authenticate blocks interface loading.
3. **Automatic Cleanup**: On clean quit or when catching termination signals, the app securely overwrites and deletes the plaintext database files, leaving only encrypted files (`.enc`) on disk.

### Scanning Modes (Standard vs. Full Mode)
Upon triggering any scan, the platform prompts the user for their system **sudo password**:
* **Standard Mode (Default)**: If no password is provided, scanners run with standard privileges. OS detection (`-O`) and ICMP traceroute (`-I`) are skipped to prevent permission errors.
* **Full Mode (Elevated)**: Entering a valid sudo password elevates scanner capabilities. The orchestrator prepends `sudo -S` to execution threads:
  * **Nmap**: Adds OS detection (`-O`) and default scripts (`-sC`) to the scan.
  * **Traceroute**: Uses ICMP mode (`-I`) which is faster and bypassed by fewer firewalls than standard UDP traceroute.

### Timeout Capping & Pipeline Resiliency
To prevent the scan queue from stalling indefinitely on slower targets:
* The initial scan sequence caps individual scanner runtimes to a maximum of **180 seconds** (configurable in settings).
* If a tool is stuck and times out, the process group is forcefully terminated, the failure is logged, and the orchestrator moves on to the next scanner step.
* At the conclusion of the initial sequence, any deferred scanners are retried in a dedicated **Retry Queue** with their full, un-capped timeout settings.

---

## J. Disaster Recovery & Complete System Resets

If you encounter system corruptions, lose passwords, or need to restore the platform to a clean slate, follow these reset procedures:

### 1. Resetting the Master Password (Fresh Database Setup)
If you forget your Master Password, you will be locked out of the encrypted databases and configurations. Since the databases are securely encrypted using your password, recovery is not cryptographically possible. 

To wipe target databases and start fresh:
1. Delete the authentication configuration and encrypted databases:
   ```bash
   rm -f config/auth.json database/security.db* backup/*.db*
   ```
2. Relaunch the application:
   ```bash
   ./run.sh
   ```
3. You will be prompted to configure a new Master Password upon startup.

### 2. Resetting User Configurations & Settings
If you want to clear SMTP passwords, custom tool paths, or scheduler configurations:
```bash
# Delete local configuration settings
rm -f config/settings.json
# Restore the settings template
cp config/settings.example.json config/settings.json
```

### 3. Resetting Threat Intelligence & CVE Cache
If you want to force a full re-download and sync of NVD, CISA, and GitHub Advisories:
```bash
# Delete cached EPSS / intelligence cache files
rm -f cache/intel_cache.json
```

### 4. Cleaning All Audit Logs & Scan Logs
To flush the terminal views and start with blank log displays:
```bash
# Clear all logs
rm -rf logs/*
```

### 5. Cleaning Generated PDF & HTML Reports
To delete all previously generated report files:
```bash
# Remove all reports
rm -rf reports/html/* reports/pdf/*
```

### 6. Full Factory Reset (All-in-One Command)
To revert the entire application directory to its pristine post-cloned state (wiping all local configurations, logs, databases, cache, and reports):
```bash
rm -rf config/auth.json config/settings.json config/license.key database/* backup/* logs/* cache/* reports/html/* reports/pdf/*
```
*Note: Make sure to copy `license/license.key` into `config/license.key` manually after resetting to enable startup.*

---

### License Verification Setup
For user awareness and license key security:
* A public copy of the valid license key is provided in the [license.key](file:///home/dxt/Downloads/SecurityManagementPlatform-main/license/license.key) file within the `license/` folder.
* To authenticate the platform for execution, you must manually copy this file into the gitignored config directory as `config/license.key`.
* Running the platform without copying the license key will trigger a security halt and exit on launch.