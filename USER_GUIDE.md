# Security Management Platform (SMP) — User Guide & Reference Manual

**Author:** mrQhere  
**Version:** V3.4 (Stable Release)  
**Security Status:** Protected under Cryptographic License Signature Verification

---

## 🔒 SECURITY & COPYRIGHT NOTICE

This software and its documentation are proprietary assets created by **mrQhere**. To prevent unauthorized copying, theft, or distribution, the application incorporates a cryptographic hardware/license signature check. 

At startup, the runtime engine validates that the cryptographic hash in `config/license.key` matches the primary owner signature:
`3cbe2fa02c6dbcfc3b7a5482390a319f071476d6342898cf4a6a57cb7605d3c8`

Any modification or deletion of the licensing validation triggers a system security halt, terminating the application process instantly to safeguard the intellectual property.

---

## 📖 Table of Contents
1. [A. Welcome to SMP & Installation](#a-welcome-to-smp--installation)
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

## 🍏 A. Welcome to SMP & Installation

Welcome to the **Security Management Platform (SMP)**. We designed this tool to be incredibly powerful on the inside, yet beautifully simple on the outside. Whether you are a seasoned security auditor or a complete beginner, SMP automates complex cybersecurity checks with just a few clicks.

> [!TIP]
> **Pro Tip for Beginners:** You don't need to understand every single tool (like Nmap or Nuclei) to use SMP. Just add your website's URL to the Targets tab and hit "Scan". SMP handles all the complex terminal commands for you behind the scenes!

### Prerequisite System Environment
- **Operating System:** Linux/Ubuntu (20.04 LTS or newer)
- **Python Version:** Python 3.11 or newer
- **System Privileges:** Standard user with `sudo` capability (you will need to enter your computer password once during setup).

### Automated Setup (Linux)
The platform features a fully automated, non-interactive installation script. You literally just paste one command and grab a coffee.

1. Open your Terminal.
2. Navigate to the project folder.
3. Run the setup script:

```bash
bash setup.sh
```

**What the installer does while you wait:**
1. Checks for Python and installs it if missing.
2. Creates a safe "sandbox" (`./venv`) so it doesn't mess with your computer's other programs.
3. Downloads all the required cybersecurity tools (Nmap, Nikto, ffuf, etc.) automatically.
4. Secures your files so nobody else on your network can read your reports.

### Launching the Application
Once setup is complete, you can launch the beautiful GUI dashboard anytime by running:

```bash
bash run.sh
```

> [!NOTE]
> **Pro Tip:** Always use `bash run.sh` to start the app. It automatically handles all the complex environment variables and paths for you!

---

## 🚀 First Walkthrough (Before Your First Scan)

If you've just installed SMP and this is your very first time launching it, you must complete a few quick setup steps before you can scan a target.

### Step 1: Create Your Master Password
When you run `bash run.sh` for the first time, you will immediately be greeted by a Master Password prompt. 
- Create a strong password. 
- **Write it down safely.** SMP uses military-grade AES-256 encryption. If you lose this password, your databases are cryptographically locked forever and you must perform a Factory Reset.

### Step 2: Accept the Responsibility Disclaimer
After unlocking the app, a Legal Responsibility dialog will appear. 
- Read the terms carefully. 
- You must physically check the **"I acknowledge"** box to proceed. 
- *Note:* The exact time you click this box is permanently logged in the secure database for legal compliance.

### Step 3: Configure Your Email Alerts (Optional but Recommended)
Before scanning, you probably want to receive PDF reports automatically.
1. Click the **Settings** tab on the left menu.
2. Under SMTP Settings, enter your Gmail address (e.g., `you@gmail.com`).
3. You cannot use your normal Google password. You must generate a **16-character App Password** from your Google Account Security settings and paste it here.
4. Enter the receiver email (where you want the PDFs sent) and click **Save Settings**.
5. Click **Test Connection** to ensure it works!

### Step 4: Add Your First Target
1. Click the **Targets** tab on the left menu.
2. In the "Add New Target" box, type the URL you have permission to test (e.g., `https://example.com`).
3. Click the **Add Target** button. You will see it appear in your Monitored Pipeline Table below.

You are now ready to click **Scan**!

---

## 🖱️ B. System Navigation & GUI Control

The SMP Console features a premium, Apple-inspired high-contrast graphical user interface. We've removed the clutter so you can focus on what matters: your security posture.

> [!TIP]
> **Pro Tip:** The interface is divided into 5 main tabs on the left. Think of "Dashboard" as your bird's-eye view, and "Targets" as your control room where you actually launch scans.

1. **Dashboard Tab**:
   - **KPI Metric Banners**: Live count of Monitored Targets, CVE Threat database volume, Active ongoing scans, and Alert dispatch status.
   - **Target Risk Summary Table**: List of monitored domains with their live operational status and calculated risk classification.
   - **Recent Security Events**: Scrollable widget displaying real-time warning logs, scan triggers, and sync occurrences.
   - **Refresh Button**: Instantly clears memory and redraws the dashboard elements. If things ever look stuck, click this!
   - **Scan All Targets Button**: Bulk-triggers the 22-step scan pipeline for all enabled targets. Perfect for overnight audits.
   - **Responsibility Disclaimer**: A legal disclaimer must be accepted before first use. Upon acceptance, the exact confirmation timestamp is permanently recorded on screen and inside the database for compliance.

2. **Targets Tab**:
   - **Add New Target**: Simply type your website address (e.g. `https://example.com`) and click "Add Target" to add it to your monitoring pool.
   - **Monitored Pipeline Table**: Shows each target's current status, last completed scan timestamp, and action keys (`Scan`, `Report`, `Toggle`, `Delete`).
   - **Ongoing Scans Feed**: Live feedback showing exactly which tool is currently analyzing your website.

3. **Threat Intel Tab**:
   - **Filters**: Dropdowns to search the global vulnerability database. 
   - **CVE Advisory Feed**: Hover over any entry to read what the vulnerability actually does. Color-coded from Info (Grey) to Critical (Red).

4. **Settings Tab**:
   - **Scanner Binary Paths**: Advanced users can customize where the terminal tools are installed.
   - **SMTP Configuration**: Connect your email here so the platform can send you PDF reports automatically when it finds a critical issue.

5. **Audit Logs Tab**:
   - **Master Log**: Your chronological history of everything the app has done.
   - **Scan Events Log**: Terminal output. Useful if you want to see the "Matrix" code of the scanners working.

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

## H. Database Backups & 4-Layer Redundancy

To prevent data corruption and ensure compliance, the platform maintains a highly redundant 4-layer backup system. Every time a scan completes, the database orchestrator automatically synchronizes the live data.

### The 4 Redundant Backup Databases (`/backup/`)
1. **`active_scans.db` (Audit Trail)**: Archives the absolute raw JSON output of every tool (Nmap, ffuf, SQLMap, etc) exactly as it was captured, preserving forensic integrity.
2. **`important_results.db` (Executive Backup)**: Separates and stores only High and Critical severity findings. Useful for rapid remediation workflows.
3. **`cve_secondary.db` (Threat Intel Mirror)**: A complete mirror of the synchronized threat intelligence feeds (NVD, CISA, GitHub Advisories) ensuring offline availability.
4. **`full_backup.db` (Disaster Recovery)**: A perfect, structural 1:1 mirror of all 8 primary application tables (`targets`, `scans`, `findings`, `logs`, `alerts`, `risk_scores`, `technologies`, `responsibility_log`). If your live `security.db` is corrupted or deleted, the system can instantly restore your exact state using `restore_from_backup()`.

### Backup Protection Mechanisms
- **Write-Ahead Logging (WAL)**: Enabled by default to permit concurrent read and write transactions.
- **Transactional Backoff**: Exponential backoff retry loop resolves locks if writes conflict.
- **Safe WAL Checkpoints**: `PRAGMA wal_checkpoint(TRUNCATE)` is executed before copying the database to ensure all logs are fully committed.
- **Zipped Backups**: Backups are archived directly into a zip file (`backup/archive_container_{timestamp}.zip`).
- **Raw Data Export**: Export SQLite raw data scans directly to a zip file using the GUI.

---

---

## 🚨 I. Security Locks & Scanner Capabilities

### Master Password Security Lock
To protect your sensitive vulnerability data, SMP automatically encrypts your databases using military-grade **AES-256 Encryption**. 

1. **Initial Startup**: On your very first launch, you will be asked to create a **Master Password**. Don't lose this!
2. **Subsequent Launches**: Every time you open the app, you must type this password to unlock your data.
3. **Automatic Cleanup**: When you close the app, it instantly scrambles and encrypts your files on the hard drive, so even if someone steals your laptop, they cannot read your security reports.

> [!CAUTION]
> **Warning:** If you forget your Master Password, there is absolutely no "Forgot Password" button. Your data is cryptographically locked forever. You will have to perform a Factory Reset (see Section J).

### Scanning Modes (Standard vs. Deep Scan)
When you click "Scan", you'll see a popup asking for your computer's administrator (`sudo`) password.

* **Standard Mode (Leave Blank)**: If you just click OK without typing your computer password, the scan runs safely using standard permissions. It's fast and effective.
* **Deep Mode (Enter Password)**: If you type your computer password, you give SMP permission to use advanced "Root" techniques. This allows Nmap to attempt to guess the exact operating system of the target, and allows Traceroute to bypass certain firewalls.

---

## 🛠️ J. Disaster Recovery & Complete System Resets

Sometimes things go wrong, or you just want a completely fresh start. Here are the exact copy-paste commands to clean up your system.

> [!IMPORTANT]
> **Pro Tip:** Open your Terminal, navigate to the `SecurityManagementPlatform-main` folder, and literally copy-paste the grey command blocks below.

### 1. Resetting the Master Password (Fresh Database Setup)
Forgot your Master Password? You are locked out. To wipe everything and start entirely fresh:

```bash
# 1. Delete your old encrypted databases
rm -f config/auth.json database/security.db* backup/*.db*

# 2. Relaunch the app to set a new password
bash run.sh
```

### 2. Resetting User Configurations & Settings
Messed up your settings or SMTP passwords? Reset them back to factory defaults:

```bash
# Delete your current settings and restore the blank template
rm -f config/settings.json
cp config/settings.example.json config/settings.json
```

### 3. Cleaning All Logs & Cached Data
Want to clear your audit logs and force the app to re-download the global CVE Threat Database?

```bash
# Delete all logs and cache
rm -rf logs/*
rm -f cache/intel_cache.json
```

### 4. Cleaning Generated PDF & HTML Reports
Too many old PDF reports cluttering up your system?

```bash
# Delete all generated reports
rm -rf reports/html/* reports/pdf/*
```

### 5. THE NUCLEAR OPTION: Full Factory Reset
Want to completely obliterate all your data, settings, logs, and passwords to make the app exactly like the day you downloaded it? Run this single command:

```bash
rm -rf config/auth.json config/settings.json config/license.key database/* backup/* logs/* cache/* reports/html/* reports/pdf/*
```
*(Note: After a nuclear reset, you must copy `license/license.key` back into `config/license.key` manually before the app will launch again).*

---

### License Verification Setup
For user awareness and license key security:
* A public copy of the valid license key is provided in the [license.key](file:///home/dxt/Downloads/SecurityManagementPlatform-main/license/license.key) file within the `license/` folder.
* To authenticate the platform for execution, you must manually copy this file into the gitignored config directory as `config/license.key`.
* Running the platform without copying the license key will trigger a security halt and exit on launch.