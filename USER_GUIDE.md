# Security Management Platform (SMP) — User Guide & Reference Manual

**Author:** mrQhere  
**Version:** V4.7 (Stable Release — 2026-06-27)  
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
3. [C. The 24-Step Sequential Scan Pipeline](#c-the-24-step-sequential-scan-pipeline)
4. [D. Threat Intelligence Feed Integration](#d-threat-intelligence-feed-integration)
5. [E. Vulnerability Reporting (HTML & PDF)](#e-vulnerability-reporting-html--pdf)
6. [F. SMTP Alert Engine & Failover Routing](#f-smtp-alert-engine--failover-routing)
7. [G. Security Audits & Logs Interpretation](#g-security-audits--logs-interpretation)
8. [H. Database Backups & Data Portability](#h-database-backups--data-portability)
9. [I. Security Locks & Scanner Capabilities](#i-security-locks--scanner-capabilities)
10. [J. Disaster Recovery & Complete System Resets](#j-disaster-recovery--complete-system-resets)
11. [K. New Scanning Tools & Automated Action Plans](#k-new-scanning-tools--automated-action-plans)
12. [L. V4.7 Defensive Analytics (Implemented)](#l-v47-defensive-analytics-implemented)
13. [M. Future Roadmap (V5.0)](#m-future-roadmap-v50)
14. [N. Scenarios & Troubleshooting Guide (Top 7)](#n-scenarios--troubleshooting-guide-top-7)

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

```bash
bash setup.sh
```

### Launching the Application
Once setup is complete, you can launch the beautiful GUI dashboard anytime by running:

```bash
bash run.sh
```

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
3. (Optional) Provide the **Company Name** and **Submitted To** name so that the PDF report generates correctly with this metadata.
4. Click the **Add Target** button. You will see it appear in your Monitored Pipeline Table below.

You are now ready to click **Scan**!

---

## 🖱️ B. System Navigation & GUI Control

The SMP Console features a premium, Apple-inspired high-contrast graphical user interface. We've removed the clutter so you can focus on what matters: your security posture.

1. **Dashboard Tab**:
   - **KPI Metric Banners**: Live count of Monitored Targets, CVE Threat database volume, Active ongoing scans, and Alert dispatch status.
   - **Target Risk Summary Table**: List of monitored domains with their live operational status and calculated risk classification.
   - **Recent Security Events**: Scrollable widget displaying real-time warning logs, scan triggers, and sync occurrences.
   - **Refresh Button**: Instantly clears memory and redraws the dashboard elements.
   - **Scan All Targets Button**: Bulk-triggers the 24-step scan pipeline for all enabled targets.

2. **Targets Tab**:
   - **Add New Target**: Simply type your website address and click "Add Target".
   - **Monitored Pipeline Table**: Shows each target's current status and action keys (`Scan`, `Report`, `Toggle`, `Delete`).
   - **Ongoing Scans Feed**: Live feedback showing exactly which tool is currently analyzing your website.

3. **Threat Intel Tab**:
   - **Filters**: Dropdowns to search the global vulnerability database. 
   - **CVE Advisory Feed**: Hover over any entry to read what the vulnerability actually does.

4. **Settings Tab**:
   - **Scanner Binary Paths**: Customize where the terminal tools are installed.
   - **GitHub Token**: Provide your token for higher API rate limits when pulling Advisories.
   - **SMTP Configuration**: Connect your email here so the platform can send you PDF reports automatically.

5. **Audit Logs Tab**:
   - **Master Log**: Your chronological history of everything the app has done.
   - **Scan Events Log**: Terminal output of the scanners working.

---

## C. The 24-Step Sequential Scan Pipeline

To protect networks from Denial of Service (DoS) triggers, the pipeline runs **sequentially (one tool at a time)**.

| Step | Tool | Category | Output Metric / Inference |
|------|------|----------|---------------------------|
| 1 | **HTTPx Probe** | Reconnaissance | Validates the target is online. Pipeline skips early if down. |
| 2 | **WhatWeb** | Fingerprinting | Identifies underlying server technologies (Apache, WordPress, PHP). |
| 3 | **Subfinder** | Subdomain Enum | Identifies active subdomains via passive query feeds. |
| 4 | **theHarvester** | OSINT | Passive search engine scraping for exposed emails and subdomains. |
| 5 | **CRT.sh** | Subdomain Enum | Queries Certificate Transparency logs to find subdomains. |
| 6 | **HackerTarget** | DNS Recon | Resolves IP ranges and reverse DNS maps. |
| 7 | **Whois** | Registry Recon | Pulls registrar dates and contact names. |
| 8 | **Wayback Machine**| URL Recon | Searches archive archives to extract historical URL endpoints. |
| 9 | **Traceroute** | Network Mapping | Performs a UDP path trace without root dependencies. |
| 10 | **Nmap** | Port Scanner | Scans top-100 ports (`-F -sV -T4`) for open ports and banners. |
| 11 | **SSL Scanner** | Cryptography | Evaluates TLS configuration vulnerabilities via `sslyze`. |
| 12 | **Security Headers**| Web Audits | Verifies presence of CSP, HSTS, X-Frame-Options, etc. |
| 13 | **Robots Scanner** | Path Recon | Parses `robots.txt` and locates `sitemap.xml` for hidden paths. |
| 14 | **CORS Scanner** | API Audits | Validates origin parameters to check for wildcard CORS. |
| 15 | **CMS Scanner** | Platform Audits | Specifically probes theme/plugin structures on WordPress/Drupal. |
| 16 | **Nikto Web Scan** | Web Vulnerability | Runs CGI and file-based checks (CSV formatted). |
| 17 | **Nuclei** | Vulnerabilities | Runs template-based YAML scanners for CVE exposures. |
| 18 | **ffuf** | Path Fuzzing | Directory fuzzer using wordlist; isolates output via JSON temp file. |
| 19 | **Open Redirect** | Web Audits | Tests parameters (e.g. `?url=`, `?next=`) for open redirection. |
| 20 | **Tech Fingerprint**| Fingerprinting | Performs deep response header profiling. |
| 21 | **Wapiti** | Web Vulnerability | Performs active OWASP injection checks using `wapiti3`. |
| 22 | **SQLMap** | Injection Audits | Tests potential SQL injection points with `--forms --batch --smart`. |
| 23 | **Shodan profile** | IoT profiling | Queries Shodan InternetDB passively to verify external exposures. |
| 24 | **Gitleaks** | Secret Scanning | Checks for hardcoded passwords, keys, and credentials in repos. |

---

## D. Threat Intelligence Feed Integration

The Threat Intelligence engine syncs periodically to compile a local vulnerability database, which maps directly to target technologies:

1. **NVD NIST Feed**: Fetches paginated base records published since 2018.
2. **CISA KEV Feed**: Syncs CISA's catalog of Known Exploited Vulnerabilities.
3. **GitHub Advisories**: Gathers production-grade advisory CVE records via tokenized authentication.
4. **EPSS scoring**: Enriches entries with Exploit Prediction Scoring System probabilities.

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
13. **Hardening Recommendations**: Actionable items mapped to findings (e.g., Nginx/Apache configuration changes).
14. **References & Citations**: Educational URLs to mapping sources.
15. **Historical Timeline**: Charts comparing findings with previous scans.

Reports are saved in `reports/html/` and `reports/pdf/` and are accessible directly from the Targets tab.

**🔒 Digital Verification Signature:**
Every PDF generated by SMP V4.7 is digitally signed. The engine hashes the PDF using SHA-256 and appends this unique hash directly to the final filename (e.g., `VAPT_Report_example_2026_hash1234.pdf`). Any modification to the file contents will invalidate the hash. You can also drag and drop the PDF into the Settings tab's SHASUM Validator to instantly verify it against the database.

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

### Database Storage Architecture & Encryption Matrix

| Database Name | File Path | Purpose / Description | Encryption (AES-256) |
| :--- | :--- | :--- | :--- |
| **Primary Database** | `database/security.db` | Contains the primary schema: targets, scans, findings, technologies, baselines, etc. | **Yes** (encrypted at rest) |
| **Audit Trail** | `backup/active_scans.db` | Archives the absolute raw JSON output of every tool exactly as it was captured. | **Yes** (encrypted at rest) |
| **Executive Backup** | `backup/important_results.db` | Stores only High and Critical severity findings. | **Yes** (encrypted at rest) |
| **Disaster Recovery** | `backup/full_backup.db` | Structural 1:1 replica of all 8 primary application tables. | **Yes** (encrypted at rest) |
| **Threat Intel Mirror** | `backup/cve_secondary.db` | A local cache mirror of synchronized threat intelligence feeds. | **No** (Stored in plain text) |

---

## I. Security Locks & Scanner Capabilities

### Master Password Security Lock
To protect your sensitive vulnerability data, SMP automatically encrypts your databases using military-grade **AES-256 Encryption**. 

> [!CAUTION]
> **Warning:** If you forget your Master Password, there is absolutely no "Forgot Password" button. Your data is cryptographically locked forever. You will have to perform a Factory Reset (see Section J).

> [!WARNING]
> **OWASP ZAP Note:** ZAP active scanning requires a running Java daemon (`zaproxy`) that must be started separately before the SMP scan runs. It is not auto-started. (ZAP is disabled by default).

### Scanning Modes (Standard vs. Deep Scan)
When you click "Scan", you'll see a popup asking for your computer's administrator (`sudo`) password.

* **Standard Mode (Leave Blank)**: If you just click OK without typing your computer password, the scan runs safely using standard permissions. **Active vulnerability scanners (Nikto, Nuclei, ffuf, Wapiti, SQLMap) will be skipped** because they require the MAC anonymisation step to proceed.
* **Deep Mode (Enter Password)**: If you type your computer password, SMP:
  1. **Randomises your MAC address** — your network adapter's address is changed to a random same-vendor address.
  2. **Enables all active scanners** — Nikto, Nuclei, ffuf, Wapiti, and SQLMap are enabled.
  3. **Unlocks deep Nmap** — Nmap attempts OS fingerprinting and Traceroute bypasses certain firewalls.

---

## J. Disaster Recovery & Complete System Resets

### 1. Resetting the Master Password (Fresh Database Setup)
Forgot your Master Password? You are locked out. To wipe everything and start entirely fresh:

```bash
# 1. Delete your old encrypted databases
rm -f config/auth.json database/security.db* backup/*.db*

# 2. Relaunch the app to set a new password
bash run.sh
```

### 2. THE NUCLEAR OPTION: Full Factory Reset
Want to completely obliterate all your data, settings, logs, and passwords to make the app exactly like the day you downloaded it? Run this single command:

```bash
rm -rf config/auth.json config/settings.json config/license.key database/* backup/* logs/* cache/* reports/html/* reports/pdf/*
```
*(Note: After a nuclear reset, you must copy `license/license.key` back into `config/license.key` manually before the app will launch again).*

---

## K. New Scanning Tools & Automated Action Plans

### 1. OSINT Email & Domain Harvesting (theHarvester)
- **What it does**: Passive search engine scraping of Google, DuckDuckGo, and Bing for target domain’s exposed email addresses and hosts/subdomains.
- **Severity**: Info/Medium.
- **Execution Step**: [4/24].

### 2. Exposed Repositories & Secret Leaks (Gitleaks)
- **What it does**: 
  - Checks if the target web server exposes `.git/config` to the internet (Critical risk).
  - Performs full code repository credential scanning, checking for hardcoded passwords, keys, and credentials.
- **Severity**: Critical.
- **Execution Step**: [24/24].

### 3. Automated Hardening Recommendations & Action Plan
- **What it does**: Matches active scan findings against a local security configuration dictionary (`config/hardening_rules.json`). Output is sorted by severity and includes Nginx, Apache, and Linux Shell/Bash commands that are copy-pasteable to remediate findings instantly.

---

## L. V4.7 Defensive Analytics (Implemented)

The Security Management Platform has been updated to include advanced defensive monitoring and analytics capabilities as part of the V4.7 release:

### Newly Implemented Defensive Features

1. **Fail2Ban Log Reader (Active Threat Visibility)**: The platform now includes `tools/fail2ban_reader.py`, which parses local fail2ban logs to provide active threat intelligence on IP addresses currently banned by the server.
2. **MITRE ATT&CK Technique Mapper**: We have integrated an intelligent mapper (`intelligence/mitre_mapper.py`) that automatically correlates findings with standard MITRE ATT&CK technique IDs (e.g., T1190 for Exploit Public-Facing Application). This context is embedded directly in the VAPT PDF reports.
3. **Historical Scan Trend Analysis**: The reporting engine now tracks historical deltas between scans. The PDF report's Executive Summary displays the exact number of new, resolved, and persisting vulnerabilities compared to the previous assessment.
4. **Response Baseline Diffing (Watchdog)**: The continuous monitoring engine (`scanners/watchdog.py`) is fully active, running every **2 hours** to hash page content, check ports, and monitor SSL certificates for drift or defacement.
5. **Advanced Threat Intel DB**: All new Threat Intelligence feeds are now stored in an isolated `analytics.db` to ensure your primary operational database remains incredibly fast.

*Note: Active exploitation and aggressive fuzzing tools (such as Amass, Feroxbuster, Dnsx, and Wfuzz) are not integrated by design to maintain a purely defensive, zero-harm operational posture.*

---

## M. Future Roadmap (V5.0)

We are actively developing the **V5.0 release**, which will focus on massive enterprise scalability and deep AI integration:
1. **Multi-Node Distributed Scanning:** Run scans across horizontal workers for faster deep scans.
2. **AI-Driven Remediation:** A local, offline LLM that interprets your scan results and generates exact code-blocks for developers to fix the vulnerabilities.
3. **Automated Zero-Day Correlation:** Push notifications to Slack/Discord when a newly published CVE strictly matches an old scan target's technology stack.
4. **Compliance Dashboard:** Real-time metrics mapping your findings directly to PCI-DSS, SOC 2, and HIPAA controls directly in the UI.

---

## N. Scenarios & Troubleshooting Guide (Top 7)

Things don't always go according to plan. We built SMP V4.7 to be incredibly resilient. Here are the 7 most common scenarios you might run into, and the exact steps (and copy-paste commands) to fix them, designed so even a non-coding person can use them.

### Scenario 1: The Configuration is Broken or App Won't Start Properly
**What Happened:** You edited a setting, entered something wrong, or the `config/settings.json` file got corrupted, and now the dashboard behaves weirdly or fails to start.
**The Fix (UI Method):**
1. Go to the **Settings** tab.
2. Scroll to the very bottom to the **Danger Zone**.
3. Click **Reset to Default**. This clears caches, disables OWASP ZAP, and resets your scanning targets.
**The Fix (Terminal Method):**
Open your terminal and paste this code to reset the settings file:
```bash
rm -f config/settings.json
bash run.sh
```

### Scenario 2: You Forgot Your Master Password
**What Happened:** You launched the app and it's asking for the Master Password, but you lost it. Because the databases are encrypted (AES-256) using this password, there is no "Forgot Password" button.
**The Fix:** You must delete the authentication file and databases to start fresh. 
Open your terminal and paste exactly this code:
```bash
rm -f config/auth.json database/*.db* backup/*.db*
bash run.sh
```
*Note: This will delete your past scan results, but it will let you create a new password and get back into the app.*

### Scenario 3: Missing Dependencies or Tools Failing to Run
**What Happened:** You hit "Scan", but the logs show errors like `Command not found` or tools skipping.
**The Fix (UI Method):**
1. Go to the **Settings** tab.
2. Click **Check Dependencies & Tools**. Wait for the popup saying it is complete.
**The Fix (Terminal Method):**
If the UI button doesn't fix it, run the master installer again to ensure all Linux packages are installed.
```bash
bash setup.sh
```

### Scenario 4: The Database is Corrupted or CVE Sync is Stuck
**What Happened:** Power was lost during a scan, or the 2015+ CVE database sync got interrupted, leaving the database locked or corrupted.
**The Fix (Terminal Method):**
We included a safe script specifically to wipe and rebuild the databases without touching your settings or passwords. Run this code:
```bash
python3 reset_db.py
```
This safely deletes `database/` and `backup/` contents and rebuilds the tables instantly.

### Scenario 5: OWASP ZAP or Caching is Breaking the Scan
**What Happened:** You enabled "OWASP ZAP Active Scanning" in settings, but ZAP isn't installed properly on your machine, causing the scan pipeline to hang, or the cache is too large.
**The Fix (UI Method):**
1. Go to the **Settings** tab.
2. Scroll down to the **Danger Zone**.
3. Click **Reset to Default**. This explicitly toggles ZAP off and deletes the `cache/` directory.

### Scenario 6: PDF Reports Not Being Sent via Email
**What Happened:** The scan finishes, you see the report in the dashboard, but you didn't receive an email.
**The Fix:**
1. Ensure you used an **App Password** (16 characters) and not your standard Google password.
2. Ensure you filled out **Report Email Address** in the Report & Operator Settings.
3. Go to the **Settings** tab and click **Test Connection** next to the SMTP settings to verify your credentials. 

### Scenario 7: You Want a "First Install" Factory Reset
**What Happened:** You want to wipe the slate completely clean. You want all targets, all databases, all PDF reports, all logs, and all configurations deleted so it's exactly like the day you downloaded it.
**The Fix (UI Method):**
1. Go to the **Settings** tab.
2. Scroll to the **Danger Zone**.
3. Click **Full Reset**. 
**The Fix (Terminal Method):**
If you can't even access the dashboard, open your terminal and paste this code (The Nuclear Option):
```bash
rm -rf config/auth.json config/settings.json database/* backup/* logs/* cache/* reports/html/* reports/pdf/*
bash run.sh
```
*(After this, you will be prompted to create a new Master Password upon launch).*

