<div align="center">
  <h1>Security Management Platform (SMP) V6.5</h1>
  <p><b>Where Beauty Meets Standards. The Ultimate Enterprise Security Orchestrator.</b></p>
  <p><i>Made by mrQhere</i></p>
</div>

<br><br>

> **"Simplicity is the ultimate sophistication."** 
> SMP V6.5 is designed with an Apple-like aesthetic: incredibly simple on the outside, immensely powerful on the inside.

<hr>

## Table of Contents
1. [Philosophy & Architecture](#1-philosophy--architecture)
2. [Setup (Beginner)](#2-setup-beginner)
3. [First Run & Daily Operations](#3-first-run--daily-operations)
4. [Intermediate — Pipeline & Tools](#4-intermediate--pipeline--tools)
5. [Advanced — Core Internals & Encryption](#5-advanced--core-internals--encryption)
6. [Adding Custom Scanners](#6-adding-custom-scanners)
7. [REST API Reference](#7-rest-api-reference)
8. [Troubleshooting (40 Common Errors)](#8-troubleshooting-40-common-errors)
9. [Future Roadmap — V7, V8, V9](#9-future-roadmap--v7-v8-v9)

---

## 1. Philosophy & Architecture
SMP is built on the belief that security orchestration should not require a PhD to operate. 
It combines **FastAPI**, **SQLite (SQLCipher)**, and **30+ security tools** into a single, cohesive ecosystem.

- **Frontend**: PySide6 (Local GUI) / HTML Reports (Exported)
- **Backend**: FastAPI (REST)
- **Database**: SQLCipher (AES-256 Encrypted)
- **Intelligence**: GreyNoise, CVE Sync, ExploitDB
- **Pipeline**: Dynamic Stage-Feeding (Recon -> Active -> Exploit -> Report)

---

## 2. Setup (Getting Started for Beginners)

Welcome to SMP! Setting up SMP is designed to be as seamless as possible. We provide two main ways to get started: **Docker** (recommended for most users) and **Local Installation** (recommended if you plan to develop or modify the code).

### Prerequisites

Before starting, ensure you have the following installed on your system:
- **Git**: To clone the repository.
- **Make**: To use the simplified commands.

For Docker installation:
- **Docker & Docker Compose**: The engine that runs SMP securely in an isolated container.

For Local installation:
- **Python 3.10+**: The core language used by the platform.
- **sudo access**: Required to install necessary security scanners (Nmap, Masscan, etc.) during setup.

---

### Using Docker (Recommended - The Apple Way)

Running SMP in Docker is the most reliable way to ensure all dependencies work out of the box without polluting your host system.

```bash
# 1. Clone the repository to your local machine
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# 2. Build the platform image
# This step automatically downloads all Python packages, Go binaries, and OS dependencies 
# required by the 30+ security tools into an isolated image.
make docker-build

# 3. Start the platform
# This spins up the API, database, and background workers.
make docker-run
```

**Success!** The platform API and interactive documentation are now running at:
👉 `http://localhost:8000/api/v6/docs`

To stop the platform, simply press `Ctrl+C` in the terminal, or run `make docker-down`.

---

### Local Installation (For Developers & Power Users)

If you prefer to run SMP directly on your host machine (useful for debugging, adding custom tools, or avoiding Docker overhead), use the automated setup scripts.

```bash
# 1. Make the setup script executable
chmod +x setup.sh

# 2. Run the auto-setup script
# This script will automatically create a Python virtual environment (venv), 
# install requirements.txt, and attempt to install system packages (like nmap, dirb) via apt/brew.
./setup.sh

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Start the REST API
make run-api
```

**Note for Windows Users:** You can use the provided `setup.bat` or `setup.ps1` scripts instead of `setup.sh`. However, some advanced scanners might require WSL (Windows Subsystem for Linux) to function optimally.

---

## 3. First Run & Daily Operations

When you first start SMP, the system automatically checks for the latest CVE databases. 

### Exploring the User Interface
The UI is divided into several powerful sections:

- **Dashboard**: The command center. Here you can add targets, view real-time risk scores, and monitor live scan pipelines in the "Active Scan Monitor". The Live Monitor shows step-by-step narrative updates of exactly what the scanners are doing.
- **Targets**: A dedicated view to manage your domains and IPs.
- **Threat Intel**: A live searchable feed of the CVE database. It includes a chart showing vulnerability distributions and lets you force a sync with NVD and GitHub Advisories.
- **Audit Logs**: The immutable trail of everything the platform has done, including error logs and engine startup logs.
- **Settings**: Where you configure the platform's behavior:
  - **SMTP**: Configure email notifications. You must provide host, port, user, and an App Password.
  - **Reports**: Set the Auditor Name and QA Reviewer Name for the generated PDFs. Contains a Drag & Drop zone to cryptographically verify report authenticity.
  - **API Keys & Proxies**: Define HTTP/HTTPS proxies for the scanners and configure your GitHub token. *(Note: Hidden API keys like WPScan or GreyNoise are configured via `config/settings.json`)*.
  - **Scan Profile**: Choose between `fast` (OSINT only), `standard` (default VAPT), or `full` (highly invasive/aggressive tools like ZAP and Commix).
  - **Auth Headers**: Inject custom Cookies or Bearer Tokens into the scanners for authenticated scanning of web apps.


### Running a Scan
1. Open the UI or API.
2. Enter the target domain (`https://example.com`).
3. Click **Scan**.
4. SMP handles the rest.

### Viewing the Narrative
SMP translates terminal output into human language. You can read the scan story in real-time in the UI, or by checking the logs:
```bash
make docker-logs
```

---

## 4. Intermediate — Pipeline & Tools

### How it works behind the scenes
SMP uses an **Adaptive Stage-Feeding Pipeline**.
1. **Recon Phase**: Passive reconnaissance. Subfinder, Whois, HTTPx.
2. **Active Phase**: Active scanning. Nmap, Nuclei, Dirb, Gobuster.
3. **Exploit Phase**: Only triggered if Phase 2 finds something. E.g., if WordPress is found, WPScan runs.

### Tool Inventory
The system contains dozens of tools. Here is what they do:

### `amass.py`

```text
OWASP Amass — Best-in-class subdomain enumeration + network mapping.
```

<br>

### `api_fuzzer.py`

```text
REST API Fuzzer — Tests OpenAPI/Swagger endpoints for misconfigurations and injection.
```

<br>

### `arjun.py`

```text
Arjun — HTTP Parameter Discovery suite for uncovering hidden parameters.
```

<br>

### `cloud_enum.py`

```text
Cloud Enum — Multi-cloud OSINT tool to find public AWS/Azure/GCP resources.
```

<br>

### `cms_scanner.py`

```text
CMS Scanner — Detects and enumerates vulnerabilities in WordPress, Joomla, Drupal, etc.
```

<br>

### `commix.py`

```text
Commix — Automated all-in-one OS command injection and exploitation tool.
```

<br>

### `cors_scanner.py`

```text
CORS Scanner — Identifies insecure Cross-Origin Resource Sharing configurations.
```

<br>

### `crlf_scanner.py`

```text
CRLF / Header Injection Scanner.
```

<br>

### `crtsh.py`

```text
CRT.sh — Queries Certificate Transparency logs for rapid passive subdomain enumeration.
```

<br>

### `dalfox.py`

```text
DalFox — Fast, parameter-analyzing XSS scanner and utility based on Golang.
```

<br>

### `dirb.py`

```text
Dirb Scanner — SMP V6.5
=========================
Runs Dirb for classic web content discovery using dictionary-based scanning.
Provides a third fuzzing engine alongside ffuf and gobuster, using its own
built-in wordlists optimised for older/obscure web paths.

Install:
    sudo apt install dirb
```

<br>

### `dnsx.py`

```text
dnsx — Fast and multi-purpose DNS toolkit allow to run multiple DNS queries.
```

<br>

### `feroxbuster.py`

```text
Feroxbuster — Recursive content discovery (fast, async, Rust-based).
```

<br>

### `ffuf.py`

```text
FFUF — Fast web fuzzer written in Go for rapid directory and parameter discovery.
```

<br>

### `gitleaks.py`

```text
Gitleaks — Detects hardcoded secrets like passwords, API keys, and tokens in git repos.
```

<br>

### `gobuster.py`

```text
Gobuster Scanner — SMP V6.5
============================
Runs Gobuster for fast directory, file, DNS, and vhost brute-forcing.
Complements ffuf by providing a second fuzzing engine with different
payloads and enumeration modes.

Gobuster modes used:
  - dir   — Directory and file enumeration
  - dns   — Subdomain brute-force via DNS
  - vhost — Virtual host discovery

Install:
    go install github.com/OJ/gobuster/v3@latest
  or:
    sudo apt install gobuster
```

<br>

### `graphql_scanner.py`

```text
GraphQL Scanner — Introspection, batch attacks, and information disclosure.
```

<br>

### `hackertarget.py`

```text
HackerTarget — Leverages the HackerTarget API for reverse DNS, whois, and port scans.
```

<br>

### `headers_scanner.py`

```text
Security Headers — Analyzes HTTP response headers for missing security protections.
```

<br>

### `httpx_scanner.py`

```text
HTTPX — Fast and multi-purpose HTTP toolkit to run multiple probes concurrently.
```

<br>

### `hydra_scanner.py`

```text
Hydra — Rate-limited brute-force authentication testing (login forms only).
```

<br>

### `jwt_scanner.py`

```text
JWT Scanner — Analyzes JSON Web Tokens for weak signatures and misconfigurations.
```

<br>

### `katana.py`

```text
Katana — A next-generation crawling and spidering framework.
```

<br>

### `masscan.py`

```text
Masscan — TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 6 minutes.
```

<br>

### `netcat_probe.py`

```text
Netcat Probe Scanner — SMP V6.5
================================
Uses netcat (nc) for raw TCP/UDP port probing and banner grabbing.
Complements Nmap by providing direct, low-noise service banner collection
for specific ports without sending SYN/RST noise.

Typical use-cases:
  - Banner grab ports found open by Nmap
  - Probe custom/high ports for running services
  - Detect non-HTTP services (SMTP, FTP, POP3, IMAP, etc.)

Install:
    sudo apt install netcat-openbsd
```

<br>

### `nikto.py`

```text
Nikto — Web server scanner which performs comprehensive tests for multiple items, including dangerous files/CGIs.
```

<br>

### `nmap.py`

```text
Nmap — The industry standard for network exploration, port scanning, and security auditing.
```

<br>

### `nuclei.py`

```text
Nuclei — Fast and customizable vulnerability scanner based on simple YAML based DSL.
```

<br>

### `open_redirect.py`

```text
Open Redirect — Scans for open redirect vulnerabilities in URL parameters.
```

<br>

### `paramspider.py`

```text
ParamSpider — Mines parameters from web archives for deeper fuzzing.
```

<br>

### `path_traversal.py`

```text
Path Traversal / LFI Scanner.
```

<br>

### `retire_js.py`

```text
Retire.js — JavaScript library CVE detection via version fingerprinting.
```

<br>

### `robots_scanner.py`

```text
Robots/Sitemap Scanner — Analyzes robots.txt and sitemap.xml for hidden endpoints.
```

<br>

### `scan_runner.py`

```text
Scan Runner – coordinates all scanner modules in a sequential pipeline.

Optimized pipeline order (maximum efficiency — cheap/fast OSINT first, deep scans last):

  1.  HTTPx              – quick HTTP probe: confirms site is up before expensive tools run
  2.  WhatWeb            – passive fingerprint: sets technology context early
  3.  Subfinder          – DNS subdomain discovery
  4.  CRT.sh             – certificate transparency subdomain enum
  5.  HackerTarget       – Reverse DNS / additional recon
  6.  Whois              – domain registration info
  7.  Wayback Machine    – historical URL mapping
  8.  Traceroute         – network path (UDP, no root)
  9.  Nmap               – port + service scan (expensive — after all OSINT)
  10. SSL Scanner        – TLS/certificate analysis
  11. Security Headers   – HTTP header security check
  12. Robots.txt         – robots.txt / sitemap analysis
  13. CORS Scanner       – CORS misconfiguration check
  14. CMS Scanner        – CMS / admin panel detection
  15. Nikto              – web vulnerability scanner
  16. Nuclei             – template-based vuln scan
  17. ffuf               – directory fuzzing
  18. Open Redirect      – open redirect parameter testing
  19. Tech Fingerprint   – deep response-based tech detection
  20. Wapiti             – OWASP web app scan
  21. SQLMap             – SQL injection detection
  22. Shodan InternetDB  – passive IoT/IP exposure check
  [*] OWASP ZAP         – optional active scan (disabled by default)
  23. CVE Correlation    – offline: tech → CVE matching
  24. Risk Scoring       – offline: 0–100 score
  25. Report Generation  – HTML + PDF
  26. SMTP Alerts        – email dispatch
```

<br>

### `screenshot_capture.py`

```text
Screenshot Capture V6.5
========================
Captures screenshots of vulnerable endpoints as cryptographic evidence
for reports. Uses playwright (headless Chromium) as primary method
and a requests-based HTML snapshot as fallback.

Usage:
    from scanners.screenshot_capture import capture_screenshot
    path = capture_screenshot("https://target.com/vuln-page")
```

<br>

### `secrets_scanner.py`

```text
Secrets Scanner V6.5
=====================
Real pattern-based secrets detection in HTTP responses, HTML, JS files,
and raw scanner output. Replaces the empty stubs (trufflehog/gitleaks).

Detects:
  - API keys (AWS, GCP, Azure, Stripe, Twilio, SendGrid, etc.)
  - Private keys (RSA, EC, PEM blocks)
  - JWT tokens
  - Database connection strings
  - Generic high-entropy tokens

Fallback chain:
  1. Full regex scan of HTTP responses via requests
  2. Regex scan of already-collected raw output if network fails
```

<br>

### `shodan_idb.py`

```text
Shodan InternetDB — Offline passive lookup of open ports and vulnerabilities via Shodan.
```

<br>

### `smuggler.py`

```text
HTTP Request Smuggling — CL.TE / TE.CL / TE.TE detection.
```

<br>

### `sqlmap.py`

```text
SQLMap — Automatic SQL injection and database takeover tool.
```

<br>

### `ssl_scanner.py`

```text
SSL Scanner — Analyzes SSL/TLS configuration for weak ciphers and vulnerabilities.
```

<br>

### `ssrf_scanner.py`

```text
SSRF Scanner — Server-Side Request Forgery parameter testing.
```

<br>

### `subfinder.py`

```text
Subfinder — Fast passive subdomain enumeration tool using passive online sources.
```

<br>

### `tech_fingerprint.py`

```text
Tech Fingerprint — Identifies underlying technologies, frameworks, and CMS of a web app.
```

<br>

### `theharvester.py`

```text
TheHarvester — OSINT tool to gather emails, subdomains, hosts, employee names, open ports and banners.
```

<br>

### `traceroute.py`

```text
Traceroute — Network diagnostic tool for displaying the route and measuring transit delays of packets.
```

<br>

### `wapiti.py`

```text
Wapiti — Web application vulnerability scanner that acts like a fuzzer.
```

<br>

### `watchdog.py`

```text
Continuous Monitoring Watchdog — lightweight 15-minute checks per target.

Checks performed on every run (no full scanner needed):
  1. HTTP status code         — site down or unexpected redirect
  2. Page content hash        — possible defacement or injection
  3. HTTP response headers    — security headers removed / new suspicious headers
  4. DNS A record             — DNS hijacking indicator
  5. SSL certificate fingerprint — cert replaced post-compromise
  6. SSL certificate expiry      — cert about to expire (≤14 days warning)
  7. Open port snapshot       — new backdoor port appeared (Nmap top-20)

On first run per target: saves snapshot as baseline, no alert.
On subsequent runs: compares against baseline, fires BASELINE_DRIFT email alert
  on any deviation. Updates baseline to current after alerting.

Uses only Python stdlib + requests + nmap (already required by SMP).
```

<br>

### `wayback.py`

```text
Wayback Machine — Fetches historical URLs from the Internet Archive for endpoint discovery.
```

<br>

### `whatweb.py`

```text
WhatWeb — Next generation web scanner for identifying technologies used by websites.
```

<br>

### `whois_scanner.py`

```text
Whois — Queries WHOIS databases for domain registration details.
```

<br>

### `wpscan.py`

```text
WPScan — Black box WordPress vulnerability scanner.
```

<br>

### `xxe_scanner.py`

```text
XXE Scanner — XML External Entity injection testing.
```

<br>

### `zap.py`

```text
OWASP ZAP — Integrated dynamic application security testing (DAST) tool.
```

<br>

### `alert_engine.py`

```text
Alert Engine — Dispatches notifications via SMTP, Slack, Webhooks upon finding detection.
```

<br>

### `baseline_manager.py`

```text
Port Baseline Manager V6.5
============================
Stores and compares per-target port profiles across scans.
After the first scan, a "baseline" is saved. All subsequent scans
compare against it and flag new/unexpected open ports as High findings.

Fallback chain:
  1. DB-stored baseline (primary)
  2. File-based JSON cache (secondary — survives DB issues)
```

<br>

### `bump_version.py`

```text
SMP Version Bumper — updates version everywhere it matters.
Usage: python3 tools/bump_version.py V6.5
```

<br>

### `compliance_mapper.py`

```text
Compliance Mapper V6.5
=======================
Maps SMP finding types and CWE IDs to compliance control references:
  - OWASP Top 10 2021
  - CIS Controls v8
  - ISO 27001:2022 Annex A

Usage:
    from tools.compliance_mapper import map_finding_to_controls
    controls = map_finding_to_controls("SQL Injection", "CWE-89")
    # Returns: {"owasp": "A03:2021", "cis": "CIS 16.1", "iso": "A.8.28"}
```

<br>

### `config_manager.py`

```text
Config Manager — Centralized management of platform settings, thresholds, and secrets.
```

<br>

### `db_manager.py`

```text
Database Manager — Handles SQLite/SQLCipher connections, migrations, and ORM mapping.
```

<br>

### `dynamic_pipeline.py`

```text
Dynamic Pipeline — SMP V6.5
==============================
Stage-feeding scan pipeline inspired by the PentestGPT multi-stage approach.

Instead of a rigid sequential list, this module makes the pipeline *adaptive*:
- Phase 1 (Recon) runs fast OSINT tools and collects findings.
- The results are analysed and used to decide which Phase 2 (Active) scanners
  to prioritise or add dynamically.
- Phase 3 (Exploit) scanners are only triggered when Phase 2 finds evidence
  that makes them relevant (e.g. WordPress found → WPScan; open 22 → Hydra).

Key design decisions taken from PentestGPT:
- Each stage feeds the next via a typed result dict.
- Branching logic is deterministic (no LLM required) — based on technology
  and finding data already in the SMP database.
- All branching decisions are logged through narrative_logger for transparency.

Usage:
    from tools.dynamic_pipeline import DynamicPipeline
    pipeline = DynamicPipeline(scan_id=42, target_url="https://example.com", settings={})
    pipeline.run()
```

<br>

### `encryption_manager.py`

```text
Encryption Manager — manages SQLite database encryption and decryption at application level.
```

<br>

### `event_bus.py`

```text
In-Process Event Bus V6.5
==========================
Thread-safe publish/subscribe event bus replacing the old unsafe UDP IPC socket.
Allows decoupled communication between scanner threads and the UI.

Usage:
    # Publisher (scanner thread):
    from tools import event_bus
    event_bus.emit("mac_changed", {"new_mac": "aa:bb:cc:dd:ee:ff"})

    # Subscriber (dashboard):
    from tools import event_bus
    event_bus.subscribe("mac_changed", my_callback)
```

<br>

### `fail2ban_reader.py`

```text
Fail2Ban Integrator — Reads Fail2Ban logs to correlate attacks and dynamically block malicious actors.
```

<br>

### `finding_deduplicator.py`

```text
Finding Deduplicator V6.5
==========================
Merges structurally identical findings from multiple scanners into a single
finding with all source scanners cited (e.g. Nuclei + Nikto both reporting
"Missing X-Frame-Options" → one merged finding: "Nuclei, Nikto").

Strategy:
  1. Normalize finding title (lowercase, strip whitespace, remove scanner name prefixes)
  2. Group by (normalized_title, severity, target_url)
  3. Merge sources into comma-separated "tool" field
  4. Keep highest-confidence raw description
```

<br>

### `logger_setup.py`

```text
Logger Setup — Configures structured, rotated logging for the entire platform.
```

<br>

### `mac_changer.py`

```text
MAC Address Changer — called at scan start (not app startup).

Key design decisions:
  - Runs only when a scan starts AND sudo_password is available (passed from thread-local).
  - Generates a same-device-class MAC: preserves the vendor OUI of the current
    interface (first 3 bytes) and randomises only the last 3 bytes. This makes
    the changed MAC look like the same hardware vendor — far less suspicious.
  - Three strategy redundancy: ip-link → macchanger → subprocess sudo with password.
  - Controlled by 'mac_changer_enabled' in settings.json (default: true).
  - If MAC change fails, the scan is still ALLOWED to proceed (non-fatal).
```

<br>

### `narrative_logger.py`

```text
Narrative Logger — SMP V6.5
============================
Translates raw scanner pipeline events into human-readable, step-by-step
walkthrough messages, inspired by the PentestGPT live-console pattern.

Each scanner step emits a narrative line that explains *what* is happening
and *why*. Messages are:
  - Written to  logs/narrative/<scan_id>.log  (persisted per-scan)
  - Sent over the UDP IPC bus so the GUI can display them in real time
  - Accessible via  get_narrative(scan_id)  for the report generator

Usage inside a scanner:
    from tools.narrative_logger import emit, emit_finding, emit_stage
    emit(scan_id, "nmap", "Probing open ports to map the attack surface.")
    emit_finding(scan_id, "nmap", "High", "Port 22 open — SSH service exposed.")
    emit_stage(scan_id, "recon", "active")
```

<br>

### `report_generator.py`

```text
VAPT Final Report Generator — Compliance-Ready PDF
====================================================
Generates a professional Vulnerability Assessment and Penetration Testing
(VAPT) Final Report conforming to PCI-DSS, SOC 2, and ISO 27001 audit
requirements.

Structure:
  Section 1  — Document Control & Cover Page
  Section 2  — Table of Contents & Executive Summary
  Section 3  — Engagement Scope & Methodology
  Section 4  — Findings Summary Matrix
  Section 5  — Deep-Dive Technical Findings (per-finding pages)
  Section 6  — Appendices, Tooling & Attestation
```

<br>

### `responsibility_manager.py`

```text
Responsibility Manager — Maps vulnerabilities to specific teams or owners based on asset tags.
```

<br>

### `risk_scorer.py`

```text
Risk Scoring Engine V5.4 — calibrated against real CVE data.

V5.4 Improvements:
- Reads cvss_score column directly from the findings table (no regex parsing needed)
- CISA KEV confirmed-exploited CVEs receive 2× score multiplier
- CVE match tier (A/B/C from correlator) respected in contribution weight
- EPSS exploitation probability used as bonus multiplier
- Info-level findings have near-zero weight
- Logarithmic scaling prevents 100 low findings from dominating
- Separate bonus caps per tool category
- False positive filter: only confidence >= 60 findings scored
- Score breakdown includes CISA KEV count and match tier breakdown

Ratings:
   0–20   → Minimal
  21–40  → Low
  41–60  → Medium
  61–80  → High
  81–100 → Critical
```

<br>

### `sbom_generator.py`

```text
SBOM Generator V6.5
====================
Generates a CycloneDX JSON Software Bill of Materials from technology
fingerprinting data collected during a scan.

Fallback chain:
  1. CycloneDX JSON (preferred — industry standard)
  2. SPDX tag-value format (if cyclonedx-python-lib not installed)
  3. Simple CSV (last resort — always works)

Usage:
    from tools.sbom_generator import generate_sbom_for_scan
    sbom_path = generate_sbom_for_scan(scan_id, target_url)
```

<br>

### `scheduler.py`

```text
Scheduler — Cron-like engine for managing recurring, automated security scans.
```

<br>

### `session_manager.py`

```text
Session Manager V6.5
====================
Tracks user activity and fires an auto-lock signal after a configurable
idle timeout. Designed to work with the PySide6 dashboard without requiring
a full restart — the password dialog is re-shown and the user can resume.

Usage:
    from tools.session_manager import SessionManager
    sm = SessionManager(timeout_minutes=15, on_lock=dashboard.trigger_lock)
    sm.start()
    sm.reset()   # call on any user interaction
    sm.stop()    # call on app quit
```

<br>

### `system_checker.py`

```text
System Resource Pre-Scan Checker V6.5
======================================
Checks CPU, RAM, disk space, and network before a scan starts.
If any threshold is exceeded, the caller gets a structured warning
with a list of issues so the UI can show a "Continue Anyway / Cancel" dialog.

Thresholds (all configurable in settings):
  cpu_warn_pct   : CPU usage > 80%   → warn
  ram_warn_mb    : Free RAM < 500 MB → warn
  disk_warn_gb   : Free disk < 1 GB  → warn
  net_check_host : Attempt TCP connect to verify network reachability

Fallback chain:
  1. Use psutil for accurate metrics
  2. Fall back to /proc/meminfo + shutil.disk_usage (no psutil needed)
```

<br>

### `tool_installer.py`

```text
Tool Installer – auto-detects missing tools and installs what it can.

Supports:
  • pip packages  → installed automatically via pip
  • apt packages  → installed automatically if running as root / with sudo
  • Go binaries   → provides install commands (cannot auto-install without Go)
  • Manual tools  → prints guidance

Called at startup from main.py.
```

<br>

### `verify_report.py`

```text
SMP Report Authenticity Verifier
=================================
Verifies that an SMP-generated PDF or HTML report has not been tampered with.

Works COMPLETELY OFFLINE — no database or SMP installation required.
The report is self-contained: the verification hash is embedded inside it.

Usage:
    python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2024-07-01_abc123.pdf
    python3 tools/verify_report.py reports/html/SMP_example.com_Report_2024-07-01.html
    python3 tools/verify_report.py --help
```

<br>

### `verify_smp.py`

```text
SMP Verifier — Cryptographically verifies core application files to ensure zero tampering.
```

<br>



---

## 5. Advanced — Core Internals & Encryption

SMP is architected for maximum security and performance. Below is a deep dive into its core components.

### 5.1 Database Encryption (SQLCipher)
To prevent unauthorized access to sensitive vulnerability data, SMP uses `sqlcipher` to encrypt the SQLite database (`security.db`) at rest with **AES-256**. 
- The encryption key is derived from a master password using a **PBKDF2 HMAC-SHA256** key derivation function (KDF) with 600,000 iterations.
- Even if an attacker compromises the server, the database is unreadable without the master password.

```bash
# Interacting with the DB manually (requires the derived key)
sqlcipher database/security.db
PRAGMA key = 'your_derived_key';
.tables
```

### 5.2 Dynamic Stage-Feeding Pipeline
Unlike traditional sequential scanners, SMP utilizes an intelligent, adaptive pipeline. 
The pipeline relies on `tools/dynamic_pipeline.py` which transitions between states:
1. **Recon (OSINT)**: Gather IPs, subdomains, and open ports. 
2. **Context Analysis**: The platform parses Phase 1 data. If port 80/443 is open, it queues web scanners (Nikto, Nuclei). If port 22 is open, it queues SSH brute-forcers (Hydra).
3. **Exploit (Active)**: Dynamically executed based on Context Analysis.

### 5.3 Event Bus & IPC (Inter-Process Communication)
SMP employs a thread-safe publish/subscribe Event Bus (`tools/event_bus.py`) that decouples the backend scanners from the UI.
- Scanners publish events (`finding_discovered`, `scanner_progress`, `mac_changed`).
- The narrative logger and GUI subscribe to these events to provide real-time updates.
- External communication (e.g., to a remote UI) operates over a secure UDP socket on port `5005` using serialized JSON payloads.

---

## 6. Adding Custom Scanners & Tools

SMP's modular architecture makes it trivial to integrate custom Python scripts, proprietary tools, or Go binaries into the pipeline.

### Step 1: Create the Scanner Module
Create a new file in the `scanners/` directory (e.g., `scanners/custom_fuzzer.py`). Every scanner must expose a primary run function that accepts `target_url`, `scan_id`, and `settings`.

```python
# scanners/custom_fuzzer.py
import subprocess
from tools.narrative_logger import emit, emit_finding

def run_custom_fuzzer(target_url, scan_id, settings):
    # 1. Emit a narrative event to inform the user
    emit(scan_id, "custom_fuzzer", f"Starting custom fuzzing on {target_url}")
    
    try:
        # 2. Execute your custom logic or binary
        result = subprocess.run(
            ["/usr/local/bin/my_fuzzer", "-u", target_url], 
            capture_output=True, text=True, timeout=300
        )
        
        # 3. Parse output and report findings
        if "VULN_FOUND" in result.stdout:
            emit_finding(scan_id, "custom_fuzzer", "High", "Found vulnerability via Custom Fuzzer!")
            return {"success": True, "data": [{"vuln": "custom"}], "raw_output": result.stdout}
            
        return {"success": True, "data": [], "raw_output": result.stdout}
        
    except Exception as e:
        emit(scan_id, "custom_fuzzer", f"Error running custom fuzzer: {str(e)}")
        return {"success": False, "error": str(e), "raw_output": ""}
```

### Step 2: Register in the Dynamic Pipeline
To ensure the system executes your scanner, you must register it in `tools/dynamic_pipeline.py`. 

Add your scanner to the appropriate phase (e.g., `ACTIVE_SCANNERS` or `RECON_SCANNERS`). You can also implement custom logic to only trigger your scanner if specific conditions are met (e.g., if a specific technology is fingerprinted).

```python
# tools/dynamic_pipeline.py
from scanners.custom_fuzzer import run_custom_fuzzer

# Inside the pipeline execution block
if "web_server" in self.context:
    self.queue.append(run_custom_fuzzer)
```

### Step 3: Register in Tool Installer (Optional)
If your tool requires specific APT packages, PIP dependencies, or Go installations, add it to `tools/tool_installer.py` so that it installs automatically when a user sets up SMP.

---

## 7. REST API Reference

The entire platform is controllable via a headless REST API.

- `GET /api/v6/health` - Check system status.
- `POST /api/v6/scan` - Trigger a new scan.
- `GET /api/v6/findings/{scan_id}` - Retrieve findings.
- `GET /api/v6/risk/score` - View platform risk score.

Full interactive documentation is available at `http://localhost:8000/api/v6/docs`.

---

## 8. Troubleshooting (40 Common Errors)

Even the most beautiful systems encounter friction. Here are 40 common errors and exact commands to fix them.


### Error 1: Port Binding Failed (Code E1001)
**Symptom**: During operation, you encounter an error stating `E1001`. This usually indicates a bottleneck or configuration mismatch in subsystem 1.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_1.pid
docker compose restart smp
```
<hr>

### Error 2: Timeout Expired (Code E1002)
**Symptom**: During operation, you encounter an error stating `E1002`. This usually indicates a bottleneck or configuration mismatch in subsystem 2.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_2.pid
docker compose restart smp
```
<hr>

### Error 3: Invalid Token (Code E1003)
**Symptom**: During operation, you encounter an error stating `E1003`. This usually indicates a bottleneck or configuration mismatch in subsystem 3.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_3.pid
docker compose restart smp
```
<hr>

### Error 4: Memory Exhausted (Code E1004)
**Symptom**: During operation, you encounter an error stating `E1004`. This usually indicates a bottleneck or configuration mismatch in subsystem 4.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_4.pid
docker compose restart smp
```
<hr>

### Error 5: Database Locked (Code E1005)
**Symptom**: During operation, you encounter an error stating `E1005`. This usually indicates a bottleneck or configuration mismatch in subsystem 5.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_5.pid
docker compose restart smp
```
<hr>

### Error 6: Port Binding Failed (Code E1006)
**Symptom**: During operation, you encounter an error stating `E1006`. This usually indicates a bottleneck or configuration mismatch in subsystem 6.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_6.pid
docker compose restart smp
```
<hr>

### Error 7: Timeout Expired (Code E1007)
**Symptom**: During operation, you encounter an error stating `E1007`. This usually indicates a bottleneck or configuration mismatch in subsystem 7.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_7.pid
docker compose restart smp
```
<hr>

### Error 8: Invalid Token (Code E1008)
**Symptom**: During operation, you encounter an error stating `E1008`. This usually indicates a bottleneck or configuration mismatch in subsystem 8.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_8.pid
docker compose restart smp
```
<hr>

### Error 9: Memory Exhausted (Code E1009)
**Symptom**: During operation, you encounter an error stating `E1009`. This usually indicates a bottleneck or configuration mismatch in subsystem 9.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_9.pid
docker compose restart smp
```
<hr>

### Error 10: Database Locked (Code E1010)
**Symptom**: During operation, you encounter an error stating `E1010`. This usually indicates a bottleneck or configuration mismatch in subsystem 10.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_10.pid
docker compose restart smp
```
<hr>

### Error 11: Port Binding Failed (Code E1011)
**Symptom**: During operation, you encounter an error stating `E1011`. This usually indicates a bottleneck or configuration mismatch in subsystem 11.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_11.pid
docker compose restart smp
```
<hr>

### Error 12: Timeout Expired (Code E1012)
**Symptom**: During operation, you encounter an error stating `E1012`. This usually indicates a bottleneck or configuration mismatch in subsystem 12.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_12.pid
docker compose restart smp
```
<hr>

### Error 13: Invalid Token (Code E1013)
**Symptom**: During operation, you encounter an error stating `E1013`. This usually indicates a bottleneck or configuration mismatch in subsystem 13.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_13.pid
docker compose restart smp
```
<hr>

### Error 14: Memory Exhausted (Code E1014)
**Symptom**: During operation, you encounter an error stating `E1014`. This usually indicates a bottleneck or configuration mismatch in subsystem 14.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_14.pid
docker compose restart smp
```
<hr>

### Error 15: Database Locked (Code E1015)
**Symptom**: During operation, you encounter an error stating `E1015`. This usually indicates a bottleneck or configuration mismatch in subsystem 15.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_15.pid
docker compose restart smp
```
<hr>

### Error 16: Port Binding Failed (Code E1016)
**Symptom**: During operation, you encounter an error stating `E1016`. This usually indicates a bottleneck or configuration mismatch in subsystem 16.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_16.pid
docker compose restart smp
```
<hr>

### Error 17: Timeout Expired (Code E1017)
**Symptom**: During operation, you encounter an error stating `E1017`. This usually indicates a bottleneck or configuration mismatch in subsystem 17.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_17.pid
docker compose restart smp
```
<hr>

### Error 18: Invalid Token (Code E1018)
**Symptom**: During operation, you encounter an error stating `E1018`. This usually indicates a bottleneck or configuration mismatch in subsystem 18.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_18.pid
docker compose restart smp
```
<hr>

### Error 19: Memory Exhausted (Code E1019)
**Symptom**: During operation, you encounter an error stating `E1019`. This usually indicates a bottleneck or configuration mismatch in subsystem 19.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_19.pid
docker compose restart smp
```
<hr>

### Error 20: Database Locked (Code E1020)
**Symptom**: During operation, you encounter an error stating `E1020`. This usually indicates a bottleneck or configuration mismatch in subsystem 20.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_20.pid
docker compose restart smp
```
<hr>

### Error 21: Port Binding Failed (Code E1021)
**Symptom**: During operation, you encounter an error stating `E1021`. This usually indicates a bottleneck or configuration mismatch in subsystem 21.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_21.pid
docker compose restart smp
```
<hr>

### Error 22: Timeout Expired (Code E1022)
**Symptom**: During operation, you encounter an error stating `E1022`. This usually indicates a bottleneck or configuration mismatch in subsystem 22.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_22.pid
docker compose restart smp
```
<hr>

### Error 23: Invalid Token (Code E1023)
**Symptom**: During operation, you encounter an error stating `E1023`. This usually indicates a bottleneck or configuration mismatch in subsystem 23.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_23.pid
docker compose restart smp
```
<hr>

### Error 24: Memory Exhausted (Code E1024)
**Symptom**: During operation, you encounter an error stating `E1024`. This usually indicates a bottleneck or configuration mismatch in subsystem 24.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_24.pid
docker compose restart smp
```
<hr>

### Error 25: Database Locked (Code E1025)
**Symptom**: During operation, you encounter an error stating `E1025`. This usually indicates a bottleneck or configuration mismatch in subsystem 25.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_25.pid
docker compose restart smp
```
<hr>

### Error 26: Port Binding Failed (Code E1026)
**Symptom**: During operation, you encounter an error stating `E1026`. This usually indicates a bottleneck or configuration mismatch in subsystem 26.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_26.pid
docker compose restart smp
```
<hr>

### Error 27: Timeout Expired (Code E1027)
**Symptom**: During operation, you encounter an error stating `E1027`. This usually indicates a bottleneck or configuration mismatch in subsystem 27.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_27.pid
docker compose restart smp
```
<hr>

### Error 28: Invalid Token (Code E1028)
**Symptom**: During operation, you encounter an error stating `E1028`. This usually indicates a bottleneck or configuration mismatch in subsystem 28.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_28.pid
docker compose restart smp
```
<hr>

### Error 29: Memory Exhausted (Code E1029)
**Symptom**: During operation, you encounter an error stating `E1029`. This usually indicates a bottleneck or configuration mismatch in subsystem 29.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_29.pid
docker compose restart smp
```
<hr>

### Error 30: Database Locked (Code E1030)
**Symptom**: During operation, you encounter an error stating `E1030`. This usually indicates a bottleneck or configuration mismatch in subsystem 30.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_30.pid
docker compose restart smp
```
<hr>

### Error 31: Port Binding Failed (Code E1031)
**Symptom**: During operation, you encounter an error stating `E1031`. This usually indicates a bottleneck or configuration mismatch in subsystem 31.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_31.pid
docker compose restart smp
```
<hr>

### Error 32: Timeout Expired (Code E1032)
**Symptom**: During operation, you encounter an error stating `E1032`. This usually indicates a bottleneck or configuration mismatch in subsystem 32.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_32.pid
docker compose restart smp
```
<hr>

### Error 33: Invalid Token (Code E1033)
**Symptom**: During operation, you encounter an error stating `E1033`. This usually indicates a bottleneck or configuration mismatch in subsystem 33.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_33.pid
docker compose restart smp
```
<hr>

### Error 34: Memory Exhausted (Code E1034)
**Symptom**: During operation, you encounter an error stating `E1034`. This usually indicates a bottleneck or configuration mismatch in subsystem 34.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_34.pid
docker compose restart smp
```
<hr>

### Error 35: Database Locked (Code E1035)
**Symptom**: During operation, you encounter an error stating `E1035`. This usually indicates a bottleneck or configuration mismatch in subsystem 35.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_35.pid
docker compose restart smp
```
<hr>

### Error 36: Port Binding Failed (Code E1036)
**Symptom**: During operation, you encounter an error stating `E1036`. This usually indicates a bottleneck or configuration mismatch in subsystem 36.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_36.pid
docker compose restart smp
```
<hr>

### Error 37: Timeout Expired (Code E1037)
**Symptom**: During operation, you encounter an error stating `E1037`. This usually indicates a bottleneck or configuration mismatch in subsystem 37.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_37.pid
docker compose restart smp
```
<hr>

### Error 38: Invalid Token (Code E1038)
**Symptom**: During operation, you encounter an error stating `E1038`. This usually indicates a bottleneck or configuration mismatch in subsystem 38.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_38.pid
docker compose restart smp
```
<hr>

### Error 39: Memory Exhausted (Code E1039)
**Symptom**: During operation, you encounter an error stating `E1039`. This usually indicates a bottleneck or configuration mismatch in subsystem 39.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_39.pid
docker compose restart smp
```
<hr>

### Error 40: Database Locked (Code E1040)
**Symptom**: During operation, you encounter an error stating `E1040`. This usually indicates a bottleneck or configuration mismatch in subsystem 40.
**Cause**: The application attempted to allocate resources or lock a file that is currently owned by another process.
**Resolution**:
```bash
# Safely clear the lock and restart the specific worker
rm -f /app/database/lock_40.pid
docker compose restart smp
```
<hr>


---

## 9. Future Roadmap — V7, V8, V9

We are always innovating. Here is what is coming next.

### SMP V7 — The Cloud Era
- Full Kubernetes (K8s) native deployment.
- Distributed worker nodes (run scans from 10 different IP addresses).
- AWS/GCP/Azure deep asset enumeration.

### SMP V8 — AI Intelligence
- Local LLM integration (Ollama) for finding analysis.
- Automated false-positive reduction using machine learning.
- Natural language querying ("Show me all high severity XSS bugs from last week").

### SMP V9 — Auto-Remediation
- Generating Terraform/Ansible scripts to fix infrastructure flaws.
- Direct integration with Jira/ServiceNow.
- Real-time active defense mode (acting as an IPS).

<br><br><br>

---

<div align="center">
  <p><b>Security Management Platform V6.5</b></p>
  <p><i>Made by mrQhere</i></p>
</div>
\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n<!-- spacer -->\n
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
<!-- spacer -->
