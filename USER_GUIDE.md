<!-- ╔══════════════════════════════════════════════════════════════════════════╗ -->
<!-- ║          SECURITY MANAGEMENT PLATFORM — THE COMPLETE GUIDE              ║ -->
<!-- ║          Version V5.2 · Built for Humans, Loved by Hackers              ║ -->
<!-- ╚══════════════════════════════════════════════════════════════════════════╝ -->

<div align="center">

```
  ███████╗███╗   ███╗██████╗
  ██╔════╝████╗ ████║██╔══██╗
  ███████╗██╔████╔██║██████╔╝
  ╚════██║██║╚██╔╝██║██╔═══╝
  ███████║██║ ╚═╝ ██║██║
  ╚══════╝╚═╝     ╚═╝╚═╝     The Complete Guide
```

**Security Management Platform** · V5.2 · The Guide Every Security Professional Deserves

</div>

---

> [!IMPORTANT]
> 🔐 **LEGAL NOTICE**: SMP is built for **authorised security testing only**. Always obtain written permission before scanning any target. Unauthorised scanning is illegal and unethical. If you have permission — read on and be amazed.

---

## 📖 Table of Contents

| Part | Section | Who It's For |
|------|---------|-------------|
| [**Part 0**](#part-0--the-philosophy) | The Philosophy | Everyone |
| [**Part 1**](#part-1--normal-user-guide) | Normal User Guide | First-timers & everyday users |
| [**Part 2**](#part-2--developer-guide) | Developer Guide | Plugin writers & integrators |
| [**Part 3**](#part-3--serious-developer-guide) | Serious Developer Guide | Core contributors |
| [**Part 4**](#part-4--complete-feature-catalogue) | Feature Catalogue | Everyone |
| [**Part 5**](#part-5--known-shortcomings--technical-debt) | Known Shortcomings | Quality-focused engineers |
| [**Part 6**](#part-6--future-vision) | Future Vision | Dreamers & contributors |

---

# Part 0 — The Philosophy

> *"Security tools should be as powerful as the threats they fight — and as easy to use as the apps we love."*

SMP was born from a simple frustration: penetration testing tools are scattered, hard to set up, and produce reports that only other hackers can read. Business owners, developers, and compliance officers needed something better.

**SMP's three laws:**
1. 🤖 **Zero manual intervention** — if a tool isn't installed, SMP installs it. If it breaks, SMP fixes it.
2. 📊 **Reports that executives can read** — beautiful PDFs that tell a story, not a raw dump.
3. 🧠 **Intelligence, not just scanning** — CVE correlation, trend analysis, risk scoring, OSINT.

SMP is not a script. It's a platform. And once you use it, you'll wonder how you ever worked without it.

---

# Part 1 — Normal User Guide

## 1.1 — Installation (Zero to Hero in 3 Minutes)

### Prerequisites

| Requirement | Why | Where to Get |
|------------|-----|-------------|
| Python 3.10+ | Core runtime | [python.org](https://python.org) |
| Git | To clone the repo | Already on most systems |
| Internet connection | For tool downloads | — |

That's it. **Everything else SMP installs for you.**

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/SecurityManagementPlatform.git
cd SecurityManagementPlatform
```

### Step 2: Run Setup

```bash
chmod +x setup.sh
./setup.sh
```

> [!NOTE]
> ☕ **Go grab a coffee.** Setup downloads and installs up to 35 scanning tools automatically. It typically takes 3–8 minutes depending on your internet speed. Everything is installed locally inside the project — **nothing is installed system-wide without your permission.**

You'll see output like:

```
  ✅  Python environment ready
  ✅  pip packages installed (sslyze, wapiti, sqlmap...)
  ✅  Nuclei downloaded → bin/nuclei
  ✅  Subfinder downloaded → bin/subfinder
  ✅  Nikto downloaded → bin/nikto_src/
  ⚠️  Masscan: attempting to compile from source...
  ✅  Masscan compiled → bin/masscan
  ✅  Setup Complete! All tools installed.
  Run: ./run.sh
```

### Step 3: Launch

```bash
./run.sh
```

The SMP dashboard opens. You're ready to scan.

> [!TIP]
> 💡 **Pro Tip**: Bookmark `./run.sh`. That's all you'll ever type to start SMP. No virtual environments to activate, no PATH to set — it's all handled.

---

## 1.2 — First Boot

When SMP launches for the first time, you'll see the **splash screen** loading your tool environment, then the **main dashboard**.

### The Dashboard — At a Glance

```
┌─────────────────────────────────────────────────────────────┐
│  ← Dashboard  Targets  Findings  Threat Intel  Reports  →  │
├──────────────────────┬──────────────────────────────────────┤
│  🎯 Targets          │  📊 KPI Strip                        │
│  ─────────────────── │  ───────────────────────────────────  │
│  example.com  ▶      │  Risk Score  Findings  CVEs  Scans   │
│  test.org     ▶      │     87/100      14      3      2     │
│                      ├──────────────────────────────────────┤
│  [+ Add Target]      │  🔄 Active Scan Monitor              │
│                      │  🎯 example.com  ████░░░░  42%       │
│                      │  ⬤  Running Nuclei [16/34]  00:04:21 │
└──────────────────────┴──────────────────────────────────────┘
```

**Key areas:**
- **Left sidebar**: Navigation between modules
- **KPI Strip**: Live risk scores, finding counts, CVE matches
- **Active Scan Monitor**: Real-time progress for running scans (now with visual progress bar!)
- **Main content area**: Changes based on selected module

---

## 1.3 — Your First Scan

### Adding a Target

1. Click **Targets** in the left nav
2. Click **+ Add Target**
3. Fill in the form:

```
URL:              https://your-target.com
Company Name:     ACME Corp (appears in report)
Submitted To:     John Smith, CTO (appears in report)
QA Reviewer:      Jane Doe (appears in report)
Lead Tester:      Your Name
```

> [!WARNING]
> ⚠️ **ALWAYS enter the full URL with `https://` or `http://`. Do NOT scan targets you don't own or have written permission to test.**

### Running a Scan

1. Click the target row to select it
2. Click **▶ Start Scan**
3. Watch the **Active Scan Monitor** — it shows each of the 34 scanner steps in real time with a progress bar

### What Happens During a Scan

SMP runs scanners in a dependency graph (DAG). Here's the order:

```
Phase 1 — Reconnaissance
  HTTPx → WhatWeb → Subfinder → CRT.sh → HackerTarget → Whois → Wayback

Phase 2 — Infrastructure
  Traceroute → Nmap → SSL Scan → Security Headers

Phase 3 — Web Analysis
  Robots.txt → CORS → CMS Scanner → Nikto → Nuclei → ffuf

Phase 4 — Exploitation Checks
  SQLMap → Wapiti → Open Redirect → Tech Fingerprint

Phase 5 — Advanced Scanners
  Dalfox → Arjun → DNSx → Katana → Commix → JWT Scanner

Phase 6 — OSINT
  Shodan → theHarvester → Gitleaks → WPScan → Masscan
  ParamSpider → Cloud Enum

Phase 7 — Final
  CVE Correlation → Report Generation
```

**Each step is self-healing**: if a tool fails or isn't installed, SMP attempts to install it on-the-fly and retry.

---

## 1.4 — Reading Your Report

### How to Generate a Report

After a scan completes:

1. Go to **Reports** tab
2. Your scan appears in the table
3. Click **📄 Open** to view the PDF

### Report Structure & Dual-Audience Design

SMP reports feature a **dual-audience design** engineered to satisfy both high-level stakeholders (executives) and technical experts (security engineers and developers):

| Section | Target Audience | What It Contains |
|---------|-----------------|-----------------|
| **Cover Page** | Everyone | Target, date, tester name, version, classification |
| **Executive Summary** | Executives / board | Risk posture, CVE matches, SSL issues, trend analysis |
| **Findings Matrix** | Everyone | All vulnerabilities sorted by severity with dynamic CVSS scores |
| **Deep-Dive Findings** | Developers / Techs | Detailed proof-of-concept (POC), impact, and remediation blocks |
| **Action Plan** | Executives / Techs | Timestamped remediation priorities (0–24h, 72h, 2wk) |
| **Appendices** | Techs | Comprehensive tool list, clean-up log, severity glossary, sign-off |

### 🛠️ Enriched Enterprise Report Fields

For every vulnerability identified, SMP renders specific fields mapped directly to the database:

- 📊 **Executive & Business Risk Overview**: A prominent highlighted callout card explaining the high-level business impact (`business_impact`) of exploitation, enabling non-technical decision makers to quickly assess risk.
- 🏷️ **Taxonomy Mappings**: A key-value metadata block detailing the OWASP Category (`owasp_category`), CVE Identifier (`cve_id`), dynamic CVSS v4.0 Score and Vector (`cvss_score`), and the specific Affected Component (`affected_component`).
- 📝 **Technical Breakdown**: In-depth description of the vulnerability logic.
- 💻 **How to Reproduce (Proof of Concept)**: A step-by-step reproduction command block or manual instructions (`reproduction_steps`) allowing developers to quickly reproduce and confirm the finding on local setups.
- 🔍 **Scan Result Evidence**: Syntax-highlighted raw scanner logs and tool output evidence (`evidence`) captured directly from the tool's execution.
- 🔧 **Remediation Blueprint**: Contains strategic mitigation advice (`recommendation`) alongside concrete **Code-Level or Config-Level Remediation Snippets** (`remediation_code`) for instant patching.
- 🔗 **References**: Parsed external links and documentation references (`references_json`) for further investigation.

> [!NOTE]
> 📝 **"Generated By"**: Reports say "Security Management Platform (SMP) V5.2 Stable" — no individual usernames or personal identifiers appear in any report. Your report is professional and neutral.

### Understanding the Executive Summary

The executive summary is **situational** — it adapts to what was found:

- 🔴 **Critical findings?** → Emergency language, immediate action required
- 🟠 **High findings only?** → 72-hour remediation window, WAF interim mitigation advice
- 🟡 **Medium findings only?** → Scheduled remediation, 2-week timeline
- ✅ **Clean scan?** → Positive posture statement, continued periodic assessment
- 🔍 **CVEs matched?** → Adds a CVE-specific paragraph with exploitation pathway context
- 🔐 **SSL issues?** → Adds TLS/compliance violation paragraph
- 📈 **Historical data?** → Adds trend comparison: resolved vs. persisting vs. new

---

## 1.5 — CVE Alerts & Threat Intelligence

### The CVE Database

SMP ships with an **offline CVE database** (300,000+ entries) stored in `database/cve.db`. This means:

- ✅ No internet required for CVE lookups
- ✅ Instant correlation against your scan results
- ✅ Works air-gapped

### Using the Threat Intel Tab

1. Click **Threat Intel** in nav
2. Use the **Severity filter** dropdown to narrow results
3. Type in the **Search box** — matches CVE ID, description, keywords

```
Example searches:
  "apache 2.4"         → All Apache 2.4 CVEs
  "CVE-2021"           → All 2021 CVEs
  "critical"           → All critical severity entries
  "remote code"        → RCE vulnerabilities
```

4. Click **⚡ Fetch CVEs** to pull the latest CVEs from NVD (requires internet)

---

## 1.6 — Scheduling & Automation

### Setting Up Scheduled Scans

1. Go to **Settings** → **Scan Profiles**
2. Select a target
3. Enable **Scheduled Scan**
4. Set recurrence: Daily / Weekly / Monthly
5. SMP uses APScheduler internally — no cron setup needed

```python
# What happens under the hood (for the curious):
scheduler.add_job(
    func=run_scan,
    trigger='cron',
    hour=2,
    minute=0,
    args=[target_id]
)
```

### Email Notifications

1. Go to **Settings** → **SMTP Settings**
2. Fill in your email server details:

```
SMTP Host:    smtp.gmail.com
SMTP Port:    587
Username:     your@email.com
Password:     your-app-password
From:         reports@yourcompany.com
To:           security-team@yourcompany.com
```

3. Click **Test Connection** — SMP sends a test email
4. Enable **Email on Scan Complete**

> [!TIP]
> 💡 For Gmail: Use an **App Password**, not your account password. Go to Google Account → Security → 2FA → App Passwords.

---

## 1.7 — Troubleshooting (Top 25 Issues)

### 🔧 Installation Issues

**Problem**: `./setup.sh` fails with "Permission denied"
```bash
# Fix:
chmod +x setup.sh
./setup.sh
```

**Problem**: Python not found
```bash
# Check version:
python3 --version
# If missing, install:
sudo apt install python3 python3-pip  # Debian/Ubuntu
brew install python3                   # macOS
```

**Problem**: `venv` creation fails
```bash
# Fix: install venv module
sudo apt install python3-venv
./setup.sh  # Re-run setup
```

**Problem**: Tool download fails (no internet)
```bash
# SMP works offline once set up. On first setup you need internet.
# If behind proxy:
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
./setup.sh
```

**Problem**: `masscan` build fails (missing make/gcc)
```bash
# Fix:
sudo apt install build-essential libpcap-dev
./setup.sh  # It will try again
```

---

### 🔧 Scan Issues

**Problem**: Scan stuck on "Running Nmap"
```bash
# Nmap can take a long time. Check if it's actually running:
ps aux | grep nmap
# If not running, kill and restart the scan from the dashboard
```

**Problem**: Tool shows as missing mid-scan
```
The self-healer kicks in automatically. Watch the Scan Monitor —
if you see "[Self-Heal] Installing nuclei...", it's fixing itself.
After install it retries the step automatically.
```

**Problem**: "Permission denied" running masscan
```bash
# Masscan needs raw sockets. Fix:
sudo setcap cap_net_raw+eip bin/masscan
# OR run as root (not recommended for the entire app)
```

**Problem**: Scan completes but no report
```bash
# Check logs:
cat logs/smp_$(date +%Y%m%d).log | grep ERROR
# Common cause: reportlab not installed
pip install reportlab
```

**Problem**: OWASP ZAP scan not running
```bash
# ZAP needs to be installed separately (it's 200MB+)
# Download from https://www.zaproxy.org/download/
# Then configure in Settings → ZAP Settings
```

---

### 🔧 Database Issues

**Problem**: `database/security.db` is corrupted
```bash
# SMP has a redundancy database. Check if it exists:
ls -la database/redundancy.db

# To restore from redundancy:
cp database/redundancy.db database/security_restored.db
# Then in Python:
python3 -c "
from tools.db_manager import restore_from_redundancy
restore_from_redundancy()
print('Restored!')
"
```

**Problem**: CVE database missing
```bash
# Download it:
python3 tools/cve_sync.py
# Or click 'Fetch CVEs' in the Threat Intel tab
```

**Problem**: Database locked error
```bash
# Another SMP instance is running. Check:
ps aux | grep main.py
# Kill the old instance:
pkill -f "python.*main.py"
# Restart SMP
./run.sh
```

---

### 🔧 Report Issues

**Problem**: PDF generation fails
```bash
pip install reportlab pillow
```

**Problem**: Report shows wrong version number
```bash
python3 tools/bump_version.py V5.2  # Updates everywhere
```

**Problem**: Report still shows "mrQhere" (old version)
```bash
# This was fixed in V5.2. Run version bump:
python3 tools/bump_version.py V5.2
# Then regenerate the report
```

---

### 🔧 UI Issues

**Problem**: Dashboard is blank / white
```bash
# Check PySide6 installation:
pip install PySide6
./run.sh
```

**Problem**: Scan monitor is too small
```bash
# Fixed in V5.2! The scan panel now defaults to 400px height.
# If still small, drag the splitter handle between the targets
# table and the scan monitor panel.
```

**Problem**: Dark theme looks wrong
```bash
# Try forcing Qt style:
QT_STYLE_OVERRIDE=Fusion ./run.sh
```

---

# Part 2 — Developer Guide

> Welcome, developer. SMP is built to be extended. This section is your plugin passport.

## 2.1 — Architecture Overview

```
SecurityManagementPlatform/
├── main.py                  ← Entry point, Qt application bootstrap
├── setup.sh                 ← Zero-touch installer
├── run.sh                   ← Launch wrapper (sets PATH + PYTHONPATH)
│
├── scanners/                ← 35 scanner modules
│   ├── scan_runner.py       ← DAG orchestrator, self-healer
│   └── *.py                 ← One file per scanner
│
├── tools/
│   ├── db_manager.py        ← Thread-safe DB API (primary + redundancy)
│   ├── report_generator.py  ← PDF + HTML report engine (ReportLab)
│   ├── tool_installer.py    ← Self-healing tool installer
│   ├── bump_version.py      ← Version propagation across all files
│   ├── config_manager.py    ← Settings, paths, encryption
│   ├── cve_sync.py          ← CVE database sync (NVD API)
│   └── verify_smp.py        ← Test suite (10 tests)
│
├── ui/
│   ├── dashboard.py         ← Main Qt window
│   ├── views/               ← Layout builders (pure UI)
│   └── controllers/         ← Business logic controllers
│
├── database/
│   ├── security.db          ← Primary encrypted SQLite database
│   ├── redundancy.db        ← Ephemeral hot-mirror (auto-cleaned)
│   └── cve.db               ← 300k+ CVE offline intelligence
│
├── config/
│   ├── metadata.json        ← Version, app name, build info
│   └── settings.json        ← User preferences
│
├── bin/                     ← All downloaded tool binaries
│   ├── nuclei               ← Pre-built Go binary
│   ├── katana               ← Pre-built Go binary
│   ├── cloud_enum_src/      ← Python source with wrapper
│   ├── paramspider_src/     ← Python source with wrapper
│   └── ...
│
└── logs/                    ← Rotating daily log files
```

---

## 2.2 — Adding a Custom Scanner

Every scanner in SMP is a Python function decorated with `@register_scanner`. Adding a new scanner is just two steps:

### Step 1: Create the scanner file

```python
# scanners/my_scanner.py
import logging
from scanners.base_scanner import register_scanner
from tools.db_manager import add_finding, add_log_entry

logger = logging.getLogger("smp.scan")

@register_scanner(
    name="My Custom Scanner",        # Display name
    step_name="Running MyScanner",   # Status shown in Active Scan Monitor
    depends_on=["Subfinder"],        # Run after these steps complete
    binary_name="mytool",            # Binary to check/install (or "" for Python-only)
    needs_binary=True,               # False for pure-Python scanners
    confidence=85                    # Confidence score (0-100)
)
def run_my_scanner(url):
    """
    My custom scanner — describe what it does here.
    """
    logger.info(f"MyScanner: Starting scan of {url}")
    add_log_entry("INFO", f"MyScanner started: {url}")

    findings = []

    # ── Your scanner logic here ──────────────────────────────────────────────
    try:
        import subprocess
        result = subprocess.run(
            ["mytool", "--target", url, "--json"],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout

        # Parse and add findings
        if "VULNERABLE" in output:
            finding = {
                "title": "My Scanner Found Something",
                "severity": "High",         # Critical/High/Medium/Low/Info
                "description": "Detailed description of the vulnerability.",
                "evidence": output[:500],   # Truncate long output
                "recommendation": "How to fix this issue.",
                "cvss_score": 7.5,
                "url": url,
            }
            findings.append(finding)

    except subprocess.TimeoutExpired:
        logger.warning("MyScanner: Timeout after 120s")
    except FileNotFoundError:
        logger.warning("MyScanner: mytool binary not found — will be self-healed")
        raise  # Let scan_runner.py handle the self-heal

    # ── Save findings to both primary and redundancy databases ──────────────
    for f in findings:
        add_finding(
            scan_id=None,          # Will be set by the caller
            title=f["title"],
            severity=f["severity"],
            description=f["description"],
            evidence=f["evidence"],
            recommendation=f["recommendation"],
            url=f["url"],
            tool="MyScanner",
        )

    return findings
```

### Step 2: Register in scan_runner.py

```python
# In scanners/scan_runner.py, add to the imports:
from scanners.my_scanner import run_my_scanner

# Add to the DAG steps list:
SCAN_STEPS = [
    ...
    ("Running MyScanner", run_my_scanner, ["Subfinder"]),
    ...
]
```

> [!TIP]
> 💡 The DAG automatically resolves `depends_on` ordering. You can depend on multiple steps: `depends_on=["Subfinder", "Nmap"]`. The scanner won't run until all dependencies complete.

---

## 2.3 — Database API Reference

All DB operations go through `tools/db_manager.py`. **Never write to SQLite directly** — use these functions to get automatic redundancy mirroring.

### Findings API

```python
from tools.db_manager import (
    add_finding, get_findings_for_scan,
    get_all_findings, delete_finding
)

# Add a finding (written to security.db AND redundancy.db)
finding_id = add_finding(
    scan_id=scan_id,
    title="SQL Injection in login form",
    severity="Critical",          # Critical/High/Medium/Low/Info
    description="The login form at /auth/login is vulnerable to SQL injection...",
    evidence="' OR 1=1 --  → 200 OK with user data",
    recommendation="Use parameterised queries. Never interpolate user input into SQL.",
    url="https://target.com/auth/login",
    tool="SQLMap",
    cvss_score=9.8,               # Optional
    cve_id="CVE-2023-12345",      # Optional
)

# Retrieve findings for a scan
findings = get_findings_for_scan(scan_id)
# Returns: list of dicts with keys: id, title, severity, description, etc.

# Retrieve all findings across all scans
all_findings = get_all_findings(limit=1000, severity_filter="Critical")
```

### Scan Management API

```python
from tools.db_manager import (
    create_scan, update_scan_status, get_active_scans,
    get_scan_by_id, get_all_scans
)

# Create a new scan record
scan_id = create_scan(target_id=target_id, scanned_by="Security Team")

# Update scan progress (shown in Active Scan Monitor)
update_scan_status(
    scan_id=scan_id,
    status="running",
    scanner_status="Running Nuclei"   # This text appears in the monitor
)

# Get all active scans
active = get_active_scans()
# Returns: list of dicts with scan details

# Mark scan complete
update_scan_status(scan_id, status="completed", scanner_status="Completed")
```

### Target API

```python
from tools.db_manager import (
    add_target, get_target, get_all_targets,
    update_target, delete_target
)

# Add a new scan target
target_id = add_target(
    url="https://example.com",
    company_name="Example Corp",
    submitted_to="John Smith, CTO",
    qa_reviewer="Jane Doe",
    scanned_by="Security Team",
)

# Get all targets
targets = get_all_targets()
```

### Logging API

```python
from tools.db_manager import add_log_entry, get_log_entries

# Add to the scan log (shown in the Logs tab)
add_log_entry("INFO", "Starting Nuclei scan against https://target.com")
add_log_entry("WARNING", "Nuclei timeout after 120s — retrying")
add_log_entry("ERROR", "SQLMap crashed: see logs/smp_20240701.log")
add_log_entry("SUCCESS", "Report generated: reports/scan_42_report.pdf")
```

---

## 2.4 — Redundancy Database API

The redundancy database (`database/redundancy.db`) auto-mirrors all writes and is cleaned after each scan.

```python
from tools.db_manager import (
    restore_from_redundancy,
    clear_redundancy_db,
    get_findings_for_scan,   # Automatically falls back to redundancy
)

# Check if security.db is OK
import os
db_ok = os.path.exists("database/security.db")

if not db_ok:
    print("Primary DB missing — checking redundancy...")
    findings = get_findings_for_scan(scan_id)
    # ↑ This automatically falls back to redundancy.db if security.db is missing

# Force restore from redundancy (emergency use)
restore_from_redundancy()

# Manually clear redundancy (done automatically after each scan)
clear_redundancy_db()
```

> [!IMPORTANT]
> 🔁 **Redundancy lifecycle**: Written at every add_finding() / add_technology() call → Automatically cleared in the `finally:` block of scan_runner.py after the scan completes OR fails. It's a hot-standby, not a backup.

---

## 2.5 — Self-Healing Installer API

```python
from tools.tool_installer import (
    install_single_tool,
    check_and_install_all,
    _is_tool_available,
)

# Check if a tool is available (PATH + bin/ + import)
if not _is_tool_available("Nuclei", "nuclei", "go", "..."):
    print("Nuclei not found — installing...")
    success = install_single_tool("nuclei")
    if success:
        print("✅ Nuclei installed and ready")
    else:
        print("❌ Install failed — scan step will be skipped")

# Run a full tool audit + install pass
results = check_and_install_all(auto_install=True)
print(f"Ready: {len(results['installed'])} tools")
print(f"Missing: {results['missing']}")
print(f"Manual-only: {results['skipped']}")

# With progress callback (for UI progress bars)
def on_progress(current, total, tool_name):
    print(f"[{current}/{total}] Checking {tool_name}...")

check_and_install_all(auto_install=True, progress_callback=on_progress)
```

### Install Method Registry

```python
# Each tool has an install method in TOOLS list:
# ("Display Name", "binary_name", "method", "install_arg")

# method = "pip"    → pip install <install_arg>
# method = "apt"    → apt-get install <install_arg>, fallback to binary download
# method = "go"     → go install <install_arg>, fallback to binary download
# method = "binary" → download from GitHub releases/master
# method = "manual" → logged but not auto-installed
```

---

## 2.6 — Custom Report Sections

To add a custom section to the PDF report:

```python
# In tools/report_generator.py, inside _generate_vapt_pdf():

from reportlab.platypus import Paragraph, Spacer, PageBreak
from reportlab.lib.units import mm

# After Section 5 (Deep-Dive Findings):

# ── My Custom Section ─────────────────────────────────────────
story.append(PageBreak())
story.append(_section_header(st, "7", "My Custom Analysis"))
story.append(Paragraph(
    "This section contains my custom analysis results.",
    st["body"]
))

# Add a data table:
from reportlab.platypus import Table, TableStyle
data = [
    ["Header 1", "Header 2", "Header 3"],
    ["Value A",  "Value B",  "Value C"],
]
table = Table(data, colWidths=[BW/3]*3)
table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), _c(_P["accent2"])),
    ("GRID", (0, 0), (-1, -1), 0.3, _c(_P["border"])),
]))
story.append(table)
```

---

## 2.7 — Config Manager API

```python
from tools.config_manager import (
    get_setting, set_setting,
    BASE_DIR, REPORTS_DIR, DATABASE_DIR, LOGS_DIR,
    get_encryption_key
)

# Get a user setting
wordlist = get_setting("ffuf_wordlist", default="/usr/share/wordlists/dirb/common.txt")
timeout = get_setting("scan_timeout", default=120)

# Set a setting
set_setting("max_concurrent_scans", 3)
set_setting("report_author", "Security Team")

# Path constants (always use these, never hardcode paths)
print(BASE_DIR)       # /home/user/.../SecurityManagementPlatform
print(REPORTS_DIR)    # .../SecurityManagementPlatform/reports
print(DATABASE_DIR)   # .../SecurityManagementPlatform/database
print(LOGS_DIR)       # .../SecurityManagementPlatform/logs
```

---

# Part 3 — Serious Developer Guide

> You're going deeper. Internals, DAG mechanics, IPC protocol, database schema. Buckle up.

## 3.1 — DAG Orchestrator Deep-Dive

### How scan_runner.py Schedules Scanners

```python
# The core scheduling loop (simplified):
def run_scan_dag(scan_id, url):
    completed = set()
    running = {}

    while True:
        # Find all steps whose dependencies are satisfied
        ready = [
            step for step in ALL_STEPS
            if step.name not in completed
            and step.name not in running
            and all(dep in completed for dep in step.depends_on)
        ]

        # Launch ready steps concurrently (up to MAX_CONCURRENT)
        for step in ready[:MAX_CONCURRENT - len(running)]:
            future = executor.submit(run_with_resilience, step, url)
            running[step.name] = future

        # Check completed futures
        done = {name for name, f in running.items() if f.done()}
        for name in done:
            result = running.pop(name).result()
            completed.add(name)
            # Write result to DB immediately (before next step)

        if len(completed) == len(ALL_STEPS):
            break
        time.sleep(0.5)
```

### run_with_resilience — The Self-Healer

```python
def run_with_resilience(step_func, url, max_retries=2):
    """
    Wraps every scanner step with:
    1. Error catching
    2. Binary-missing detection
    3. Auto-install + retry
    4. Graceful degradation (skip and continue)
    """
    for attempt in range(max_retries + 1):
        try:
            return step_func(url)
        except FileNotFoundError as e:
            binary = extract_binary_name(e)
            if attempt < max_retries:
                logger.info(f"[Self-Heal] {binary} missing — installing...")
                if install_single_tool(binary):
                    logger.info(f"[Self-Heal] Retry {attempt+1} for {step_func.__name__}")
                    continue
            logger.warning(f"[Self-Heal] Could not install {binary}. Skipping.")
            return []  # Return empty results, don't crash
        except Exception as e:
            logger.error(f"Scanner {step_func.__name__} failed: {e}")
            return []
```

---

## 3.2 — Database Schema Reference

### security.db (Primary Database)

```sql
-- Core scan management
CREATE TABLE targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL,
    company_name  TEXT,
    submitted_to  TEXT,
    qa_reviewer   TEXT,
    scanned_by    TEXT,
    status        TEXT DEFAULT 'Enabled',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER REFERENCES targets(id),
    status          TEXT DEFAULT 'pending',
    scanner_status  TEXT,            -- "Running Nuclei" etc.
    start_time      DATETIME,
    end_time        DATETIME,
    scanned_by      TEXT,
    risk_score      INTEGER
);

-- Findings (vulnerabilities found)
CREATE TABLE findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER REFERENCES scans(id),
    title           TEXT NOT NULL,
    severity        TEXT,             -- Critical/High/Medium/Low/Info
    description     TEXT,
    evidence        TEXT,
    recommendation  TEXT,
    url             TEXT,
    tool            TEXT,
    cvss_score      REAL,
    cve_id          TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Detected technologies
CREATE TABLE technologies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id),
    name        TEXT,
    version     TEXT,
    category    TEXT              -- Web Server, CMS, Framework, etc.
);

-- Risk scores
CREATE TABLE risk_scores (
    scan_id      INTEGER PRIMARY KEY REFERENCES scans(id),
    total_score  INTEGER,
    breakdown    TEXT             -- JSON: {ssl: 20, headers: 15, ...}
);

-- Raw scanner output storage
CREATE TABLE raw_scan_outputs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER REFERENCES scans(id),
    tool      TEXT,
    output    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- In-app log stream
CREATE TABLE scan_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    level     TEXT,              -- INFO/WARNING/ERROR/SUCCESS
    message   TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### cve.db (Threat Intelligence Database)

```sql
CREATE TABLE cves (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT,
    severity      TEXT,           -- CRITICAL/HIGH/MEDIUM/LOW
    cvss_score    REAL,
    published     TEXT,
    references    TEXT,           -- JSON array of URLs
    cpe_list      TEXT            -- JSON array of CPE strings
);

CREATE INDEX idx_cve_severity ON cves(severity);
CREATE INDEX idx_cve_published ON cves(published);
-- Full-text search index for fast keyword lookups
CREATE VIRTUAL TABLE cves_fts USING fts5(cve_id, description, cpe_list);
```

---

## 3.3 — Encryption & Security Model

### Database Encryption

```python
# tools/config_manager.py

# Key derivation: PBKDF2 with machine-specific salt
key = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode(),
    machine_salt,     # Derived from hostname + MAC address
    iterations=100000
)

# Database-level encryption via SQLCipher pragmas:
conn.execute(f"PRAGMA key='{derived_key}'")
conn.execute("PRAGMA cipher_page_size=4096")
conn.execute("PRAGMA kdf_iter=64000")
```

### File Permissions

```bash
database/   chmod 700   # Only owner can access
config/     chmod 700
logs/       chmod 700
backup/     chmod 700
database/security.db  chmod 600  # Only owner can read/write
bin/        chmod 750   # Owner + group can execute
```

---

## 3.4 — Adding to the Core Pipeline

### Adding a New Scanner Step (Full Example)

```python
# 1. Create scanners/my_advanced_scanner.py
# 2. Implement the @register_scanner decorated function
# 3. Add to SCAN_STEPS in scan_runner.py
# 4. Add the tool to TOOLS in tool_installer.py:

("MyTool", "mytool", "pip", "mytool-package")
# or:
("MyTool", "mytool", "binary", "")  # For GitHub download
# Add URL to _download_missing_tools_locally():
urls_amd64["MyTool"] = "https://github.com/org/mytool/releases/download/v5.2/mytool_linux_amd64.zip"

# 5. Update status_label_map in dashboard_logic.py:
"Running MyTool": "MyTool — what it does",

# 6. Update TOTAL_STEPS count and step_index_map in dashboard_logic.py
# 7. Run tests: python3 tools/verify_smp.py
```

---

## 3.5 — Writing Tests

```python
# tools/verify_smp.py — How to add your own test

class TestSMPComponents(unittest.TestCase):

    def test_my_feature(self):
        """Test that my new feature works correctly."""

        # Setup — use temp directory, not the real database
        with tempfile.TemporaryDirectory() as tmpdir:
            # Override BASE_DIR for this test
            with patch('tools.config_manager.BASE_DIR', tmpdir):
                from tools.db_manager import init_database, add_finding

                init_database()

                # Create test scan
                scan_id = 1  # For unit tests, hardcode or mock

                # Test your feature
                result = my_feature(scan_id, "https://test.example.com")

                # Assert expected behaviour
                self.assertIsNotNone(result)
                self.assertIn("expected_key", result)
                self.assertEqual(result["severity"], "High")
```

Run the full test suite:
```bash
cd SecurityManagementPlatform
python3 tools/verify_smp.py -v
```

---

## 3.6 — Performance Tuning

### Parallel Scanner Execution

```python
# scan_runner.py: Control concurrency
MAX_CONCURRENT_SCANNERS = 4  # Default: 4

# For faster scans (more CPU/RAM required):
MAX_CONCURRENT_SCANNERS = 8

# For conservative systems:
MAX_CONCURRENT_SCANNERS = 2
```

### Database Optimisations

```python
# db_manager.py: Connection pooling settings
SQLITE_TIMEOUT = 30          # seconds to wait for lock
SQLITE_CHECK_SAME_THREAD = False   # Required for thread pool

# WAL mode for concurrent access:
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA synchronous=NORMAL")
conn.execute("PRAGMA cache_size=10000")
conn.execute("PRAGMA temp_store=MEMORY")
```

### Scanner Timeout Configuration

```python
# config/settings.json
{
    "scan_timeout": 120,          # Per-scanner timeout (seconds)
    "nmap_timeout": 300,          # Nmap gets longer timeout
    "wapiti_timeout": 600,        # Wapiti is comprehensive = slow
    "nuclei_timeout": 180,        # Nuclei template scan
    "max_scan_duration": 7200     # Total max scan time (2 hours)
}
```

---

# Part 4 — Complete Feature Catalogue

## Core Scanning Engine

| Feature | Status | Description |
|---------|--------|-------------|
| **49-Module VAPT Pipeline** | ✅ Stable | Full automated pentest pipeline with DAG scheduling |
| **Self-Healing Installer** | ✅ Stable | Detects missing tools, installs, retries automatically |
| **Dependency Graph (DAG)** | ✅ Stable | Scanners run in dependency order, parallel where possible |
| **Scan Cancellation** | ✅ Stable | Cancel any running scan from the Active Scan Monitor |
| **Scheduled Scans** | ✅ Stable | Daily/weekly/monthly via APScheduler |
| **Multi-Target** | ✅ Stable | Multiple targets, independent scan queues |
| **Authenticated Scans** | ✅ Stable | Custom HTTP headers (Bearer tokens, session cookies) |
| **Scan Profiles** | ✅ Stable | Per-target scan configuration (timeout, thread count) |

## Scanner Modules

| Scanner | Category | What It Finds |
|---------|----------|--------------|
| **HTTPx** | Recon | HTTP/HTTPS probe, status codes, headers, redirects |
| **WhatWeb** | Fingerprint | CMS, framework, server, plugin detection |
| **Subfinder** | Recon | Subdomain enumeration (passive, 40+ sources) |
| **CRT.sh** | OSINT | Certificate transparency — subdomain discovery |
| **HackerTarget** | OSINT | Reverse DNS, WHOIS, hosted domains |
| **Whois** | OSINT | Domain registrar, registrant, nameservers |
| **Wayback Machine** | OSINT | Historical URL discovery, deleted content |
| **Traceroute** | Network | Network path, hop analysis, latency |
| **Nmap** | Network | Port scanning, service detection, OS fingerprinting |
| **SSL Scanner** | Crypto | TLS version, cipher suite, certificate validity, HSTS |
| **Security Headers** | Web | Missing/misconfigured HTTP security headers |
| **Robots.txt** | Web | Disallowed paths, hidden directories |
| **CORS Scanner** | Web | Cross-origin misconfiguration, wildcard origins |
| **CMS Scanner** | Web | WordPress, Joomla, Drupal detection + version |
| **Nikto** | Web | 6700+ web vulnerability checks |
| **Nuclei** | Web | 5000+ CVE-matched template-based checks |
| **ffuf** | Web | Directory/file fuzzing, backup file discovery |
| **Open Redirect** | Web | Parameter-based open redirect detection |
| **Tech Fingerprint** | Analysis | Deep tech stack analysis, version correlation |
| **Wapiti** | OWASP | SQLi, XSS, XXE, SSRF, command injection |
| **SQLMap** | Injection | SQL injection (GET/POST parameters) |
| **Shodan** | OSINT | Passive target profiling (API key optional) |
| **Gitleaks** | Secret Scan | Exposed API keys, passwords, tokens in web content |
| **theHarvester** | OSINT | Email addresses, hostnames, employee names |
| **Dalfox** | XSS | DOM-based and reflected XSS parameter scanning |
| **Arjun** | Parameter | Hidden HTTP parameter discovery |
| **DNSx** | DNS | DNS record enumeration, zone transfer, DNSSEC |
| **Katana** | Crawler | JavaScript-aware web crawler, endpoint discovery |
| **Commix** | Injection | OS command injection in web parameters |
| **JWT Scanner** | Auth | Weak JWT secrets, algorithm confusion attacks |
| **WPScan** | WordPress | WordPress plugin/theme vulnerabilities |
| **Masscan** | Network | Ultra-fast port scanner (100k ports/second) |
| **ParamSpider** | Parameter | URL parameter mining from Wayback Machine |
| **Cloud Enum** | Cloud | AWS/Azure/GCP public resource enumeration |
| **OWASP ZAP** | Active Scan | Comprehensive active scanner (optional, manual config) |
| **Amass** | Recon | OWASP Amass passive subdomain enum & attack surface mapper |
| **SpiderFoot OSINT** | OSINT | OSINT automation profiling over DNS/WHOIS/SSL/Shodan data |
| **HTTP Smuggling** | Web | Request smuggling (CL.TE/TE.CL) front-end proxy bypass |
| **Feroxbuster** | Crawler | Async Rust directory crawler, hidden resources finder |
| **API Fuzzer** | API | Fuzz Swagger/OpenAPI docs, endpoints authorization bypass |
| **GraphQL Scanner** | API | Introspection queries leakage, query batching exploits |
| **Retire.js Scanner** | Audit | Detect outdated client-side JS libraries with known vulnerabilities |
| **CRLF Scanner** | Injection | CRLF & response HTTP header injection parameter testing |
| **SSRF Scanner** | Injection | Server-Side Request Forgery metadata credentials auditor |
| **XXE Scanner** | Injection | XML External Entity arbitrary server-side file reader |
| **Path Traversal** | Injection | LFI/RFI directory path traversal, sensitive file exposure |
| **Auth Brute-Force** | Auth | Dictionary brute-force testing for known-weak admin logons |
| **TruffleHog** | Secrets | Searches filesystem structures for hardcoded secret API keys |
| **Semgrep** | SAST | Code pattern security scanner for configuration/JS sources |
| **Trivy** | Containers | Static vulnerable components and container package analyzer |


## Intelligence & Analysis

| Feature | Status | Description |
|---------|--------|-------------|
| **CVE Correlation** | ✅ Stable | Matches detected technologies to 300k+ CVE database |
| **Risk Scoring** | ✅ Stable | Per-scan risk score (0-100) with component breakdown |
| **Trend Analysis** | ✅ Stable | Compare scans: new/resolved/persisting findings |
| **Offline CVE Database** | ✅ Stable | 300,000+ CVEs, works air-gapped |
| **CVE Sync** | ✅ Stable | Pull latest CVEs from NVD API with one click |
| **Technology Detection** | ✅ Stable | 400+ technology signatures |

## Reporting

| Feature | Status | Description |
|---------|--------|-------------|
| **Professional PDF Report** | ✅ Stable | ReportLab-powered, dark-themed, board-ready |
| **Modular Executive Summary** | ✅ V5.2 | Situational paragraphs — adapts to findings automatically |
| **Historical Trend in Report** | ✅ Stable | Previous scan comparison in every report |
| **CVSS Scores** | ✅ Stable | Per-finding CVSS v5.2 scoring |
| **Action Plan Timeline** | ✅ Stable | 0-24h / 72h / 2-week / Ongoing priorities |
| **SHA-256 Report Hash** | ✅ Stable | Embedded in filename for integrity verification |
| **Version-Stamped Reports** | ✅ V5.2 | Reports show current SMP version (no hardcoded V5.2) |
| **Anonymous Reports** | ✅ V5.2 | No personal identifiers — "Security Management Platform" only |
| **HTML Report** | ✅ Stable | Responsive web-based report view |

## Database & Reliability

| Feature | Status | Description |
|---------|--------|-------------|
| **Primary Database** | ✅ Stable | SQLite3 encrypted with SQLCipher, WAL mode |
| **Redundancy Database** | ✅ V5.2 | Hot-mirror of every scan, fallback if primary missing |
| **Auto-Clean Redundancy** | ✅ V5.2 | Cleaned after each scan completes or fails |
| **DB Fallback Reads** | ✅ V5.2 | All reads fall back to redundancy.db if primary missing |
| **CVE Database** | ✅ Stable | Separate SQLite with FTS5 indexing |
| **Database Encryption** | ✅ Stable | PBKDF2 key derivation, SQLCipher encryption |

## UI & UX

| Feature | Status | Description |
|---------|--------|-------------|
| **Dark Mode Dashboard** | ✅ Stable | Pure dark theme, #0D0D0D base |
| **Active Scan Monitor** | ✅ V5.2 | Progress bar, step name, elapsed time, cancel button |
| **KPI Strip** | ✅ Stable | Live: risk score, finding count, CVE matches, scans |
| **Findings Browser** | ✅ Stable | Filter by severity, search, export |
| **CVE Feed Browser** | ✅ Stable | Filterable CVE list with FTS search |
| **Reports Manager** | ✅ Stable | Open/delete reports, SHA-256 integrity check |
| **System Health Monitor** | ✅ Stable | Tool availability, DB health, scheduler status |
| **Version Bumping** | ✅ V5.2 | `bump_version.py` updates all files atomically |
| **Splash Screen** | ✅ Stable | Boot animation with tool loading progress |

---

# Part 5 — Known Shortcomings & Technical Debt

> Honesty is the best policy. Here's what we know isn't perfect yet.

## 🔴 Critical Issues

**1. No Authentication Between UI and Scanner**
- The scan runner has no authentication layer between the UI and backend
- **Risk**: On multi-user systems, any local user could trigger scans
- **Fix**: Add UNIX socket authentication or token-based IPC

**2. SQLCipher Dependency**
- Full database encryption requires SQLCipher but many systems only have plain SQLite3
- **Current behaviour**: Falls back to unencrypted SQLite (with a warning)
- **Fix**: Bundle SQLCipher as a pip wheel or compile statically

**3. Tool Binary Signatures Not Verified**
- Downloaded binaries (nuclei, subfinder, etc.) are not GPG-signature-verified
- **Risk**: MITM attacks could replace binaries
- **Fix**: Verify SHA-256 checksums against published hashes before executing

**4. WPScan Ruby Dependency**
- WPScan requires Ruby 2.5+ which many systems don't have
- **Current behaviour**: Graceful skip with warning
- **Fix**: Provide a Docker-based fallback or a Python reimplementation

## 🟠 Significant Issues

**5. Masscan Requires Raw Sockets (root/CAP_NET_RAW)**
- Masscan needs elevated privileges for raw packet sending
- **Current behaviour**: Skips if not root, logs warning
- **Fix**: Add `setcap cap_net_raw+eip bin/masscan` to setup.sh

**6. Shodan Requires API Key**
- No API key = no Shodan data
- **Current behaviour**: Silent skip
- **Fix**: Document free-tier key acquisition, provide better UI hint

**7. No Rate Limiting on Scans**
- SMP can hammer a target with 34 concurrent tool streams
- **Risk**: Could trigger target's DDoS protection or cause unintended outage
- **Fix**: Add inter-request delay and respect `Retry-After` headers

**8. Report Generator Has No Template System**
- All PDF layout is hardcoded in `report_generator.py`
- **Issue**: Cannot customise company logo, colours, or branding without editing source
- **Fix**: ReportLab-based template system with JSON/YAML config

**9. Wapiti Scan Duration Unpredictable**
- Wapiti can take 30 seconds to 2 hours depending on target complexity
- **Current behaviour**: Fixed 600s timeout
- **Fix**: Adaptive timeout based on discovered endpoint count

**10. No Proxy Support in All Scanners**
- HTTP proxy is not universally supported across all 34 scanners
- **Current behaviour**: Works for Python-based scanners, inconsistent for binaries
- **Fix**: Standardise proxy env vars across all subprocess calls

## 🟡 Minor Issues & Tech Debt

**11. `theHarvester` Shodan/Censys Integration Requires Paid API Keys**
- Many OSINT sources in theHarvester need API keys
- **Fix**: Guide users through free-tier key setup in settings UI

**12. Nuclei Templates Not Auto-Updated**
- Templates are fetched once during setup but may become stale
- **Fix**: Add `nuclei -update-templates` to the weekly scheduler

**13. ffuf Wordlist is Minimal**
- Default wordlist has ~70 entries (intentionally small for reliability)
- **Fix**: Auto-download SecLists `common.txt` during setup

**14. Log Rotation Not Enforced**
- Logs in `logs/` can grow unbounded
- **Fix**: Add `logging.handlers.RotatingFileHandler` with 10MB / 5 backup limit

**15. UI Splitter Position Not Persisted**
- Drag the scan monitor panel taller → closes SMP → it resets
- **Fix**: Save `QSplitter.sizes()` to `config/settings.json` on close

**16. No Undo/Redo for Target Deletion**
- Deleting a target is permanent with no recovery
- **Fix**: Soft-delete with 30-day recovery window

**17. Redundancy DB Not Encrypted**
- `redundancy.db` is plaintext SQLite
- **Risk**: Transient sensitive data visible during scan
- **Fix**: Apply same SQLCipher encryption as `security.db`

**18. No CI/CD Pipeline**
- No automated test running on commit
- **Fix**: Add GitHub Actions workflow running `python3 tools/verify_smp.py`

**19. Cloud Enum Keyword List Unmaintained**
- The cloud enumeration wordlist (company name variations) is static
- **Fix**: Accept custom keyword lists per-target in the scan profile

**20. No API Mode**
- SMP is UI-only — no REST API for external integration
- **Fix**: Flask/FastAPI wrapper for headless scan triggering and result retrieval

---

# Part 6 — Future Vision

> This is where we're going. Read this section when you want to contribute to something that matters.

## V5.2 — The Performance Release ⚡

```
Goals:
  ✦ Parallel scan engine rewrite (asyncio-based, no ThreadPoolExecutor)
  ✦ Nuclei template auto-update scheduler
  ✦ Adaptive scanner timeouts (smart, not fixed)
  ✦ Database query optimisation (materialised views, indexes)
  ✦ SecLists integration for ffuf wordlists
  ✦ Proxy support unified across all scanners
  ✦ CI/CD pipeline with GitHub Actions
```

## V5.2 — The API Release 🔌

```
Goals:
  ✦ RESTful API (FastAPI) — scan via curl/Postman/code
  ✦ Webhook support — POST to Slack/Teams/JIRA on finding
  ✦ Docker image — docker run smp scan https://target.com
  ✦ CLI mode — smp scan https://target.com --output report.pdf
  ✦ Headless mode — run on servers without display
```

```bash
# Future CLI vision:
smp scan https://example.com --profile full --output report.pdf
smp report --scan-id 42 --format pdf --format html
smp targets list
smp findings --severity Critical --since 7d
```

## V5.2 — The Intelligence Release 🧠

```
Goals:
  ✦ ML-powered false positive filtering
  ✦ Attack path graph (how findings chain together)
  ✦ Exploitation simulation (safe PoC verification)
  ✦ Compliance mapping (PCI-DSS, ISO 27001, SOC2, NIST)
  ✦ Remediation ticket auto-creation (JIRA/Linear/GitHub Issues)
  ✦ Custom scanner marketplace (community plugins)
```

## V5.2 — The Collaboration Release 👥

```
Goals:
  ✦ Multi-user with RBAC (Admin/Analyst/Viewer roles)
  ✦ Team findings review workflow (assign, comment, approve)
  ✦ Evidence screenshot capture (browser automation)
  ✦ Video recording of exploitation steps
  ✦ Shared finding knowledge base across scans
  ✦ Organisation-wide vulnerability lifecycle management
```

## V5.2 — The Enterprise Release 🏢

```
Goals:
  ✦ Multi-tenant SaaS deployment capability
  ✦ Air-gapped enterprise installation package
  ✦ SIEM integration (Splunk, QRadar, Microsoft Sentinel)
  ✦ Asset management integration (ServiceNow, Tenable)
  ✦ Executive dashboard (board-level risk metrics)
  ✦ Red team / blue team collaboration mode
  ✦ Custom report templates with company branding
```

---

## 🌟 Contributing to SMP

Want to help build the future? Here's how:

### Quick wins (pick up any time):
- ✅ Add a new scanner module using `@register_scanner`
- ✅ Improve an existing scanner's parsing
- ✅ Add tests to `tools/verify_smp.py`
- ✅ Fix a known shortcoming from Part 5

### Bigger contributions:
- 🔄 Rewrite scan engine with asyncio
- 🔌 Build the REST API
- 🧠 Add ML false-positive filtering
- 📝 Improve report template system

### Contribution guidelines:
```bash
# 1. Fork the repo
# 2. Create a feature branch
git checkout -b feature/my-awesome-scanner

# 3. Write your scanner
# 4. Add a test
python3 tools/verify_smp.py

# 5. Bump the version
python3 tools/bump_version.py V5.2

# 6. Submit PR with:
#    - What it does
#    - How to test it
#    - Which shortcoming it fixes
```

---

<div align="center">

```
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   "The best security tool is the one that actually gets       ║
  ║    used — and used right."                                    ║
  ║                                                               ║
  ║   Security Management Platform V5.2                          ║
  ║   Built for authorised security testing only.                ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
```

</div>

---

> [!CAUTION]
> 🔴 **REMINDER**: Always obtain written permission before scanning any target. Unauthorised use of this tool may be illegal in your jurisdiction. The developers of SMP are not responsible for misuse.

---

*Security Management Platform · V5.2 Stable · Complete User Guide*
*For issues, contributions, or feedback — open an issue in the project repository.*


---

# Part 7 — Report Authenticity & Verification

> Even if every database SMP ever wrote to is wiped from the face of the earth, the report file itself carries everything needed to prove it's real.

## 7.1 — The Problem with Traditional Report Verification

Most tools do this:
1. Generate report → compute SHA-256 of the **file**
2. Store hash in **database**
3. To verify → check database

**The flaw**: if the database is lost, verification is gone too. The hash was never in the report — it was only in a table somewhere.

SMP does it differently.

---

## 7.2 — How SMP Report Verification Works

SMP computes a **content hash** — not a file hash — from the **facts printed on the cover page**:

```python
canonical = {
    "url":            "https://example.com",  # Target URL
    "scan_date":      "2024-07-01",           # Date (YYYY-MM-DD only)
    "findings_count": 14,                     # Total findings
    "critical":       2,                      # Critical count
    "high":           5,                      # High count
    "medium":         4,                      # Medium count
    "low":            3,                      # Low count
    "scanned_by":     "Security Team",        # Tester name
    "generator":      "SMP V5.2",             # SMP version
}
content_hash = SHA256(json.dumps(canonical, sort_keys=True))
```

This hash is then:
1. **Printed visibly** on the cover page ("Verification Hash (SHA-256): `abc123...`")
2. **Embedded invisibly** inside the PDF and HTML as a machine-readable marker
3. **In the filename**: `SMP_example.com_Report_2024-07-01_abc123def456abcd.pdf` (first 16 chars)
4. **Stored in the database** (but not required for verification)

---

## 7.3 — Report File Naming

Every SMP report follows this exact naming convention:

```
SMP_{target-domain}_Report_{YYYY-MM-DD}_{HASH16}.pdf
SMP_{target-domain}_Report_{YYYY-MM-DD}.html

Examples:
  SMP_example.com_Report_2024-07-01_b298ff256c9d009a.pdf
  SMP_api.company.org_Report_2024-07-01_3f9a12cd56ef8a00.pdf
```

The 16-character suffix is the first 16 characters of the full 64-char SHA-256 verification hash. It's a quick-scan authenticity signal — if two reports for the same scan have different 16-char suffixes, one of them was tampered with.

---

## 7.4 — Verifying a Report (3 Ways)

### Method 1 — Using the SMP Verifier Tool (Recommended)

```bash
# Verify a PDF report
python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2024-07-01_b298ff256c9d009a.pdf

# Verify an HTML report
python3 tools/verify_report.py reports/html/SMP_example.com_Report_2024-07-01.html

# Verify + print manual verification instructions
python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2024-07-01_b298ff256c9d009a.pdf --manual
```

**Output if authentic:**
```
  ╔══════════════════════════════════════════════════════════════════╗
  ║       Security Management Platform — Report Verifier            ║
  ╚══════════════════════════════════════════════════════════════════╝

  Report: SMP_example.com_Report_2024-07-01_b298ff256c9d009a.pdf
  Size:   342.1 KB

  Embedded hash: b298ff256c9d009a4f3b2c1e0a8d7f6b...

  ✅  VERIFIED — Report is authentic and unmodified.
  The content hash matches the embedded signature.
  This report was genuinely generated by Security Management Platform.
```

**Output if tampered:**
```
  ❌  VERIFICATION FAILED — Hash mismatch detected!
  The report content does not match its embedded signature.
  The report may have been tampered with or manually edited.
```

---

### Method 2 — Manual Verification (No SMP Required)

If you only have the report PDF and a Python interpreter (no SMP installation at all):

**Step 1**: Read the cover page. You'll see:
```
Verification Hash (SHA-256): b298ff256c9d009a4f3b2c1e0a8d7f6b3c9e2a1d5f8b4e7c0a3d6f9b2e5a8c1d
```

**Step 2**: Note the values on the cover page:
- Target URL: `https://example.com`
- Date of Assessment: `2024-07-01`
- Finding counts: Critical=2, High=5, Medium=4, Low=3
- Lead Tester: `Security Team`

**Step 3**: Open Python (any computer, no SMP needed):
```python
import hashlib, json

data = {
    "url":            "https://example.com",
    "scan_date":      "2024-07-01",
    "findings_count": 14,         # total findings
    "critical":       2,
    "high":           5,
    "medium":         4,
    "low":            3,
    "scanned_by":     "Security Team",
    "generator":      "SMP V5.2",
}

h = hashlib.sha256(
    json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
).hexdigest()

print(h)
# Output must exactly match the hash on the cover page
```

> [!IMPORTANT]
> 🔑 **Key insight**: The hash is derived from **data printed on the cover page**, not from the file binary. This means verification survives: database deletion, file copy, email attachment, format conversion (print to PDF), and even manual transcription of the numbers.

---

### Method 3 — Filename Quick-Check

A fast sanity check — if the first 16 characters of the cover-page hash match the filename suffix:

```
Cover page hash:  b298ff256c9d009a4f3b2c1e0a8d7f6b...
                  ←── 16 chars ──→
Filename:         SMP_example.com_Report_2024-07-01_b298ff256c9d009a.pdf
                                                    ←── same ──────→
```

✅ Match = filename hasn't been renamed / file hasn't been swapped  
❌ No match = the filename was changed or it's not a genuine SMP report

---

## 7.5 — Ideology: Why This Matters

Traditional security report verification has a circular trust problem:

```
"Is this report authentic?"
  → "Check the database"
  → "The database says it is"
  → "Can we trust the database?"
  → "Check the database"  ← 🔁 circular
```

SMP breaks this circle. The hash is deterministically derived from facts visible on the report itself. No database, no SMP installation, no internet connection required. Anyone with Python can verify any SMP report, forever.

**Analogy**: It's like signing a document with your handwriting + a notarised stamp. Even if the notary's office burns down, the signature on the document is still checkable.

---

## 7.6 — Report Structure Reference

Every SMP report follows this exact structure (PDF and HTML):

| Section | For Whom | Content |
|---------|----------|---------|
| **Cover Page** | Everyone | Target, tester, date, verification hash |
| **Executive Summary** | Management / Client | Risk posture in plain English, no jargon |
| **Findings Overview** | Everyone | Severity matrix, CVSS scores, tool attribution |
| **Technical Findings Detail** | Security Engineers | Full description, evidence, CVE IDs, reworking steps |
| **Remediation Code Examples** | Developers | Nginx/Apache configs, firewall rules, code fixes |
| **Action Plan & Timeline** | Project Managers | 0–24h / 72h / 2-week / Ongoing priorities |
| **Appendices** | Auditors / Compliance | Tool list, clean-up log, severity glossary, sign-off |

> [!TIP]
> 💡 The report is intentionally comprehensive because the primary audience is **technical practitioners** who need reworking steps, evidence, and code examples — not just a summary. The executive summary at the top gives non-technical readers everything they need without wading through the technical sections.

---

## 7.7 — Sharing Reports Safely

> [!CAUTION]
> 🔴 Reports are marked **CONFIDENTIAL — INTERNAL USE ONLY**. Never share a report outside the authorised scope of the engagement.

**Safe sharing checklist:**
- ✅ Encrypt the PDF before emailing (7-Zip with AES-256, or PGP)
- ✅ Use a time-limited file share link (not email attachment for large reports)
- ✅ Include the verification hash separately so the recipient can verify integrity
- ✅ Ensure the recipient knows not to forward the report
- ❌ Never upload reports to public file sharing services
- ❌ Never include client data in public bug reports or GitHub issues

