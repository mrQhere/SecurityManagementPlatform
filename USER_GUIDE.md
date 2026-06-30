<div align="center">

# 🛡️ Security Management Platform (SMP)
## V5.2 Comprehensive User Guide & Developer Manual 🚀

**Version V5.2 Stable** · Published 2026-06-30 · All Rights Reserved

</div>

---

> [!CAUTION]
> **The Golden Rule**: SMP is basically a digital battering ram. It is designed exclusively for security testing on systems **you actually own** or have explicit, written authorization to test. Pointing this at random websites is highly illegal and will end very badly for you. By using this software, you accept sole legal responsibility for all your activities. Stay safe, stay legal. 🛑

---

## 📖 Table of Contents

| # | Section | What You'll Learn |
|---|---|---|
| 1 | [Welcome to SMP: Setup & Liftoff](#1-welcome-to-smp-setup--liftoff-🚀) | How to install and launch this beast. |
| 2 | [Platform Walkthrough & Operations](#2-platform-walkthrough--operations-🎮) | Clicking buttons and hacking things (legally). |
| 3 | [Internal Architecture: Under the Hood](#3-internal-architecture-under-the-hood-⚙️) | The nerd stuff: DAGs, UDP, and Multiprocessing. |
| 4 | [Database Architecture](#4-database-architecture-🗄️) | How we store your precious data. |
| 5 | [The 35-Tool Arsenal](#5-the-35-tool-arsenal-🛠️) | A quick look at the weapons at your disposal. |
| 6 | [Developer Guide: Adding Custom Tools 🧩](#6-developer-guide-adding-custom-tools-🧩) | **[REAL DEVS START HERE]** Bring your own tools! |
| 7 | [Developer Guide: Database Interactions 💾](#7-developer-guide-database-interactions-💾) | Copy-paste code to write directly to the DB. |
| 8 | [Developer Guide: Custom PDF Reports 📊](#8-developer-guide-custom-pdf-reports-📊) | Hack the report generator to fit your brand. |
| 9 | [Top 10 Troubleshooting Guide](#9-top-10-troubleshooting-guide-🚑) | Oh no, it broke! (Here is how to fix it). |
| 10 | [Platform Roadmap (V5 to V8)](#10-platform-roadmap-v5-to-v8-🗺️) | Where we are going next! |

---

## 1. Welcome to SMP: Setup & Liftoff 🚀

Welcome to **Security Management Platform (SMP) V5.2**! If you're used to legacy scanners that run one tool at a time and freeze your computer, you're in for a treat. SMP uses a **Directed Acyclic Graph (DAG)** and true OS-level multiprocessing to run up to 35 top-tier security tools simultaneously. It’s like having an entire Red Team working in parallel.

### 1.1 Automated Zero-Friction Installation (Linux/Ubuntu)
We hate manual setups just as much as you do. So, we completely automated it.

```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the magical setup script
bash setup.sh
```

That's it! `setup.sh` installs the dependencies, builds the virtual environment, hardens permissions, and immediately launches the platform. 

For future runs, you don't even need to touch python. Just run:
```bash
bash run.sh
```

### 1.2 Initial Configuration (Locking it down 🔒)
On your very first boot, SMP will ask you to set a **Master Password**. 
> [!IMPORTANT]
> Your Master Password is used to symmetrically **AES-256 encrypt** your database. We do not store this password. We cannot recover this password. If you lose it, your data is turned into digital dust. Write it down!

### 1.3 Threat Intelligence Sync (The Big Download 📥)
On the first launch, SMP will sync the *entire* NVD CVE database (over 300,000+ entries going back to 1999). This takes about 20-60 minutes because the government servers enforce a 6-second delay between requests. Go grab a coffee ☕. Subsequent syncs will be incremental and finish in seconds!

### 1.4 License & Responsibility Activation
Before you can unleash SMP, you must activate it and accept legal responsibility:
1. Copy your `license.key` into the `config/` directory.
2. Tick the legally-binding box stating you have authorization. 
3. Boom. The key is cryptographically bound to your machine. You're ready.

---

## 2. Platform Walkthrough & Operations 🎮

SMP features a gorgeous, Apple-inspired interface. It hides the terminal chaos and presents a clean, executive view of your security posture.

### 2.1 The Dashboard Panel
Your command center. 
- **KPI Metrics**: Total monitored targets, active vulnerabilities, and system health.
- **Risk Table**: A CVSS-weighted risk score for all your targets.
- **Recent Events**: Watch the Zero-Latency UDP event bus stream real-time logs from the background scanners like a scene from The Matrix.
- **Hash Signature Verification (New in V5.2!)**: You can now verify the cryptographical SHA-256 hash of all generated PDF reports directly from the dashboard!

### 2.2 The Targets Panel (Let's Go Hunting 🎯)
1. Go to the **Targets** tab.
2. Type in your authorized URL (e.g., `https://example.com`) and click **Add Target**.
3. Click the shiny **Scan** button.
4. A live terminal window appears in the GUI showing you exactly what the DAG Orchestrator is doing in the background. Sit back and watch it map the attack surface in parallel!

### 2.3 Advanced CVE Correlation 
SMP doesn't just match text anymore. It's smart.
- **MITRE ATT&CK Mapping**: Vulnerabilities are automatically mapped to specific MITRE tactics (e.g., *TA0001 Initial Access*).
- **CISA KEV Alerting**: Using the Exploit Prediction Scoring System (EPSS), if a vulnerability has a >20% chance of being exploited in the wild, SMP explicitly flags it as a **[CISA KEV ALERT]**. Fix these *immediately*.

### 2.4 Executive Reporting (Looking Good for the Boss 📊)
When a scan finishes, click the **Report** button. SMP generates a boardroom-ready PDF that includes:
- **Historical Tracking**: If you've scanned this target before, the report compares the results, explicitly shaming *Persisting Findings* that haven't been fixed!
- **SMP Verified Stamp**: The final page includes a cryptographic stamp with the scanner's local/public IP address, date, and your target website name (e.g., *SMP (example.com) Verified Report*).

---

## 3. Internal Architecture: Under the Hood ⚙️

For the developers reading this, SMP V5.2 is an absolute marvel of Python engineering. 

### 3.1 The Subprocess Boundary
Python has a Global Interpreter Lock (GIL). Running 35 heavy hacking tools on the UI thread would instantly freeze the app. So, `scan_runner.py` spawns a completely isolated `multiprocessing.Process`. The scan runs on a totally different CPU core than the UI!

### 3.2 The Directed Acyclic Graph (DAG)
Inside that subprocess, the `DAGOrchestrator` dynamically maps out tool dependencies (e.g., "SQLMap cannot run until Nmap finishes"). It spins up a massive ThreadPool and executes every non-dependent tool in parallel. It is lightning fast. ⚡

### 3.3 Zero-Latency UDP IPC
Because the scanner is in a different memory space, it can't tell the UI to update directly. Instead, when a tool finishes, the Database Manager fires a JSON payload to a local UDP socket (`127.0.0.1:5005`). The UI has a background listener that catches this and triggers a surgical Qt Signal to update the screen. Zero polling. Zero lag.

---

## 4. Database Architecture 🗄️

We take data integrity very seriously. SMP uses a highly optimized SQLite WAL (Write-Ahead Logging) database with 5 layers of redundancy:
1. **In-Memory Caching**: To prevent disk thrashing.
2. **Periodic Disk Flushing**: Saves to disk safely.
3. **AES-256 Encryption**: Your data is encrypted at rest using your Master Password.
4. **Automated Daily Backups**: Backups are rotated automatically.
5. **Auto-healing**: If the database gets corrupted, SMP can restore from the latest backup gracefully.

---

## 5. The 35-Tool Arsenal 🛠️

SMP orchestrates 35 of the world's best open-source security tools. These include:
- **Recon**: Nmap, Shodan, Wayback Machine, Subfinder
- **Vulnerability Scanners**: Nuclei, Nikto, WPScan
- **Exploitation/Fuzzing**: SQLMap, Dalfox, ffuf, Commix

The DAG Engine figures out the optimal way to run them all without overlapping or crashing your network.

---

## 6. Developer Guide: Adding Custom Tools 🧩

**Real Devs, this section is for you.** Want to add your own proprietary scanning script or integrate a new open-source tool? SMP’s Dynamic Registry makes it painfully easy. You don't need to dig into the core loop.

### 6.1 Creating a New Scanner Module
Navigate to the `scanners/plugins/` directory and create a new Python file. Let's call it `my_custom_fuzzer.py`.

Here is the exact **copy-paste boilerplate** you need:

```python
# scanners/plugins/my_custom_fuzzer.py
import subprocess
import logging
from scanners.registry import register_scanner
from tools.db_manager import add_finding

# 1. Use the decorator to register your tool.
# - 'name': How it appears in the UI and logs
# - 'dependencies': What tools MUST finish before this runs?
# - 'binary_req': (Optional) What bash command must exist on the system?
@register_scanner(
    name="MyCustomFuzzer",
    dependencies=["Nmap", "Subfinder"], # Wait for recon!
    binary_req="curl" # We just need curl for this example
)
def run_custom_fuzzer(target_url, scan_id):
    """
    This function is executed dynamically by the DAG Orchestrator on its own thread.
    """
    logger = logging.getLogger("smp")
    logger.info(f"[MyCustomFuzzer] Starting fuzz on {target_url} (Scan ID: {scan_id})")
    
    # 2. Execute your logic (e.g., run a shell command)
    try:
        # Example: Hit a specific endpoint to see if it responds with 200 OK
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"{target_url}/.env"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            http_code = result.stdout.strip()
            if http_code == "200":
                logger.warning(f"[MyCustomFuzzer] CRITICAL: .env file exposed on {target_url}!")
                
                # 3. Save the finding to the database (See Section 7 for details)
                add_finding(
                    scan_id=scan_id,
                    severity="Critical",
                    title="Exposed Environment File (.env)",
                    description="The web server is publicly exposing its .env file. This likely leaks database credentials, API keys, and secret tokens.",
                    source_tool="MyCustomFuzzer",
                    confidence=95,
                    mitre_id="T1552.001" # Credentials in Files
                )
            else:
                logger.info(f"[MyCustomFuzzer] Endpoint secure. HTTP {http_code}")
                
    except subprocess.TimeoutExpired:
        logger.error("[MyCustomFuzzer] Scan timed out.")
    except Exception as e:
        logger.error(f"[MyCustomFuzzer] Crash: {str(e)}")
        
    logger.info("[MyCustomFuzzer] Completed successfully.")
```

### 6.2 How it works
1. You drop that file in `scanners/plugins/`.
2. When SMP boots, `registry.py` scans the directory, finds the `@register_scanner` decorator, and adds it to memory.
3. During a scan, the DAG Orchestrator notices `MyCustomFuzzer` depends on `Nmap` and `Subfinder`. It will hold execution until those two finish, then immediately fire `run_custom_fuzzer` on a background thread.
4. Any findings you push via `add_finding` instantly appear in the UI via the UDP event bus!

---

## 7. Developer Guide: Database Interactions 💾

We use SQLite with Write-Ahead Logging (WAL). You should **never** access `database/security.db` directly using raw `sqlite3` modules from your scanners, or you will cause a `database is locked` error and crash the parallel threads.

Instead, ALWAYS use the thread-safe functions provided in `tools/db_manager.py`.

### 7.1 Copy-Paste Code: Adding a Finding
The most common task is logging a vulnerability. Use this function in your scanner.

```python
from tools.db_manager import add_finding

# Add a critical vulnerability
success = add_finding(
    scan_id=current_scan_id,       # Integer: Get this from the scan runner
    severity="High",               # String: "Critical", "High", "Medium", "Low", or "Info"
    title="SQL Injection in Login",# String: Short title
    description="Payload: ' OR 1=1--", # String: Detailed description / proof of concept
    source_tool="CustomSQLi",      # String: The name of your tool
    confidence=100,                # Integer: 0 to 100
    mitre_id="T1190"               # String: MITRE ATT&CK tactic ID (optional, defaults to 'Unknown')
)

if success:
    print("Finding saved and UDP event fired to the dashboard!")
```

### 7.2 Copy-Paste Code: Reading the Latest Scan Data
If you are writing a custom report generator or an analytics dashboard, here is how you safely pull data.

```python
from tools.db_manager import get_db_connection

def get_findings_for_target(target_url):
    """Safely retrieves all findings for the most recent scan of a target."""
    conn = get_db_connection() # Thread-safe connection with exponential backoff
    
    try:
        # 1. Find the target ID
        target_row = conn.execute("SELECT id FROM targets WHERE url = ?", (target_url,)).fetchone()
        if not target_row:
            return []
            
        target_id = target_row["id"]
        
        # 2. Find their most recent completed scan
        scan_row = conn.execute("""
            SELECT id FROM scans 
            WHERE target_id = ? AND status = 'Completed' 
            ORDER BY id DESC LIMIT 1
        """, (target_id,)).fetchone()
        
        if not scan_row:
            return []
            
        scan_id = scan_row["id"]
        
        # 3. Fetch all findings
        findings_rows = conn.execute("""
            SELECT severity, title, source_tool, mitre_id 
            FROM findings 
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()
        
        # Return as a clean list of dictionaries
        return [dict(row) for row in findings_rows]
        
    except Exception as e:
        print(f"DB Error: {e}")
        return []
    finally:
        conn.close() # ALWAYS CLOSE THE CONNECTION!

# Usage:
data = get_findings_for_target("https://example.com")
print(data)
```

### 7.3 Raw Queries (Advanced)
If you MUST run a raw query that isn't wrapped in `db_manager.py`, follow this exact context manager pattern to ensure you don't lock the DB for other threads:

```python
from tools.db_manager import get_db_connection

def custom_raw_query():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # We wrap in a transaction to ensure atomic execution
        conn.execute("BEGIN TRANSACTION")
        
        cursor.execute("UPDATE targets SET status = 'Disabled' WHERE url LIKE '%.xyz'")
        
        # Must commit!
        conn.commit()
    except Exception as e:
        # Rollback on failure so we don't corrupt data!
        conn.rollback()
        print(f"Failed: {e}")
    finally:
        # Regardless of success or failure, close the connection to release the lock!
        conn.close()
```

---

## 8. Developer Guide: Custom PDF Reports 📊

SMP generates stunning executive PDF reports using the `reportlab` library in `tools/report_generator.py`. If you want to change the branding, the fonts, or add new sections, this is how you do it.

### 8.1 The PDF Lifecycle
When a scan finishes, the DAG Orchestrator calls `generate_scan_reports(scan_id, ...)`.
1. It queries the DB for the target, findings, and previous scan data.
2. It builds a `ctx` (Context) dictionary.
3. It passes `ctx` to `_generate_vapt_pdf(pdf_path, ctx)`.
4. `_generate_vapt_pdf` builds a list of "Story" elements (Paragraphs, Tables, Spacers).
5. It compiles the PDF.
6. It takes the SHA-256 hash of the generated PDF file and appends the hash to the filename for cryptographic verification in the dashboard!

### 8.2 Copy-Paste Code: Adding a Custom Section to the PDF
Open `tools/report_generator.py` and locate the `_generate_vapt_pdf` function. You can inject your own blocks of content into the `story` array before the document is built.

```python
# Inside tools/report_generator.py -> _generate_vapt_pdf()

from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

styles = getSampleStyleSheet()
my_custom_style = styles["Normal"]

# 1. Create a heading
story.append(Paragraph("My Custom Corporate Section", st["h1"]))
story.append(Spacer(1, 10))

# 2. Add some dynamic text based on the context
story.append(Paragraph(
    f"This scan on {c['url']} was executed on {c['scan_time']}. "
    f"We discovered {len(c['findings'])} total vulnerabilities.",
    my_custom_style
))
story.append(Spacer(1, 20))

# 3. Add a custom table
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors

table_data = [
    ["Component", "Status", "Notes"],
    ["Firewall", "Active", "No bypass detected"],
    ["WAF", "Bypassed", "SQLi slipped through"],
    ["Database", "Vulnerable", "Needs immediate patching"]
]

custom_table = Table(table_data, colWidths=[150, 100, 200])
custom_table.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1A2A3A")),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#0D0D0D")),
    ('TEXTCOLOR', (0, 1), (-1, -1), colors.lightgrey),
    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#333333"))
]))

story.append(custom_table)
story.append(Spacer(1, 30))
```

### 8.3 Verifying the PDF Hash Programmatically
In V5.2, every PDF is cryptographically hashed. If a client wants to verify the PDF wasn't tampered with, they can run this script to ensure the hash matches the database:

```python
import hashlib
from tools.db_manager import get_db_connection

def verify_report(pdf_path, scan_id):
    # 1. Hash the local file
    with open(pdf_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
        
    # 2. Check the database
    conn = get_db_connection()
    row = conn.execute("SELECT report_hash FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    
    if not row or not row["report_hash"]:
        return False, "No hash found in database for this scan."
        
    # 3. Compare
    db_hash = row["report_hash"]
    if file_hash == db_hash:
        return True, f"Verified! Hash: {file_hash}"
    else:
        return False, f"TAMPERED! Expected {db_hash}, got {file_hash}"

# Usage
is_valid, msg = verify_report("reports/pdf/VAPT_Report_example_com_123456_a1b2c3d4.pdf", 42)
print(msg)
```

---

## 9. Top 10 Troubleshooting Guide 🚑

Stuff happens. Here is how to fix the most common issues without breaking a sweat.

### 1. "Nmap is not installed!"
**Cause**: The system is missing the nmap binary.
**Fix**: `sudo apt install nmap -y`

### 2. "Database is locked"
**Cause**: Too many tools writing to SQLite simultaneously.
**Fix**: We implemented WAL mode in V5.1 to prevent this, but if it happens, restart SMP. The auto-healer will fix the lock.

### 3. "UI Freezes during scan"
**Cause**: The UDP event bus port (5005) is blocked or in use by another app.
**Fix**: Ensure no other application is using UDP port 5005 on localhost. `lsof -i UDP:5005`

### 4. "License Key Invalid"
**Cause**: The file in `config/license.key` is missing or corrupted.
**Fix**: Re-copy your license key into the directory and restart.

### 5. "Missing CVE Data / Unknown CVE"
**Cause**: The Threat Intel sync didn't finish.
**Fix**: Leave the app running. The background scheduler will automatically resume the NVD sync.

### 6. "Scan fails immediately"
**Cause**: The target URL is unreachable or you are offline.
**Fix**: Check your internet connection and ensure the target isn't blocking your IP.

### 7. "PDF Report looks weird / fonts missing"
**Cause**: Missing system fonts for ReportLab.
**Fix**: `sudo apt install ttf-mscorefonts-installer -y`

### 8. "Out of Memory (OOM) Killer"
**Cause**: Running 35 tools on a 2GB RAM machine.
**Fix**: Upgrade your server. SMP recommends at least 8GB of RAM for full parallel scanning.

### 9. "Master Password Rejected"
**Cause**: You typed it wrong.
**Fix**: There is no fix. If you lost the password, you must delete `database/security.db` and start fresh.

### 10. "Corrupted Database / File Missing"
**Cause**: Power loss or accidental deletion.
**Fix**: If a file is deleted, SMP will attempt to auto-regenerate it. If the DB is corrupted, it will automatically rollback to the last backup in the `backup/` folder.

---

## 10. Platform Roadmap (V5 to V8) 🗺️

We are always building. Here is a sneak peek at where SMP is heading!

### 📍 V6.0: The Enterprise Fleet
- **Multi-Node Distributed Scanning**: Deploy "worker" nodes across different VPS instances to scan from multiple IP addresses simultaneously.
- **Enterprise Webhooks**: Native integration with Slack, Microsoft Teams, and Jira for automated ticket creation.

### 📍 V7.0: The AI Analyst
- **LLM Integration**: Feed terminal output into a local Large Language Model to automatically write custom proof-of-concept exploits and remediation guides.
- **False Positive Eradication**: Machine learning models trained to ignore noisy Nuclei templates.

### 📍 V8.0: Active Defense & Auto-Remediation
- **WAF Ruleset Generation**: Automatically generate and deploy ModSecurity/AWS WAF rules based on scan findings.
- **Self-Healing Infrastructure**: SMP will not just find the holes, it will SSH in and patch them (with permission, of course).

---
*End of Guide. Now go hack the planet (safely).* 🌍
