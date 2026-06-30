<div align="center">

# 🛡️ Security Management Platform (SMP)
## V5.1 Comprehensive User Guide & Developer Manual 🚀

**Version V5.1 Stable** · Published 2026-06-30 · All Rights Reserved

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
| 6 | [Adding Custom Tools (Dynamic Registry)](#6-adding-custom-tools-dynamic-registry-🧩) | How to bring your own tools to the party! |
| 7 | [Top 10 Troubleshooting Guide](#7-top-10-troubleshooting-guide-🚑) | Oh no, it broke! (Here is how to fix it). |
| 8 | [Platform Roadmap (V5 to V8)](#8-platform-roadmap-v5-to-v8-🗺️) | Where we are going next! |

---

## 1. Welcome to SMP: Setup & Liftoff 🚀

Welcome to **Security Management Platform (SMP) V5.1**! If you're used to legacy scanners that run one tool at a time and freeze your computer, you're in for a treat. SMP uses a **Directed Acyclic Graph (DAG)** and true OS-level multiprocessing to run up to 35 top-tier security tools simultaneously. It’s like having an entire Red Team working in parallel.

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

### 2.2 The Targets Panel (Let's Go Hunting 🎯)
1. Go to the **Targets** tab.
2. Type in your authorized URL (e.g., `https://example.com`) and click **Add Target**.
3. Click the shiny **Scan** button.
4. A live terminal window appears in the GUI showing you exactly what the DAG Orchestrator is doing in the background. Sit back and watch it map the attack surface in parallel!

### 2.3 Advanced CVE Correlation (New in V5.1! 🔥)
SMP doesn't just match text anymore. It's smart.
- **MITRE ATT&CK Mapping**: Vulnerabilities are automatically mapped to specific MITRE tactics (e.g., *TA0001 Initial Access*).
- **CISA KEV Alerting**: Using the Exploit Prediction Scoring System (EPSS), if a vulnerability has a >20% chance of being exploited in the wild, SMP explicitly flags it as a **[CISA KEV ALERT]**. Fix these *immediately*.

### 2.4 Executive Reporting (Looking Good for the Boss 📊)
When a scan finishes, click the **Report** button. SMP generates a boardroom-ready PDF that includes:
- **Historical Tracking**: If you've scanned this target before, the report compares the results, explicitly shaming *Persisting Findings* that haven't been fixed!
- **SMP Verified Stamp**: The final page includes a cryptographic stamp with the scanner's local/public IP address and date, guaranteeing authenticity for corporate audits.

---

## 3. Internal Architecture: Under the Hood ⚙️

For the developers reading this, SMP V5.1 is an absolute marvel of Python engineering. 

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

## 6. Adding Custom Tools (Dynamic Registry) 🧩

Want to add your own secret hacking script to SMP? It's ridiculously easy in V5.1!

1. Create a new python file in the `scanners/` directory (e.g. `my_tool.py`).
2. Use the `@register_scanner` decorator.

```python
from scanners.registry import register_scanner

@register_scanner(
    name="MyCustomTool",
    dependencies=["Nmap"], # SMP will wait for Nmap to finish before running this!
    binary_req="my_script.sh"
)
def run_my_tool(target_url, scan_id):
    # Your python logic here!
    # Call db_manager.add_finding() if you find something cool!
    pass
```
SMP will automatically discover your tool, inject it into the DAG, and run it. No messy hardcoding required!

---

## 7. Top 10 Troubleshooting Guide 🚑

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

## 8. Platform Roadmap (V5 to V8) 🗺️

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
