<div align="center">

# Security Management Platform (SMP)
## V5.0 Comprehensive User Guide & Developer Manual

**Version V5.0 Stable** · Published 2026-06-30 · All Rights Reserved

</div>

---

> [!CAUTION]
> **Legal Responsibility**: SMP is designed exclusively for security testing on systems you own or have explicit written authorization to test. Using this tool against systems you do not have permission to test is illegal and may result in criminal prosecution. By using this software, you accept sole legal responsibility for all activities performed with it.

---

## 📖 Table of Contents

| # | Section |
|---|---|
| 1 | [Welcome to SMP: Installation & Setup](#1-welcome-to-smp-installation--setup) |
| 2 | [Platform Walkthrough & Operations](#2-platform-walkthrough--operations) |
| 3 | [Internal Architecture: How It Works](#3-internal-architecture-how-it-works) |
| 4 | [Database Architecture & 5-Layer Redundancy](#4-database-architecture--5-layer-redundancy) |
| 5 | [The 35-Step Sequential Scan Pipeline](#5-the-35-step-sequential-scan-pipeline) |
| 6 | [Adding Custom Tools (Dynamic Registry)](#6-adding-custom-tools-dynamic-registry) |
| 7 | [Top 20 Troubleshooting Guide](#7-top-20-troubleshooting-guide) |
| 8 | [Platform Roadmap (V5 to V8)](#8-platform-roadmap-v5-to-v8) |

---

## 1. Welcome to SMP: Installation & Setup

Welcome to the Security Management Platform (SMP) V5.0. This platform is a massive leap forward from standard sequential vulnerability scanners. It utilizes a powerful Directed Acyclic Graph (DAG) and true OS-level multiprocessing to run 35 top-tier security tools simultaneously against your target. 

### 1.1 Automated Zero-Friction Installation (Linux/Ubuntu)
```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the fully automated, self-healing setup script
# This will install all dependencies, build the virtual environment, and launch the platform automatically!
bash setup.sh
```

### 1.2 Initial Configuration
On first boot, the platform will auto-generate your local SQLite databases. It will prompt you to set a Master Password. 
> [!IMPORTANT]
> Your Master Password is used to symmetrically AES-256 encrypt the database. If you lose this password, your data is gone forever. Write it down.

### 1.3 Threat Intelligence Sync
On the very first launch, SMP will download the complete NVD CVE database (300,000+ entries going back to 1999). This is a one-time operation that takes 20-60 minutes depending on your internet connection. NVD enforces a mandatory 6-second delay between API requests. Do not interrupt this process. Subsequent syncs are incremental and complete in under a minute.

### 1.4 License & Responsibility Activation
Before you can run any scans, you must activate the platform using your proprietary license key and explicitly accept legal responsibility.
1. Locate your `license.key` file provided upon enterprise purchase.
2. Copy this file directly into the `config/` directory:
```bash
cp /path/to/downloaded/license.key config/license.key
```
3. Upon next boot, a legally-binding prompt will appear. You must physically tick the box stating: **"I accept sole legal responsibility for all activities performed and confirm I have explicit written authorization for all targets."** Once ticked, the key is cryptographically bound to your machine.

---

## 2. Platform Walkthrough & Operations

SMP is designed with a sleek, Apple-inspired interface to abstract away the complexity of managing 35 terminal-based hacking tools.

### 2.1 The Dashboard Panel
When you launch SMP, you land on the Dashboard. This panel gives you a high-level overview of your security posture. 
- **KPI Metrics**: View total monitored targets, active vulnerabilities, and engine health.
- **Risk Table**: See a calculated CVSS-weighted risk score for all your targets.
- **Recent Events**: Watch the Zero-Latency UDP event bus stream real-time logs from the background scanners.

### 2.2 The Targets Panel (Starting a Scan)
1. Navigate to the **Targets** tab on the left sidebar.
2. In the input field, type your authorized target URL (e.g., `https://example.com`).
3. Click **Add Target**. It will appear in the table below.
4. Click the **Scan** button next to your target. 
5. A live terminal window will appear within the GUI, showing you the exact tools being run in real-time. 

### 2.3 Threat Intelligence Panel
- **Severity Filters**: Filter the CVE database by Critical, High, Medium, Low.
- **Source Filters**: Filter by NVD, CISA KEV, or GitHub Advisories.
- **Search**: Full-text search across all 300,000+ CVEs.

### 2.4 Viewing Results (Reporting)
Once a scan finishes, a PDF and HTML report are automatically generated.
1. Click the **Report** button next to your scanned target.
2. The HTML report will open in your default browser.
3. The report contains a beautiful **Executive Summary**, a **Findings Matrix**, and a deep-dive into the exact terminal output that triggered each vulnerability. 

---

## 3. Internal Architecture: How It Works

For developers, SMP V5.0 is an absolute marvel of Python engineering. Here is exactly what happens under the hood when you click "Scan".

### 3.1 The Subprocess Boundary
Because Python suffers from the Global Interpreter Lock (GIL), running 35 heavy tools on the UI thread would freeze the application. 
When you start a scan, `scan_runner.py` spawns a completely isolated `multiprocessing.Process`. This means the scan runs on a completely different CPU core than the UI. 

### 3.2 The Directed Acyclic Graph (DAG)
Inside that subprocess, the `DAGOrchestrator` kicks in. It dynamically reads all the tools in the `scanners/` folder. It maps out their dependencies (e.g., "SQLMap cannot run until Nmap finishes"). It then spins up a massive ThreadPool and executes every non-dependent tool in parallel. 

### 3.3 Zero-Latency UDP IPC 
Because the scanner is in a different memory space, it cannot tell the UI to update. Instead, when a tool finishes, it saves its finding to the SQLite database via `db_manager.py`. The Database Manager immediately fires a JSON payload to a local UDP socket (`127.0.0.1:5005`). 
The PySide6 UI has a background `UDPListenerThread` that catches this payload and triggers a surgical Qt Signal to instantly update the UI without ANY polling or disk thrashing.

### 3.4 MAC Address Randomization (Deep Scan Mode)
When running active scanners, the platform will automatically prompt for `sudo` to randomize your network adapter's MAC address using `tools/mac_changer.py`. This ensures anonymous profiling and avoids vendor-specific network blocking during heavy fuzzing.

---

## 4. Database Architecture & 5-Layer Redundancy

SMP maintains a highly robust local database structure ensuring maximum data retention and ultra-fast query times.

### 4.1 Database Matrix

| Database | Path | Purpose | AES-256 Encrypted |
|---|---|---|---|
| **Primary** | `database/security.db` | Core schema: targets, scans, findings, technologies, baselines | Yes |
| **Raw Archive** | `backup/active_scans.db` | Full JSON output of every tool per scan | Yes |
| **Important Findings** | `backup/important_results.db` | High and Critical severity findings only | Yes |
| **Disaster Recovery** | `backup/full_backup.db` | 1:1 replica of all 8 primary application tables | Yes |
| **Threat Intel Mirror** | `backup/cve_secondary.db` | Local cache of synced CVE feeds | No (public data) |

### 4.2 Core Schema (security.db)
```sql
CREATE TABLE targets (id INTEGER PRIMARY KEY, url TEXT, status TEXT);
CREATE TABLE scans (id INTEGER PRIMARY KEY, target_id INTEGER, status TEXT);
CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id INTEGER, severity TEXT, title TEXT, source_tool TEXT);
CREATE TABLE cves (id INTEGER PRIMARY KEY, cve TEXT, severity TEXT, description TEXT);
```

### 4.3 Automated Backup & File Recovery
SMP features an immutable, automated backup engine. Every time a scan completes, the platform takes a cryptographic snapshot of the primary database and archives it into `backup/full_backup.db`. 
If your primary database becomes corrupted or is accidentally deleted, you can instantly recover it using the following copy-paste command:
```bash
# Instantly restore the primary database from the last known good backup
cp backup/full_backup.db database/security.db
```

### 4.4 Auto-Generation of Missing Files
The platform is designed to be self-healing. If any critical configuration file, directory, or even the local SQLite database is accidentally deleted, **do not panic**. 
Upon the next boot (`python3 main.py`), the Core Initialization routine will detect the missing assets and automatically regenerate them with safe, default values. This includes rebuilding the `config/` folder, the `database/` folder, and all requisite JSON configuration files natively, ensuring zero downtime.

---

## 5. The 35-Step Sequential Scan Pipeline

The DAG orchestrator dynamically executes the following 35 security profiling tools. Below is an exhaustive breakdown of every tool integrated into the V5.0 platform.

### 5.1 Arjun

**Step Name**: Running Arjun
**Depends On**: Dalfox
**Binary Required**: `arjun`

#### Overview
The `Arjun` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Arjun` step, it spawns an isolated OS subprocess to execute `arjun` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Dalfox` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Arjun` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Arjun` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Arjun` phase.

---

### 5.2 CMS Scanner

**Step Name**: Running CMS Scanner
**Depends On**: CORS
**Binary Required**: ``

#### Overview
The `CMS Scanner` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running CMS Scanner` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `CORS` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `CMS Scanner` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `CMS Scanner` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running CMS Scanner` phase.

---

### 5.3 CORS

**Step Name**: Running CORS
**Depends On**: Robots.txt
**Binary Required**: ``

#### Overview
The `CORS` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running CORS` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Robots.txt` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `CORS` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `CORS` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running CORS` phase.

---

### 5.4 CRT.sh

**Step Name**: Running CRT.sh
**Depends On**: theHarvester
**Binary Required**: ``

#### Overview
The `CRT.sh` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running CRT.sh` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `theHarvester` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `CRT.sh` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `CRT.sh` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running CRT.sh` phase.

---

### 5.5 Cloud Enum

**Step Name**: Running Cloud Enum
**Depends On**: ParamSpider
**Binary Required**: `cloud_enum`

#### Overview
The `Cloud Enum` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Cloud Enum` step, it spawns an isolated OS subprocess to execute `cloud_enum` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `ParamSpider` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Cloud Enum` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Cloud Enum` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Cloud Enum` phase.

---

### 5.6 Commix

**Step Name**: Running Commix
**Depends On**: Katana
**Binary Required**: `commix`

#### Overview
The `Commix` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Commix` step, it spawns an isolated OS subprocess to execute `commix` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Katana` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Commix` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Commix` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Commix` phase.

---

### 5.7 DNSx

**Step Name**: Running DNSx
**Depends On**: Arjun
**Binary Required**: `dnsx`

#### Overview
The `DNSx` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running DNSx` step, it spawns an isolated OS subprocess to execute `dnsx` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Arjun` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `DNSx` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `DNSx` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running DNSx` phase.

---

### 5.8 Dalfox

**Step Name**: Running Dalfox
**Depends On**: Gitleaks
**Binary Required**: `dalfox`

#### Overview
The `Dalfox` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Dalfox` step, it spawns an isolated OS subprocess to execute `dalfox` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Gitleaks` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Dalfox` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Dalfox` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Dalfox` phase.

---

### 5.9 Gitleaks

**Step Name**: Running Gitleaks
**Depends On**: Shodan
**Binary Required**: ``

#### Overview
The `Gitleaks` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Gitleaks` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Shodan` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Gitleaks` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Gitleaks` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Gitleaks` phase.

---

### 5.10 HTTPx

**Step Name**: Running HTTPx
**Depends On**: None
**Binary Required**: `httpx`

#### Overview
The `HTTPx` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running HTTPx` step, it spawns an isolated OS subprocess to execute `httpx` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Initial boot` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `HTTPx` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `HTTPx` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running HTTPx` phase.

---

### 5.11 HackerTarget

**Step Name**: Running HackerTarget
**Depends On**: CRT.sh
**Binary Required**: ``

#### Overview
The `HackerTarget` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running HackerTarget` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `CRT.sh` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `HackerTarget` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `HackerTarget` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running HackerTarget` phase.

---

### 5.12 JWT Scanner

**Step Name**: Running JWT Scanner
**Depends On**: Commix
**Binary Required**: `jwt_tool`

#### Overview
The `JWT Scanner` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running JWT Scanner` step, it spawns an isolated OS subprocess to execute `jwt_tool` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Commix` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `JWT Scanner` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `JWT Scanner` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running JWT Scanner` phase.

---

### 5.13 Katana

**Step Name**: Running Katana
**Depends On**: DNSx
**Binary Required**: `katana`

#### Overview
The `Katana` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Katana` step, it spawns an isolated OS subprocess to execute `katana` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `DNSx` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Katana` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Katana` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Katana` phase.

---

### 5.14 Masscan

**Step Name**: Running Masscan
**Depends On**: WPScan
**Binary Required**: `masscan`

#### Overview
The `Masscan` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Masscan` step, it spawns an isolated OS subprocess to execute `masscan` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `WPScan` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Masscan` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Masscan` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Masscan` phase.

---

### 5.15 Nikto

**Step Name**: Running Nikto
**Depends On**: CMS Scanner
**Binary Required**: `nikto`

#### Overview
The `Nikto` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Nikto` step, it spawns an isolated OS subprocess to execute `nikto` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `CMS Scanner` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Nikto` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Nikto` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Nikto` phase.

---

### 5.16 Nmap

**Step Name**: Running Nmap
**Depends On**: Traceroute
**Binary Required**: `nmap`

#### Overview
The `Nmap` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Nmap` step, it spawns an isolated OS subprocess to execute `nmap` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Traceroute` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Nmap` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Nmap` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Nmap` phase.

---

### 5.17 Nuclei

**Step Name**: Running Nuclei
**Depends On**: Nikto
**Binary Required**: `nuclei`

#### Overview
The `Nuclei` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Nuclei` step, it spawns an isolated OS subprocess to execute `nuclei` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Nikto` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Nuclei` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Nuclei` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Nuclei` phase.

---

### 5.18 Open Redirect

**Step Name**: Running Open Redirect
**Depends On**: ffuf
**Binary Required**: ``

#### Overview
The `Open Redirect` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Open Redirect` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `ffuf` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Open Redirect` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Open Redirect` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Open Redirect` phase.

---

### 5.19 ParamSpider

**Step Name**: Running ParamSpider
**Depends On**: Masscan
**Binary Required**: `paramspider`

#### Overview
The `ParamSpider` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running ParamSpider` step, it spawns an isolated OS subprocess to execute `paramspider` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Masscan` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `ParamSpider` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `ParamSpider` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running ParamSpider` phase.

---

### 5.20 Robots.txt

**Step Name**: Running Robots.txt
**Depends On**: Security Headers
**Binary Required**: ``

#### Overview
The `Robots.txt` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Robots.txt` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Security Headers` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Robots.txt` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Robots.txt` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Robots.txt` phase.

---

### 5.21 SQLMap

**Step Name**: Running SQLMap
**Depends On**: Wapiti
**Binary Required**: `sqlmap`

#### Overview
The `SQLMap` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running SQLMap` step, it spawns an isolated OS subprocess to execute `sqlmap` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Wapiti` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `SQLMap` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `SQLMap` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running SQLMap` phase.

---

### 5.22 SSL

**Step Name**: Running SSL Scan
**Depends On**: Nmap
**Binary Required**: ``

#### Overview
The `SSL` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running SSL Scan` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Nmap` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `SSL` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `SSL` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running SSL Scan` phase.

---

### 5.23 Security Headers

**Step Name**: Running Security Headers
**Depends On**: SSL
**Binary Required**: ``

#### Overview
The `Security Headers` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Security Headers` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `SSL` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Security Headers` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Security Headers` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Security Headers` phase.

---

### 5.24 Shodan

**Step Name**: Running Shodan
**Depends On**: SQLMap
**Binary Required**: ``

#### Overview
The `Shodan` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Shodan` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `SQLMap` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Shodan` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Shodan` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Shodan` phase.

---

### 5.25 Subfinder

**Step Name**: Running Subfinder
**Depends On**: WhatWeb
**Binary Required**: `subfinder`

#### Overview
The `Subfinder` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Subfinder` step, it spawns an isolated OS subprocess to execute `subfinder` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `WhatWeb` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Subfinder` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Subfinder` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Subfinder` phase.

---

### 5.26 Tech Fingerprint

**Step Name**: Running Tech Fingerprint
**Depends On**: Open Redirect
**Binary Required**: ``

#### Overview
The `Tech Fingerprint` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Tech Fingerprint` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Open Redirect` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Tech Fingerprint` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Tech Fingerprint` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Tech Fingerprint` phase.

---

### 5.27 Traceroute

**Step Name**: Running Traceroute
**Depends On**: Wayback Machine
**Binary Required**: `traceroute`

#### Overview
The `Traceroute` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Traceroute` step, it spawns an isolated OS subprocess to execute `traceroute` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Wayback Machine` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Traceroute` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Traceroute` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Traceroute` phase.

---

### 5.28 WPScan

**Step Name**: Running WPScan
**Depends On**: JWT Scanner
**Binary Required**: `wpscan`

#### Overview
The `WPScan` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running WPScan` step, it spawns an isolated OS subprocess to execute `wpscan` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `JWT Scanner` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `WPScan` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `WPScan` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running WPScan` phase.

---

### 5.29 Wapiti

**Step Name**: Running Wapiti
**Depends On**: Tech Fingerprint
**Binary Required**: `wapiti`

#### Overview
The `Wapiti` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Wapiti` step, it spawns an isolated OS subprocess to execute `wapiti` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Tech Fingerprint` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Wapiti` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Wapiti` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Wapiti` phase.

---

### 5.30 Wayback Machine

**Step Name**: Running Wayback Machine
**Depends On**: Whois
**Binary Required**: ``

#### Overview
The `Wayback Machine` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Wayback Machine` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Whois` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Wayback Machine` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Wayback Machine` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Wayback Machine` phase.

---

### 5.31 WhatWeb

**Step Name**: Running WhatWeb
**Depends On**: HTTPx
**Binary Required**: `whatweb`

#### Overview
The `WhatWeb` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running WhatWeb` step, it spawns an isolated OS subprocess to execute `whatweb` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `HTTPx` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `WhatWeb` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `WhatWeb` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running WhatWeb` phase.

---

### 5.32 Whois

**Step Name**: Running Whois
**Depends On**: HackerTarget
**Binary Required**: `whois`

#### Overview
The `Whois` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running Whois` step, it spawns an isolated OS subprocess to execute `whois` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `HackerTarget` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `Whois` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `Whois` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running Whois` phase.

---

### 5.33 ZAP

**Step Name**: Running ZAP
**Depends On**: Cloud Enum
**Binary Required**: `zap`

#### Overview
The `ZAP` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running ZAP` step, it spawns an isolated OS subprocess to execute `zap` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Cloud Enum` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `ZAP` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `ZAP` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running ZAP` phase.

---

### 5.34 ffuf

**Step Name**: Running ffuf
**Depends On**: Nuclei
**Binary Required**: `ffuf`

#### Overview
The `ffuf` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running ffuf` step, it spawns an isolated OS subprocess to execute `ffuf` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Nuclei` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `ffuf` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `ffuf` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running ffuf` phase.

---

### 5.35 theHarvester

**Step Name**: Running theHarvester
**Depends On**: Subfinder
**Binary Required**: ``

#### Overview
The `theHarvester` module is a critical component of the V5.0 DAG pipeline. When the Orchestrator reaches the `Running theHarvester` step, it spawns an isolated OS subprocess to execute `` against the target domain. This tool operates seamlessly within the multiprocessing boundaries, ensuring that any segmentation faults or heavy memory usage do not impact the core SMP UI thread.

#### Technical Execution Details
- **Process Isolation**: Handled via `subprocess.Popen` with `os.setsid()` to guarantee orphan process cleanup.
- **DAG Resolution**: This tool will only execute after `Subfinder` has fully completed and successfully exited with a `0` status code.
- **Database Pipeline**: Once `theHarvester` completes, the raw STDOUT buffer is parsed by the plugin's generic JSON extractor. Findings are immediately piped into the `findings` SQLite table via the unified `_save_findings` wrapper.
- **Confidence Score**: Findings generated by this tool are assigned a baseline confidence score. The Correlation Engine later adjusts this based on historical precision.

#### Common Usage & Remediation
If `theHarvester` flags a vulnerability, it typically indicates a misconfiguration in the target's attack surface. Administrators should review the raw scan logs generated in `backup/active_scans.db` to see the exact payload that triggered the alert. Standard remediation involves updating dependencies, patching the affected service, or sanitizing the input vectors identified during the `Running theHarvester` phase.

---


---

## 6. Adding Custom Tools (Dynamic Registry)

In V4.0, adding a tool required modifying 6 different files and writing complex database schema migrations. 
In V5.0, this process is completely automated. 

To add a new tool (e.g., `MyHackerTool`), follow these exact steps:

### Step 1: Create the Scanner File
Create a new file at `scanners/myhackertool.py`:

```python
from scanners.core.registry import register_scanner
import subprocess

# The decorator automatically injects this tool into the DAG Orchestrator!
@register_scanner(
    name="MyHackerTool",
    step_name="Running My Hacker Tool",
    depends_on=["Nmap"],         # Wait for Nmap to finish first
    binary_name="myhackertool",  # The OS binary to check for
    needs_binary=True,           # Fail gracefully if binary isn't installed
    confidence=95                # Confidence score (0-100)
)
def run_myhackertool(target_url):
    try:
        # Run your tool
        res = subprocess.check_output(["myhackertool", "--target", target_url])
        
        # Return a list of findings. 
        # The engine will automatically pipe these into the database and PDF report!
        return [{
            "severity": "Critical",
            "title": "My Hacker Tool Found A Vuln!",
            "description": str(res)
        }]
    except Exception as e:
        return None
```

### Step 2: Restart SMP
That's it! When you restart SMP, the DAG Orchestrator will dynamically read the `scanners/` folder, find your `@register_scanner` decorator, and automatically inject it into the parallel execution pipeline. The results will seamlessly appear in the database and PDF reports without any extra code!

---

## 7. Top 20 Troubleshooting Guide

Here are the 20 most common issues and exactly how to fix them in code.

### 7.1 `ModuleNotFoundError: No module named 'PySide6'`
**Cause**: The virtual environment is not activated or packages aren't installed.
**Fix**: 
```bash
source venv/bin/activate
pip install PySide6
```

### 7.2 UI Freezes when clicking "Scan"
**Cause**: The `multiprocessing.Process` failed to spawn, causing the scanner to run on the main thread.
**Fix**: Ensure you are using `if __name__ == '__main__':` in `main.py` before calling `QApplication`.

### 7.3 UDP Port 5005 is already in use
**Cause**: An old SMP process crashed and left the socket open.
**Fix**: 
```bash
# Find and kill the zombie process
sudo lsof -i :5005
kill -9 <PID>
```

### 7.4 Database Lock Errors (`database is locked`)
**Cause**: Multiple processes tried to write to SQLite simultaneously without WAL mode.
**Fix**: Ensure WAL mode is active in `tools/db_manager.py`:
```python
conn.execute("PRAGMA journal_mode=WAL")
```

### 7.5 Custom Tool Not Appearing in Reports
**Cause**: The tool's python file doesn't end in `.py` or isn't in the `scanners/` folder. 
**Fix**: Ensure the file is `scanners/my_tool.py` and uses the `@register_scanner` decorator.

### 7.6 Subprocess Hitting Timeout Limits
**Cause**: A tool like Nmap is taking longer than 3 minutes to scan a large target.
**Fix**: The DAG engine has a built-in timeout limit. You can edit this in the `@register_scanner` config or inside `scanners/core/dag.py`.

### 7.7 MAC Address Randomization Fails
**Cause**: The `mac_changer.py` script requires `sudo` privileges. 
**Fix**: Run SMP with `sudo` if you want active anonymity, or disable the MAC changer in the GUI settings.

### 7.8 SMTP Alerts Not Sending
**Cause**: Gmail blocks standard password authentication.
**Fix**: You MUST generate a 16-character "App Password" from your Google Account settings and use that in SMP's SMTP Settings panel.

### 7.9 Forgot Master Password (Database Encrypted)
**Cause**: The AES-256 key is lost.
**Fix**: You cannot decrypt the database. You must perform a factory reset:
```bash
rm -rf database/*.db*
rm -rf config/auth.json
```

### 7.10 `Permission Denied` when running binaries
**Cause**: The downloaded security binaries (like `subfinder` or `httpx`) don't have execute permissions.
**Fix**:
```bash
chmod +x /usr/local/bin/subfinder
chmod +x /usr/local/bin/httpx
```

### 7.11 Target Status Stuck on "Scanning"
**Cause**: An unhandled exception in the DAG orchestrator caused the thread to exit without updating the status to Failed.
**Fix**: The platform has a Smart Resume feature. Simply restart SMP, and it will auto-resume the scan from the exact step it crashed on!

### 7.12 No vulnerabilities found when scanning localhost
**Cause**: Localhost is missing an active web server, or the firewall is dropping loopback packets.
**Fix**: Ensure Apache or Nginx is running, or scan a remote authorized test domain.

### 7.13 Cannot open PDF report
**Cause**: Missing fonts or the PDF engine crashed during generation.
**Fix**: Run `sudo apt install fonts-liberation` to install the required PDF fonts for ReportLab.

### 7.14 NVD Sync getting 403 Forbidden
**Cause**: Your IP is blacklisted by NIST for violating the 6-second rate limit.
**Fix**: The sync engine automatically implements exponential backoff. Wait 24 hours for the block to clear.

### 7.15 High CPU Usage during Idle
**Cause**: The legacy active-polling loop wasn't fully removed.
**Fix**: Ensure you are running V5.0 which uses the UDP Event Bus. Run `git pull` to get the latest V5 architecture.

### 7.16 `GLIBC_2.32 not found` running Nuclei
**Cause**: The Go binary was compiled on a newer OS than your current Ubuntu version.
**Fix**: Reinstall the tool via Go: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

### 7.17 ZAP Daemon Not Connecting
**Cause**: OWASP ZAP is enabled in settings but the Java daemon isn't running on port 8090.
**Fix**: Start ZAP in daemon mode: `zaproxy -daemon -port 8090`

### 7.18 PDF Hash Verification Fails
**Cause**: The PDF was modified after generation.
**Fix**: The PDF is digitally signed. If the hash doesn't match the filename, it has been tampered with. Do not trust the contents.

### 7.19 Out of Memory (OOM) Killer triggering
**Cause**: The DAG orchestrator spawned 35 tools on a machine with less than 2GB RAM.
**Fix**: Increase your swap file size:
```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### 7.20 Missing `sqlite3` driver
**Cause**: Python was compiled without sqlite3 support.
**Fix**: `sudo apt install libsqlite3-dev` and recompile Python, or use the system python packages.

---

## 8. Platform Roadmap (V5 to V8)

Here is where we are, and where the Security Management Platform is going over the next two years.

### ✅ V5.0 (Current Release)
- **The Architecture Overhaul**: Replaced sequential threading with a Directed Acyclic Graph (DAG) and Multiprocessing.
- **Zero-Latency IPC**: Eliminated aggressive polling with UDP event streams.
- **Dynamic Extensibility**: Added the `@register_scanner` plugin registry.

### 🚀 V6.0 (Planned Q4 2026)
- **Distributed Agents**: Moving from local multiprocessing to distributed network processing. SMP will become a central Coordinator, and you can deploy "Scanner Agents" on AWS, DigitalOcean, or Raspberry Pis to scan targets from multiple global IPs simultaneously.
- **Redis Integration**: Replacing SQLite with Redis for instantaneous message brokering across distributed agents.
- **WebSocket Dashboard**: Upgrading the desktop UI to use WebSockets for remote monitoring of scan agents.

### 🌌 V7.0 (Planned Q2 2027)
- **AI Remediation Engine**: Integration with local LLMs (Ollama + Llama-3). After a scan finishes, the AI will ingest the vulnerabilities and generate highly specific, context-aware remediation code patches for the PDF report.
- **Automated Exploitation**: Upgrading from passive vulnerability detection to active, safe exploitation (similar to Metasploit auto-pwn) to verify the impact of critical findings.
- **Zero-Day Predictive Analytics**: Using EPSS scores to predict which vulnerabilities will be exploited in the wild before a patch exists.

### 👑 V8.0 (Planned Q4 2027)
- **Enterprise Web Dashboard**: Transitioning the PySide6 desktop application into a fully-fledged Next.js web application for multi-user collaboration.
- **Continuous CI/CD Integration**: Webhook triggers that allow GitHub Actions or Jenkins to automatically trigger an SMP scan whenever a developer pushes new code. 
- **Kubernetes Native**: Helm charts to deploy the entire SMP architecture on Kubernetes clusters with auto-scaling scanner pods.

---
*End of Document. Godspeed, and happy hunting.*
