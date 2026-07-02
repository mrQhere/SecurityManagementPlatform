<div align="center">

# 🛡️ Security Management Platform (SMP) v5.2

![Platform Overview](https://via.placeholder.com/1200x400.png?text=Security+Management+Platform+v5.2+Enterprise)

**An enterprise-grade, multi-process Security Management Platform utilizing a Directed Acyclic Graph (DAG) for high-performance concurrent vulnerability scanning.**

[![Version](https://img.shields.io/badge/version-5.2-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#) [![License](https://img.shields.io/badge/license-Proprietary-red.svg)](#) [![Architecture](https://img.shields.io/badge/architecture-DAG%20%7C%20MVC-success.svg)](#) [![Database](https://img.shields.io/badge/database-SQLite%20WAL%20AES--256-orange.svg)](#) [![Self--Healing](https://img.shields.io/badge/tools-Self--Healing%20Installer-brightgreen.svg)](#)

</div>

---

## 🚀 Welcome to V5.2: The Concurrency Update

The Security Management Platform has been entirely re-engineered from the ground up. Moving away from legacy sequential scanning, V5.2 introduces true OS-level multiprocessing powered by a smart **Directed Acyclic Graph (DAG)**.

By calculating tool dependencies in real-time, SMP can now run up to **35 industry-standard security tools concurrently** across isolated processes, completely eliminating UI freezing and reducing scan times by **up to 80%**.

> [!NOTE]
> **First time here?** Jump straight to the [Quick Start](#-installation--quick-start) section. The entire setup is automated — one `bash setup.sh` and you're done. ☕

---

### 🔥 Key V5.2 Features

| Feature | What it does |
|---|---|
| 🕸️ **DAG Orchestration** | Resolves dependency graphs, executes non-dependent scanners in fully parallel Python subprocesses |
| ⚡ **Zero-Latency UDP IPC** | Active-polling eradicated. UI updates via `127.0.0.1:5005` — 98% less idle CPU & Disk I/O |
| 🧩 **Dynamic Plugin Registry** | Add new scanners with a single `@register_scanner` decorator — zero core modifications |
| 🏛️ **Strict MVC Architecture** | `ui/views/` + `ui/controllers/` — business logic and UI rendering are perfectly isolated |
| 🔧 **Self-Healing Tool Installer** | Missing binary? SMP auto-installs it at runtime and retries the scan step automatically |
| 🔄 **Redundancy Database** | All live scan data is hot-mirrored to a backup DB. If main DB is gone, reports still generate |
| 🔐 **AES-256 Encryption** | Every database byte is symmetrically encrypted at rest with your Master Password |

---

## 🏗️ System Architecture Deep Dive

SMP V5.2 is built on a highly modular, decoupled architecture designed for scale and stability. The system is split into distinct functional domains to ensure fault tolerance.

### 🖥️ The UI & Event Bus
The frontend is constructed using PySide6. However, unlike traditional desktop applications, the UI acts purely as a "dumb" terminal that listens for events. When a background scan completes a task, the Database Manager emits a JSON payload over a local UDP socket (`127.0.0.1:5005`). The UI catches this payload and triggers a Qt Signal, refreshing the screen instantly.

### 🧠 The DAG Execution Engine
The true power of SMP lies in its Orchestrator. When a scan starts, a new `multiprocessing.Process` is spawned to bypass Python's Global Interpreter Lock (GIL). Inside this process, the Orchestrator analyzes the dependencies of 35 security tools, builds a Directed Acyclic Graph, and launches a ThreadPool to execute them concurrently. If one tool crashes (e.g. out of memory), the Orchestrator safely catches the SIGSEGV and continues executing the remaining branches of the graph.

### 🔧 Self-Healing at Runtime

> [!TIP]
> **SMP heals itself!** If a scanner binary is missing from your system when a scan starts, SMP doesn't just give up — it automatically installs the tool on-the-fly using `pip`, `apt`, or Go, then retries the scan step. No babysitting required.

The self-healing loop works like this:

```
🔍 Binary Missing?
      ↓
🔧 install_single_tool("nmap")  ← looks up TOOLS registry
      ↓
✅ Installed?  →  Retry scan step  →  Success!
❌ Failed?     →  Log & skip step gracefully
```

---

## 🗄️ Database Architecture

SMP uses **three purpose-built SQLite databases**, each with a specific role in the data lifecycle. Never touch these files with external tools while the app is running!

> [!IMPORTANT]
> All databases are **AES-256 encrypted** at rest using your Master Password. They are stored under `database/`. Never lose your Master Password — there is no recovery mechanism.

| Database | File | Purpose | Lifecycle |
|---|---|---|---|
| 🏦 **Main DB** | `security.db` | Primary store for all targets, scans, findings, technologies, risk scores, and raw outputs | Permanent — survives reboots |
| 🔄 **Redundancy DB** | `redundancy.db` | Hot-mirror of the *active scan only* — all data written here in parallel during scanning. If `security.db` is missing or corrupt, reports read from here instead | **Wiped after every scan** completes |
| 🧬 **CVE Intelligence DB** | `cve.db` | 300,000+ NVD CVE entries. Read-only during scans. Synced incrementally by the background scheduler | Permanent — updated nightly |

### 🔄 How the Redundancy System Works

```
scan starts
     │
     ├──► write findings ──────────────► security.db  ✅ (primary)
     │                     └──────────► redundancy.db 🔄 (mirror)
     │
     ├──► write technologies ──────────► security.db  ✅
     │                     └──────────► redundancy.db 🔄
     │
     ├──► write risk scores ───────────► security.db  ✅
     │                     └──────────► redundancy.db 🔄
     │
     └── scan complete:
             ├── generate report ◄──── (read security.db OR redundancy.db if primary is gone)
             └── clear redundancy.db  ← 🧹 wiped clean, ready for next scan
```

> [!WARNING]
> `redundancy.db` is automatically cleared after every scan. It is **not** a long-term backup — it is a live safety net for the *current scan only*. For long-term backups, use the encrypted ZIP exports from the Dashboard.

---

## 💻 Installation & Quick Start

### 1. System Requirements
- **OS**: Linux (Ubuntu 22.04+ recommended)
- **RAM**: 8GB+ recommended for full parallel scanning
- **Dependencies**: Everything is handled automatically by `setup.sh`

### 2. Automated Zero-Friction Setup
```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the fully automated setup script
bash setup.sh
```

### 3. Running Your First Scan
Once the setup is complete, run the platform:
```bash
bash run.sh
```

1. On first boot, create your **Master Password** (AES-256 encrypted — never forgotten, never recovered).
2. Navigate to the **Targets** tab and enter an authorized target URL.
3. Click **Scan**. Watch the DAG Orchestrator parallelize the attack surface mapping in real-time!
4. If a tool binary is missing, **SMP self-heals** — it installs it automatically and retries the step. 🔧
5. Click **Report** to generate a comprehensive, executive-ready VAPT PDF.

> [!CAUTION]
> **LEGAL NOTICE**: SMP is a powerful battering ram. Using it on systems you do not own or have explicit written authorization to test is **highly illegal**. By launching a scan, you accept full legal responsibility for all activity. Stay safe, stay legal. ⚖️

---

## 🛠️ 35 Integrated Security Modules

SMP acts as a centralized orchestrator for 35 of the world's best open-source security tools. The DAG Engine dynamically maps out their dependencies and executes them concurrently for maximum speed.

| Category | Tools |
|---|---|
| 🔭 **Recon & OSINT** | HTTPx, Subfinder, CRT.sh, HackerTarget, Whois, Wayback Machine, Shodan, theHarvester |
| 🌐 **Network** | Nmap, Traceroute, Masscan, DNSx |
| 🔐 **SSL/TLS** | SSL Scanner, Security Headers |
| 🕷️ **Web Scanning** | Nikto, Nuclei, Wapiti, WhatWeb, Robots.txt, CORS Scanner, CMS Scanner |
| 💥 **Exploitation & Fuzzing** | SQLMap, Dalfox, ffuf, Commix, Open Redirect, Arjun, Katana, ParamSpider |
| 🔑 **Auth & Secrets** | JWT Scanner, WPScan, Gitleaks |
| ☁️ **Cloud & Enterprise** | Cloud Enum, OWASP ZAP |
| 🧠 **Intelligence** | CVE Correlation, MITRE ATT&CK Mapping, Risk Scoring |

---

## 📖 Comprehensive Documentation

For a deep dive into the platform's inner workings, troubleshooting guides, the self-healing installer, the redundancy database lifecycle, and instructions on how to add your own custom tools using the new Plugin Registry, please consult the **[V5.2 USER GUIDE](./USER_GUIDE.md)**.

The User Guide contains **detailed technical documentation** covering every aspect of the platform, with copy-paste code examples, beautiful diagrams, and step-by-step troubleshooting guides.

---

## ⚖️ Legal & Copyright

> **CRITICAL NOTICE**: This software is highly proprietary.
> You are explicitly forbidden from modifying, refactoring, reverse-engineering, or redistributing this code without human consent.
> By using this software, you accept sole legal responsibility for all activities performed with it. Ensure you have explicit written authorization before scanning any target.

*Security Management Platform (SMP) © Authorised Personnel Only. All Rights Reserved.*
