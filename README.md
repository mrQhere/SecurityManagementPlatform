<div align="center">

# 🛡️ Security Management Platform (SMP) v5.4

![Platform Overview](https://via.placeholder.com/1200x400.png?text=Security+Management+Platform+v5.4+Enterprise)

**An enterprise-grade, multi-process Security Management Platform utilizing a Directed Acyclic Graph (DAG) for high-performance concurrent vulnerability scanning.**

[![Version](https://img.shields.io/badge/version-5.4-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#) [![License](https://img.shields.io/badge/license-Proprietary-red.svg)](#) [![Architecture](https://img.shields.io/badge/architecture-DAG%20%7C%20MVC-success.svg)](#) [![Database](https://img.shields.io/badge/database-SQLite%20WAL%20AES--256-orange.svg)](#) [![Self--Healing](https://img.shields.io/badge/tools-Self--Healing%20Installer-brightgreen.svg)](#)

</div>

---

## 🚀 Welcome to V5.4: The Stability & Intelligence Update

Building on V5.4's concurrency engine, V5.4 focuses on robustness, professionalism, and security hardening. The DAG Orchestrator now has a **global 60-minute watchdog** that prevents hanging scanners from freezing the pipeline. Email alerts are fully redesigned with responsive HTML templates and dynamic metadata injection. Reports now carry proper company, tester, and QA reviewer metadata on the cover page. All hardcoded tool lists have been replaced with dynamic registry lookups — add a new scanner once and it automatically appears everywhere.

> [!NOTE]
> **First time here?** Jump straight to the [Quick Start](#-installation--quick-start) section. The entire setup is automated — one `bash setup.sh` and you're done. ☕

---

### 🔥 Key V5.4 Features & New Additions

| Feature | What it does |
|---|---|
| 🕸️ **DAG Orchestration** | Resolves dependency graphs, executes non-dependent scanners in fully parallel threads |
| ⏱️ **60-Minute Watchdog** | Hanged scanner threads auto-fail; the pipeline **never freezes** even if a tool locks up |
| 🔁 **Deferred Retry Queue** | Failed plugins get a second attempt at 1.5× timeout after the main DAG pass |
| 🧩 **Dynamic Plugin Registry** | Add a scanner with one `@register_scanner` decorator — splash screen, tests, and DAG update automatically |
| 🏗️ **Strict MVC Architecture** | `ui/views/` + `ui/controllers/` — business logic and UI rendering are perfectly isolated |
| 🔧 **Self-Healing Installer** | Missing binary? SMP installs it on-the-fly via `pip`, `apt`, or Go, then retries automatically |
| 🔄 **Redundancy Database** | All live scan data hot-mirrored; if `security.db` is gone, reports still generate from the mirror |
| 🔐 **AES-256 Encryption** | Every database byte encrypted at rest, including the redundancy DB |
| 📧 **Professional Email Alerts** | Responsive HTML templates with company, tester & QA metadata — Critical/High summaries only |
| 📊 **Cover Page Metadata** | Company Name, Lead Tester, and QA Reviewer injected dynamically into every PDF cover page |

---

## 🏗️ System Architecture Deep Dive

SMP V5.4 is built on a highly modular, decoupled architecture designed for scale and stability.

### 🖥️ The UI & Event Bus
The frontend is constructed using PySide6. The UI acts purely as a "dumb" terminal that listens for events. When a background scan completes a task, the Database Manager emits a JSON payload over a local UDP socket (`127.0.0.1:5005`). The UI catches this payload and triggers a Qt Signal, refreshing the screen instantly.

### 🧠 The DAG Execution Engine (V5.4 Enhanced)
The Orchestrator analyses tool dependencies, builds a Directed Acyclic Graph, and launches a thread pool to execute scanners concurrently. **New in V5.4**: each plugin thread has a 60-minute watchdog — if any scanner hangs beyond that, it is marked `failed` and the pipeline continues without losing all subsequent dependent steps.

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

## 🛠️ Integrated Security Modules

SMP acts as a centralized orchestrator for the world's best open-source security tools. The DAG Engine dynamically maps out their dependencies and executes them concurrently for maximum speed. The tool list grows automatically as new scanners are registered.

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

For a deep dive into the platform's inner workings, troubleshooting guides, the self-healing installer, the redundancy database lifecycle, and instructions on how to add your own custom tools using the new Plugin Registry, please consult the **[V5.4 USER GUIDE](./USER_GUIDE.md)**.

The User Guide contains **detailed technical documentation** covering every aspect of the platform, with copy-paste code examples, beautiful diagrams, and step-by-step troubleshooting guides.

---

## ⚖️ Legal & Copyright

> **CRITICAL NOTICE**: This software is highly proprietary.
> You are explicitly forbidden from modifying, refactoring, reverse-engineering, or redistributing this code without human consent.
> By using this software, you accept sole legal responsibility for all activities performed with it. Ensure you have explicit written authorization before scanning any target.

*Security Management Platform (SMP) © Authorised Personnel Only. All Rights Reserved.*


## Changelog — V5.4 Stability & Intelligence Update

> This release resolves every architectural flaw documented in the V5.4 audit. For the full technical details, see [USER_GUIDE.md Part 8](./USER_GUIDE.md).

### 🔒 Security & Reliability
| Change | Details |
|--------|---------|
| SQLCipher Graceful Fallback | Falls back to sqlite3 with UI warning if SQLCipher unavailable |
| Tool SHA-256 Checksums | All binary downloads verified before execution |
| Redundancy DB Encryption | SQLCipher PRAGMA now on `redundancy.db` too |
| WPScan Docker Fallback | Docker used when Ruby/gem missing |
| Masscan Rootless Setup | `setcap cap_net_raw+eip` in `setup.sh` |

### 🧠 DAG Engine & Robustness
| Change | Details |
|--------|---------|
| 60-Minute Watchdog | Hanging plugins auto-fail; pipeline never freezes |
| Deferred Retry Queue | Failed DAG steps retried at 1.5× timeout after main pass |
| Dynamic Plugin Registry | `@register_scanner` auto-populates all consumers |
| Rate Limiting (Jitter) | Prevents WAF bans during aggressive parallel scans |
| Universal Proxy Env | All subprocesses inherit `HTTP_PROXY`/`HTTPS_PROXY` |
| Wapiti Adaptive Timeout | Scales with endpoint count, no longer fixed at 600s |

### 📊 Reports & Email
| Change | Details |
|--------|---------|
| Professional Email Templates | Responsive HTML with metadata card (Company, Tester, QA, Max Severity) |
| Cover Page Metadata | Company Name & QA Reviewer injected via SQL JOIN on `targets` table |
| Report Template Config | Layout constants moved to `config/report_template.json` |

### 🖥️ UI & Settings
| Change | Details |
|--------|---------|
| QA Reviewer Field | New globally configurable field in Settings Dashboard |
| Dynamic Splash Screen | Tool count auto-derived from registry — always accurate |
| Splitter Persistence | Panel sizes saved/restored across sessions |
| Target Soft-Delete | 30-day recovery window instead of permanent deletion |
| API Keys & Proxies UI | Shodan, Censys, GitHub tokens, and HTTP proxy settings |

### 🧪 Testing & CI/CD
| Change | Details |
|--------|---------|
| Resilient Test Suite | `test_10` patches via `scanners.scan_runner` namespace — matches GenericPlugin resolution |
| Dynamic Test Discovery | All tests iterate live registry, not hardcoded lists |
| GitHub Actions CI | `verify_smp.py` runs on every push and PR |
| Weekly Nuclei Updates | `nuclei -update-templates` in scheduler |
| Log Rotation | `RotatingFileHandler` (10MB, 5 backups) enforced |

### 🧹 Code Quality
| Change | Details |
|--------|---------|
| Proprietary Header Cleanup | Duplicate headers removed from 29+ scanner files |
| Cloud Enum Keywords | Custom per-target keyword lists |
| API / Headless Mode | `--api` flag for programmatic scan triggering via FastAPI |

