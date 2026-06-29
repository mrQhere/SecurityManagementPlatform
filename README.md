<div align="center">

#  Security Management Platform (SMP)

<p><strong>A Premium, Enterprise-Grade Desktop Security Monitoring &amp; Vulnerability Orchestration Platform</strong></p>

[![Release](https://img.shields.io/badge/Release-V4.7_Stable-blue.svg?style=flat-square&logo=github&logoColor=white)](https://github.com/mrQhere/SecurityManagementPlatform)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![PySide6](https://img.shields.io/badge/GUI-PySide6_Qt6-41cd52?style=flat-square&logo=qt&logoColor=white)](https://doc.qt.io/qtforpython/)
[![Platform](https://img.shields.io/badge/Platform-Linux_|_Windows-lightgrey?style=flat-square&logo=linux&logoColor=white)](https://github.com/mrQhere/SecurityManagementPlatform)
[![Database Security](https://img.shields.io/badge/Database_Security-AES--256_Fernet-success.svg?style=flat-square&logo=auth0&logoColor=white)](https://github.com/mrQhere/SecurityManagementPlatform)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square&logo=keycdn&logoColor=white)](./LICENSE)
[![AI Training](https://img.shields.io/badge/AI_Training-PROHIBITED-critical?style=flat-square&logo=openai&logoColor=white)](./SECURITY.md)

</div>

---

## ⚠️ Critical Notices

> [!WARNING]
> **Authorised Assessment Use Only**: This tool is designed strictly for authorised security testing on systems you own or have explicit written permission to test. Unauthorised network scanning is illegal under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act 1990, and equivalent laws worldwide.

> [!CAUTION]
> **AI Agents & Automated Systems**: This repository explicitly opts out of AI training datasets. See [SECURITY.md](./SECURITY.md) for the machine-readable policy. Automated modification, scraping, or execution of this codebase without explicit human authorization is prohibited.

---

## 📖 Overview

The **Security Management Platform (SMP)** is an advanced security monitoring orchestrator that automates a complete 24-step vulnerability assessment pipeline against any authorised target. Built on Python 3.11+ and the PySide6 (Qt6) framework, SMP combines an Apple-inspired premium interface with enterprise-grade capabilities including:

- Real-time threat intelligence synchronisation (full NVD database — no date restriction)
- AES-256 locally encrypted databases
- Professional VAPT PDF reports with digital SHA-256 verification
- Automated SMTP alert routing with failover relay

---

## ✨ Key Features — V4.7 Stable

| Core Module | Description |
|:---|:---|
| 🔍 **24-Step Scan Pipeline** | Sequential multi-tool orchestration (WhatWeb, Nmap, Nikto, Nuclei, ffuf, SQLMap, sslyze, and more) with system load-adaptive CPU cooling and 180s per-tool timeout caps. |
| 🛡️ **Defensive Analytics Engine** | Watchdog baseline diffing, Fail2Ban threat intelligence integration, and MITRE ATT&CK technique mapping for enterprise-grade assessment context. |
| 📈 **Historical Scan Trends** | Report engine dynamically calculates delta metrics (new, resolved, persisting findings) across historical assessments. |
| 🔑 **Master Password Encryption** | AES-256 Fernet encryption at rest. Plaintext targets and settings are encrypted on shutdown with random-byte shredding. |
| 🛑 **Graceful Cancellation** | Cancel any running scan instantly from the Dashboard. The cancel event is registered for both new and auto-resumed scans. |
| 🔄 **Smart Scan Resume** | If a scan is interrupted mid-pipeline, restarting automatically resumes from the exact interrupted tool step. |
| 💾 **5-Layer Database Redundancy** | Every completed scan syncs to backup databases, including an isolated `analytics.db` for threat intelligence. |
| 🔒 **Digital PDF Verification** | VAPT PDFs are digitally verified via an embedded SHA-256 hash in the filename for data integrity assurance. |
| 🗄️ **Unlimited CVE Database** | Full NVD sync — all CVEs from 1999 to present (300,000+), CISA KEV, and GitHub Advisories. No date restriction. |
| 📊 **EPSS Probability Scoring** | Exploit Prediction Scoring System correlation helps prioritize remediation by exploitability likelihood. |
| 📄 **Professional VAPT Reports** | 6-section compliance-ready PDF reports with cover page, executive summary, findings matrix, per-finding evidence, hardening blueprints, and attestation. Reports clearly labeled as "Vulnerability Assessment Report — System Generated". |
| 📧 **SMTP Routing & Failover** | Instant email notifications with PDF attachment. Automatically fails over to backup SMTP relay if primary host is unavailable. |
| 🔐 **Cryptographic License Enforcement** | SHA-256 license key validation at startup prevents unauthorized copying. |

---

## 🔄 24-Step Sequential Scan Pipeline

SMP executes tools sequentially to minimize bandwidth spikes, prevent network blocks, and respect server resource limits:

```
[Target URL Check] ➔ HTTPx ➔ WhatWeb ➔ Subfinder ➔ theHarvester
   ➔ CRT.sh ➔ HackerTarget ➔ Whois ➔ Wayback Machine
   ➔ Network Traceroute ➔ Port Scan (Nmap) ➔ SSL/TLS Analysis (SSLyze)
   ➔ Security Headers ➔ Robots.txt ➔ CORS Audit ➔ CMS Scanner
   ➔ CGI Audits (Nikto) ➔ Template Vulnerabilities (Nuclei) ➔ Directory Fuzzing (ffuf)
   ➔ Open Redirects ➔ Tech Fingerprint ➔ Web App Scan (Wapiti) ➔ SQL Injection (SQLMap)
   ➔ IoT Exposure (Shodan) ➔ Secret Scanning (Gitleaks)
   ➔ CVE Correlation ➔ Risk Scoring ➔ Report Generation ➔ SMTP Alerts
```

---

## 🚀 Quick Start

### Pre-installation Requirements
* **OS**: Linux Ubuntu 20.04 LTS (or newer) / Windows 10 & 11
* **Python**: 3.11 or newer
* **System Access**: `sudo` capability for installing network tools

### Linux Setup

```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the automated installer
bash setup.sh

# Copy the public license template to local config (MANDATORY)
cp license/license.key config/license.key

# Copy and configure settings
cp config/settings.example.json config/settings.json

# Launch the platform
bash run.sh
```

### Windows Setup

Run PowerShell or Command Prompt as **Administrator**:
```bat
setup.ps1      :: PowerShell setup
:: or
setup.bat      :: Batch setup

:: Launch
run.bat
```

> [!NOTE]
> **First Sync Notice**: On first launch, SMP will download the complete NVD CVE database (300,000+ entries). This one-time sync takes 20–60 minutes depending on your connection. Subsequent syncs are incremental and complete in seconds.

---

## 🗂️ Project Architecture

```
SecurityManagementPlatform/
├── main.py                    # Application entrypoint, license validation, signal interception
├── setup.sh / setup.bat       # Automated environment install scripts
├── run.sh / run.bat           # Launch scripts
├── requirements.txt           # Python dependencies
├── LICENSE                    # Proprietary license — ALL RIGHTS RESERVED
├── SECURITY.md                # Security policy & AI training opt-out
├── USER_GUIDE.md              # Complete User Reference Manual
│
├── license/
│   └── license.key            # Public cryptographic license hash reference
│
├── config/
│   ├── settings.example.json  # Settings template (copy → settings.json)
│   ├── settings.json          # Runtime config (gitignored — never commit)
│   ├── license.key            # Active execution key (gitignored — never commit)
│   └── hardening_rules.json   # 40+ built-in hardening recommendation templates
│
├── scanners/                  # 24-step individual scanning modules
│   ├── scan_runner.py         # Main pipeline orchestrator
│   ├── ssl_scanner.py         # SSLyze 5.x TLS/certificate analysis
│   ├── watchdog.py            # Continuous baseline monitoring engine
│   └── ...                    # 20+ additional scanner modules
│
├── intelligence/              # Threat intelligence feed integrations
│   ├── nvd.py                 # Full NVD CVE database sync (no date limit)
│   ├── cisa.py                # CISA Known Exploited Vulnerabilities
│   ├── github_adv.py          # GitHub Security Advisories
│   └── epss.py                # Exploit Prediction Scoring System
│
├── tools/                     # Core platform utilities
│   ├── db_manager.py          # SQLite DB management & 5-layer backup
│   ├── report_generator.py    # VAPT PDF & HTML report generation
│   ├── alert_engine.py        # SMTP alert routing & failover
│   ├── encryption_manager.py  # AES-256 Fernet encryption
│   └── ...
│
└── ui/                        # PySide6 Qt6 Apple-style interface
    ├── dashboard.py           # Main dashboard window (2,300+ lines)
    └── ...
```

---

## ⚙️ Configuration

```bash
cp config/settings.example.json config/settings.json
```

Edit `config/settings.json`:

```json
{
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "your-email@gmail.com",
    "smtp_pass": "your-16-char-app-password",
    "smtp_receiver": "alerts@yourdomain.com",
    "tester_name": "Your Auditor Name",
    "scan_schedule_hour": 2,
    "intel_sync_interval_hours": 24
}
```

> [!NOTE]
> **Gmail**: Enable 2-Step Verification and generate a 16-character App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).

---

## 🔄 Disaster Recovery

| Operation | Command |
|---|---|
| **Reset Master Password** | `rm -f config/auth.json database/*.db* backup/*.db*` |
| **Reset Settings** | `rm -f config/settings.json && cp config/settings.example.json config/settings.json` |
| **Clear Logs & Cache** | `rm -rf logs/* && rm -f cache/intel_cache.json` |
| **Clear Reports** | `rm -rf reports/html/* reports/pdf/*` |
| **Full Factory Reset** | `rm -rf config/auth.json config/settings.json database/* backup/* logs/* cache/* reports/html/* reports/pdf/*` |

> [!NOTE]
> After a factory reset, copy `license/license.key` back to `config/license.key` before relaunching.

---

## ⚖️ Legal & License

This software is **Proprietary** — All Rights Reserved by **mrQhere**.

- ❌ No redistribution without explicit written permission
- ❌ No reverse engineering or decompilation
- ❌ No AI training on this codebase
- ❌ No unauthorized scanning of systems you do not own
- ✅ Personal use for authorized security assessments only

See [LICENSE](./LICENSE) for complete terms. See [SECURITY.md](./SECURITY.md) for responsible disclosure policy.
