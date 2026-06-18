<div align="center">

<h1>🛡️ Security Management Platform</h1>
<p><strong>A professional, cross-platform desktop security monitoring application built with PySide6</strong></p>

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![PySide6](https://img.shields.io/badge/GUI-PySide6_Qt6-41cd52?logo=qt)](https://doc.qt.io/qtforpython/)
[![Platform](https://img.shields.io/badge/Platform-Linux_|_Windows-lightgrey)](https://github.com)
[![License](https://img.shields.io/badge/License-Proprietary-red)](./way.md)

</div>

---

## Overview

**Security Management Platform (SMP)** continuously monitors a list of target URLs by running a sequential multi-tool security scan pipeline. All results are stored in a local SQLite database, professional HTML and PDF reports are generated automatically, and SMTP email alerts are dispatched on newly discovered vulnerabilities.

> **⚠️ Authorised Use Only** — This software is designed for authorised security assessments on systems you own or have explicit written permission to test. Unauthorised scanning is illegal.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **15-Tool Scan Pipeline** | Sequential execution of Traceroute, Nmap, SSL, Nikto, Nuclei, ffuf, Wapiti, SQLMap, and more |
| 🗄️ **240,000+ CVE Database** | Full NVD, CISA KEV (1,600+), and GitHub Advisory sync — continuously updated |
| 📄 **15-Section Reports** | Professional HTML + PDF reports covering ports, directories, vulnerabilities, CVE matches, risk scores |
| 📧 **SMTP Alert Engine** | Automatic email alerts on Critical/High findings and new CVE matches |
| 📊 **Risk Scoring** | 0–100 risk score calculated from all findings with severity breakdown |
| 🖥️ **Modern Dark GUI** | PySide6 Qt6 dashboard with live scan progress, threat intel browser, and settings management |
| ⏰ **Scheduled Automation** | Daily scans and hourly intel syncs via APScheduler |

---

## 🚀 Quick Start

### Linux / Ubuntu

```bash
# Clone the repository
git clone https://github.com/your-username/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# One-time setup (fully automatic — downloads Go, installs all tools)
bash setup.sh

# Configure your settings (see Configuration section below)
cp config/settings.example.json config/settings.json
# Edit config/settings.json with your SMTP credentials and preferences

# Launch the application
bash run.sh
```

### Windows

```bat
:: Run PowerShell or CMD as Administrator
setup.ps1      :: or: setup.bat
run.bat
```

> **Note:** `setup.sh` is fully automatic. It downloads Go, installs all Python packages, system tools (nmap, nikto, whatweb), and pre-built binaries for nuclei/subfinder/httpx/ffuf. No manual steps required.

---

## 📋 Requirements

### System
- Ubuntu Linux 20.04+ or Windows 10/11
- Python 3.11+
- Internet access (for CVE database sync and Go tool downloads)

### Python Packages (auto-installed by setup.sh)
```
PySide6          APScheduler>=3.10.0    requests>=2.31.0
reportlab>=4.0.0 sslyze>=5.2.0         sqlmap
wapiti3          python-owasp-zap-v2.4
```

### External Tools (auto-installed by setup.sh on Linux)
| Tool | Method | Purpose |
|------|--------|---------|
| nmap | apt | Port scanning |
| nikto | apt | Web vulnerability scanning |
| whatweb | apt | Technology fingerprinting |
| traceroute | apt | Network path discovery |
| nuclei | Go / pre-built binary | Template-based CVE scanning |
| subfinder | Go / pre-built binary | Subdomain discovery |
| httpx | Go / pre-built binary | HTTP probing |
| ffuf | Go / pre-built binary | Directory fuzzing |
| sqlmap | pip | SQL injection detection |
| wapiti3 | pip | Web app vulnerability scanning |

---

## ⚙️ Configuration

Copy the example settings file and fill in your values:

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
    "tester_name": "Your Name",
    "scan_schedule_hour": 2,
    "intel_sync_interval_hours": 1
}
```

> **Gmail users:** `smtp_pass` must be a **16-character App Password**, not your regular Gmail password.
> Generate one at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) after enabling 2-Step Verification.

---

## 🔄 Scan Pipeline

All tools run **sequentially** (one at a time) to avoid IDS triggers and target rate-limiting:

```
Traceroute → HTTPx → WhatWeb → Subfinder → Nmap →
SSL Scan → Nikto → Nuclei → ffuf → Wapiti → SQLMap →
CVE Correlator → Risk Scorer → Report Generator → SMTP Alerts
```

---

## 📄 Report Structure (15 Sections)

Generated automatically as both HTML (dark theme) and PDF after every scan:

1. Cover Page with live metrics
2. Table of Contents
3. Executive Summary (severity breakdown)
4. Scope & Authorization Statement
5. Scan Methodology & Tool Pipeline
6. Network Reconnaissance (Traceroute)
7. Open Ports & Services (Nmap)
8. SSL/TLS Certificate Analysis
9. Technology Stack Identified
10. Directory & File Discovery (ffuf)
11. Web Vulnerability Findings (Nuclei / Nikto)
12. Injection & Active Tests (Wapiti / SQLMap)
13. CVE Correlation & Threat Intelligence Matches
14. Risk Score & Scoring Breakdown
15. Security Recommendations
16. References & Citations (NVD, CISA, GitHub)
17. Historical Comparison & Timeline

---

## 🗄️ Threat Intelligence

The platform maintains a local SQLite database continuously synced from:

| Source | Volume | Sync Mode |
|--------|--------|-----------|
| **NVD (NIST)** | 240,000+ CVEs | Full paginated on first run; 30-day incremental after |
| **CISA KEV** | ~1,600 entries | Full catalog every sync |
| **GitHub Advisories** | Thousands | All pages via Link-header pagination |
| **EPSS** | Per-CVE scores | Enriches existing CVE records |

> **First sync note:** NVD full download takes 20–40 minutes due to the API's mandatory 6-second inter-request delay. Subsequent syncs (30-day window) complete in seconds.

---

## 🗂️ Project Structure

```
SecurityManagementPlatform/
├── main.py                    # Entry point
├── setup.sh / setup.bat       # One-click installers
├── run.sh / run.bat           # Launchers
├── requirements.txt           # Python dependencies
├── way.md                     # Master reference documentation
├── handoff.md                 # Developer handoff guide
│
├── config/
│   ├── settings.example.json  # ← Copy to settings.json and fill in your details
│   └── settings.json          # Runtime config (gitignored — never commit)
│
├── scanners/                  # Individual tool wrapper modules
├── intelligence/              # CVE feed sync modules
├── tools/                     # Core utilities (DB, alerts, reports, scheduler)
└── ui/                        # PySide6 GUI dashboard
```

---

## 🔐 Security & Privacy

- `config/settings.json` is in `.gitignore` — your credentials **never** leave your machine
- The SQLite database (`database/security.db`) is gitignored — scan data is local-only
- All logs and generated reports are gitignored
- No telemetry, no analytics, no external data sharing

---

## ⚖️ Legal Notice

> This software is **proprietary**. All rights reserved.
>
> - Authorised use only — scan only systems you own or have explicit written permission to test
> - Unauthorised security testing is illegal in most jurisdictions
> - The owner accepts no liability for misuse, damage, or legal consequences arising from use of this software
> - All source files contain a proprietary notice header — see `way.md` for full terms

---

## 📚 References

- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD — National Vulnerability Database](https://nvd.nist.gov)
- [GitHub Security Advisories](https://github.com/advisories)
- [OWASP Top 10](https://owasp.org/Top10)
- [ProjectDiscovery Nuclei](https://nuclei.projectdiscovery.io)
