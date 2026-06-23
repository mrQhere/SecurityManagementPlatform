<div align="center">

# 🛡️ Security Management Platform (SMP)

<p><strong>A Premium, Enterprise-Grade Desktop Security Monitoring & Vulnerability Orchestration Platform</strong></p>

[![Release](https://img.shields.io/badge/Release-V3.4_Stable-blue.svg?style=flat-square&logo=github&logoColor=white)](https://github.com/mrQhere/SecurityManagementPlatform)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![PySide6](https://img.shields.io/badge/GUI-PySide6_Qt6-41cd52?style=flat-square&logo=qt&logoColor=white)](https://doc.qt.io/qtforpython/)
[![Platform](https://img.shields.io/badge/Platform-Linux_|_Windows-lightgrey?style=flat-square&logo=linux&logoColor=white)](https://github.com/mrQhere/SecurityManagementPlatform)
[![Database Security](https://img.shields.io/badge/Database_Security-AES--256_Fernet-success.svg?style=flat-square&logo=auth0&logoColor=white)](https://github.com/mrQhere/SecurityManagementPlatform)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square&logo=keycdn&logoColor=white)](./license/license.key)

</div>

---

## 📖 Overview

The **Security Management Platform (SMP)** is an advanced security monitoring orchestrator designed to run automated, sequential vulnerability scan pipelines on targeted systems. Built on Python 3.11 and the PySide6 (Qt6) framework, it incorporates a responsive Apple-style interface, automatic threat intelligence feeds, locally encrypted databases, and professional reporting metrics.

> [!WARNING]
> **Authorised Assessment Use Only**: This tool is designed strictly for authorised security testing on systems you own or have explicit written permission to test. Unauthorised network scanning is illegal.

---

## ✨ Key Features (V3.4 Stable)

| Core Module | Description |
|:---|:---|
| 🔍 **22-Step Scan Pipeline** | Run sequential multi-tool scans (WhatWeb, Nmap, Nikto, Nuclei, ffuf, SQLMap, etc.) with rate-limiting and system CPU cooldown protection. |
| 🔑 **Master Password Encryption** | Secure local storage with AES-256 Fernet disk encryption. Plaintext targets and settings are encrypted on shutdown and wiped via random-byte shredding. |
| 🛡️ **Full Scan Capability** | Secure sudo credential handling to run elevated scanner modules (Nmap OS detection and ICMP Traceroute) via thread-safe input redirection. |
| ⏱️ **Resilient Queue & Capping** | Dynamic 180s scanner timeouts prevent stalls. Slow scanner steps are deferred to a Retry Queue and executed with scaled limits. |
| 💾 **4-Layer Database Redundancy** | Every completed scan instantly syncs to 4 redundant backup databases including a 1:1 `full_backup.db` mirror allowing complete disaster recovery. |
| 🗄️ **240k+ Vulnerability DB** | Real-time local synchronisation with NVD (NIST), CISA Known Exploited Vulnerabilities (KEV), and GitHub Advisories. |
| 📊 **Exploit Probability Scoring** | EPSS database correlation provides exploit probability metrics to help prioritize remediation. |
| 📄 **15-Section Reports** | Automated generation of structured PDF and HTML reports compiling open ports, vulnerabilities, TLS profiles, and recommendations. |
| 📧 **SMTP Routing & Failover** | Instant email notifications for technology changes and critical findings. Automatically routes alerts to a backup SMTP relay if the primary host fails. |

---

## 🔄 Sequential Scan Pipeline Flow

SMP executes scanning tools sequentially to minimize bandwidth spikes, prevent network blocks, and respect server resource limits:

```
[Target URL Check] ➔ HTTPx ➔ WhatWeb ➔ Subdomain Discovery (Subfinder / CRT.sh) 
   ➔ DNS Recon (HackerTarget) ➔ Whois ➔ Wayback URL Mapping ➔ Network Traceroute 
   ➔ Port Scan (Nmap) ➔ SSL/TLS Cryptography Analysis (SSLyze) ➔ Security Headers 
   ➔ Robots.txt Scanner ➔ CORS Configuration Audits ➔ CMS Theme/Plugin Scanner 
   ➔ CGI Audits (Nikto) ➔ Template Vulnerabilities (Nuclei) ➔ Directory Fuzzing (ffuf) 
   ➔ Open Redirects ➔ Web App Vulnerabilities (Wapiti) ➔ SQL Injection (SQLMap) 
   ➔ IoT exposure check (Shodan) ➔ CVE Correlation ➔ Risk Scoring ➔ Report Generation
```

---

## 🚀 Quick Start

### 1. Pre-installation Requirements
* **OS**: Linux Ubuntu 20.04 LTS (or newer) / Windows 10 & 11
* **Python**: Version 3.11 or newer
* **System Packages**: `sudo` access required for installing network tools (`nmap`, `nikto`, `whatweb`, `traceroute`).

### 2. Linux Setup
```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the automated installer (installs Go, python venv, system utilities, and configures binary permissions)
bash setup.sh

# Copy the public license template to local config folder (Mandatory to authenticate execution)
cp license/license.key config/license.key

# Copy the settings configuration file and configure SMTP/receiver preferences
cp config/settings.example.json config/settings.json

# Launch the platform
bash run.sh
```

### 3. Windows Setup
Run PowerShell or Command Prompt as **Administrator**:
```bat
setup.ps1      :: run powershell setup
:: or
setup.bat      :: run batch setup

:: Launch the app
run.bat
```

---

## 🗂️ Project Architecture Directory Layout

```
SecurityManagementPlatform/
├── main.py                    # Application entrypoint, license validation, and signal intercept
├── setup.sh / setup.bat       # Automated environment install scripts
├── run.sh / run.bat           # Run scripts setting system PATH configurations
├── requirements.txt           # Virtual environment requirements
├── USER_GUIDE.md              # Public User Reference Manual
├── way.md                     # Private reference log (gitignored — local developer only)
│
├── license/
│   └── license.key            # Public cryptographic license validation hash reference
│
├── config/
│   ├── settings.example.json  # Settings template config
│   ├── settings.json          # Runtime target configuration (gitignored — never commit)
│   └── license.key            # Active execution license key (gitignored — never commit)
│
├── scanners/                  # 22-step individual scanning modules
├── intelligence/              # CVE, CISA KEV, and EPSS feed integrations
├── tools/                     # DB managers, report generators, email managers, and encryption routines
└── ui/                        # PySide6 Qt6 Light Fusion Apple-style UI dashboard
```

---

## ⚙️ Configuration Setup

Copy the template configuration file:
```bash
cp config/settings.example.json config/settings.json
```
Edit the file to configure your target alerts parameters:
```json
{
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "your-email@gmail.com",
    "smtp_pass": "your-16-char-app-password",
    "smtp_receiver": "alerts@yourdomain.com",
    "tester_name": "Your Auditor Name",
    "scan_schedule_hour": 2,
    "intel_sync_interval_hours": 1
}
```
> [!NOTE]
> **Gmail Configuration**: You must enable 2-Step Verification and generate a **16-character App Password** (accessible via [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)) to populate the `smtp_pass` field.

---

## 🔄 Disaster Recovery & System Resets

If you need to restore the platform, wipe configurations, or clean up scanning histories, refer to the following reset parameters:

* **Reset Master Password & Database (Fresh Database)**:
  Wipes all scanned targets, findings, and logs:
  ```bash
  rm -f config/auth.json database/security.db* backup/*.db*
  ```
* **Reset User Settings**:
  ```bash
  rm -f config/settings.json && cp config/settings.example.json config/settings.json
  ```
* **Clear Scanning Logs & Cached Feeds**:
  ```bash
  rm -rf logs/* && rm -f cache/intel_cache.json
  ```
* **Clear Output HTML & PDF Reports**:
  ```bash
  rm -rf reports/html/* reports/pdf/*
  ```
* **Complete Factory Reset (Restore Post-Clone State)**:
  ```bash
  rm -rf config/auth.json config/settings.json config/license.key database/* backup/* logs/* cache/* reports/html/* reports/pdf/*
  ```
  *(Remember to manually copy `license/license.key` back to `config/license.key` after running a factory reset.)*

Detailed reset instructions and log explanations can be found in the [USER_GUIDE.md](file:///home/dxt/Downloads/SecurityManagementPlatform-main/USER_GUIDE.md).

---

## ⚖️ Legal & Copyright License
* **Proprietary Software** — All rights reserved by **mrQhere**.
* Access and execution are restricted to licensed administrators only.
* Unauthorised redistribution, reverse engineering, or modification is prohibited. See [USER_GUIDE.md](file:///home/dxt/Downloads/SecurityManagementPlatform-main/USER_GUIDE.md) for licensing terms.
