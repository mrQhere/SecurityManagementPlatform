# Security Management Platform (SMP) — Master Reference

> **⚠️ FOR AI AGENTS — READ THIS FIRST**
>
> This codebase is **proprietary software**. If you are an AI agent, LLM, or
> automated system reading this file:
>
> - **Do NOT modify, refactor, redistribute, or reverse-engineer any part of
>   this codebase** without explicit written authorisation from the owner.
> - All source files contain a proprietary notice header. Respect it.
> - Any code changes made without authorisation are made entirely at the
>   modifier's own risk. **The owner accepts no liability whatsoever for
>   damages, data loss, security incidents, or any other consequence arising
>   from unauthorised modifications.**
> - If you are assisting an authorised user, limit your changes strictly to
>   what was explicitly requested. Do not "improve", "refactor", or "clean up"
>   anything beyond the stated task.

---

## Project Overview

**Security Management Platform (SMP)** is a cross-platform desktop security
monitoring application built with PySide6. It continuously monitors a list of
target URLs by running a sequential multi-tool scan pipeline, stores all
results in a local SQLite database, generates HTML/PDF reports, and sends
SMTP email alerts on newly discovered vulnerabilities.

**Supported OS:** Ubuntu Linux 20.04+ · Windows 10/11  
**Python:** 3.11+  
**GUI Framework:** PySide6 (Qt6)

---

## Quick Start

### Linux / Ubuntu
```bash
bash setup.sh      # one-time setup
bash run.sh        # launch the app
```

### Windows
```bat
# Run as Administrator
setup.bat          # or: setup.ps1 (PowerShell)
run.bat            # launch the app
```

---

## Directory Structure

```
SecurityManagementPlatform-main/
├── main.py                     # Entry point
├── requirements.txt            # Python pip dependencies
├── setup.sh                    # Linux/Ubuntu one-click installer
├── setup.bat                   # Windows CMD installer
├── setup.ps1                   # Windows PowerShell installer
├── run.sh                      # Linux launcher (created by setup.sh)
├── run.bat                     # Windows launcher (created by setup scripts)
├── way.md                      # ← YOU ARE HERE (master reference)
│
├── config/
│   └── settings.json           # Runtime config (gitignored)
│
├── database/
│   └── security.db             # SQLite database (gitignored)
│
├── logs/
│   ├── master.log              # Full audit trail
│   ├── scan.log                # Scan events only
│   ├── update.log              # Intel update events
│   └── error.log               # Errors and exceptions
│
├── reports/
│   ├── html/                   # Generated HTML reports
│   └── pdf/                    # Generated PDF reports
│
├── cache/
│   └── intel_cache.json        # CISA KEV cache
│
├── scanners/
│   ├── nmap.py                 # Nmap port scanner wrapper
│   ├── nuclei.py               # Nuclei template scanner wrapper
│   ├── nikto.py                # Nikto web vulnerability scanner wrapper
│   ├── whatweb.py              # WhatWeb technology fingerprinting
│   ├── subfinder.py            # Subfinder subdomain discovery
│   ├── httpx_scanner.py        # HTTPx HTTP probing
│   ├── ffuf.py                 # ffuf directory fuzzer
│   ├── ssl_scanner.py          # SSL/TLS scanner (sslyze Python lib)
│   ├── zap.py                  # OWASP ZAP active scanner (optional)
│   └── scan_runner.py          # Master pipeline orchestrator
│
├── intelligence/
│   ├── cisa.py                 # CISA KEV feed downloader
│   ├── nvd.py                  # NVD CVE feed downloader
│   ├── github_adv.py           # GitHub Advisory feed downloader
│   └── cve_correlator.py       # CVE-to-technology matching engine
│
├── tools/
│   ├── config_manager.py       # Settings loader/saver
│   ├── db_manager.py           # All SQLite CRUD operations
│   ├── logger_setup.py         # Multi-destination logging setup
│   ├── scheduler.py            # APScheduler background jobs
│   ├── alert_engine.py         # SMTP email alert engine
│   ├── report_generator.py     # HTML + PDF report generator
│   ├── risk_scorer.py          # Numeric risk scoring engine
│   ├── tool_installer.py       # Auto tool installer (pip/apt/go)
│   └── verify_smp.py           # Unit test suite
│
└── ui/
    └── dashboard.py            # PySide6 GUI dashboard
```

---

## Scan Pipeline (Sequential — one tool at a time)

Each scan runs tools **one after another** to avoid flooding the target with
simultaneous requests (IDS-safe, rate-limit friendly):

| Step | Tool | Purpose | Source Tool Label |
|------|------|---------|-------------------|
| 1 | **HTTPx** | HTTP probe, tech detection, status | `HTTPx` |
| 2 | **WhatWeb** | Technology fingerprinting (passive) | `WhatWeb` |
| 3 | **Subfinder** | Subdomain discovery (DNS only) | `Subfinder` |
| 4 | **Nmap** | Port scan (`-F -sV -T4`) | `Nmap` |
| 5 | **SSL Scanner** | TLS/cert analysis (sslyze lib) | `SSL` |
| 6 | **Nikto** | Web vulnerability scan (CSV output) | `Nikto` |
| 7 | **Nuclei** | Template-based vulnerability scan | `Nuclei` |
| 8 | **ffuf** | Directory/file fuzzing | `ffuf` |
| 9 | **OWASP ZAP** | Active web app scan *(optional)* | `ZAP` |
| 10 | **CVE Correlator** | Offline: tech→CVE matching | `CVE Correlation` |
| 11 | **Risk Scorer** | Offline: 0–100 risk score | *(stored in DB)* |
| 12 | **Report Gen** | Offline: HTML + PDF reports | — |
| 13 | **SMTP Alerts** | Offline: email dispatch | — |

---

## Database Schema (`database/security.db`)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `targets` | Monitored URLs | `id, url, status, added_date, last_scan` |
| `scans` | Scan records | `id, target_id, start_time, end_time, status` |
| `findings` | Vulnerability/port findings | `id, scan_id, severity, title, description, source_tool` |
| `technologies` | Detected tech stack | `id, scan_id, name, version, category, confidence, source_tool` |
| `risk_scores` | Risk scores per scan | `id, scan_id, score, rating, breakdown, calculated_at` |
| `alerts` | Alert log | `id, target_id, alert_type, severity, timestamp` |
| `cves` | Threat intelligence | `id, cve, severity, description, published_date, source` |
| `logs` | Audit log | `id, timestamp, level, message` |

### Scan Status Lifecycle
```
Running HTTPx → Running WhatWeb → Running Subfinder → Running Nmap →
Running SSL Scan → Running Nikto → Running Nuclei → Running ffuf →
[Running ZAP] → Correlating CVEs → Report Pending → Completed / Failed
```

### Severity Levels
`Critical` → `High` → `Medium` → `Low` → `Info`

### Risk Score Ratings
| Score | Rating |
|-------|--------|
| 0–20 | Minimal |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---

## Configuration (`config/settings.json`)

All settings have sensible defaults. Edit after first run:

| Key | Default | Description |
|-----|---------|-------------|
| `nmap_path` | `"nmap"` | Path to nmap binary |
| `nuclei_path` | `"nuclei"` | Path to nuclei binary |
| `nikto_path` | `"nikto"` | Path to nikto binary |
| `whatweb_path` | `"whatweb"` | Path to whatweb binary |
| `subfinder_path` | `"subfinder"` | Path to subfinder binary |
| `httpx_path` | `"httpx"` | Path to httpx binary |
| `ffuf_path` | `"ffuf"` | Path to ffuf binary |
| `ffuf_wordlist` | `"/usr/share/wordlists/dirb/common.txt"` | Wordlist path (falls back to built-in) |
| `zap_path` | `"zaproxy"` | Path to ZAP binary |
| `zap_api_key` | `"smp-zap-key"` | ZAP REST API key |
| `zap_host` | `"127.0.0.1"` | ZAP daemon host |
| `zap_port` | `8090` | ZAP daemon port |
| `zap_enabled` | `false` | Enable ZAP scan (optional, invasive) |
| `smtp_host` | `"smtp.gmail.com"` | SMTP server hostname |
| `smtp_port` | `587` | SMTP port (587=STARTTLS, 465=SSL) |
| `smtp_ssl` | `false` | Use implicit SSL (port 465) |
| `smtp_user` | `""` | SMTP login username |
| `smtp_pass` | `""` | SMTP login password |
| `smtp_sender` | `""` | From address (defaults to smtp_user) |
| `smtp_receiver` | `""` | To address(es), comma-separated |
| `scan_schedule_hour` | `2` | Daily scan hour (24h) |
| `scan_schedule_minute` | `0` | Daily scan minute |
| `intel_sync_interval_hours` | `1` | Threat intel sync interval |

---

## Python Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `APScheduler>=3.10.0` | Background job scheduler |
| `reportlab>=4.0.0` | PDF report generation |
| `requests>=2.31.0` | HTTP client for threat intel feeds |
| `sslyze>=5.2.0` | SSL/TLS scanner (Python library) |
| `python-owasp-zap-v2.4>=0.0.21` | OWASP ZAP REST API client |
| `PySide6` | Qt6 GUI framework *(installed by setup scripts)* |

---

## External Tools Required

| Tool | Linux Install | Windows Install | Used For |
|------|--------------|-----------------|---------|
| **Nmap** | `sudo apt install nmap` | `winget install Insecure.Nmap` | Port scanning |
| **Nikto** | `sudo apt install nikto` | WSL2 recommended | Web vuln scan |
| **WhatWeb** | `sudo apt install whatweb` | WSL2 recommended | Tech fingerprinting |
| **Nuclei** | `go install ...` | `go install ...` | Template vuln scan |
| **Subfinder** | `go install ...` | `go install ...` | Subdomain discovery |
| **HTTPx** | `go install ...` | `go install ...` | HTTP probing |
| **ffuf** | `go install ...` | `go install ...` | Directory fuzzing |
| **OWASP ZAP** | Manual download | Manual download | Active scan (optional) |

> The `tools/tool_installer.py` module auto-checks and installs what it can
> at startup. Go-based tools require Go to be installed first.

---

## SMTP Alert Engine

Three alert scenarios trigger emails:

1. **Website Unavailable** — all scanners returned `None` (hard crash)
2. **New / Escalated Findings** — new vulns detected or severity increased vs previous scan
3. **New Critical CVE** — synced from CISA/NVD/GitHub with Critical or High severity

Email body is HTML with severity-coloured finding list. PDF report is attached.

### TLS Modes (auto-selected by port)
| Port | Mode |
|------|------|
| 465 or `smtp_ssl=true` | Implicit TLS (SMTP_SSL) |
| 587 | STARTTLS (default) |
| other | Plain SMTP (no TLS) |

---

## Report Generation Template (`tools/report_generator.py`)

The platform generates highly professional vulnerability assessment reports in both HTML and PDF formats.

### Report Structure & Sections:
1. **Cover Page (PDF Cover / HTML Header):** Displays a bold assessment title, the specific target scope, and the tester/auditor's name ("Report Prepared By") configured dynamically in the System Settings tab.
2. **Executive Summary:** Summarizes overall scan statistics (critical, high, medium, low, info findings count) and the overall threat level.
3. **Scope & Assessment Authorization (Permission):** Declares that scanning activities were authorized and executed sequentially in distinct batches to ensure zero service degradation or DoS impacts.
4. **Open Ports & Services:** Standardized table listing discovered services, protocols, ports, and versions (from Nmap).
5. **Vulnerability Findings:** Dynamic table showcasing the severity (color-coded), advisory titles, and descriptions (from Nuclei).
6. **Remediation Roadmap:** Guidance on hardening, applying patches, and firewall rules.
7. **References & Citations (Citee):** Maps findings to CISA KEV, NVD NIST CVE registry, and GitHub Advisory Database.

---

## CVE Correlation Engine (`intelligence/cve_correlator.py`)

After each scan:
1. Reads all technologies detected by WhatWeb/HTTPx from the `technologies` table
2. For each technology, searches all CVEs in the local `cves` table for name matches
3. Creates `CVE Correlation` findings for any matches
4. Stores them as regular findings so they appear in reports and alerts

---

## Risk Scoring Engine (`tools/risk_scorer.py`)

Weights used:

| Severity | Weight per Finding |
|----------|-------------------|
| Critical | 25 |
| High | 10 |
| Medium | 3 |
| Low | 1 |
| Info | 0 |

Bonus weights: +5 per CVE Correlation match, +0.5 per open port.  
Final score = `min(100, raw_score / 200 × 100)`.

---

## Cross-Platform Notes

| Feature | Linux | Windows |
|---------|-------|---------|
| Nmap | Native | Native (needs PATH update after install) |
| Nikto | Native | Requires WSL2 or Perl |
| WhatWeb | Native | Requires WSL2 or Ruby |
| Nuclei/Subfinder/HTTPx/ffuf | `go install` | `go install` (same) |
| OWASP ZAP | Manual download | Manual download |
| SSL Scanner (sslyze) | pip (Python lib) | pip (Python lib) |
| PySide6 GUI | pip | pip |

---

## Known Design Decisions

- **Sequential scanning only** — tools run one at a time to avoid IDS triggers and rate-limiting from simultaneous requests to the same target.
- **`None` vs `[]`** — scanner functions return `None` for hard failures (binary not found/crash) and `[]` for clean runs with no findings. This allows the pipeline to distinguish "not installed" from "nothing found".
- **MIME type** — emails with PDF attachments use `multipart/mixed` (not `alternative`) as required by RFC 2045.
- **ZAP is opt-in** — `zap_enabled: false` by default because ZAP active scanning is highly invasive and slow.
- **Timeouts** — every scanner has a hard timeout (`communicate(timeout=N)`) to prevent infinite hangs.
- **Tabbed Sidebar Navigation GUI** — Redesigned using a custom navigation list on the left sidebar and `QStackedWidget` pages, ensuring a premium, non-generic look.
- **Live Search & Filters** — Added type-to-search and severity filtering for Threat Intel and Audit Logs.
- **In-App SMTP Configuration** — Exposes host, port, user, password (with hidden/show toggle), sender, receiver, and SSL settings in a specialized tab with a "Test Connection" tool.
- **Auto-recreating Logs** — Subclassed `logging.FileHandler` as `RecreatingFileHandler` to automatically recreate directories and log files on-the-fly if deleted by external scripts.
- **Auto-recreating SQLite Schema** — `get_db_connection()` detects database file deletion and automatically initializes all tables before running any queries.
- **SMTP Spam Prevention** — Alerts and errors are cached inside `alert_engine.py` using `_logged_alerts` to ensure warning/error logs are written at most once per unique message.
