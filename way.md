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
bash setup.sh      # one-time setup (fully automatic — no user input required)
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
├── setup.sh                    # Linux/Ubuntu fully-automatic installer (Go auto-downloaded)
├── setup.bat                   # Windows CMD installer
├── setup.ps1                   # Windows PowerShell installer
├── run.sh                      # Linux launcher (PATH includes bin/, ~/go/bin, /usr/local/go/bin)
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
│   └── intel_cache.json        # CISA KEV + NVD + GitHub sync state cache
│
├── bin/                        # Project-local tool binaries (auto-populated by setup.sh)
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
│   ├── zap.py                  # OWASP ZAP active scanner (optional — NOT IN USE by default)
│   ├── traceroute.py           # Network path tracer (UDP mode, no root required)
│   ├── sqlmap.py               # SQL injection scanner (pip-installed sqlmap)
│   ├── wapiti.py               # Web vulnerability scanner (pip-installed wapiti3)
│   └── scan_runner.py          # Master pipeline orchestrator
│
├── intelligence/
│   ├── cisa.py                 # CISA KEV feed (full catalog, ~1600+ entries)
│   ├── nvd.py                  # NVD CVE feed (full paginated database, 240 000+ CVEs)
│   ├── github_adv.py           # GitHub Advisory feed (all pages, Link-header pagination)
│   ├── epss.py                 # EPSS exploit prediction scores (enrichment)
│   └── cve_correlator.py       # CVE-to-technology matching engine
│
├── tools/
│   ├── config_manager.py       # Settings loader/saver
│   ├── db_manager.py           # All SQLite CRUD operations
│   ├── logger_setup.py         # Multi-destination logging setup
│   ├── scheduler.py            # APScheduler background jobs
│   ├── alert_engine.py         # SMTP email alert engine + test_smtp_connection()
│   ├── report_generator.py     # HTML + PDF report generator
│   ├── risk_scorer.py          # Numeric risk scoring engine
│   ├── tool_installer.py       # Auto tool installer (pip/apt/go/pre-built binary)
│   └── verify_smp.py           # Unit test suite
│
└── ui/
    └── dashboard.py            # PySide6 GUI dashboard
```

---

## Scan Pipeline (Sequential — one tool at a time)

Each scan runs tools **one after another** to avoid flooding the target with
simultaneous requests (IDS-safe, rate-limit friendly):

| Step | Tool | Purpose | Source Tool Label | Notes |
|------|------|---------|-------------------|-------|
| 1 | **Traceroute** | Network path discovery (UDP, no root) | `Traceroute` | Uses `-n` flag (no DNS) |
| 2 | **HTTPx** | HTTP probe, tech detection, status | `HTTPx` | |
| 3 | **WhatWeb** | Technology fingerprinting (passive) | `WhatWeb` | |
| 4 | **Subfinder** | Subdomain discovery (DNS only) | `Subfinder` | |
| 5 | **Nmap** | Port scan (`-F -sV -T4`) | `Nmap` | Top-100 ports, no root required |
| 6 | **SSL Scanner** | TLS/cert analysis (sslyze lib) | `SSL` | |
| 7 | **Nikto** | Web vulnerability scan (CSV output) | `Nikto` | |
| 8 | **Nuclei** | Template-based vulnerability scan | `Nuclei` | |
| 9 | **ffuf** | Directory/file fuzzing | `ffuf` | Output via temp file (not stdout) |
| 10 | **OWASP ZAP** | Active web app scan *(optional)* | `ZAP` | **NOT IN USE** — `zap_enabled: false` |
| 11 | **Wapiti** | Web app vulnerability scan (OWASP) | `Wapiti` | pip-installed wapiti3 |
| 12 | **SQLMap** | SQL injection detection | `SQLMap` | pip-installed sqlmap |
| 13 | **CVE Correlator** | Offline: tech→CVE matching | `CVE Correlation` | |
| 14 | **Risk Scorer** | Offline: 0–100 risk score | *(stored in DB)* | |
| 15 | **Report Gen** | Offline: HTML + PDF reports | — | |
| 16 | **SMTP Alerts** | Offline: email dispatch | — | |

---

## Database Schema (`database/security.db`)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `targets` | Monitored URLs | `id, url, status, added_date, last_scan` |
| `scans` | Scan records | `id, target_id, start_time, end_time, status, scanned_by` |
| `findings` | Vulnerability/port findings | `id, scan_id, severity, title, description, source_tool` |
| `technologies` | Detected tech stack | `id, scan_id, name, version, category, confidence, source_tool` |
| `risk_scores` | Risk scores per scan | `id, scan_id, score, rating, breakdown, calculated_at` |
| `alerts` | Alert log | `id, target_id, alert_type, severity, timestamp` |
| `cves` | Threat intelligence | `id, cve, severity, description, published_date, source, epss_score` |
| `logs` | Audit log | `id, timestamp, level, message` |

### Scan Status Lifecycle
```
Running Traceroute → Running HTTPx → Running WhatWeb → Running Subfinder →
Running Nmap → Running SSL Scan → Running Nikto → Running Nuclei →
Running ffuf → [Running ZAP] → Running Wapiti → Running SQLMap →
Correlating CVEs → Report Pending → Completed / Failed
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
| `sqlmap_path` | `"sqlmap"` | Path to sqlmap binary (venv/bin) |
| `wapiti_path` | `"wapiti"` | Path to wapiti binary (venv/bin) |
| `traceroute_path` | `"traceroute"` | Path to traceroute binary |
| `ffuf_wordlist` | `"/usr/share/wordlists/dirb/common.txt"` | Wordlist path (falls back to built-in) |
| `zap_path` | `"zaproxy"` | Path to ZAP binary (**NOT IN USE** by default) |
| `zap_api_key` | `"smp-zap-key"` | ZAP REST API key (**NOT IN USE** by default) |
| `zap_host` | `"127.0.0.1"` | ZAP daemon host (**NOT IN USE** by default) |
| `zap_port` | `8090` | ZAP daemon port (**NOT IN USE** by default) |
| `zap_enabled` | `false` | Enable ZAP scan — **NOT IN USE** (set `true` to enable, invasive) |
| `smtp_host` | `"smtp.gmail.com"` | SMTP server hostname |
| `smtp_port` | `587` | SMTP port (587=STARTTLS, 465=SSL) |
| `smtp_ssl` | `false` | Use implicit SSL (port 465) |
| `smtp_user` | `""` | SMTP login username |
| `smtp_pass` | `""` | SMTP App Password — **Gmail requires a 16-char App Password, NOT your regular password** |
| `smtp_sender` | `""` | From address (defaults to smtp_user) |
| `smtp_receiver` | `""` | To address(es), comma-separated |
| `scan_schedule_hour` | `2` | Daily scan hour (24h) |
| `scan_schedule_minute` | `0` | Daily scan minute |
| `intel_sync_interval_hours` | `1` | Threat intel sync interval |
| `tester_name` | `"Security Auditor"` | Name shown on generated reports |

---

## Python Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `APScheduler>=3.10.0` | Background job scheduler |
| `reportlab>=4.0.0` | PDF report generation |
| `requests>=2.31.0` | HTTP client for threat intel feeds |
| `sslyze>=5.2.0` | SSL/TLS scanner (Python library) |
| `python-owasp-zap-v2.4>=0.0.21` | OWASP ZAP REST API client (**NOT IN USE** unless zap_enabled=true) |
| `PySide6` | Qt6 GUI framework *(installed by setup scripts)* |
| `sqlmap` | SQL injection scanner CLI (pip-installed into venv) |
| `wapiti3` | Web vulnerability scanner CLI (pip-installed into venv) |

---

## External Tools Required

| Tool | Linux Install | Windows Install | Used For | Auto-installed? |
|------|--------------|-----------------|---------|-----------------|
| **Nmap** | `sudo apt install nmap` | `winget install Insecure.Nmap` | Port scanning | ✅ apt (setup.sh) |
| **Nikto** | `sudo apt install nikto` | WSL2 recommended | Web vuln scan | ✅ apt (setup.sh) |
| **WhatWeb** | `sudo apt install whatweb` | WSL2 recommended | Tech fingerprinting | ✅ apt (setup.sh) |
| **Traceroute** | `sudo apt install traceroute` | Built-in (`tracert`) | Network path | ✅ apt (setup.sh) |
| **Nuclei** | `go install ...` | `go install ...` | Template vuln scan | ✅ pre-built binary (setup.sh) |
| **Subfinder** | `go install ...` | `go install ...` | Subdomain discovery | ✅ pre-built binary (setup.sh) |
| **HTTPx** | `go install ...` | `go install ...` | HTTP probing | ✅ pre-built binary (setup.sh) |
| **ffuf** | `go install ...` | `go install ...` | Directory fuzzing | ✅ pre-built binary (setup.sh) |
| **SQLMap** | `pip install sqlmap` | `pip install sqlmap` | SQL injection | ✅ pip (setup.sh) |
| **Wapiti** | `pip install wapiti3` | `pip install wapiti3` | Web vuln scan | ✅ pip (setup.sh) |
| **OWASP ZAP** | Manual download | Manual download | Active scan (optional) | ❌ Manual only — **NOT IN USE** |
| **Go language** | Auto-downloaded by setup.sh | Manual install | Required for Go tools | ✅ auto-download (setup.sh) |

> `tools/tool_installer.py` auto-checks all tools at startup. `setup.sh` handles
> full installation including downloading Go and pre-built binaries — no manual steps needed.

---

## Setup Script (`setup.sh`) — Fully Automatic

The Linux setup script requires **zero user intervention**:

1. Detects or installs Python 3.11+
2. Creates the `venv` virtual environment
3. Installs all Python packages (core + PySide6 + sqlmap + wapiti3)
4. Installs system tools via `apt` (nmap, nikto, whatweb, traceroute)
5. **Auto-downloads Go** (`1.23.4`) from `dl.google.com` if not installed — no manual step
6. Installs Go tools via `go install` (falls back to pre-built GitHub release binaries)
7. Downloads pre-built binaries (nuclei, subfinder, httpx, ffuf) into `./bin/` as fallback
8. Updates Nuclei templates
9. Creates `run.sh` with full PATH including `./bin/`, `~/go/bin`, `/usr/local/go/bin`
10. Collects non-fatal errors and shows a summary — setup always completes

> **Important:** `set -e` was removed. All errors are soft-failures shown in a summary.
> This means a missing optional tool never aborts the entire setup.

---

## SMTP Alert Engine (`tools/alert_engine.py`)

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

### Gmail Setup — App Password Required

Gmail has **blocked regular passwords** for SMTP since May 2022.
`smtp_pass` **must** be a 16-character App Password:

1. Go to **myaccount.google.com → Security**
2. Enable **2-Step Verification** (required before App Passwords appear)
3. Go to **App Passwords** → Create for "Mail"
4. Paste the 16-character code as `smtp_pass` in settings (spaces are optional)
5. Reference: https://support.google.com/accounts/answer/185833

### `test_smtp_connection()` function
`alert_engine.py` exposes `test_smtp_connection() → (bool, str)` which can be called
from the UI Settings tab. It connects, authenticates, sends a real test email,
and returns a plain-English success/failure message including the Gmail App Password
instructions when authentication fails.

---

## Threat Intelligence Engine

### CVE Sync Sources

| Source | Volume | Sync Mode | Frequency |
|--------|--------|-----------|-----------|
| **NVD (NIST)** | 240 000+ CVEs | Full paginated on first run; 30-day incremental after | Every `intel_sync_interval_hours` |
| **CISA KEV** | ~1 600 entries | Full catalog every sync | Every `intel_sync_interval_hours` |
| **GitHub Advisories** | Thousands | All pages via Link-header pagination | Every `intel_sync_interval_hours` |
| **EPSS** | Per-CVE scores | Enriches CVEs missing EPSS scores (100 at a time) | Every `intel_sync_interval_hours` |

### NVD Sync Details (`intelligence/nvd.py`)

- **First run (empty DB):** Downloads the entire NVD database in pages of 2 000 CVEs.
  This takes **20–40 minutes** due to NVD's mandatory 6-second inter-request delay.
- **Subsequent runs:** Fetches only CVEs published in the **last 30 days** (fast, ~seconds).
- **Rate limiting:** 6.5 s sleep between every page request (NVD enforces ≥6 s).
- **Retry logic:** 3 attempts with 10 s / 30 s / 60 s backoff on 429/503/timeout.
- **Severity parsing:** CVSS v3.1 → v3.0 → v2 fallback; derives severity from base score if no label.

### CISA Sync Details (`intelligence/cisa.py`)

- Downloads the full CISA Known Exploited Vulnerabilities catalog in a single request.
- Version-check skipped if DB was cleared (forces full re-import).
- Severity: CVEs with "remote code execution" or "critical" in description → `Critical`; else → `High`.

### GitHub Advisory Sync Details (`intelligence/github_adv.py`)

- Fetches `type=reviewed` advisories (those with assigned CVE IDs) — 100 per page.
- Follows `Link: rel="next"` response headers to paginate all available pages.
- 1-second polite delay between pages.

### EPSS Sync Details (`intelligence/epss.py`)

- Queries `api.first.org/data/v1/epss` for up to 100 CVEs per batch.
- Only enriches CVEs where `epss_score IS NULL` in the DB.
- Sets unscored CVEs to `0.0` after query to avoid re-querying.

### HTTP Resilience (all intelligence modules)

All four intelligence modules share the same pattern:
- `User-Agent: SecurityManagementPlatform/1.0 (contact@smp.local)`
- `Accept: application/json`
- 3 retries with backoff on HTTP 429, 500, 502, 503, and connection/timeout errors
- `Retry-After` header respected for 429 responses

---

## Scanner Fixes & Known Behaviour

### Nmap (`scanners/nmap.py`)
- **Flags used:** `-F -sV -T4 --max-rate 50 -oX -`
- **`-F`** — top-100 ports only (fast; `-p-` scanning all 65 535 ports was removed — too slow)
- **`-O` removed** — OS detection requires `root`/`CAP_NET_RAW`; crashes as normal user
- **`-sC` removed** — default scripts can trigger IDS; not needed for service detection
- `--max-rate 50` keeps scan IDS-friendly
- Output: XML to stdout, parsed by `parse_nmap_xml()`

### ffuf (`scanners/ffuf.py`)
- **`-o -` removed** — this flag created a literal file named `-` in the CWD, not stdout
- **Fix:** output written to a `tempfile.NamedTemporaryFile` (`ffuf_out_*.json`), read back after run
- Temp files are cleaned up on normal exit, timeout, and `FileNotFoundError`
- Built-in wordlist (56 common paths) used when no system wordlist is found

### Traceroute (`scanners/traceroute.py`)
- **`-I` flag removed** — ICMP mode requires `root`/`CAP_NET_RAW`; fails as normal user
- **Fix:** uses default UDP traceroute with `-n` (no reverse DNS, faster)
- Returns `None` if binary not found; `[]` if run succeeds with no hops recorded

### SQLMap (`scanners/sqlmap.py`)
- Binary resolved via `settings.get("sqlmap_path", "sqlmap")`
- Installed into venv via `pip install sqlmap` — binary at `venv/bin/sqlmap`
- Uses `--crawl=3 --level=5 --risk=3 --batch --smart --delay=1`
- Reads output from sqlmap's per-domain log file in a temp directory

### Wapiti (`scanners/wapiti.py`)
- Binary resolved via `settings.get("wapiti_path", "wapiti")`
- Installed into venv via `pip install wapiti3` — binary at `venv/bin/wapiti`
- Outputs JSON report to a temp file; parsed for `vulnerabilities` dict
- Severity mapped: level ≥3 → High, 2 → Medium, 1 → Low, 0 → Info

### OWASP ZAP (`scanners/zap.py`) — **NOT IN USE**
- ZAP is opt-in: `zap_enabled: false` by default
- Requires ZAP daemon to be running separately; highly invasive active scan
- Enable by setting `zap_enabled: true` in `config/settings.json`

---

## Tool Installer (`tools/tool_installer.py`)

### Install Method Registry

| Tool | Method | Package/Binary |
|------|--------|----------------|
| sslyze | pip | `sslyze` |
| python-owasp-zap-v2.4 | pip | `python-owasp-zap-v2.4` |
| APScheduler | pip | `APScheduler` |
| reportlab | pip | `reportlab` |
| requests | pip | `requests` |
| **Wapiti** | **pip** | **`wapiti3`** (binary in venv/bin) |
| **SQLMap** | **pip** | **`sqlmap`** (binary in venv/bin) |
| Nmap | apt | `nmap` |
| Nikto | apt | `nikto` |
| WhatWeb | apt | `whatweb` |
| Traceroute | apt | `traceroute` |
| Nuclei | go + pre-built | `github.com/projectdiscovery/nuclei/v3/...` |
| Subfinder | go + pre-built | `github.com/projectdiscovery/subfinder/v2/...` |
| HTTPx | go + pre-built | `github.com/projectdiscovery/httpx/...` |
| ffuf | go + pre-built | `github.com/ffuf/ffuf/v2@latest` |
| OWASP ZAP | manual | https://www.zaproxy.org/download/ — **NOT IN USE** |

> **Wapiti and SQLMap were previously listed as `apt` packages — this was wrong.**
> They are Python packages with CLI binaries; they must be installed via `pip` into the venv.

### Binary Discovery
- `shutil.which(binary)` searches `PATH`, which includes `venv/bin/`, `./bin/`, and `~/go/bin/`
- For library-only pip packages (no binary), `__import__(module)` is used to check presence

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
| Traceroute | Native (`traceroute`) | Built-in (`tracert` — different binary name) |
| Nuclei/Subfinder/HTTPx/ffuf | `go install` or pre-built | `go install` (same) |
| SQLMap | `pip install sqlmap` (venv) | `pip install sqlmap` (venv) |
| Wapiti | `pip install wapiti3` (venv) | `pip install wapiti3` (venv) |
| OWASP ZAP | Manual download — **NOT IN USE** | Manual download — **NOT IN USE** |
| SSL Scanner (sslyze) | pip (Python lib) | pip (Python lib) |
| PySide6 GUI | pip | pip |
| Go language | Auto-downloaded by setup.sh | Manual install from go.dev/dl |

---

## Known Design Decisions

- **Sequential scanning only** — tools run one at a time to avoid IDS triggers and rate-limiting from simultaneous requests to the same target.
- **`None` vs `[]`** — scanner functions return `None` for hard failures (binary not found/crash) and `[]` for clean runs with no findings. This allows the pipeline to distinguish "not installed" from "nothing found".
- **MIME type** — emails with PDF attachments use `multipart/mixed` (not `alternative`) as required by RFC 2045.
- **ZAP is opt-in** — `zap_enabled: false` by default because ZAP active scanning is highly invasive and slow. **NOT IN USE** unless explicitly enabled.
- **Timeouts** — every scanner has a hard timeout (`communicate(timeout=N)`) to prevent infinite hangs.
- **Tabbed Sidebar Navigation GUI** — Redesigned using a custom navigation list on the left sidebar and `QStackedWidget` pages, ensuring a premium, non-generic look.
- **Live Search & Filters** — Added type-to-search and severity filtering for Threat Intel and Audit Logs.
- **In-App SMTP Configuration** — Exposes host, port, user, password (with hidden/show toggle), sender, receiver, and SSL settings in a specialized tab with a "Test Connection" tool.
- **Auto-recreating Logs** — Subclassed `logging.FileHandler` as `RecreatingFileHandler` to automatically recreate directories and log files on-the-fly if deleted by external scripts.
- **Auto-recreating SQLite Schema** — `get_db_connection()` detects database file deletion and automatically initializes all tables before running any queries.
- **SMTP Spam Prevention** — Alerts and errors are cached inside `alert_engine.py` using `_logged_alerts` to ensure warning/error logs are written at most once per unique message.
- **NVD rate limit compliance** — NVD mandates ≥6 second delay between API requests. The sync engine sleeps 6.5 s between every page to stay within limits.
- **ffuf temp-file output** — ffuf does not support writing JSON to stdout via `-o -` (creates a literal file named `-`). Output is redirected to a named `tempfile` and read back after process exit.
- **No root required** — Nmap `-O` (OS detection) and traceroute `-I` (ICMP) both require root/`CAP_NET_RAW`. Both flags were removed so the platform runs correctly as a normal user.
- **Wapiti/SQLMap via pip** — These tools are Python packages installed into the project venv. They must NOT be listed as `apt` packages in the tool registry.
- **Go auto-download** — `setup.sh` downloads Go from `dl.google.com` automatically if not present, removing the requirement for users to install Go manually before running the installer.
- **Pre-built binary fallback** — If `go install` fails or Go is unavailable, `setup.sh` downloads pre-compiled GitHub release binaries for nuclei/subfinder/httpx/ffuf into `./bin/`.
- **Gmail App Password** — Gmail has rejected regular passwords for SMTP since May 2022. `smtp_pass` must be a 16-character App Password from `myaccount.google.com/apppasswords`.

---

## Changelog (Fixes Applied)

### Session 1 — Scanner & Intelligence Bug Fixes

| File | Fix |
|------|-----|
| `intelligence/nvd.py` | Added `User-Agent`/`Accept` headers; 3-retry backoff; full paginated sync (240k+ CVEs); incremental 30-day mode after first run |
| `intelligence/cisa.py` | Added `User-Agent`/`Accept` headers; 3-retry backoff; version-skip bypass when DB is empty |
| `intelligence/github_adv.py` | Full paginated sync via `Link` headers; 100/page; `type=reviewed` filter; retry backoff |
| `intelligence/epss.py` | Added `User-Agent`/`Accept` headers; 3-retry backoff |
| `scanners/nmap.py` | Removed `-O` (needs root), `-p-` (too slow), `-sC`; replaced with `-F -sV -T4` |
| `scanners/ffuf.py` | Replaced `-o -` (created file named `-`) with `tempfile.NamedTemporaryFile`; temp cleanup on all exit paths |
| `scanners/traceroute.py` | Removed `-I` (ICMP, needs root); replaced with `-n` (UDP, no root) |
| `tools/tool_installer.py` | Changed Wapiti and SQLMap from `apt` to `pip`; updated binary-check logic |
| `tools/config_manager.py` | Added `sqlmap_path`, `wapiti_path`, `traceroute_path` to `DEFAULT_SETTINGS` |
| `tools/alert_engine.py` | Added `test_smtp_connection()`; Gmail App Password error guidance; actionable auth error messages |
| `setup.sh` | Full rewrite: auto-downloads Go; pre-built binary fallback; removed `set -e`; added sqlmap/wapiti/traceroute installs |
| `run.sh` | Added `./bin/`, `~/go/bin`, `/usr/local/go/bin` to PATH |
| Project root | Deleted stray file named `-` (created by ffuf `-o -` bug) |
