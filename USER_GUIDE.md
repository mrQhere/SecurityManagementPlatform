<div align="center">

```
███████╗███╗   ███╗██████╗
██╔════╝████╗ ████║██╔══██╗
███████╗██╔████╔██║██████╔╝
╚════██║██║╚██╔╝██║██╔═══╝
███████║██║ ╚═╝ ██║██║
╚══════╝╚═╝     ╚═╝╚═╝
```

**Security Management Platform**

`local-first` &nbsp;·&nbsp; `zero-cloud` &nbsp;·&nbsp; `encrypted at rest` &nbsp;·&nbsp; `correlation-driven`

*Made by [@mrQhere](https://github.com/mrQhere)*

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-orange)

</div>

---

> SMP is designed like a precision instrument — invisible internals, deliberate output, zero noise.

---

## 📋 Table of Contents

| # | Section |
|---|---------|
| 0 | [⚡ Beginner Quick Start](#0--beginner-quick-start) — **start here if new** |
| 1 | [Philosophy & Architecture](#1--philosophy--architecture) |
| 2 | [Setup & Installation](#2--setup--installation) — Linux · macOS · Windows · Docker |
| 3 | [First Run & Daily Operations](#3--first-run--daily-operations) |
| 4 | [Scanner Pipeline & Tool Inventory](#4--scanner-pipeline--tool-inventory) |
| 5 | [Intelligence & Correlation Stack](#5--intelligence--correlation-stack) |
| 6 | [Compliance Mapping & Reports](#6--compliance-mapping--reports) |
| 7 | [Core Internals & Encryption](#7--core-internals--encryption) |
| 8 | [Custom Scanners & REST API](#8--custom-scanners--rest-api) |
| 9 | [Troubleshooting](#9--troubleshooting) |
| 10 | [Roadmap & Future Timeline](#10--roadmap--future-timeline) |

---

## 0 · Beginner Quick Start

> **Never used a security scanner before? Start here.** You only need to follow 4 steps.

### What is SMP?

SMP is a tool that checks a website or server for security weaknesses. Think of it as a medical checkup — but for computers. It runs a series of automated tests, then produces a report showing what it found and how serious each issue is.

**It does NOT**:
- Hack anything without your permission
- Send your data to any cloud service
- Require an internet subscription or account

**You need**: A Linux/macOS computer, internet access to download it once, and permission to test the target.

### 4-Step Setup (Linux)

```bash
# Step 1 — Download SMP
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Step 2 — Install everything automatically (takes ~2 minutes)
bash setup.sh

# Step 3 — Start SMP
./run.sh

# Step 4 — Open your browser and go to:
# http://localhost:8000/api/v7/docs
```

The installer handles Python, Go, all security tools, and the encrypted database automatically. You do not need to install anything manually.

### Running your first scan

1. SMP opens a dashboard window automatically
2. Click **"Add Target"** and type a URL you own or have permission to scan (e.g. `https://example.com`)
3. Select **`standard`** scan profile (safe for most use cases)
4. Click **"Start Scan"** and watch the Live Monitor
5. When finished, open the PDF report from the `reports/` folder

### Scan profiles — which one to pick?

| Profile | What it does | Who should use it |
|---------|-------------|-------------------|
| `osint` | Passive info gathering only. No active probing. | Beginners, scoping phase |
| `standard` | Full scan, no destructive tools | Default — most users |
| `full` | Everything, including brute-force & active exploitation tests | **Professionals with written permission only** |

---

## 1 · Philosophy & Architecture

### Why SMP exists

Most scanner wrappers do one thing: run a tool, dump output. SMP does something structurally different — it **correlates**. After scanning, every finding is cross-referenced against four live threat-intelligence sources to produce a single risk score that reflects real-world exploitability, not just theoretical CVSS.

SMP is also **local-first by design**. Every byte of client pentest data stays on your machine. You choose which intelligence APIs to query; you get an audit log proving it.

### What it is not

- ❌ Not an AI agent. There is no LLM. Deferred to V9.
- ❌ Not competing on tool count (HexStrike has 150+, that is not the angle).
- ❌ Not cloud-dependent. No registration, no telemetry, no SaaS.

### Architecture overview

```
┌─────────────────────────────────────────────────────────────┐
│  SMP V7 Architecture                                        │
├──────────────┬──────────────────────────┬───────────────────┤
│  Interface   │  Orchestration           │  Storage          │
│              │                          │                   │
│  PySide6 GUI │  scan_runner.py          │  SQLCipher AES-256│
│  FastAPI REST│  → DAG Orchestrator      │  security.db      │
│  HTML/PDF    │  → 30+ scanner modules   │  cve.db           │
│  Reports     │  → egress_auditor        │  redundancy.db    │
│              │  → compliance_mapper     │  (all encrypted)  │
├──────────────┴──────────────────────────┴───────────────────┤
│  Intelligence Layer                                          │
│  NVD · EPSS · GreyNoise · CISA KEV · MITRE ATT&CK           │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Technology | File |
|-------|-----------|------|
| GUI | PySide6 | `dashboard.py` |
| API | FastAPI + JWT | `api/` |
| DB | SQLCipher (AES-256) | `tools/db_manager.py` |
| Pipeline | DAG + multiprocessing | `scanners/scan_runner.py` |
| Intelligence | REST + local cache | `intelligence/` |
| Encryption | Fernet + PBKDF2-SHA256 | `tools/encryption_manager.py` |

---

## 2 · Setup & Installation

### 2.1 Prerequisites

| Requirement | Minimum | Notes |
|------------|---------|-------|
| OS | Linux · macOS · Windows | All three supported with dedicated scripts |
| Python | 3.10+ | `python3 --version` |
| RAM | 2 GB free | 4 GB recommended for full scans |
| Disk | 3 GB free | Tools + databases |
| Git | Any | To clone the repository |
| sudo / Admin | Required on Linux/macOS | For Nmap, Masscan, MAC changer |

> **V7 hard requirement:** `pysqlcipher3` (SQLCipher) must be available. SMP exits loudly at startup if missing — this enforces the "encrypted at rest" guarantee unconditionally.

---

### 2.2 Linux / macOS — Automated Setup

One script handles everything: Python venv, SQLCipher, all Go tools as prebuilt binaries, WPScan with Docker fallback.

```bash
# 1. Clone
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# 2. Run the auto-installer (shows progress bar + elapsed time per step)
./setup.sh

# 3. Launch
./run.sh

# Headless API mode only
./run.sh --api
```

`run.sh` automatically activates the venv and verifies SQLCipher before starting. No manual `source venv/bin/activate` needed.

#### What `setup.sh` does — V7

| Step | Action | Speed |
|------|--------|-------|
| 1 | Python 3 check — skip if already present | ~1s |
| 2 | Go check — skip if already present | ~1s |
| 3 | apt packages — skip each if already installed | ~10s |
| 4 | Python venv + `pip install -r requirements.txt` (spinner) | ~30s |
| 5 | SQLCipher: `pip install pysqlcipher3` (hard requirement) | ~5s |
| 6 | Go tools: **prebuilt binaries via `curl`** from GitHub Releases | **~30s** |
| 7 | WPScan: `gem install` → Docker wrapper fallback | ~10s |
| 8 | Finalize, chmod, completion summary | ~1s |

> **V7 vs V6:** Step 6 previously used `go install ... @latest` (source compilation, ~15 min). V7 downloads official prebuilt release binaries — same result, 30× faster. Source build is the fallback only.

#### Prebuilt Go tool binaries

| Tool | GitHub source | Version |
|------|---------------|---------|
| `nuclei` | projectdiscovery/nuclei | v3.3.7 |
| `subfinder` | projectdiscovery/subfinder | v2.6.7 |
| `httpx` | projectdiscovery/httpx | v1.6.9 |
| `katana` | projectdiscovery/katana | v1.1.2 |
| `dnsx` | projectdiscovery/dnsx | v1.2.1 |
| `ffuf` | ffuf/ffuf | v2.1.0 |
| `gitleaks` | gitleaks/gitleaks | v9.1.3 |
| `dalfox` | hahwul/dalfox | v2.9.3 |

---

### 2.3 Windows — Automated Setup

Two Windows scripts are provided — choose one:

**Option A — PowerShell (recommended):**
```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\setup.ps1
python main.py
```

**Option B — Command Prompt / Batch:**
```cmd
:: Run as Administrator
setup.bat
python main.py
```

Both scripts use `winget` with direct-download fallbacks for Python, Go, and all security tools. SQLCipher on Windows: the scripts install the required Windows SQLCipher bindings automatically.

> Some scanners (Nmap raw SYN scan, Masscan, MAC changer) require Administrator privileges on Windows. Run `setup.bat` / `setup.ps1` as Administrator for full functionality.

---

### 2.4 Docker — All Platforms

Docker is the easiest path on any OS. All tools, dependencies, and SQLCipher are bundled — nothing to install on the host.

```bash
# Build the V7 image
make docker-build
# or: docker build -t smp:v7 .

# Start (detached)
make docker-run
# or: docker compose up -d

# Check health
make docker-health
# → http://localhost:8000/api/v7/health

# View live logs
make docker-logs

# Open interactive shell inside container
make docker-shell

# Stop
make docker-stop

# Stop and remove volumes
make docker-clean
```

API docs available at: `http://localhost:8000/api/v7/docs`

---


### 2.5 SQLCipher — if startup fails

`setup.sh` installs SQLCipher automatically. If you skipped setup or installed manually and see the fatal error on launch:

```bash
# Linux — Ubuntu 24.04 (Noble) and newer
sudo apt install libsqlcipher-dev libsqlcipher0t64
pip install pysqlcipher3

# Linux — Ubuntu 22.04 / Debian Bookworm and older
sudo apt install libsqlcipher-dev libsqlcipher0
pip install pysqlcipher3

# Not sure which Ubuntu you have?
lsb_release -rs   # 24.04+ → use libsqlcipher0t64 ; 22.04 → use libsqlcipher0

# macOS (Homebrew)
brew install sqlcipher
pip install pysqlcipher3

# Windows — handled by setup.ps1 / setup.bat automatically
```

Then re-run `./run.sh`. SMP will not start in plaintext mode — this is by design.

---

### 2.6 Local-Only Mode (Zero Egress)

Blocks all outbound intelligence API calls. Every call attempt is still logged to `logs/egress_audit.log` as `BLOCKED` — giving you a provable audit trail.

```bash
# Linux / macOS
SMP_LOCAL_ONLY=1 ./run.sh

# Windows
$env:SMP_LOCAL_ONLY="1"; python main.py
```

Or set permanently in `config/settings.json`:
```json
{ "local_only_mode": true }
```

---


## 3 · First Run & Daily Operations

### 3.1 First launch checklist

On first launch, SMP automatically:
1. Verifies SQLCipher is available (hard fail if not)
2. Creates encrypted databases (`database/security.db`, `database/cve.db`)
3. Starts background CVE sync from NVD
4. Starts the FastAPI server on `localhost:8000`
5. Opens the PySide6 dashboard

### 3.2 UI Sections

| Section | Purpose |
|---------|---------|
| 🏠 **Dashboard** | Add targets, view risk scores, monitor live scans |
| 🎯 **Targets** | Manage domains/IPs, view scan history |
| 🧠 **Threat Intel** | Live CVE database, force NVD sync, EPSS scores |
| 📋 **Audit Logs** | Immutable activity trail, egress audit log |
| ⚙️ **Settings** | SMTP, proxies, scan profile, auth headers |

### 3.3 Running a scan

```
1. Dashboard → "Add Target" → enter https://example.com
2. Select scan profile:
   • osint   — passive recon only (safe, no active probing)
   • standard — full VAPT, no destructive tools (default)
   • full    — includes ZAP active scan, Commix, Hydra (invasive)
3. Click "Start Scan"
4. Watch the Live Monitor — real-time narrative of every step
```

### 3.4 Scan profiles

| Profile | Phases run | Use case |
|---------|-----------|---------|
| `osint` | Recon only | External recon, scoping |
| `standard` | Recon + Active + Conditional | Standard pentest engagement |
| `full` | All phases, aggressive tools | With explicit written permission |

### 3.5 Reading scan output

The Live Monitor streams narrative log lines:

```
[00:00:02] [STAGE]    RECON started — passive reconnaissance
[00:00:04] [INFO]     HTTPx — target alive, 200 OK, nginx/1.24
[00:00:18] [INFO]     WhatWeb — WordPress 6.4.3 detected
[00:01:45] [BRANCH]   WordPress detected → WPScan queued
[00:03:12] [FINDING]  [HIGH] Nuclei — CVE-2024-1234 confirmed
[00:04:01] [INFO]     EPSS score: 0.847 (84.7% exploitation probability)
[00:04:01] [INFO]     CISA KEV: YES — actively exploited in the wild
```

### 3.6 Authenticated scanning

To scan behind login walls, add session cookies or Bearer tokens in **Settings → Auth Headers**. These are injected into Nuclei, Nikto, and HTTPx automatically.

### 3.7 Scheduled scans

Use **Settings → Scheduler** to configure recurring scans (daily/weekly). The watchdog module runs lightweight 15-minute checks between full scans:
- HTTP status drift
- Page content hash (defacement detection)
- DNS A record change (hijacking indicator)
- SSL certificate fingerprint change
- New open ports (backdoor detection)

---

## 4 · Scanner Pipeline & Tool Inventory

### 4.1 DAG execution model

SMP V7 runs scanners as a **Directed Acyclic Graph** — not a fixed sequence. Up to 6 scanners run in parallel where dependencies allow. Phase 3 (Conditional) steps only activate when Phase 1/2 evidence warrants it.

```
Phase 1 — Recon (parallel)
  HTTPx ──┐
  WhatWeb ─┤
  Subfinder┤──→ Phase 2 — Active (parallel)
  CRT.sh ──┤       Nmap ─────┐
  Whois ───┤       SSL ──────┤──→ Phase 3 — Conditional
  Wayback ─┘       Nuclei ───┘       WPScan (if WordPress)
                   Nikto             Dalfox (if XSS surface)
                   ffuf              Hydra  (if SSH open)
                   Gitleaks          ZAP    (if full profile)
```

### 4.2 Complete tool inventory

#### 🔍 Reconnaissance

| Tool | What it finds | File |
|------|-------------|------|
| **HTTPx** | HTTP metadata, redirects, tech headers | `scanners/httpx_scanner.py` |
| **WhatWeb** | CMS, frameworks, server software | `scanners/whatweb.py` |
| **Subfinder** | Passive subdomain enumeration (50+ sources) | `scanners/subfinder.py` |
| **CRT.sh** | Certificate Transparency subdomain logs | `scanners/crtsh.py` |
| **HackerTarget** | Reverse DNS, AS info, port scan API | `scanners/hackertarget.py` |
| **Whois** | Domain registration, registrar, nameservers | `scanners/whois_scanner.py` |
| **Wayback Machine** | Historical URL archive, hidden endpoints | `scanners/wayback.py` |
| **theHarvester** | Emails, subdomains, hosts, employee names | `scanners/theharvester.py` |
| **Traceroute** | Network path, hop latency | `scanners/traceroute.py` |

#### 🔬 Active Scanning

| Tool | What it finds | File |
|------|-------------|------|
| **Nmap** | Open ports, service versions, OS fingerprint | `scanners/nmap.py` |
| **SSL Scanner** | Weak ciphers, expired certs, TLS version | `scanners/ssl_scanner.py` |
| **Security Headers** | Missing CSP, HSTS, X-Frame-Options, etc. | `scanners/headers_scanner.py` |
| **CORS Scanner** | Insecure CORS policies | `scanners/cors_scanner.py` |
| **Robots.txt** | Hidden paths, admin panels in sitemap | `scanners/robots_scanner.py` |
| **CMS Scanner** | WordPress/Joomla/Drupal version + plugins | `scanners/cms_scanner.py` |
| **Nikto** | 6700+ web server vulnerability checks | `scanners/nikto.py` |
| **Nuclei** | Template-based CVE/misconfiguration scan | `scanners/nuclei.py` |
| **ffuf** | Directory/file fuzzing (SPA false-positive filtered) | `scanners/ffuf.py` |
| **Open Redirect** | URL parameter redirect injection | `scanners/open_redirect.py` |
| **Tech Fingerprint** | Deep response-based stack detection | `scanners/tech_fingerprint.py` |
| **Shodan InternetDB** | Passive IP exposure, open ports, CVEs | `scanners/shodan_idb.py` |
| **Gitleaks** | Hardcoded secrets in git repos | `scanners/gitleaks.py` |
| **Wapiti** | OWASP web app fuzzer | `scanners/wapiti.py` |
| **SQLMap** | SQL injection detection | `scanners/sqlmap.py` |

#### ⚡ Conditional (Phase 3)

<table>
<thead>
<tr><th>Tool</th><th>Trigger condition</th><th>What it tests</th></tr>
</thead>
<tbody>
<tr><td><strong>WPScan</strong></td><td>WordPress detected</td><td>WordPress CVEs, plugin vulns</td></tr>
<tr><td><strong>Dalfox</strong></td><td>XSS surface found</td><td>Parameter-level XSS, DOM XSS</td></tr>
<tr><td><strong>Arjun</strong></td><td>Web app detected</td><td>Hidden HTTP parameters</td></tr>
<tr><td><strong>DNSx</strong></td><td>Subdomains found</td><td>DNS record analysis</td></tr>
<tr><td><strong>Katana</strong></td><td>Web app alive</td><td>Deep crawling &amp; spidering</td></tr>
<tr><td><strong>Masscan</strong></td><td>Port scan needed at scale</td><td>High-speed TCP SYN scan</td></tr>
<tr><td><strong>ParamSpider</strong></td><td>URL parameters found</td><td>Web archive parameter mining</td></tr>
<tr><td><strong>Cloud Enum</strong></td><td>Cloud assets referenced</td><td>AWS/Azure/GCP public buckets</td></tr>
<tr><td><strong>JWT Scanner</strong></td><td>JWT tokens in responses</td><td>Algorithm confusion, weak keys</td></tr>
<tr><td><td colspan="3"><span style="color:red"><strong>⚠ WARNING — ACTIVE EXPLOITATION — full profile only — requires written permission from target owner</strong></span></td></tr>
<tr><td><strong>Commix</strong></td><td>Command injection surface found</td><td>OS command injection attempts</td></tr>
<tr><td><strong>OWASP ZAP</strong></td><td><code>full</code> profile only</td><td>Active DAST — sends malicious payloads</td></tr>
<tr><td><strong>Hydra</strong></td><td>SSH/FTP port open + <code>full</code> profile</td><td>Brute-force credential attacks</td></tr>
</tbody>
</table>

> <span style="color:red">**⚠ LEGAL WARNING**</span> — Tools marked above (Commix, ZAP active scan, Hydra) **send attack payloads** to the target. Running them against systems you do not own or have **written, explicit permission** to test is **illegal** in most jurisdictions (Computer Fraud and Abuse Act, UK Computer Misuse Act, EU Directive 2013/40/EU, and equivalents worldwide). SMP gates these tools behind the `full` profile precisely to prevent accidental use. Always obtain written authorisation before enabling `full` profile.

#### 🛠️ Support Tools

| Tool | Purpose |
|------|---------|
| **Screenshot Capture** | Headless Chromium evidence screenshots |
| **Secrets Scanner** | API keys/JWT/PEM detection in HTTP responses |
| **Netcat Probe** | Raw TCP banner grabbing |
| **HTTP Smuggler** | CL.TE / TE.CL request smuggling |
| **SSRF Scanner** | Server-Side Request Forgery parameters |
| **XXE Scanner** | XML External Entity injection |
| **Path Traversal** | LFI / directory traversal |
| **GraphQL Scanner** | Introspection abuse, batch attacks |
| **CRLF Scanner** | Header injection |

#### 🏢 Enterprise & Cloud Tools (V9.1.3)

| Tool | What it tests | Trigger condition |
|------|---------------|-------------------|
| **Trivy** | Container image and filesystem vulnerabilities, SBOM generation | Cloud/Container setting enabled |
| **Prowler** | AWS/Azure/GCP Cloud Security Posture Management (CSPM) | Cloud/Container setting enabled |
| **ClamAV** | File-based malware and YARA rule static analysis | Malware Scan setting enabled |
| **MobSF** | Mobile App Security (APK/IPA) reverse engineering API | MobSF API key provided |
| **CrackMapExec** | Internal Active Directory, SMB, and lateral movement | Internal network target |

### 4.3 SPA false-positive filter

ffuf on React/Vue/Angular SPAs returns 200 for every path (catch-all routing). SMP detects when ≥80% of results share the same Content-Length and removes them automatically. Code: `scan_runner.py::_filter_spa_ffuf_results`.

### 4.4 Deferred retry queue

Any scanner that times out or fails in Phase 1 is added to a deferred retry queue. After the main pipeline completes, failed steps are re-attempted with 1.5× timeout. This prevents a slow network from permanently skipping steps.

### 4.5 Adding Custom Scanners in 60 Seconds

Thanks to the **V9.1.3 Zero-Friction Plugin Registry**, adding your own custom security tools to the SMP pipeline is fully automated. You no longer need to wire up databases, UI toggles, or orchestration logic.

Simply use the built-in generator:

```bash
python3 tools/create_scanner.py --name "MyTool" --binary "mytool" --severity High
```

This will automatically scaffold a new python file in the `scanners/` directory (e.g., `scanners/mytool.py`). 

**All you have to do is:**
1. Open the newly generated `scanners/mytool.py`.
2. Update the `cmd` variable to pass your specific CLI arguments.
3. Update the parser logic (Step 3 in the generated file) to map your tool's output to SMP's findings database.

The next time you run SMP, it will **auto-discover** your tool, run it during the scan pipeline, save its output to the database, and automatically inject its findings into the final PDF report.

---

## 5 · Intelligence & Correlation Stack

This is V7's primary differentiator. Most scanner wrappers report raw CVSS. SMP cross-references every CVE finding against four live sources.

### 5.1 How correlation works

```
Finding: "Apache 2.4.49 detected"
          │
          ▼
    NVD lookup → CVE-2021-41773 (CVSS 9.8)
          │
          ├─→ EPSS → 0.974  (97.4% exploitation probability)
          │
          ├─→ CISA KEV → YES (actively exploited, added 2021-11-03)
          │
          ├─→ GreyNoise → 847 scanners hitting this daily
          │
          └─→ Composite Risk Score → 98/100 CRITICAL
```

### 5.2 Intelligence sources

#### 🟠 NVD — National Vulnerability Database
- **Source:** `https://services.nvd.nist.gov/`
- **What it adds:** CVSSv3 base score, affected product/version matching, CWE classification
- **Sync:** Background worker syncs new CVEs hourly
- **File:** `intelligence/nvd.py`

#### 🔴 EPSS — Exploit Prediction Scoring System
- **Source:** `https://api.first.org/data/v1/epss` (FIRST.org)
- **What it adds:** A 0.0–1.0 score representing the probability of exploitation in the wild within the next 30 days. A CVE with CVSS 9.8 and EPSS 0.02 is far less urgent than one with CVSS 7.5 and EPSS 0.94.
- **Sync:** Batch enrichment of up to 2,000 CVEs per run
- **File:** `intelligence/epss.py`
- **Egress:** Logged to `logs/egress_audit.log`; blocked in local-only mode

#### 🟤 GreyNoise — Internet Scanner Intelligence
- **Source:** `https://api.greynoise.io/v3/community/{ip}` (Community API — free, no key)
- **What it adds:** Classifies discovered IPs as:
  - `noise` — known mass-scanners (Shodan bots, search engine crawlers)
  - `riot` — known benign infrastructure (AWS, Cloudflare)
  - `malicious` — known threat actor infrastructure
  - `unknown` — no data
- **Effect:** Malicious IPs in findings trigger severity escalation (Info/Low → Medium)
- **File:** `intelligence/greynoise.py`
- **Egress:** Logged; skipped for RFC1918 private IPs

#### 🔵 CISA KEV — Known Exploited Vulnerabilities
- **Source:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **What it adds:** A boolean flag: is this CVE on the US government's confirmed-exploited list? KEV CVEs receive a **2× score multiplier** in the risk scorer.
- **Update:** Synced daily
- **File:** `intelligence/cisa.py`

#### 🟣 MITRE ATT&CK
- **What it adds:** Maps findings to ATT&CK tactics (Initial Access, Execution, Persistence…) and technique IDs (T1190, T1059…)
- **File:** `intelligence/mitre_mapper.py`

### 5.3 Risk scoring formula

```python
# tools/risk_scorer.py (simplified)
base_score = cvss_score / 10           # 0.0–1.0
epss_bonus  = epss_score * 0.3         # up to +0.3
kev_mult    = 2.0 if is_cisa_kev else 1.0
gn_mult     = 1.3 if greynoise_malicious else 1.0

risk = min(100, base_score * kev_mult * gn_mult * 100 + epss_bonus * 10)
```

Full implementation at `tools/risk_scorer.py`. Only findings with confidence ≥ 60 are scored. Info-level findings have near-zero weight.

| Score | Rating |
|-------|--------|
| 0–20 | Minimal |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---
## 6 · Compliance Mapping & Reports

### 6.1 What compliance mapping does

Every finding is automatically mapped to control IDs across five frameworks. This is the difference between a report that says "40 vulnerabilities found" and one that says "here is what is blocking your SOC 2 audit."

**Code:** `tools/compliance_mapper.py`

### 6.2 Supported frameworks

| Framework | Controls mapped | Key use case |
|-----------|----------------|-------------|
| **OWASP Top 10 2021** | A01–A10 | Web application security baseline |
| **CIS Controls v8** | 11 controls | Infrastructure hardening benchmark |
| **ISO 27001:2022** | Annex A controls | International ISMS certification |
| **SOC 2 Type II** | CC6.1–CC9.2 | SaaS / cloud audit readiness |
| **PCI-DSS v9.1.3** | Req 4, 6, 7, 8, 11, 12 | Payment card industry compliance |

### 6.3 Using the compliance mapper

```python
from tools.compliance_mapper import map_finding_to_controls, get_compliance_summary

# Map a single finding
controls = map_finding_to_controls("SQL Injection", "CWE-89")
# Returns:
# {
#   "owasp":    ["A03:2021 - Injection"],
#   "cis":      ["CIS 16 - Application Software Security"],
#   "iso27001": ["A.8.28 - Secure Coding"],
#   "soc2":     ["CC6.6 - Security Threats from Outside Boundaries"],
#   "pci_dss":  ["Req 6.2.4 - Injection Prevention"]
# }

# Get summary across all scan findings
summary = get_compliance_summary(findings)
# Returns coverage % per framework + audit_blocking_findings
```

### 6.4 Audit-blocking findings

The most actionable output: `audit_blocking_findings` lists Critical/High severity findings that directly violate SOC 2 or PCI-DSS controls. This is what an auditor will ask about.

```python
summary["audit_blocking_findings"]
# [
#   {
#     "title": "SQL Injection in /login",
#     "severity": "Critical",
#     "soc2":    ["CC6.6", "CC7.2"],
#     "pci_dss": ["Req 6.2.4", "Req 6.4.1"]
#   }
# ]
```

### 6.5 Report structure

Every completed scan automatically generates:

```
reports/
├── html/   SMP_target.com_Report_2026-07-25.html
├── pdf/    SMP_target.com_Report_2026-07-25_a1b2c3d4.pdf
└── sbom/   SMP_target.com_SBOM_2026-07-25.json
```

**PDF sections:**

| Section | Content |
|---------|---------|
| 1 — Cover | Target, date, auditor, SHA-256 content hash |
| 2 — Executive Summary | Risk posture, trend delta vs. previous scan |
| 3 — Scope & Methodology | Tools used, phase boundaries |
| 4 — Findings Matrix | Severity distribution table |
| 5 — Deep-Dive Findings | Per-finding: description, evidence, CVSS, EPSS, compliance IDs, remediation |
| 6 — Appendices | Tool list, clean-up log, severity glossary, attestation |

### 6.6 SBOM — Software Bill of Materials

Every scan produces a CycloneDX JSON SBOM alongside the pentest report. No separate tool or run required.

**What goes in the SBOM:** Every software component detected during technology fingerprinting (WhatWeb, HTTPx, Tech Fingerprint) — framework name, version, category, confidence score.

**Fallback chain:**
1. CycloneDX JSON (preferred — industry standard, NTIA-compliant)
2. SPDX tag-value format (if `cyclonedx-python-lib` not installed)
3. CSV (always works)

```python
# Auto-called from report_generator.py on every scan
from tools.sbom_generator import generate_sbom_for_scan
sbom_path = generate_sbom_for_scan(scan_id, target_url, output_dir="reports/sbom/")
```

### 6.7 Report verification

Reports embed a SHA-256 content hash derived from scan facts (URL, date, finding counts, auditor name). Verify a report offline — no database needed:

```bash
python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2026-07-25_a1b2c3d4.pdf
# ✔  Report is authentic. Content hash verified.

python3 tools/verify_report.py reports/html/SMP_example.com_Report_2026-07-25.html
```

The hash is also stored in the database via `save_report_hash()` for cross-reference.

---

## 7 · Core Internals & Encryption

### 7.1 SQLCipher — Encrypted at rest (hard requirement)

**V7 change:** SMP now exits at startup if `pysqlcipher3` is not installed. There is no plaintext fallback.

All three databases are AES-256 encrypted:

```
database/
├── security.db     — targets, scans, findings, technologies
├── cve.db          — NVD CVE data, EPSS scores, CISA KEV flags
└── redundancy.db   — backup mirror for HA failover
```

Key derivation:
- **Algorithm:** PBKDF2-HMAC-SHA256
- **Iterations:** 600,000 (NIST 2024 recommendation)
- **Salt:** Random 32-byte salt stored alongside derived key

To manually inspect (requires the derived key):
```bash
sqlcipher database/security.db
sqlite> PRAGMA key = 'your_derived_key';
sqlite> .tables
```

### 7.2 Fernet encryption for raw scan output

Raw scanner stdout is compressed (gzip) and encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before storage:

```python
# tools/encryption_manager.py
encrypt_data(raw_output)   # → compressed + encrypted bytes
decrypt_data(blob)         # → original raw output
```

### 7.3 Egress Audit Log

**V7 addition:** Every outbound network request SMP makes during intelligence enrichment is recorded.

**File:** `logs/egress_audit.log` — one JSON line per call:
```json
{"ts":"2026-07-25T18:30:01Z","service":"GreyNoise","url":"https://api.greynoise.io/v3/community/1.2.3.4","purpose":"IP reputation / wild scanning check","status":"ALLOWED"}
{"ts":"2026-07-25T18:30:02Z","service":"EPSS (FIRST.org)","url":"https://api.first.org/data/v1/epss","purpose":"EPSS exploitation probability — batch of 47 CVEs","status":"ALLOWED"}
```

In local-only mode (`SMP_LOCAL_ONLY=1`), status becomes `BLOCKED` and the call is suppressed.

**API:**
```python
from tools.egress_auditor import egress_auditor

# Get session summary for a scan
summary = egress_auditor.get_session_summary()
# {
#   "total_outbound_calls": 14,
#   "allowed": 14, "blocked": 0,
#   "external_services": ["CISA KEV", "EPSS (FIRST.org)", "GreyNoise", "NVD"],
#   "local_only_mode": false,
#   "audit_log_path": "logs/egress_audit.log"
# }
```

### 7.4 Event Bus (IPC)

Thread-safe publish/subscribe bus decoupling scanner threads from the UI:

```python
from tools import event_bus

# Publisher (scanner thread)
event_bus.emit("finding_discovered", {"severity": "High", "title": "..."})
event_bus.emit("scanner_progress", {"step": "Nmap", "pct": 45})

# Subscriber (dashboard)
event_bus.subscribe("finding_discovered", my_callback)
```

### 7.5 MAC Address OPSEC

At scan start (not app start), SMP randomises the last 3 octets of the network interface MAC address while preserving the vendor OUI. This makes the changed MAC look like the same hardware — far less suspicious on managed networks.

- Controlled by `"mac_changer_enabled": true` in `config/settings.json`
- Non-fatal: if MAC change fails, scan proceeds
- Restored on scan completion

### 7.6 Session auto-lock

After configurable idle time (default: 15 minutes), the dashboard re-requires password. No full restart needed.

```python
from tools.session_manager import SessionManager
sm = SessionManager(timeout_minutes=15, on_lock=dashboard.trigger_lock)
sm.start()
sm.reset()  # call on any user interaction
```

---

## 8 · Custom Scanners & REST API

### 8.1 Adding a Custom Scanner (Detailed Guide)

Adding a new tool to SMP involves three phases: **Provisioning**, **Execution Logic**, and **Pipeline Registration**. SMP’s architecture abstracts away the threading and logging, allowing you to focus purely on the tool’s logic.

#### Phase 1: Provisioning (Tool Requirements)

If your new tool requires external dependencies (Go binaries, apt packages, pip libraries, or Ruby gems), you must declare them in the automated installer so `setup.sh` and `Docker` handle them gracefully.

**Step 1:** Open `tools/tool_installer.py` (or equivalent setup scripts) and add your tool’s requirements.

*Example — Adding a new Go-based tool:*
```bash
# In setup.sh
# SMP V7 prefers downloading prebuilt binaries for Go tools to save time.
curl -sL https://github.com/projectdiscovery/newtool/releases/download/v1.0/newtool-linux.zip -o newtool.zip
unzip newtool.zip -d /usr/local/bin/
```

*Example — Adding a Python-based tool:*
Add it to `requirements.txt` to ensure it is installed within the virtual environment:
```text
new_python_tool>=2.1.0
```

#### Phase 2: Execution Logic

Create a new wrapper script in the `scanners/` directory. This script will execute the tool, parse its output, and yield structured findings.

**Step 2:** Create `scanners/my_custom_tool.py`:

```python
import subprocess
import json
from tools.narrative_logger import emit, emit_finding

def run_my_custom_tool(target_url: str, scan_id: int, settings: dict) -> list:
    """
    Executes 'my_custom_tool' and parses the output.
    """
    # 1. Announce that the tool is starting in the Live Monitor
    emit(scan_id, "my_custom_tool", f"Starting scan on {target_url}")
    
    results = []
    
    # 2. Build the command line array (prevents shell injection)
    command = ["my_custom_tool", "--target", target_url, "--json"]
    
    try:
        # 3. Execute the tool with a strict timeout
        process = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=120  # Always enforce timeouts!
        )
        
        # 4. Handle tool-specific errors
        if process.returncode != 0:
            emit(scan_id, "my_custom_tool", f"Tool exited with code {process.returncode}")
            return []
            
        # 5. Parse the output (assuming JSON for this example)
        output_data = json.loads(process.stdout)
        
        # 6. Translate raw output into SMP Findings
        for vuln in output_data.get("vulnerabilities", []):
            title = vuln.get("name", "Unknown Vulnerability")
            severity = vuln.get("severity", "Medium")
            
            # Broadcast finding to the UI immediately
            emit_finding(scan_id, "my_custom_tool", severity, title)
            
            # Append structured finding to the results list
            results.append({
                "title": title,
                "severity": severity,
                "description": vuln.get("desc", "No description provided."),
                "recommendation": vuln.get("remediation", "Investigate manually."),
                "confidence": 85,  # 0-100 scale
                "cwe": vuln.get("cwe", "CWE-200") # Optional but recommended
            })
            
    except subprocess.TimeoutExpired:
        emit(scan_id, "my_custom_tool", "Error: Scan timed out after 120s")
    except Exception as e:
        emit(scan_id, "my_custom_tool", f"Unexpected error: {e}")
        
    return results
```

#### Phase 3: Pipeline Registration

SMP uses a Directed Acyclic Graph (DAG) to determine when a tool should run. You must register your tool so the `scan_runner` knows about it.

**Step 3:** Open `scanners/core/registry.py` and register your tool:

```python
from scanners.my_custom_tool import run_my_custom_tool

register_scanner(
    name="My Custom Tool",
    step_name="Running My Custom Tool",
    scan_func=run_my_custom_tool,
    
    # The name of the binary on the system (used for pre-flight checks)
    binary_name="my_custom_tool", 
    
    # DAG dependencies: This tool will ONLY run after HTTPx finishes successfully.
    # Use empty list [] for Phase 1 (Recon) tools.
    depends_on=["HTTPx"], 
    
    # Base confidence score for this tool's findings (used by the risk scorer)
    confidence=85,
    
    # If True, SMP will refuse to run this step if the binary is missing
    needs_binary=True,
    
    # (Optional) Restrict this tool to specific scan profiles:
    # allowed_profiles=["standard", "full"] 
)
```

**Testing your new tool:**
Run a local test using the headless API to ensure your tool fires correctly:
```bash
./run.sh --api
# Trigger a scan via curl or the dashboard and monitor the logs
```

### 8.2 REST API reference

Base URL: `http://localhost:8000/api/v7/`  
Auth: Bearer JWT — obtain via `POST /auth/token`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/token` | ❌ | Get JWT token |
| GET | `/health` | ❌ | Platform health check |
| GET | `/target` | ✅ | List all targets |
| POST | `/target` | ✅ | Add target (`{"url": "https://..."}`) |
| DELETE | `/target/{id}` | ✅ | Remove target |
| GET | `/scan` | ✅ | List scans |
| POST | `/scan/{target_id}` | ✅ | Trigger scan |
| GET | `/scan/{id}/status` | ✅ | Scan status + current step |
| GET | `/findings/{scan_id}` | ✅ | All findings for scan |
| GET | `/cve/stats` | ✅ | CVE database statistics |
| GET | `/risk/score` | ✅ | Risk scores per target |
| GET | `/compliance/{scan_id}` | ✅ | Compliance mapping summary |
| GET | `/sbom/{scan_id}` | ✅ | Download SBOM for scan |
| GET | `/egress/audit` | ✅ | Current egress audit log |
| GET | `/version` | ✅ | Platform version |

Interactive docs: `http://localhost:8000/api/v7/docs`

### 8.3 API authentication example

```bash
# 1. Get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v7/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' | jq -r .access_token)

# 2. Add target
curl -X POST http://localhost:8000/api/v7/target \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# 3. Trigger scan
curl -X POST http://localhost:8000/api/v7/scan/1 \
  -H "Authorization: Bearer $TOKEN"

# 4. Poll status
curl http://localhost:8000/api/v7/scan/1/status \
  -H "Authorization: Bearer $TOKEN"
```

---
## 9 · Troubleshooting

> 📁 Extended troubleshooting guides are in [`troubleshooting/`](troubleshooting/)

### 9.1 Installation failures

#### ❌ Fatal: pysqlcipher3 not installed

```
╔══════════════════════════════════════════════════════════════╗
║  FATAL: pysqlcipher3 is not installed.                       ║
╚══════════════════════════════════════════════════════════════╝
```

**Fix — Ubuntu 24.04+ (Noble):**
```bash
sudo apt install libsqlcipher-dev libsqlcipher0t64
source venv/bin/activate
pip install pysqlcipher3
./run.sh
```

**Fix — Ubuntu 22.04 / Debian:**
```bash
sudo apt install libsqlcipher-dev libsqlcipher0
source venv/bin/activate
pip install pysqlcipher3
./run.sh
```

**Not sure which Ubuntu?** Run `lsb_release -rs` — `24.04` → use `libsqlcipher0t64`, anything older → use `libsqlcipher0`.

If `pip install pysqlcipher3` fails with compiler errors:
```bash
sudo apt install build-essential python3-dev
pip install pysqlcipher3 --no-binary pysqlcipher3
```

---

#### ❌ setup.sh: binary download failed for nuclei

Binary URL unreachable (network issue or GitHub rate limit).

**Fix:** setup.sh automatically falls back to `go install` source build. You'll see:
```
  ⚠ nuclei: prebuilt download failed — building from source (slow)
```
This takes ~5 minutes but succeeds. Re-run `./setup.sh` once network stabilises for the fast path.

---

#### ❌ Go not found after setup.sh

```bash
# Add Go to PATH if installed to /usr/local/go
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

#### ❌ WPScan not found / Docker wrapper not created

If both `gem install wpscan` and Docker are unavailable, WPScan simply won't run. This is non-fatal — all other scanners continue.

To use Docker wrapper manually:
```bash
docker pull wpscanteam/wpscan
# wrapper is at bin/wpscan after setup.sh runs with Docker available
```

---

### 9.2 Database errors

#### ❌ Database is locked

```
sqlite3.OperationalError: database is locked
```

Another SMP process is holding the connection. Find and kill it:
```bash
fuser database/security.db
kill -9 <PID>
```

Or restart cleanly:
```bash
pkill -f "python.*main.py"
./run.sh
```

---

#### ❌ SQLCipher: file is not a database

```
pysqlcipher3.dbapi2.DatabaseError: file is not a database
```

This means the database was created with a different key, or was not created by SQLCipher (e.g., imported plaintext SQLite file).

**Fix — create fresh databases:**
```bash
rm -f database/security.db database/redundancy.db
./run.sh   # will recreate with correct encryption
```

> ⚠️ This deletes all scan history. Back up first if needed.

---

#### ❌ Database migration error on upgrade

```
OperationalError: table 'xyz' already exists
```

The migration guard in `db_manager.py` uses `CREATE TABLE IF NOT EXISTS` for all tables. If you see a strict duplicate error:
```bash
python3 -c "from tools.db_manager import init_db; init_db(force=True)"
```

---

### 9.3 Scanner errors

#### ❌ Nmap: requires root / permission denied

```
QUITTING! -- Error: You requested a scan type which requires root privileges.
```

SMP runs Nmap with `sudo`. Pass your sudo password in **Settings → Scan Password** or start SMP with:
```bash
sudo -E ./run.sh    # not recommended for daily use
```

Better: add your user to sudoers for nmap specifically:
```bash
sudo visudo
# add: youruser ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

---

#### ❌ Nuclei: no templates found

```bash
nuclei -update-templates
# or
mkdir -p ~/.local/nuclei-templates
nuclei -update-templates -t ~/.local/nuclei-templates
```

---

#### ❌ ffuf returning thousands of false positives

SMP's SPA filter handles React/Vue/Angular catch-all 200s automatically. If you still see excess results, the target may genuinely expose many paths. Check the narrative log for the SPA filter message:
```
ffuf SPA Filter: Removed 847 catch-all false positives (content-length=2847 appeared in 94% of results)
```
If this line is absent, the filter didn't trigger — results are likely real.

---

#### ❌ theHarvester: module not found

```bash
source venv/bin/activate
pip install theHarvester
```

---

#### ❌ Dalfox / Katana / subfinder: binary not found

Check `bin/` directory and PATH:
```bash
ls bin/
export PATH=$PATH:$(pwd)/bin
```

Re-download a specific binary:
```bash
# Example: re-download dalfox
curl -fsSL https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz \
  | tar -xz -C bin/ dalfox
chmod +x bin/dalfox
```

---

### 9.4 API errors

#### ❌ 401 Unauthorized on all endpoints

Your JWT token has expired (default: 30 minutes). Re-authenticate:
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v7/auth/token \
  -d '{"username":"admin","password":"pass"}' | jq -r .access_token)
```

---

#### ❌ FastAPI won't start: address already in use

```bash
# Find what's on port 8000
lsof -i :8000
kill -9 <PID>
```

Or change the API port in `config/settings.json`:
```json
{ "api_port": 8001 }
```

---

#### ❌ 429 Rate Limit on API

The built-in rate limiter (per-IP) kicked in. Default: 60 requests/minute. For automated testing:
```json
{ "api_rate_limit": 300 }
```

---

### 9.5 Report generation errors

#### ❌ PDF not generated: ReportLab not installed

```bash
source venv/bin/activate
pip install reportlab
```

HTML report is always generated as fallback regardless.

---

#### ❌ SBOM generation failed

```
SBOM generation failed (non-fatal): No module named 'cyclonedx'
```

```bash
pip install cyclonedx-python-lib
```

SMP falls back to SPDX tag-value, then CSV — so a scan always completes even without this package.

---

#### ❌ Report verification: hash mismatch

```
✘  TAMPERED — content hash does not match embedded hash
```

The PDF was modified after generation (page added, content edited, or metadata changed). Use the original SMP-generated file. If you need to re-generate, re-run the report from the scan ID:
```python
from tools.report_generator import generate_scan_reports
generate_scan_reports(scan_id, target, findings)
```

---

### 9.6 Egress audit / local-only mode

#### ❌ GreyNoise returning cached/stale data

In-memory cache is per-session. Restart SMP to clear it. The cache only lives as long as the process.

#### ❌ Local-only mode not taking effect

Verify the env variable is exported:
```bash
export SMP_LOCAL_ONLY=1
./run.sh
# Check egress_audit.log — all entries should show "status": "BLOCKED"
```

Or check `config/settings.json`:
```json
{ "local_only_mode": true }
```

---

## 10 · Roadmap & Future Timeline

### Current release

| Area | What shipped |
|------|--------------|
| **Encryption** | SQLCipher AES-256 hard requirement — no plaintext fallback |
| **Install speed** | Prebuilt Go binaries via curl — 30× faster than `go install` |
| **Intelligence** | NVD + EPSS + GreyNoise + CISA KEV four-source correlation |
| **Compliance** | OWASP, CIS, ISO 27001, SOC 2, PCI-DSS auto-mapping |
| **Auditability** | Egress audit log — every outbound call logged with ALLOWED/BLOCKED |
| **Reports** | PDF + HTML + CycloneDX SBOM auto-generated per scan |
| **CI** | GitHub Actions pipeline — install, import, and SQLCipher checks |

### Future milestones

```
Q3 2026  ──────────────────────────────────────────────────────────────
         V8-alpha: multi-target queue, parallel scan workers
         Persistent scan scheduler (cron-style, not one-shot)
         REST API v2: webhook callbacks on scan completion

Q4 2026  ──────────────────────────────────────────────────────────────
         V8 stable: Kubernetes worker node support
         Distributed scan rotation across multiple IPs/proxies
         Team mode: multi-user auth, per-user audit trails

Q1 2027  ──────────────────────────────────────────────────────────────
         V9-alpha: Local LLM integration (Ollama)
           → Auto-generated finding narratives (no cloud)
           → False-positive reduction via local ML model
         Custom rule engine: user-defined scan policies

Q2 2027  ──────────────────────────────────────────────────────────────
         V9 stable: Full local-AI pentest narrative generation
         MITRE ATT&CK heatmap output in reports
         Supply-chain scanning: SBOM diff across deployments

2028+    ──────────────────────────────────────────────────────────────
         Plugin marketplace for third-party scanner modules
         Hardware token (YubiKey) support for database key unlock
         Mobile dashboard (read-only, encrypted sync)
```

> AI features (V9) are explicitly deferred — no LLM code ships until the local-first architecture is airtight. The README and codebase contain no AI-agent language until V9 actually ships.

---

<div align="center">

**SMP** · Local-first · Zero-cloud · Encrypted at rest  
Made by [@mrQhere](https://github.com/mrQhere) · © mrQhere

</div>

## 11 · Repository File Structure

> *Auto-generated by `tools/snapshot.py` on every semantic version update.*

```
SecurityManagementPlatform
├── .dockerignore
├── .github
│   └── workflows
│       ├── ci.yml
│       └── codeql-analysis.yml
├── .gitignore
├── .vscode
│   └── launch.json
├── Dockerfile
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
├── USER_GUIDE.md
├── api
│   ├── __init__.py
│   ├── auth.py
│   └── server.py
├── bin
├── cache
│   └── intel_cache.json
├── config
│   ├── hardening_rules.json
│   ├── metadata.json
│   ├── report_template.json
│   ├── responsibility.json
│   └── settings.example.json
├── database
│   ├── backup
│   └── global_intel.db
├── docker-compose.yml
├── intelligence
│   ├── brain.py
│   ├── cisa.py
│   ├── cve_correlator.py
│   ├── epss.py
│   ├── github_adv.py
│   ├── greynoise.py
│   ├── mitre_mapper.py
│   └── nvd.py
├── main.py
├── requirements.txt
├── run.sh
├── scanners
│   ├── amass.py
│   ├── api_fuzzer.py
│   ├── arjun.py
│   ├── clamav.py
│   ├── cloud_enum.py
│   ├── cms_scanner.py
│   ├── commix.py
│   ├── core
│   │   ├── dag.py
│   │   ├── pipeline.py
│   │   ├── plugin.py
│   │   └── registry.py
│   ├── cors_scanner.py
│   ├── crackmapexec.py
│   ├── crlf_scanner.py
│   ├── crtsh.py
│   ├── dalfox.py
│   ├── dirb.py
│   ├── dnsx.py
│   ├── feroxbuster.py
│   ├── ffuf.py
│   ├── gitleaks.py
│   ├── gobuster.py
│   ├── graphql_scanner.py
│   ├── hackertarget.py
│   ├── headers_scanner.py
│   ├── httpx_scanner.py
│   ├── hydra_scanner.py
│   ├── jwt_scanner.py
│   ├── katana.py
│   ├── masscan.py
│   ├── mobsf.py
│   ├── netcat_probe.py
│   ├── nikto.py
│   ├── nmap.py
│   ├── nuclei.py
│   ├── open_redirect.py
│   ├── paramspider.py
│   ├── path_traversal.py
│   ├── prowler.py
│   ├── retire_js.py
│   ├── robots_scanner.py
│   ├── scan_runner.py
│   ├── screenshot_capture.py
│   ├── secrets_scanner.py
│   ├── shodan_idb.py
│   ├── smuggler.py
│   ├── sqlmap.py
│   ├── ssl_scanner.py
│   ├── ssrf_scanner.py
│   ├── subfinder.py
│   ├── tech_fingerprint.py
│   ├── theharvester.py
│   ├── traceroute.py
│   ├── trivy.py
│   ├── wapiti.py
│   ├── watchdog.py
│   ├── wayback.py
│   ├── whatweb.py
│   ├── whois_scanner.py
│   ├── wpscan.py
│   ├── xxe_scanner.py
│   └── zap.py
├── setup.bat
├── setup.log
├── setup.ps1
├── setup.sh
├── tools
│   ├── alert_engine.py
│   ├── baseline_manager.py
│   ├── bump_version.py
│   ├── compliance_mapper.py
│   ├── config_manager.py
│   ├── create_scanner.py
│   ├── db_manager.py
│   ├── dynamic_pipeline.py
│   ├── egress_auditor.py
│   ├── encryption_manager.py
│   ├── event_bus.py
│   ├── fail2ban_reader.py
│   ├── finding_deduplicator.py
│   ├── logger_setup.py
│   ├── mac_changer.py
│   ├── narrative_logger.py
│   ├── report_generator.py
│   ├── responsibility_manager.py
│   ├── risk_scorer.py
│   ├── sbom_generator.py
│   ├── scheduler.py
│   ├── seed_intel.py
│   ├── session_manager.py
│   ├── snapshot.py
│   ├── system_checker.py
│   ├── tool_installer.py
│   ├── verify_report.py
│   └── verify_smp.py
├── troubleshooting
│   ├── README.md
│   ├── api_errors.md
│   ├── database.md
│   ├── installation.md
│   ├── reports.md
│   └── scanner_errors.md
└── ui
    ├── components
    │   ├── password_dialog.py
    │   ├── responsibility_dialog.py
    │   └── system_check_dialog.py
    ├── controllers
    │   └── dashboard_logic.py
    ├── dashboard.py
    ├── style.qss
    ├── theme.py
    ├── utils.py
    └── views
        ├── dashboard_layout.py
        └── splash_screen.py
```
