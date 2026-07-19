# Security Management Platform (SMP)
## Complete User Guide — V6.0
### From First Launch to Security Researcher Level

---

> **LEGAL NOTICE**
>
> SMP is designed exclusively for **authorised security testing**.
> Always obtain written permission before scanning any target.
> Unauthorised scanning is illegal in most jurisdictions.
> The operator assumes full legal responsibility for use of this tool.

---

## Table of Contents

| Part | Title | Audience |
|------|-------|----------|
| [Part 0](#part-0--philosophy--architecture) | Philosophy & Architecture | Everyone |
| [Part 1](#part-1--first-setup-beginner) | First Setup — Beginner | New Users |
| [Part 2](#part-2--daily-operations-intermediate) | Daily Operations — Intermediate | Regular Analysts |
| [Part 3](#part-3--power-features-advanced) | Power Features — Advanced | Power Users |
| [Part 4](#part-4--rest-api--developer-mode) | REST API & Developer Mode | Developers |
| [Part 5](#part-5--research-level-internals) | Research Level Internals | Researchers |
| [Part 6](#part-6--version-history--roadmap) | Version History & Roadmap | All |
| [Part 7](#part-7--troubleshooting) | Troubleshooting | All |

---

## Part 0 — Philosophy & Architecture

### What is SMP?

SMP started as a single script that ran Nmap and generated an HTML report (V0.1). Over six major versions it evolved into a full **Security Operations Platform** — a self-hosted, air-gappable, encrypted desktop application for professional VAPT work.

```
+--------------------------------------------------------------+
|                  SMP V6.0 Architecture                       |
+------------------+-------------------+------------------------|
|  Desktop GUI      |  Plugin System    |  REST API V6          |
|  (PySide6)        |  (Auto-discover)  |  (JWT + Rate Limit)   |
+------------------+-------------------+-----------------------+
|              Scan Orchestrator (Sequential Pipeline)         |
+------------+----------+----------+---------------------------+
|  Nmap      |  Nuclei  |  Katana  |  30+ additional scanners  |
+------------+----------+----------+---------------------------+
|              Encrypted SQLite Database (SQLCipher)           |
+--------------------------------------------------------------+
|   PBKDF2/Fernet encryption  |  UDP IPC  |  APScheduler       |
+--------------------------------------------------------------+
```

### Core Design Principles

1. **Authorization-first** — Every scan begins with a responsibility acknowledgement.
2. **Encrypted at rest** — All databases are SQLCipher-encrypted. Master password is required.
3. **Non-blocking** — All scanners run in background threads. The GUI never freezes.
4. **Self-contained** — SMP installs and verifies its own tool dependencies at startup.

### The Scanner Pipeline

SMP executes scanners in a fixed, optimised order designed for maximum efficiency:

```
[Fast / OSINT First]
 1. HTTPx            — Is the target alive?
 2. WhatWeb          — Technology fingerprint
 3. Subfinder        — Subdomain discovery
 4. CRT.sh           — Certificate transparency subdomains
 5. HackerTarget     — Reverse DNS
 6. Whois            — Domain registration
 7. Wayback Machine  — Historical URL discovery
 8. theHarvester     — OSINT: emails, names, hosts
 9. Traceroute       — Network path

[Active Scanning]
10. Nmap             — Port and service scan
11. SSL Scanner      — TLS/certificate analysis (SSLyze)
12. Security Headers — HTTP header security audit
13. Robots.txt       — Sitemap and robots analysis
14. CORS Scanner     — CORS misconfiguration check
15. CMS Scanner      — WordPress/Drupal/Joomla detection
16. Nikto            — Web vulnerability scan
17. Nuclei           — Template-based vulnerability scan
18. ffuf             — Directory and file fuzzing
19. Open Redirect    — Parameter-based redirect test
20. Tech Fingerprint — Deep technology analysis
21. Wapiti           — OWASP web application scan
22. SQLMap           — SQL injection detection
23. Shodan InternetDB — Passive internet exposure check
24. Gitleaks         — Secret/credential leak detection
25. Dalfox           — XSS parameter scan [Full profile]
26. Arjun            — HTTP parameter discovery [Full profile]
27. DNSx             — DNS enumeration [Full profile]
28. Katana           — Web crawler [Full profile]
29. Commix           — Command injection test [Full profile]
30. JWT Scanner      — JWT token analysis [Full profile]
31. WPScan           — WordPress vulnerability scan [Full profile]
32. Masscan          — Fast port scan [Full profile]
33. ParamSpider      — Parameter mining [Full profile]
34. Cloud Enum       — Cloud asset discovery [Full profile]
   [Optional]
    OWASP ZAP       — Active web scan (enable in Settings)

[Post-Scan Processing]
    CVE Correlation — Match detected technologies to CVEs
    Risk Scoring    — 0-100 composite risk score
    Report Generation — HTML + PDF reports
    SMTP Alert      — Email notification if configured
```

---

## Part 1 — First Setup (Beginner)

### 1.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04 / Debian 11 | Ubuntu 22.04 LTS |
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 10 GB | 50 GB |
| Python | 3.10 | 3.11 |
| Network | Required | Required |

External tools required (install these first):

```bash
sudo apt install -y nmap nikto gobuster sqlmap \
    libsqlcipher-dev sqlcipher git curl \
    xdg-utils wkhtmltopdf
```

### 1.2 Installation

```bash
# 1. Navigate to SMP directory
cd ~/Downloads/SecurityManagementPlatform-main

# 2. Run the automated setup
chmod +x setup.sh
./setup.sh

# 3. Launch SMP
./run.sh
```

The setup script creates a Python virtual environment, installs all packages,
and checks for required system tools.

### 1.3 First Launch — Master Password

On first launch, SMP prompts for a Master Password. This password:
- Encrypts ALL scan data using PBKDF2 (600,000 iterations) + Fernet AES-128
- Has NO recovery mechanism — if lost, all stored data is permanently inaccessible
- Should be stored in a password manager

After setting the password, the splash screen shows startup progress:
1. Database integrity verification
2. Schema initialisation
3. Tool verification (all 34 scanner tools)
4. Resume interrupted scans
5. Start background schedulers

### 1.4 The Dashboard Overview

After login you see the Dashboard with KPI cards:

| Card | What it shows |
|------|---------------|
| Targets | Total configured scan targets |
| CVE Intel | Total CVEs in local threat database |
| Active Scans | Currently running scans |
| Email Alerts | SMTP configuration status |

Left sidebar navigation:

| Page | Purpose |
|------|---------|
| Dashboard | KPIs, target summary, recent activity |
| Targets | Add, configure, scan, delete targets |
| Active Scans | Live scan pipeline status |
| Threat Intel | Browse and search local CVE feed |
| Reports | Browse, open, verify generated reports |
| Audit Logs | Master, Scan, CVE, and Error logs |
| Settings | SMTP, API keys, scan profiles, headers |

### 1.5 Adding Your First Target

1. Click **Targets** in the sidebar
2. Type the target URL (e.g., `https://example.com`)
3. Click **Add Target**
4. The target appears with status **Enabled**

### 1.6 Running Your First Scan

1. On the Targets page, click **Scan** in the Actions column
2. Accept the Responsibility Acknowledgement dialog
3. The scan starts immediately

Switch to **Active Scans** to watch live progress:
```
example.com  [9/34] Nmap — port & service scan  [00:03:22]
```

A typical scan takes 20-90 minutes depending on the profile and target.

### 1.7 Reading Your First Report

1. Click **Reports** in the sidebar
2. Find your report (newest at top)
3. Click **Open** to view in browser

Reports include:
- Executive summary with risk score (0-100)
- Discovered technologies and services
- Vulnerability findings by severity
- CVE matches for detected software
- Raw tool output
- SHA-256 hash signature

---

## Part 2 — Daily Operations (Intermediate)

### 2.1 Target Status

| Status | Meaning |
|--------|---------|
| Enabled | Participates in scheduled automatic scans |
| Disabled | Paused — manual scans still work |

Risk Score in the Targets table shows the latest composite rating:
- **Critical** (80-100) — Immediate attention required
- **High** (60-79) — Significant findings
- **Medium** (40-59) — Moderate risk
- **Low** (0-39) — Minor findings

### 2.2 Active Scan Monitor

Each scan entry shows:
```
target.com  [16/34] Nuclei — template-based scan  [00:12:07]
```

Colour indicators:
- Blue — Active scanner running
- Orange — Post-processing (CVE correlation, report generation)
- Green — Completed

Click **Cancel** to stop a scan. All collected data is preserved.

### 2.3 Threat Intel — CVE Database

The local CVE database syncs from:
- NVD (National Vulnerability Database)
- CISA Known Exploited Vulnerabilities
- GitHub Security Advisories
- EPSS (Exploit Prediction Scoring System)

Use the **Severity filter** and **Search box** to find relevant CVEs.
Double-click any CVE to see full details including CVSS score, affected products, and EPSS probability.

Sync runs automatically every hour (configurable in settings).

### 2.4 Audit Logs — Four Tabs

| Tab | Content |
|-----|---------|
| Master | All system events |
| Scan | Scanner pipeline events |
| CVE Intel | CVE sync events |
| Errors | All ERROR/CRITICAL events |

Controls: level filter, keyword search, clear view, copy logs, auto-scroll, export ZIP.

### 2.5 Reports Page

| Column | Description |
|--------|-------------|
| Filename | Report file name |
| Type | HTML or PDF |
| Date Modified | Creation time |
| Size | File size |
| Hash Signature | SHA-256 prefix for integrity check |
| Action | Open / Delete buttons |

Drag-and-drop a PDF onto the SHASUM drop zone in Settings to verify it against the stored hash.

---

## Part 3 — Power Features (Advanced)

### 3.1 Scan Profiles

| Profile | Scanners | Use Case |
|---------|---------|---------|
| **Fast** | OSINT only (steps 1-9) | Quick recon |
| **Standard** | Core scanners (default) | Regular assessments |
| **Full** | All 34 scanners including Commix, Dalfox, ZAP | Maximum coverage |

Settings → Scan Profile → select → Save Profile

### 3.2 Authenticated Scanning

Inject HTTP headers into Nuclei, Nikto, Wapiti for session-based scanning:

1. Settings → Authenticated Scan Headers → Add Header
2. Enter header name and value:
   - `Cookie` → `session=eyJ...`
   - `Authorization` → `Bearer eyJ...`
3. Click Save Headers

### 3.3 Scheduled Scanning

Default: Daily at 2:00 AM for all Enabled targets.

The scheduler also:
- Syncs CVE intelligence every hour
- Compares ports against baseline after each scan
- Triggers vulnerability growth threshold alerts

### 3.4 SMTP Email Alerts

Alerts are sent when:
- A scan completes
- A critical vulnerability is found
- A CVE matches a detected technology
- SLA breach threshold is exceeded (default: 30 days unfixed)

Settings → Email Notification Server (SMTP):

| Field | Example |
|-------|---------|
| SMTP Host | smtp.gmail.com |
| SMTP Port | 587 (TLS) or 465 (SSL) |
| Username | user@company.com |
| Password | App-specific password |
| Recipients | soc@company.com |

For Gmail: use an App Password (not your account password). Enable 2FA, then generate at
myaccount.google.com → Security → App passwords.

### 3.5 API Keys

Settings → API Keys & Proxies:

| Key | Purpose |
|-----|---------|
| Shodan API Key | Deep IoT/IP exposure data |
| Censys API Key | Certificate and host intelligence |
| GitHub API Token | Prevents 403 rate limits on advisory fetches |

HTTP/HTTPS Proxy: route all traffic through e.g. Burp Suite at `http://127.0.0.1:8080`

### 3.6 Database Backup

Settings → Backup & Raw Data Download:
- **Backup CVE Database** — Copies CVE DB to backup directory with timestamp
- **Download Raw Data ZIP** — Exports all raw scan data as compressed ZIP

Backups retained for 30 days (configurable via `backup_retention_days` in settings).

### 3.7 Port Baselining

First scan per target establishes the open-port **baseline**. Subsequent scans detect:
- New ports (creates finding + optional SMTP alert)
- Closed ports (logged as informational)

This catches stealth service changes between scans.

### 3.8 SBOM Generation

Generates a Software Bill of Materials in CycloneDX JSON format for detected technology stacks.
Saved to `reports/sbom/` for use in compliance workflows.

### 3.9 MAC Address Randomisation

For OPSEC-sensitive engagements:
- Enable `mac_changer_enabled: true` in Settings
- Requires `macchanger` tool and `sudo` access
- MAC is randomised at scan start, restored on completion
- Result shown in dashboard status bar

### 3.10 Danger Zone

| Action | Effect |
|--------|--------|
| Reset to Default | Resets all settings, clears caches |
| Full Reset | Wipes all databases, logs, reports, and settings. Irreversible. |

---

## Part 4 — REST API & Developer Mode

### 4.1 Starting the API

```bash
# Headless / API-only mode (no GUI)
./venv/bin/python main.py --api

# API available at http://127.0.0.1:8080
```

### 4.2 Authentication

```bash
# Get JWT token
curl -X POST http://127.0.0.1:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_master_password"}'

# Use token in requests
curl http://127.0.0.1:8080/api/targets \
  -H "Authorization: Bearer <token>"
```

Rate limit: 120 requests/minute per IP.

### 4.3 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/targets | List all targets |
| POST | /api/targets | Add a new target |
| DELETE | /api/targets/{id} | Remove a target |
| POST | /api/scan/{target_id} | Start a scan |
| GET | /api/scans/active | List running scans |
| GET | /api/cves | Query CVE database |
| GET | /api/findings/{scan_id} | Get findings for a scan |
| GET | /api/reports | List generated reports |
| GET | /health | Health check |

### 4.4 Writing a Custom Scanner Plugin

All scanners in `scanners/` follow the same interface:

```python
# scanners/my_scanner.py
import logging
logger = logging.getLogger("smp.scan")

def run_my_scan(target_url: str, scan_id: int, settings: dict) -> dict:
    """
    Args:
        target_url: URL to scan (e.g., "https://example.com")
        scan_id:    Database scan ID for storing findings
        settings:   Current settings dict from config_manager
    Returns:
        dict with keys: success (bool), data (any), raw_output (str)
    """
    from tools.db_manager import add_finding
    try:
        result = run_tool(target_url)
        add_finding(scan_id, "My Scanner", "High",
                   "Finding title", "Finding description",
                   evidence=result)
        return {"success": True, "data": result, "raw_output": str(result)}
    except Exception as e:
        logger.error(f"my_scanner failed: {e}")
        return {"success": False, "data": None, "raw_output": str(e)}
```

Register in `scanners/scan_runner.py` by importing and adding to the pipeline.

---

## Part 5 — Research Level Internals

### 5.1 Encryption Architecture

```
User Password
     |
     v
PBKDF2-HMAC-SHA256 (600,000 iterations, random salt)
     |
     v
Fernet key (AES-128-CBC + HMAC-SHA256)
     |
     +-- Encrypts: settings.json  -> settings.json.enc
     +-- Encrypts: security.db   -> security.db.enc
     +-- Encrypts: cve.db        -> cve.db.enc

At rest:    only .enc files exist
At runtime: decrypted to plain files for SQLCipher access
On exit:    plain files re-encrypted and deleted
```

Key derivation salt stored in `database/salt.bin`.
Encryption managed by `tools/encryption_manager.py`.

### 5.2 Database Schema

**security.db — Main operational database:**

```sql
targets       -- id, url, status, last_scan, added_date
scans         -- id, target_id, start_time, end_time, status, scanner_status, scanned_by
findings      -- id, scan_id, scanner, severity, title, description, evidence, remediation
technologies  -- id, scan_id, name, version, category
risk_scores   -- id, scan_id, score, rating, breakdown_json
alerts        -- id, type, message, timestamp
log_entries   -- id, level, message, source, timestamp
port_baselines -- id, target_id, ports_json, created_at
```

**cve.db — Threat intelligence database:**

```sql
cves    -- id, cve, title, severity, description, cvss_score, cvss_vector,
        --    affected_products, references_json, epss_score,
        --    cisa_known_exploited, published_date, source, keywords
cves_fts -- FTS5 virtual table for full-text search
```

### 5.3 IPC Architecture

The scan pipeline communicates with the GUI via:

1. **UDP IPC socket (port 5005)** — Primary channel. JSON events:
   ```json
   {"type": "scan_status", "data": {"scan_id": 42, "status": "Running Nmap"}}
   {"type": "target_update", "data": {"target_id": 7}}
   {"type": "new_log", "data": {}}
   ```
   Uses `SO_REUSEADDR` so restarts do not fail with "address already in use".

2. **Polling fallback (3-second timer)** — Safety net if UDP packets are dropped.
   Only refreshes the currently visible page to avoid main-thread blocking.

### 5.4 Risk Scoring Algorithm

```
Score = (
    severity_component    # Weighted count of Critical/High/Medium findings
  + cve_component         # CVE count weighted by CVSS score
  + exposure_component    # Open ports and exposed services
  + ssl_component         # TLS weaknesses (TLS 1.0, weak ciphers)
  + header_component      # Missing security headers
) / normalisation_factor

Rating:
  80-100  Critical
  60-79   High
  40-59   Medium
  20-39   Low
  0-19    Informational
```

### 5.5 CVE Correlation Logic

After scanning, `tools/cve_correlator.py`:

1. Normalises technology names from WhatWeb, Nmap, SSL scan output
2. Full-text searches `cves_fts` for each technology name + version
3. Ranks matches by CVSS score descending
4. Stores top matches as findings with CVE cross-references
5. Flags findings where EPSS score > 0.7 as "likely exploited in the wild"
6. Marks CISA Known Exploited Vulnerabilities with high urgency

### 5.6 Log File Locations

```
{BASE_DIR}/logs/
  master.log   — All system events
  scan.log     — Scanner pipeline events
  cve.log      — CVE intelligence sync events
  error.log    — Errors and critical failures
```

Log rotation at 10 MB. All logs readable in the Audit Logs page.

---

## Part 6 — Version History & Roadmap

### Version History

| Version | Key Features |
|---------|-------------|
| V0.1 | Nmap -> HTML report (single tool) |
| V1.0 | Added Nikto, Gobuster, basic CLI |
| V2.0 | PySide6 GUI, target management |
| V3.0 | Scheduled scanning, SMTP alerts |
| V4.0 | Plugin architecture, 20+ scanners, PDF reports |
| V4.8 | 34 scanners, sequential pipeline, CVE correlation |
| V5.0 | SQLCipher encryption, PBKDF2 master password |
| V5.3 | REST API (JWT), scan profiles, authenticated scanning |
| V6.0 | CVE intelligence sync, EPSS, CISA KEV, SBOM, MAC changer, rate limiting |

### Planned Roadmap

| Version | Target Features |
|---------|----------------|
| V7.0 | Multi-user sessions, team-based target ownership, RBAC |
| V8.0 | Cloud export (S3/GCS), centralised reporting server, webhooks |
| V9.0 | AI-assisted finding triage, automated remediation suggestions, continuous monitoring |

---

## Part 7 — Troubleshooting

### "Database error: no such table: main.cves"

**Cause:** CVE database was never initialised or got corrupted.

```bash
rm -f database/cve.db database/cve.db.enc
./run.sh  # Recreates on startup
```

### "Database error: file is not a database"

**Cause:** Encrypted .enc file being read as plain SQLite. Usually a password mismatch.

```bash
rm -f database/security.db database/cve.db
./run.sh  # Enter master password — decryption restores files
```

If the master password was changed without re-encrypting, use Full Reset in Settings -> Danger Zone.

### "OSError: [Errno 98] Address already in use" on port 5005

**Cause:** Previous SMP instance left a zombie UDP listener.

```bash
fuser -k 5005/udp
pkill -f "main.py"
rm -f ~/.smp_runtime.lock
./run.sh
```

Note: V6 uses SO_REUSEADDR so this should no longer occur. If it does, the above resolves it.

### pysqlcipher3 build fails

**Cause:** Missing libsqlcipher-dev system library.

```bash
sudo apt install -y libsqlcipher-dev sqlcipher build-essential python3-dev
pip install pysqlcipher3
```

### UI lags or feels slow

V6 fixes the main cause: refresh now only updates the currently visible page.

If lag persists:
- Check Audit Logs -> Errors for hanging scanner timeouts
- Verify no other process is holding the database file open
- Use Settings -> Danger Zone -> Reset to Default to clear caches

### Scanner tool not found

1. Settings -> Check Dependencies & Tools
2. For system tools: `sudo apt install <tool>`
3. For Go tools: `go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest`

### SMTP test fails

Common causes:
1. **Gmail** — Must use App Password, not account password. Enable 2FA first.
2. **Port mismatch** — Port 587 uses STARTTLS. Port 465 uses implicit SSL. Toggle "Use Implicit SSL/TLS" to match.
3. **Firewall** — Confirm outbound SMTP is not blocked.

### Report PDF is blank

```bash
sudo apt install -y fonts-liberation libpangocairo-1.0-0 \
    libpango-1.0-0 libgdk-pixbuf2.0-0 libffi-dev
```

### Complete uninstall

```bash
rm -rf ~/Downloads/SecurityManagementPlatform-main
rm -f ~/.smp_runtime.lock
```

No system-wide changes are made by SMP. All data is within the project directory.

---

*Security Management Platform — V6.0*
