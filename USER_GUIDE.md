```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ███████╗███╗   ███╗██████╗                                        ║
║    ██╔════╝████╗ ████║██╔══██╗                                       ║
║    ███████╗██╔████╔██║██████╔╝   Security Management Platform        ║
║    ╚════██║██║╚██╔╝██║██╔═══╝   V9.4.0 · Stable                      ║
║    ███████║██║ ╚═╝ ██║██║                                            ║
║    ╚══════╝╚═╝     ╚═╝╚═╝        © mrQhere                           ║
║                                                                      ║
║    Local-first  ·  57 Scanners  ·  AES-256  ·  Zero Cloud            ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

<div align="center">


# Security Management Platform

**Local-first VAPT orchestration. Zero cloud. Encrypted at rest.**

*© mrQhere · [github.com/mrQhere/SecurityManagementPlatform](https://github.com/mrQhere/SecurityManagementPlatform)*

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-blue)

</div>

---

## What is SMP?

SMP runs 30+ security scanners against a target, correlates every finding against live threat intelligence (NVD, EPSS, CISA KEV, GreyNoise), and produces a compliance-mapped PDF report — without sending a single byte of client data to any cloud service.

**You get:** Raw scanner power + real exploitability context (not just CVSS) + a report an auditor will accept.

---

## 0 · Quick Start

```bash
# 1. Clone
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# 2. Install (~2 min)
./setup.sh

# 3. Launch GUI
./run.sh

# Or: headless API mode
python main.py --api
# → http://localhost:8000/api/v9/docs
```

**First scan:**
1. Click **Add Target** → enter a URL you own or have written permission to test
2. Choose `standard` profile
3. Click **Start Scan** → watch the Live Monitor
4. PDF report lands in `reports/pdf/` when done

> **Antivirus blocking setup.sh?** Run `./setup.sh --skip-tools` to skip Go binary downloads, then install each tool manually from its GitHub Releases page (URLs printed by the script). PySide6 and SQLCipher install via pip/apt — AV does not block those.

---

## 1 · Installation

### Linux / macOS

```bash
./setup.sh           # full install — everything automated
./setup.sh --skip-tools  # skip Go binary downloads (for AV-restricted environments)
```

`setup.sh` installs: Python venv, SQLCipher, `nuclei`, `subfinder`, `httpx`, `katana`, `dnsx`, `ffuf`, `gitleaks`, `dalfox`, `nmap`, `nikto`, `whatweb`, WPScan, ClamAV, Trivy, Prowler, CrackMapExec.

You can also use `--no-venv` if you want to bypass the Python virtual environment creation.

Every binary is downloaded from its official GitHub Releases page and verified with SHA-256 before installation. The script prints the full URL before each download.

### SQLCipher (hard requirement — SMP won't start without it)

```bash
# Ubuntu 24.04+
sudo apt install libsqlcipher-dev libsqlcipher0t64
pip install pysqlcipher3

# Ubuntu 22.04 / Debian
sudo apt install libsqlcipher-dev libsqlcipher0
pip install pysqlcipher3

# macOS
brew install sqlcipher && pip install pysqlcipher3
```

Not sure which Ubuntu? `lsb_release -rs` → 24.04+ use `libsqlcipher0t64`.

### Docker (all platforms, including Windows)

```bash
docker compose up -d

# Useful commands
make docker-logs     # live logs
make docker-shell    # interactive shell
make docker-stop     # stop
make docker-clean    # stop + remove volumes
```

API available at `http://localhost:8000/api/v9/docs`.

> The PySide6 desktop GUI runs on Linux/macOS only. On Windows, use Docker + the REST API.

### Windows (manual path)

1. Install [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/)
2. `docker compose up -d`
3. Open `http://localhost:8000/api/v9/docs`

---

## 2 · Scan Profiles

| Profile | What runs | When to use |
|---------|-----------|-------------|
| `osint` | Passive recon only — no active probing | Scoping, reconnaissance |
| `standard` | Full recon + active scanning, no exploitation | Standard pentest engagement |
| `full` | Everything including Hydra, Commix, ZAP active scan | **Written permission required** |

> ⚠️ The `full` profile sends attack payloads. Using it without written authorisation from the asset owner is illegal in most jurisdictions.

---

## 3 · Scanner Reference

SMP runs all scanners as a **Directed Acyclic Graph (DAG)** — parallel within each phase, conditional between phases. Every scanner's full timeout is preserved for maximum coverage.

| Scanner | Profile | Phase | Depends on | What it finds |
|---------|---------|-------|-----------|---------------|
| Traceroute | osint+ | 0 | — | Network path, hops, latency |
| HTTPx | osint+ | 1 | Traceroute | HTTP/S alive, status codes, titles, tech |
| WhatWeb | osint+ | 1 | Traceroute | CMS, frameworks, server software |
| Subfinder | osint+ | 1 | Traceroute | Subdomains via passive DNS |
| CRT.sh | osint+ | 1 | Traceroute | Certificate transparency subdomains |
| Whois | osint+ | 1 | Traceroute | Domain registration, nameservers |
| Wayback | osint+ | 1 | Traceroute | Historical URLs, exposed paths |
| theHarvester | osint+ | 1 | Traceroute | Emails, names, IPs, virtual hosts |
| HackerTarget | osint+ | 1 | Traceroute | Passive recon via HackerTarget API |
| Nmap | standard+ | 2 | HTTPx | Open ports, service versions, OS |
| SSL Scanner | standard+ | 2 | Nmap | TLS versions, weak ciphers, cert expiry |
| Security Headers | standard+ | 2 | SSL | CSP, HSTS, X-Frame-Options gaps |
| CORS Scanner | standard+ | 2 | HTTPx | CORS misconfigurations |
| Robots Scanner | standard+ | 2 | HTTPx | Disallowed paths, sitemap |
| Tech Fingerprint | standard+ | 2 | HTTPx | JS libraries, version detection |
| Nikto | standard+ | 2 | Nmap | Web server misconfigs, CVEs |
| CMS Scanner | standard+ | 2 | WhatWeb | WordPress/Joomla/Drupal vulns |
| Nuclei | standard+ | 3 | Nikto | CVE templates, misconfigs, secrets (2h cap) |
| ffuf | standard+ | 3 | HTTPx | Directory/file brute-force (2h cap) |
| SQLMap | standard+ | 3 | HTTPx | SQL injection (forms and params) |
| Wapiti | standard+ | 3 | HTTPx | XSS, SQLi, SSRF, path traversal |
| Gitleaks | standard+ | 3 | HTTPx | Secrets in Git repos |
| Shodan IDB | standard+ | 3 | Nmap | CVEs for open ports from Shodan IntelDB |
| Retire.js | standard+ | 3 | Tech Fingerprint | Outdated JS library CVEs |
| Screenshot | standard+ | 3 | HTTPx | Visual evidence (Playwright) |
| Secrets Scanner | standard+ | 3 | HTTPx | API keys, tokens in source |
| GraphQL Scanner | standard+ | 3 | HTTPx | Introspection, batching, injection |
| API Fuzzer | standard+ | 3 | HTTPx | REST API endpoint fuzzing |
| Katana | standard+ | 4 | HTTPx | JS-aware crawler for deep link discovery |
| DNSx | standard+ | 4 | Subfinder | DNS record enrichment, takeover check |
| ParamSpider | standard+ | 4 | Wayback | URL parameter extraction |
| Arjun | standard+ | 4 | HTTPx | Hidden parameter discovery |
| JWT Scanner | standard+ | 4 | HTTPx | Weak/none alg, key confusion |
| SSRF Scanner | standard+ | 4 | Arjun | Server-side request forgery |
| Path Traversal | standard+ | 4 | Arjun | Directory traversal |
| CRLF Scanner | standard+ | 4 | HTTPx | Header injection |
| Open Redirect | standard+ | 4 | HTTPx | Open redirect chains |
| XXE Scanner | standard+ | 4 | HTTPx | XML external entity injection |
| Cloud Enum | standard+ | 4 | Subfinder | S3/GCS/Azure blob exposure |
| CrackMapExec | standard+ | 4 | Nmap | SMB/WinRM enumeration |
| WPScan | standard+ | 4 | CMS Scanner | WordPress plugins/themes vulns |
| Dalfox | standard+ | 4 | Wapiti | XSS exploitation validation |
| Amass | standard+ | 4 | Subfinder | Deep passive subdomain enumeration |
| DirB | standard+ | 4 | HTTPx | Directory brute-force |
| Feroxbuster | standard+ | 4 | HTTPx | Recursive directory brute-force |
| Gobuster | standard+ | 4 | HTTPx | Directory/DNS/vhost brute-force |
| MobSF | standard+ | 4 | HTTPx | Mobile app API endpoint analysis |
| Netcat Probe | standard+ | 4 | Nmap | Raw service banner grabbing |
| Masscan | standard+ | 4 | Traceroute | High-speed port scanning |
| Smuggler | standard+ | 4 | HTTPx | HTTP request smuggling |
| Trivy | standard+ | 4 | Tech Fingerprint | Container/OS vulnerability scan |
| Prowler | standard+ | 4 | Cloud Enum | AWS/GCP/Azure security posture |
| Hydra | full only | 5 | Auth surface | Credential brute-force |
| Commix | full only | 5 | Arjun | OS command injection |
| ZAP Active | full only | 5 | HTTPx | Full active OWASP ZAP scan |

> [!WARNING]
> **full** profile scanners send attack payloads. Use only with written authorisation.

> [!NOTE]
> **SPA false-positive filter:** ffuf on React/Vue/Angular apps sometimes returns HTTP 200 for every path. SMP auto-detects when ≥80% of results share the same content length and suppresses them.

---

## 4 · Intelligence & Risk Scoring

Every finding is cross-referenced against four live sources:

| Source | What it adds |
|--------|-------------|
| **NVD** | CVSSv3 score, CWE, affected version matching |
| **EPSS** | 0–1 probability of exploitation in the wild within 30 days |
| **CISA KEV** | Boolean: is this CVE on the US gov's confirmed-exploited list? (2× score multiplier) |
| **GreyNoise** | IP classification: noise / riot / malicious / unknown |

**Risk formula** (`tools/risk_scorer.py`):
```python
risk = min(100, (cvss/10) * kev_mult * gn_mult * 100 + epss * 30)
# kev_mult = 2.0 if CISA KEV, gn_mult = 1.3 if GreyNoise malicious
```

**Local-only mode** — blocks all outbound intelligence calls:
```bash
SMP_LOCAL_ONLY=1 ./run.sh
# Every blocked call is logged to logs/egress_audit.log
```

---

## 5 · Encryption

| Data | Encryption |
|------|-----------|
| Pentest DB (`security.db`, `redundancy.db`) | SQLCipher AES-256 |
| Raw scanner output (stored as blobs) | Compressed and stored in SQLCipher |
| Intelligence DBs (`cve.db`, `global_intel.db`) | Plaintext — no client data |

Key derivation: **PBKDF2-HMAC-SHA256**.

Lost your password? There is no recovery path — this is by design. Back up `database/security.db` before changing passwords.

---

## 6 · Reports

Every completed scan generates:
- `reports/pdf/SMP_target.com_Report_YYYY-MM-DD_<hash16>.pdf` — compliance-grade VAPT report
- `reports/html/SMP_target.com_Report_YYYY-MM-DD.html` — always generated (no ReportLab needed)
- `reports/sbom/SMP_target.com_SBOM_YYYY-MM-DD.json` — CycloneDX SBOM

**Verify a report hasn't been tampered with:**
```bash
python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2026-08-06_a1b2c3d4.pdf
# ✔  Report is authentic. Content hash verified.
```

---

## 7 · REST API

Base URL: `http://localhost:8000/api/v9/`

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v9/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' | jq -r .access_token)

# Add target
curl -X POST http://localhost:8000/api/v9/target \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Trigger scan
curl -X POST http://localhost:8000/api/v9/scan/1 -H "Authorization: Bearer $TOKEN"

# Poll status
curl http://localhost:8000/api/v9/scan/1/status -H "Authorization: Bearer $TOKEN"
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token` | POST | Get JWT |
| `/health` | GET | Platform health |
| `/target` | GET/POST | List / add targets |
| `/scan/{target_id}` | POST | Trigger scan |
| `/scan/{id}/status` | GET | Live status |
| `/findings/{scan_id}` | GET | All findings |
| `/compliance/{scan_id}` | GET | Compliance mapping |
| `/sbom/{scan_id}` | GET | Download SBOM |
| `/egress/audit` | GET | Egress audit log |

Interactive docs: `http://localhost:8000/api/v9/docs`

---

## 8 · Adding Custom Scanners

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for the full guide. Quick reference:

```bash
# 1. Generate scaffold
python3 tools/create_scanner.py --name "MyTool" --binary "mytool" --severity High
```

```python
# 2. Implement — scanners/mytool.py
from scanners.core.registry import register_scanner
import subprocess, logging
from tools.db_manager import add_log_entry

MYTOOL_TIMEOUT = 300  # set realistic max — do not reduce

@register_scanner(
    name="MyTool",
    step_name="Running MyTool",
    depends_on=["HTTPx"],   # DAG phase — see scanner table above
    binary_name="mytool",   # checked in PATH and bin/
    needs_binary=True,
    confidence=85,          # 0–100 — how reliable are your findings?
)
def run_mytool(url: str) -> list | None:
    add_log_entry("INFO", f"MyTool Started: {url}")
    try:
        r = subprocess.run(["mytool", url], capture_output=True,
                           text=True, timeout=MYTOOL_TIMEOUT)
    except FileNotFoundError:
        return None   # binary not installed — skip gracefully
    except subprocess.TimeoutExpired:
        return []     # timed out — return empty, not None

    findings = []
    for line in r.stdout.splitlines():
        findings.append({
            "severity":    "High",       # Critical|High|Medium|Low|Info
            "title":       "Issue title",
            "description": "Detail …",
            "confidence":  85,
            "template_id": "mytool-001", # for deduplication
        })
    add_log_entry("INFO", f"MyTool: {len(findings)} findings")
    return findings
```

**Profile guard** — restrict to `full` profile only:
```python
from tools.config_manager import load_settings
if load_settings().get("scan_profile", "standard") != "full":
    return []
```

SMP auto-discovers the scanner on next run — no further registration needed.

---

## 9 · Compliance Mapping

Findings are automatically mapped to:

| Framework | Key use case |
|-----------|-------------|
| OWASP Top 10 2021 | Web application baseline |
| CIS Controls v8 | Infrastructure hardening |
| ISO 27001:2022 | ISMS certification |
| SOC 2 Type II | SaaS/cloud audit readiness |
| PCI-DSS v4.0 | Payment card compliance |

```python
from tools.compliance_mapper import map_finding_to_controls
controls = map_finding_to_controls("SQL Injection", "CWE-89")
# {"owasp": ["A03:2021"], "pci_dss": ["Req 6.2.4"], ...}
```

---

## 10 · Troubleshooting

### Fatal: pysqlcipher3 not installed
```bash
# Ubuntu 24.04+
sudo apt install libsqlcipher-dev libsqlcipher0t64 && pip install pysqlcipher3

# Ubuntu 22.04
sudo apt install libsqlcipher-dev libsqlcipher0 && pip install pysqlcipher3

# Compiler errors?
pip install pysqlcipher3 --no-binary pysqlcipher3
# Or with explicit flags:
CFLAGS="-I/usr/include/sqlcipher" LDFLAGS="-lsqlcipher" pip install pysqlcipher3
```

### Binary not found (nuclei, dalfox, etc.)
```bash
ls bin/                          # check if it's there
export PATH=$PATH:$(pwd)/bin     # add to PATH
# Re-download a specific tool:
curl -fsSL https://github.com/hahwul/dalfox/releases/download/v2.10.0/dalfox_2.10.0_linux_amd64.tar.gz \
  | tar -xz -C bin/ dalfox && chmod +x bin/dalfox
```

### Database locked
```bash
pkill -f "python.*main.py"
./run.sh
```

### Database corrupted / wrong password
```bash
rm -f database/security.db database/redundancy.db
./run.sh   # recreates with correct encryption
```
> ⚠️ This deletes all scan history. Back up first.

### Port 8000 in use
```bash
lsof -i :8000 && kill -9 <PID>
# Or change port in config/settings.json: {"api_port": 8001}
```

### Nmap: permission denied
```bash
sudo visudo
# Add: yourusername ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

### Nuclei: no templates
```bash
nuclei -update-templates
```

### JWT expired (401 on all API endpoints)
Re-authenticate with `POST /auth/token`.

---

## 11 · Architecture Reference

```
SecurityManagementPlatform/
├── api/               FastAPI REST backend (server.py, auth.py)
├── config/            Settings, metadata, hardening rules
├── database/          SQLite databases
├── intelligence/      brain.py, nvd.py, epss.py, cisa.py, greynoise.py
├── scanners/          30+ scanner wrappers + core/ (DAG, registry, pipeline)
├── tools/             db_manager, encryption_manager, risk_scorer,
│                      report_generator, compliance_mapper, scheduler…
├── ui/                PySide6 GUI (dashboard, components, views, style.qss)
├── main.py            Entrypoint (GUI or --api mode)
├── setup.sh           Installer
└── run.sh             Launcher
```

| Layer | Tech | File |
|-------|------|------|
| GUI | PySide6 | `ui/dashboard.py` |
| API | FastAPI + JWT | `api/server.py` |
| Database | SQLCipher AES-256 | `tools/db_manager.py` |
| Pipeline | DAG + multiprocessing | `scanners/scan_runner.py` |
| Intelligence | REST + local cache | `intelligence/` |
| Encryption | SQLCipher + PBKDF2 | `tools/encryption_manager.py` |

---

## 12 · Documentation & Troubleshooting

SMP includes extensive standalone documentation for edge cases, architecture, and issue resolution:

* 🔧 **[Troubleshooting Guide](troubleshooting/README.md)**: Master index for resolving installation, database, API, and scanner errors.
* 🛡️ **[Security Policy](SECURITY.md)**: Architecture details, encryption standards, and the vulnerability reporting policy (**do not open public issues**).
* 🤝 **[Contributing Guidelines](.github/CONTRIBUTING.md)**: Rules for opening PRs, writing scanners, and code of conduct.


---

## 13 · Platform Evolution Timeline

The platform has undergone a massive architectural evolution from a simple script executor to a resilient, AI-driven, and CI-hardened desktop orchestration suite.

```text
       [ V9.4.0 ]  Base Standardization
          │      (Unified execution scripts and basic GUI)
          ╰───────────╮
                      │
      Intel Audit  [ V9.2.4 ]
                      │      (Seed data purged, SQLCipher AES-256 fixed)
          ╭───────────╯
          │
       [ V9.3.0 ]  Scanner Overhaul & UI Fixes
          │        (F821 crashes patched in 24 tools, UI styling hardened)
          ╰───────────╮
                      │
   Installer Sync  [ V9.3.1 ]
                      │      (Debian, Arch, RHEL multi-distro installers)
          ╭───────────╯
          │
       [ V9.3.2 ]  Exploitation Capability Pass
          │        (SSRF, LFI, and OSINT capabilities restored)
          ╰───────────╮
                      │
         CISA KEV  [ V9.4.0 ]
                      │      (Regenerated intelligence from live KEV catalog)
          ╭───────────╯
          │
       [ V9.4.0 ]  Architecture & Tooling Hardening
          │        (Strict `encoding="utf-8"`, Thread-safe EventBus wrapper)
          ╰───────────╮
                      │
     Neural Graph  [ V9.4.0 ]  (CURRENT)
     & API Engine     │      (TF-IDF semantic clustering, Linchpin detection,
                      │       Air-gapped sync, V10 API Client foundation)
                      V
```

### V9.4.0 (current)
- **Neural Brain Revolution**: Replaced simple CVE plotting with a classical AI heuristic engine.
- Implemented **Graph Centrality (PageRank-style)** to automatically detect network chokepoints ("Linchpins").
- Added **TF-IDF Semantic Clustering** to dynamically group zero-days and vulnerabilities by behavior (e.g. all XSS variants).
- **Event-Driven Reactivity**: Graph now recalculates and visually re-renders in real time via the unified `EventBus`.
- **Vulnerability Deduplication**: Upgraded `finding_deduplicator.py` with Levenshtein fuzzy matching (≥0.82 similarity) and vulnerability aliasing (e.g., merging "SQLi" and "SQL Injection") to aggressively reduce scanner noise.
- **Cross-Platform Hardening**: Audited all 28 internal tools and enforced strict `encoding="utf-8"` standard for seamless Windows compatibility.
- **Tooling Overhauls**: Rebuilt `bump_version.py` into a robust CLI with auto-bumping (`--minor`/`--major`) and `--dry-run` protections, and enabled `system_checker.py` for standalone execution.
- **Engine Robustness**: Hardened the module registry by implementing a thread-safe `EventBus` class wrapper to prevent plugin ImportErrors, and upgraded the plugin generator (`create_scanner.py`) to enforce the strict `scan(target, scan_id, settings)` signature, eradicating `NameError` crashes in custom scanners.
- **Air-Gapped Workstation Sync**: The intelligence brain now natively supports exporting and importing the `global_intel.db` via portable `.tar.gz` archives for physically isolated, air-gapped machine synchronization.
- **Neural Graph Filtering**: Analysts can now dynamically filter the Force-Directed Graph by AI Centrality Score using a new UI slider, instantly isolating "Linchpin" vulnerabilities by dissolving low-impact noise.
- **V10.0 API Client Foundation**: Prepared the application for distributed decoupling by establishing `ui/api_client.py`, which provides a robust HTTP/JWT interface for the UI to speak directly with the backend FastAPI engine.
- **CI/CD Reliability**: Eradicated legacy linting errors (E701, E702, E402) and resolved GitHub Dependency Graph parsing failures caused by unpinned `git+https` pip dependencies, ensuring the automated CodeQL and SMP CI pipelines pass 100%.
- Fixed scattered semantic versioning (V7 and V9.3.3 discrepancies) globally.

**V9.3.4 (past)**
- Multi-distro installer: Ubuntu/Debian/Fedora/RHEL/Arch/openSUSE/Kali/Parrot
- Updated tools: nuclei v3.3.9, subfinder v2.7.0, httpx v1.7.0, gitleaks v9.3.3, dalfox v2.10.0
- --skip-tools flag for Avast-restricted environments
- Semantic badge colours + QProgressBar/QTabWidget in UI
- PDF footer © mrQhere, body_left crash fix
- GitHub issue templates, PR template, CONTRIBUTING.md

**V10.0**
- Distributed scan agents over mTLS
- Multi-tenant MSSP workspace separation
- REST API v2 with webhook callbacks

---

## 14 · Advanced Usage for Researchers

SMP is built as a flexible orchestration layer. Security researchers can leverage its core components for custom engagements:

### Neural Graph Tuning (Centrality & TF-IDF)
The Neural Intelligence Engine (`intelligence/brain.py`) now runs a custom Degree Centrality algorithm and a TF-IDF Natural Language clustering matrix. You can manipulate the clustering tolerances in `_tf_idf_cluster(findings)` by adjusting the `cosine_sim() > 0.4` threshold, or change the structural emphasis of chokepoints by modifying the `centrality_score` weights inside `compute_centrality()`. Visual rendering forces (Coulomb repulsion and Hooke spring laws) can be tuned in `ui/components/neural_graph.py` to cluster technologies more aggressively.

### Direct SQLCipher Queries
Pentest data is encrypted at rest using AES-256. If you want to bypass the GUI to run complex analytical queries on the raw findings:
1. Extract your master key from `.smp_keystore`.
2. Access the database directly:
```bash
sqlite3 database/security.db
sqlite> PRAGMA key = 'YOUR_MASTER_KEY';
sqlite> SELECT target_url, severity, tool FROM findings WHERE confidence > 90;
```

### Developing Zero-Config Plugins
You can add custom exploit scripts or proprietary scanners to the pipeline instantly. Drop your python script into the `scanners/` directory with a `PLUGIN_META` dictionary, and the `scanners.core.registry` will automatically parse it and include it in the DAG for execution.

```python
PLUGIN_META = {
    "name": "Custom0Day",
    "binary": "exploit_bin",
    "severity": "Critical",
    "step_name": "Running Custom Exploit",
    "confidence": 100,
    "depends_on": ["Subfinder"] # Optional DAG dependency
}
def scan(target_url: str, scan_id: int, settings: dict):
    from tools.db_manager import emit_finding
    emit_finding(scan_id, "Custom0Day", "Critical", "Found 0-day!")
```

### Headless API Automation
SMP features a headless FastAPI server. To integrate SMP into a CI/CD pipeline or custom red-team orchestration bot:
```bash
./run.sh --api-only --port 8000
```

### Dynamic DAG Pipeline Manipulation
The `scanners/core/dag.py` engine calculates the execution graph via topological sorting. By default, it runs dependencies sequentially. You can override timeout constraints or inject side-car payloads by monkey-patching the `DAGManager` before execution:
```python
from scanners.core.dag import DAGManager
def custom_execution_hook(node):
    print(f"Intercepted DAG node: {node.name}")
    node.timeout = 900 # Force 15m timeout for complex subnets
    
DAGManager.pre_execute_hook = custom_execution_hook
```

### Intelligence Brain Extensibility
The Neural Correlation Engine (`intelligence/brain.py`) processes raw scanner output through heuristics. You can write custom decay models to depreciate CVSS scores over time:
```python
# In intelligence/brain.py:
def apply_time_decay(cvss_score: float, discovery_date: str) -> float:
    from datetime import datetime
    delta = (datetime.now() - datetime.fromisoformat(discovery_date)).days
    decay_factor = 1.0 - min(0.5, delta * 0.01) # Decay up to 50%
    return round(cvss_score * decay_factor, 1)
```

### Advanced REST API Interactions
The headless FastApi server is robust enough for custom SIEM integrations. To submit scans programmatically via python `requests` and subscribe to Server-Sent Events (SSE):
```python
import requests
import json
import sseclient # pip install sseclient-py

headers = {"Authorization": "Bearer YOUR_JWT"}
payload = {"target": "10.0.0.0/24", "profile": "full", "stealth": True}

# Trigger scan
resp = requests.post("http://127.0.0.1:8000/api/v9/scan/1", json=payload, headers=headers)
scan_id = resp.json()["scan_id"]

# Stream real-time events
response = requests.get(f"http://127.0.0.1:8000/api/v9/scan/{scan_id}/status", headers=headers, stream=True)
client = sseclient.SSEClient(response)
for event in client.events():
    print(f"Live Finding: {json.loads(event.data)}")
```

### Extracting Raw JSON for SIEM Ingest (Splunk / ELK)
By default, SMP generates human-readable PDF reports using PyMuPDF. To bypass the PDF renderer and tap directly into the JSON data model for Splunk or ELK ingestion, modify `tools/report_generator.py`:
```python
def export_raw_json(scan_results: dict, filepath: str):
    import json
    # Flatten DAG results for SIEM compatibility
    flat_findings = []
    for tool, output in scan_results.get("findings", {}).items():
        flat_findings.extend(output)
    
    with open(filepath, "w") as f:
        json.dump({"scan_meta": scan_results["meta"], "events": flat_findings}, f)
```

### Offline Forensics & Decryption CLI Tooling
For incident response, booting the entire platform may be undesirable. You can create an automated bash alias to dump the SQLCipher SQLite databases into a plaintext memory-mapped file for rapid `grep` forensics:
```bash
# Add to ~/.bashrc or ~/.zshrc
alias smp-dump="sqlite3 /path/to/database/security.db \"PRAGMA key='$(cat /path/to/.smp_keystore)'; .mode json; SELECT * FROM findings;\""
```

### Bypassing the UI Sandbox (PySide6 Hooks)
If you require custom context menus within the force-directed graph (e.g., right-clicking a vulnerable host to immediately pass its IP to Metasploit), hook the PySide6 signals in `ui/components/neural_graph.py`:
```python
from PySide6.QtWidgets import QMenu
from PySide6.QtGui import QAction

def contextMenuEvent(self, event):
    node = self.get_node_at(event.pos())
    if node and node.type == "VULNERABLE_HOST":
        menu = QMenu(self)
        exploit_action = QAction("Send to MSFConsole", self)
        exploit_action.triggered.connect(lambda: self.launch_msf(node.ip))
        menu.addAction(exploit_action)
        menu.exec_(event.globalPos())
```

### Customising Egress Audit Logs for Compliance
Highly secure environments often require off-site audit logging. You can tap into `tools/egress_auditor.py` to pipe outbound platform metrics (such as NVD API calls) directly to an external Graylog server:
```python
import socket
import json

def ship_to_graylog(audit_event: dict):
    # Sends GELF formatted UDP packet to Graylog
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = json.dumps({"version": "1.1", "host": "smp-agent", "short_message": audit_event["action"]})
    sock.sendto(payload.encode(), ("graylog.internal.lan", 12201))
```

### Multi-Threading Optimisation for Masscan
When scanning massive target surfaces (like `/8` subnets), the default `scan_runner` limits concurrent connections to avoid crashing local state. You can override the packet filters and rate limits in `scanners/masscan.py`:
```python
# Force BPF packet filtering and aggressive rate limits
def build_masscan_cmd(target: str) -> list:
    return [
        "masscan", target,
        "-p0-65535",
        "--max-rate", "100000",
        "--wait", "0",
        "--bpf", "tcp and not port 80 and not port 443" # Exclude heavy web ports
    ]
```

---

## 15 · Generating the Thesis PDF

The massive 100+ page professional academic thesis detailing the mathematical and technical architecture of SMP is located in `docs/thesis/SMP_Academic_Thesis.md`. 

To convert this markdown file into a beautifully formatted, print-ready PDF (complete with a table of contents, LaTeX styling, and page numbers), use `pandoc`.

**1. Install Required Packages (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install pandoc texlive-xetex texlive-fonts-recommended texlive-plain-generic
```

**2. Generate the PDF:**
```bash
# Run this from the root of the repository
pandoc docs/thesis/SMP_Academic_Thesis.md -o docs/thesis/SMP_Academic_Thesis.pdf --pdf-engine=xelatex -V geometry:margin=1in -V mainfont="DejaVu Serif" -V monofont="DejaVu Sans Mono"
```

---

<div align="center">

**SMP** · Local-first · Zero-cloud · Encrypted at rest  
© mrQhere · [GitHub](https://github.com/mrQhere/SecurityManagementPlatform)

</div>
