```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ███████╗███╗   ███╗██████╗                                        ║
║    ██╔════╝████╗ ████║██╔══██╗                                       ║
║    ███████╗██╔████╔██║██████╔╝   Security Management Platform        ║
║    ╚════██║██║╚██╔╝██║██╔═══╝   V9.3.1 · Stable                     ║
║    ███████║██║ ╚═╝ ██║██║                                            ║
║    ╚══════╝╚═╝     ╚═╝╚═╝        © mrQhere                          ║
║                                                                      ║
║    Local-first  ·  57 Scanners  ·  AES-256  ·  Zero Cloud           ║
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
# → http://localhost:8000/api/v7/docs
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

API available at `http://localhost:8000/api/v7/docs`.

> The PySide6 desktop GUI runs on Linux/macOS only. On Windows, use Docker + the REST API.

### Windows (manual path)

1. Install [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/)
2. `docker compose up -d`
3. Open `http://localhost:8000/api/v7/docs`

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

> ⚠️ **full** profile scanners send attack payloads. Use only with written authorisation.

**SPA false-positive filter:** ffuf on React/Vue/Angular apps sometimes returns HTTP 200 for every path. SMP auto-detects when ≥80% of results share the same content length and suppresses them.

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
| Raw scanner output (stored as blobs) | Fernet AES-128-CBC + HMAC-SHA256 |
| Intelligence DBs (`cve.db`, `global_intel.db`) | Plaintext — no client data |

Key derivation: **PBKDF2-HMAC-SHA256, 600,000 iterations, random 32-byte salt** (NIST 2024).

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

Base URL: `http://localhost:8000/api/v7/`

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v7/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' | jq -r .access_token)

# Add target
curl -X POST http://localhost:8000/api/v7/target \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Trigger scan
curl -X POST http://localhost:8000/api/v7/scan/1 -H "Authorization: Bearer $TOKEN"

# Poll status
curl http://localhost:8000/api/v7/scan/1/status -H "Authorization: Bearer $TOKEN"
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

Interactive docs: `http://localhost:8000/api/v7/docs`

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
| PCI-DSS v9.3.1 | Payment card compliance |

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
| Encryption | SQLCipher + Fernet + PBKDF2 | `tools/encryption_manager.py` |

---

## 12 · Roadmap

**V9.3.1 (current)**
- Multi-distro installer: Ubuntu/Debian/Fedora/RHEL/Arch/openSUSE/Kali/Parrot
- Updated tools: nuclei v3.3.9, subfinder v2.7.0, httpx v1.7.0, gitleaks v9.3.1, dalfox v2.10.0
- --skip-tools flag for Avast-restricted environments
- Semantic badge colours + QProgressBar/QTabWidget in UI
- PDF footer © mrQhere, body_left crash fix
- GitHub issue templates, PR template, CONTRIBUTING.md

**V10.0**
- Distributed scan agents over mTLS
- Multi-tenant MSSP workspace separation
- REST API v2 with webhook callbacks

---

<div align="center">

**SMP** · Local-first · Zero-cloud · Encrypted at rest  
© mrQhere · [GitHub](https://github.com/mrQhere/SecurityManagementPlatform)

</div>
