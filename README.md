<div align="center">
  <img src="https://github.com/user-attachments/assets/3fb78ea7-973b-4a41-a95b-b0bb4651eb2f" alt="SMP Banner" width="100%" />

  <br />

  <h1>Security Management Platform (SMP)</h1>
  <p><b>The Zero-Cloud, Local-First, Encrypted-at-Rest VAPT Intelligence Engine</b></p>

  <p>
    <a href="https://github.com/mrQhere/SecurityManagementPlatform/actions"><img src="https://img.shields.io/github/actions/workflow/status/mrQhere/SecurityManagementPlatform/ci.yml?style=for-the-badge" alt="Build Status" /></a>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License" /></a>
    <a href="SECURITY.md"><img src="https://img.shields.io/badge/Encryption-AES--256-critical?style=for-the-badge&logo=lock" alt="Security" /></a>
  </p>

  <p>
    <a href="#-overview"><b>Overview</b></a> •
    <a href="#-key-features"><b>Features</b></a> •
    <a href="#-quick-start"><b>Quick Start</b></a> •
    <a href="#-architecture"><b>Architecture</b></a> •
    <a href="#-documentation"><b>Documentation</b></a>
  </p>
</div>

---

## 🛡️ Overview

The **Security Management Platform (SMP)** is an Vulnerability Assessment and Penetration Testing (VAPT) orchestrator designed for high-compliance, air-gapped environments.

> **Current Version**: `V9.5` — Major architecture rebuild introducing the **Security Data Pipeline**, evidence-preserving deduplication, offline CVE intelligence, and cryptographically-signed VAPT reports.

Unlike cloud-based SIEMs that exfiltrate sensitive intelligence to third-party servers, **SMP executes 86+ distinct security tools locally**, routes all raw outputs through an **encrypted evidence store**, correlates findings via offline CVE/EPSS/KEV intelligence, and generates tamper-evident PDF/JSON reports — entirely on your own hardware.

---

## ✨ Key Features

### 🔒 Absolute Data Sovereignty
- **Zero cloud dependency** — all analysis runs locally
- **SQLCipher (AES-256)** encrypted databases with a hierarchical key model (KEK → DEK/IEK/EEK)
- **Per-file AES-256-GCM** encryption for all raw scanner evidence
- `SMP_LOCAL_ONLY=1` mode structurally blocks all external API calls
- Master password with PBKDF2-SHA256 (600,000 iterations) key derivation

### 🚀 Security Data Pipeline
SMP V9.5 treats security findings as immutable data — not mutable records. The full pipeline:
```
Nmap Discovery → Observations → Evidence Store → CVE Intelligence Matching → Finding Correlation → Risk Scoring → Signed Report
```
- **Nmap as first-class asset source** — parsed into typed AssetObservation, PortObservation, ServiceObservation, CPEObservation
- **Evidence-preserving deduplication** — SHA-256 fingerprint-based correlation, never destroys raw evidence
- **Offline CVE intelligence** — NVD, CISA KEV, EPSS via local `vulnerability.db`

### 🧠 Intelligent Orchestration
- **DAG-based concurrent execution** using Kahn's topological sort (86+ scanners)
- **Scope Engine** — CIDR, wildcard, regex authorization boundaries, prevents out-of-scope scanning
- **14-state scanner state machine** (NOT_STARTED → RUNNING → COMPLETED_WITH_FINDINGS / TIMEOUT / PARSE_FAILED etc.)
- **Autonomous self-healing** — `tools/troubleshoot.py --fix` resolves missing binaries and DB corruption

### 📊 Professional Reporting
- **Tamper-evident VAPT reports** — SHA-256 authenticity hash over entire report payload
- Sections: Cover Page · Executive Summary · Scope & Methodology · Per-Finding Detail · Asset Inventory · Appendix
- Compliance mapping: **SOC 2 Type II, ISO 27001, CIS Controls v8, PCI-DSS v4.0**
- Output formats: **PDF, Markdown, JSON**

### 🌐 API & Integration
- **FastAPI REST API** with JWT authentication (`--api` mode)
- **WebSocket real-time scan updates**
- OpenAPI/Swagger docs at `/api/v6/docs`
- Headless Docker mode for CI/CD pipelines

---

## ⚡ Quick Start

### Linux \& macOS

```bash
# 1. Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# 2. Run the automated installer (handles all system packages, Python deps, and Go tools)
./setup.sh

# 3. Verify environment integrity (optional — auto-heals missing binaries)
python3 tools/troubleshoot.py --fix

# 4. Launch the desktop GUI
./run.sh

# — or — launch in headless API mode (no display required)
./run.sh --api
# API docs available at: http://localhost:8000/api/v6/docs
```

> **Windows is not supported.** Use WSL2.

### Generate a Demo Report (no GUI required)

```bash
python3 tools/generate_demo_report.py
# → outputs: reports/demo_report.json
# → outputs: reports/demo_report.md
```

---

## 🏗️ Architecture

SMP V9.5 implements a **layered security-data pipeline** with strict separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    SMP V9.5 Architecture                     │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  PySide6 UI  │   │  FastAPI API │   │  CLI Tools   │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       └──────────────────┼──────────────────┘
                          │
               ┌──────────▼──────────┐
               │  Application Layer   │
               │  Engagement / Scope  │
               └──────────┬──────────┘
                          │
     ┌────────────────────┼───────────────────┐
     │                    │                   │
┌────▼─────┐    ┌─────────▼──────┐   ┌───────▼──────┐
│  Scope   │    │  Scan Planner  │   │  Scheduler   │
│  Engine  │    │  (DAG Builder) │   │  (Kahn's)    │
└────┬─────┘    └─────────┬──────┘   └───────┬──────┘
     └────────────────────┼──────────────────┘
                          │
               ┌──────────▼──────────┐
               │  Execution Sandbox   │
               └──────────┬──────────┘
                          │
     ┌────────────────────┼───────────────────┐
     │                    │                   │
┌────▼────────┐  ┌────────▼────────┐  ┌───────▼──────┐
│  86+ Scanner│  │  Observation    │  │  Evidence    │
│  Adapters   │  │  Parsers        │  │  Store       │
└─────────────┘  └────────┬────────┘  │  (AES-256    │
                          │           │   per-file)  │
                          │           └──────────────┘
               ┌──────────▼──────────┐
               │   Finding Engine     │
               │  (Fingerprint Dedup) │
               └──────────┬──────────┘
                          │
     ┌────────────────────┼───────────────────┐
     │                    │                   │
┌────▼────────┐  ┌────────▼────────┐  ┌───────▼──────┐
│  Vuln Intel │  │  Report         │  │  Risk Engine │
│  (NVD/KEV/  │  │  Generator      │  │              │
│   EPSS)     │  │  (PDF/MD/JSON)  │  │              │
└─────────────┘  └─────────────────┘  └──────────────┘
```

### Data Flow

```
1.  Target Definition
2.  Scope Validation (ScopeEngine)
3.  Scan Planning (ScanPlanner + DAG)
4.  Scanner Execution (ScannerAdapters + ExecutionSandbox)
5.  Raw Output → Evidence Store (AES-256-GCM per file)
6.  Observation Parsing (typed: Asset/Port/Service/CPE/Vuln)
7.  CVE Intelligence Matching (offline NVD/EPSS/KEV)
8.  Finding Correlation (SHA-256 fingerprint deduplication)
9.  Risk Scoring
10. Signed VAPT Report (SHA-256 authenticity hash)
```

### Database Architecture

```
data/
├── security.db          # Encrypted (DEK): engagements, scans, findings, observations
├── vulnerability.db     # Encrypted (IEK): CVEs, CPEs, EPSS, CISA KEV
├── evidence/            # Per-file AES-256-GCM: raw scanner outputs
│   └── <eng>/<scan>/<evidence_id>/
│       ├── evidence.enc
│       ├── metadata.json
│       └── checksum.txt
└── work/                # Temporary scanner workspaces
    └── <scan_id>/
```

---

## 🔐 Security Model

SMP uses a **4-layer hierarchical key architecture**:

```
Master Password (PBKDF2-SHA256, 600k iterations)
       ↓
Key Encryption Key (KEK)
       ↓
├── Database Encryption Key (DEK) → security.db (AES-256)
├── Intelligence Encryption Key (IEK) → vulnerability.db (AES-256)
└── Evidence Encryption Key (EEK) → per-file evidence (AES-256-GCM)
```

- Keys exist **in-memory only** — never persisted in plaintext
- Sub-keys are encrypted with AES-256-GCM under the KEK and stored in `config/auth.json`
- Key operations are audit-logged to `logs/key_audit.log`
- Password rotation re-encrypts all sub-keys without changing DEK/IEK/EEK

---

## 📚 Documentation

| Document | Description |
|---|---|
| [USER_GUIDE.md](USER_GUIDE.md) | Full operational manual, API reference, scanner configuration |
| [docs/thesis/SMP_THESIS_V9.5.md](docs/thesis/SMP_THESIS_V9.5.md) | Academic paper — mathematical proofs, algorithmic analysis |
| [CHANGELOG.md](CHANGELOG.md) | Version history and change log |
| [ERROR_CODES.md](ERROR_CODES.md) | `SMP-xxxx` error code reference |
| [SECURITY.md](SECURITY.md) | Security disclosure policy |
| [troubleshooting/](troubleshooting/) | Autonomous recovery procedures |

---

## 🤝 Contributing

Built and maintained by **mrQhere**.

This project started as a learning exercise and evolved into a sovereign, intelligence engine. The git history intentionally preserves the entire evolution for educational transparency.

Before contributing, please:
1. Read [SECURITY.md](SECURITY.md)
2. Ensure new scanner modules use the `@register_scanner` decorator from `scanners/core/registry.py`
3. Include a test fixture in `tests/`
4. Verify all 12 suites still pass: `python3 tools/verify_smp.py`

---

<div align="center">
<i>Use only against systems you have written authorisation to test.</i>
<br>
© mrQhere. Licensed under the MIT License.
</div>
