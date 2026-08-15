<div align="center">
  
# Security Management Platform (SMP) V9.5

[![CI](https://img.shields.io/github/actions/workflow/status/mrQhere/SecurityManagementPlatform/ci.yml?style=for-the-badge)](https://github.com/mrQhere/SecurityManagementPlatform/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![AES-256](https://img.shields.io/badge/Encryption-AES--256-critical?style=for-the-badge)](SECURITY.md)
[![CodeQL](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/codeql-analysis.yml/badge.svg?style=flat)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/codeql-analysis.yml)

The ultimate open-source, on-premise Vulnerability Assessment and Penetration Testing orchestration engine.

[Overview](#-overview) • [Features](#-key-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Security](#-security-model) • [Documentation](#-documentation)

</div>

<br/>

## 🛡️ Overview

The Security Management Platform (SMP) is a Vulnerability Assessment and penetration testing automation framework designed strictly for security professionals and red teams. Operating completely on-premise with a zero-cloud dependency model, SMP guarantees absolute data sovereignty. 

At its core in V9.5, SMP acts as a central nervous system for **95 scanner modules**, orchestrating them through a sophisticated Directed Acyclic Graph (DAG) pipeline. By abstracting away the complex command-line arguments, dependency management, and parsing logic of the world's most powerful open-source security tools, SMP allows security teams to focus on triage and remediation rather than tool wrangling.

Whether deployed via its comprehensive 10-tab PySide6 UI or headless via the FastAPI backend, SMP standardizes the execution, deduplication, and reporting lifecycle of vulnerability assessments.

## ✨ Key Features

### 1. Data Sovereignty & Cryptographic Security
* **Zero Cloud Dependency:** 100% on-premise execution. Your vulnerability data, target lists, and credentials never leave your infrastructure.
* **4-Layer Cryptographic Architecture:** Advanced key derivation leveraging KEK, DEK, IEK, and EEK strategies (PBKDF2-SHA256 with 600,000 iterations).
* **Database Encryption at Rest:** All sensitive operational data is secured within SQLCipher AES-256 databases (`security.db` and `redundancy.db`).
* **Encrypted Evidence Store:** Raw scanner output and exploitation proof in `data/evidence/` are individually encrypted using AES-256-GCM.
* **API Security:** Complete backend protection utilizing JWT Bearer authentication under the `/api/v6/` namespace.

### 2. DAG-Orchestrated Security Data Pipeline
* **95 Scanner Modules:** Massively parallel execution of 95 distinct tools (Nuclei, Nmap, Masscan, Metasploit, TruffleHog, Checkov, Trivy, and more).
* **Kahn's Algorithm Orchestration:** Dynamically calculates scanner execution order and resolves dependencies using graph topology to prevent port collisions.
* **14-State Machine Tracking:** Robust scanner state tracking from initialization and recon to active exploitation and finalization.
* **Typed Observation Model:** Normalizes disparate tool outputs (JSON, XML, CSV, Regex) into standard immutable Python data classes.
* **SHA-256 Deduplication:** Intelligently collapses overlapping findings (e.g., Nmap and Masscan finding the same open port) via cryptographic hashing.

### 3. Comprehensive Target Scope Engine
* **Engagement Scoping:** Define strict rules of engagement using CIDR blocks, single IP addresses, domain wildcards, and regex URLs.
* **Default-Deny Posture:** Scanners will fundamentally refuse to route traffic to any asset not explicitly allow-listed in the target scope.
* **Dynamic Resolution:** Seamlessly resolves DNS and expands subnets during the reconnaissance phase to populate the target map.
* **Out-of-Scope Drops:** Any scanner finding that falls outside the allowed engagement boundaries is automatically dropped and flagged in the audit log.
* **Target Segregation:** Complete data isolation between different clients or internal departments within the unified database structure.

### 4. High-Performance Decoupled Architecture
* **FastAPI Backend (`/api/v6/`):** Asynchronous, high-throughput REST API supporting comprehensive programmatic integration.
* **PySide6 Desktop Client:** A responsive, multi-threaded GUI featuring a 10-tab dashboard (Overview, Targets, Active Scans, Findings, Intel, etc.).
* **Asynchronous execution:** Scanner processes are heavily sandboxed with strict CPU, memory, and timeout governance.
* **CI/CD Quality Gates:** Maintained through stringent continuous integration, verified by 15 separate `tools/verify_smp.py` suites and 18 pytest suites.
* **Self-Healing Installer:** The `setup.sh` script automatically detects OS architectures, downloads required Go/Python/Ruby binaries, and handles dpkg locks.

### 5. Enterprise Reporting & Data Export
* **Customizable PDF Generation:** Beautiful, professional PDF reports complete with CVSS v3.1 scoring, PCI-DSS v4.0 mapping, and mitigation steps.
* **Multi-Format Support:** Export findings to JSON, Markdown, CSV, or standard SARIF 2.1.0 formats for CI/CD ingestion.
* **Enterprise Ticketing Exporter:** One-click integration payloads mapped for Jira, ServiceNow, and DefectDojo.
* **Authenticity Hashing:** Every generated report receives a unique SHA-256 signature to guarantee non-repudiation and tamper evidence.
* **Mandatory Legal Gates:** Enforced typed `"I AGREE"` dialogs for exporting plaintext vulnerabilities, permanently recorded in audit logs.

## ⚡ Quick Start

### 1. Pre-Flight Installation (Linux/macOS)

SMP utilizes a heavily engineered, self-healing installation script. Prior to downloading dependencies, `setup.sh` runs extensive pre-flight network checks to ensure repository mirrors (GitHub, PyPI, Go) are reachable, preventing partial installs.

```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Execute the self-healing setup engine
chmod +x setup.sh
./setup.sh
```

### 2. Launching the Platform

You can start the full PySide6 GUI interface via the run script:

```bash
# Launch the Desktop UI
./run.sh
```

### 3. Headless API Mode

For server deployments, CI/CD pipelines, or remote integrations, run the backend API directly:

```bash
source venv/bin/activate
# Starts the FastAPI server on port 8000
python -m api.server
```

## 🏗️ Architecture

### ASCII Data Flow Pipeline

The Security Management Platform processes vulnerabilities via a strictly enforced unidirectional pipeline:

```text
  [ Target ] ---> [ Scope Engine ] ---> [ DAG Orchestrator ] ---> [ 95 Scanners ]
                                                                        |
                                                                        v
  [ Report Generator ] <--- [ Risk Scoring ] <--- [ Deduplication ] <--- [ CVE Correlation ] <--- [ Evidence Store ] <--- [ Observation Parser ]
```

### Database Architecture

To maintain strict data segregation and performance, SMP distributes its schema across four distinct SQLite/SQLCipher databases:

| Database | Type | Encryption | Purpose |
|----------|------|------------|---------|
| `security.db` | Operational | **SQLCipher AES-256** | Houses all sensitive client data, scan targets, credentials, job states, and parsed vulnerability findings. |
| `redundancy.db` | Backup | **SQLCipher AES-256** | High-availability, fault-tolerant mirror of `security.db` for automated recovery in case of corruption. |
| `cve.db` | Threat Intel | Plaintext | Contains static vulnerability intelligence, CVE descriptions, and mitigation advice. **Contains no PII or client data.** |
| `analytics.db` | Telemetry | Plaintext | Stores application performance metrics, scanner execution times, and pipeline efficiency logs. **Contains no PII or client data.** |

### Verification & Testing Architecture

SMP enforces reliability through rigorous quality assurance tooling built into the core:
* **Verify Suites:** The framework is validated via `tools/verify_smp.py`, which executes **15 distinct verification suites**, verifying everything from DAG topology and Pydantic v2 compliance to CI workflow manifests.
* **Unit Testing:** The `tests/` directory contains **18 passing pytest test suites** ensuring critical path logic remains stable during updates.

## 🔐 Security Model

SMP was designed under the assumption that the host machine could be compromised. Data at rest is protected by a bespoke cryptographic key management system.

### 4-Layer Key Hierarchy

1. **Key Encryption Key (KEK):** Derived directly from the user's master password utilizing PBKDF2-SHA256 pushed to **600,000 iterations**. The KEK is never stored on disk.
2. **Database Encryption Key (DEK):** A randomly generated high-entropy key that decrypts `security.db` and `redundancy.db`. It is stored encrypted (wrapped) by the KEK.
3. **Intel Encryption Key (IEK):** Secures custom intelligence payloads or proprietary signatures. Wrapped by the KEK.
4. **Evidence Encryption Key (EEK):** Used exclusively for the `data/evidence/` directory to encrypt raw scanner dumps via AES-256-GCM. Wrapped by the KEK.

This architecture ensures that changing the master password only requires re-wrapping the DEK/IEK/EEK, avoiding computationally expensive database rewrites.

## 🧰 API Endpoints

The FastAPI backend operates under the `/api/v6/` prefix. Key endpoints include:
- `GET /api/v6/health` - System status.
- `GET /api/v6/version` - V9.5 version check.
- `POST /api/v6/auth/token` - JWT token issuance.
- `GET /api/v6/target`, `POST /api/v6/target` - Scope management.
- `GET /api/v6/scan` - DAG orchestration tracking.
- `GET /api/v6/findings` - Retrieve deduplicated results.
- `GET /api/v6/cve/stats` - Threat intelligence queries.
- `GET /api/v6/risk/score` - Organizational risk analytics.

## 📚 Documentation

Detailed documentation is essential for mastering the platform's orchestration capabilities:

- [**USER_GUIDE.md**](USER_GUIDE.md): The comprehensive 1,500+ line technical manual covering installation, configuration, and custom scanner development.
- [**Architecture Thesis**](docs/thesis/): In-depth academic analysis detailing the queuing theory, Kahn's algorithm, and cryptography behind SMP V9.5.
- [**Troubleshooting Guide**](troubleshooting/): Step-by-step resolution paths for network, dependency, and database locks.
- [**Error Codes Reference**](ERROR_CODES.md): Exhaustive index of all 1xxx to 9xxx internal error codes, root causes, and remediation steps.

## 🤝 Contributing

Pull requests are highly encouraged! Whether you are writing a new `ScannerAdapter` wrapper for the latest open-source tool, or optimizing the PySide6 UI, contributions are welcome.

For major architectural changes, please open an issue first to discuss the proposed modifications. Ensure all code conforms to the project's Ruff linting standards and that all 15 verification suites and 18 pytests pass successfully before submission.
