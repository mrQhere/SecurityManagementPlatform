# Security Management Platform (SMP) V9.4.2

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-blue)
![Security](https://img.shields.io/badge/security-AES--256-critical)
![Scanners](https://img.shields.io/badge/scanners-55_Integrated-blueviolet)
![Architecture](https://img.shields.io/badge/architecture-Local_First-success)

**Local-first VAPT platform. Zero cloud. Encrypted at rest.**

Maintained by [@mrQhere](https://github.com/mrQhere).

---

<img width="914" height="457" alt="smp_social_preview_1786038228676" src="https://github.com/user-attachments/assets/3fb78ea7-973b-4a41-a95b-b0bb4651eb2f" />

## Project Status

> [!WARNING]
> This is a personal project maintained on a best-effort basis. It is currently at **V9.4.2**.
> Please see the [CHANGELOG.md](CHANGELOG.md) for recent updates.

## What it is

> [!NOTE]
> SMP is a penetration testing orchestration platform that runs 55 open-source scanners, correlates findings across multiple threat-intelligence sources, and produces compliance-mapped reports — all without sending your client data to a third-party cloud.

**V9.4.2 Major Features:**

1. **Self-Healing Diagnostics Engine**: Built-in automated recovery for missing dependencies, broken databases, or scanner failures (`python3 tools/troubleshoot.py --fix`).
2. **Correlation & Deduplication Depth**: Levenshtein distance deduplication reduces noise, while EPSS, GreyNoise, and CISA KEV cross-referencing provide real-world exploitability context.
3. **Provable local-only operation**: Outbound intelligence logs every network call to `logs/egress_audit.log`. Set `SMP_LOCAL_ONLY=1` to block all external calls.
4. **Compliance gap analysis**: Dynamically maps findings to SOC 2 Type II, ISO 27001, CIS, and PCI-DSS v4.0.
5. **SQLCipher encryption**: "Encrypted at rest" is unconditionally enforced on all sensitive pentest data.
6. **Robust Network Evasion**: Fail-closed MAC Changer logic guarantees scanner execution even under permission constraints.

---

## Quick Start (Linux / macOS)

Copy and paste the following commands to install and run SMP:

```bash
# 1. Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# 2. Install (Creates Python venv, installs SQLCipher & 55 tools — ~2 min)
./setup.sh

# 3. Auto-Heal & Verify Environment (Fixes missing dependencies instantly)
python3 tools/troubleshoot.py --fix

# 4. Run the GUI Desktop App
./run.sh
```

**Run headless REST API instead:**
```bash
python3 main.py --api
```

> [!TIP]
> **Encountering an issue?** Run `python3 tools/troubleshoot.py --fix` to let SMP automatically diagnose and repair itself. For more details, see the [Troubleshooting Guide](troubleshooting/).

### Docker (Windows / All Platforms)

Windows users must use Docker. Read [USER_GUIDE.md](USER_GUIDE.md#1--installation) for more details.

```bash
docker compose up -d
# API Documentation is available at: http://localhost:8000/api/v6/docs
```

### Local-only mode (No outbound calls)

```bash
SMP_LOCAL_ONLY=1 ./run.sh
```
All intelligence API calls will be blocked and logged as `BLOCKED` in `logs/egress_audit.log`.

---

## 🛠️ The V9.4.2 Self-Healing Engine

SMP now features an autonomous recovery engine. Whenever a component crashes or a dependency goes missing, SMP assigns it an `SMP-xxxx` error code. 

**To automatically resolve 90% of issues:**
```bash
source venv/bin/activate
python3 tools/troubleshoot.py --fix
```
The engine will automatically:
- Fix `SMP-3001` Database locks by executing `PRAGMA wal_checkpoint(TRUNCATE)`.
- Fix `SMP-2002` Missing Binaries by auto-installing deleted scanners.
- Repair corrupted Python environments.

For a full list of error codes, see [troubleshooting/auto_fixes.md](troubleshooting/auto_fixes.md).

---

## System Architecture

```text
SecurityManagementPlatform/
├── api/                   # REST API backend (FastAPI)
├── config/                # Platform configuration & metadata
├── database/              # SQLite databases (security.db encrypted)
├── intelligence/          # Correlation engine & API connectors
├── logs/                  # Unified logging directory
├── scanners/              # 55 pentesting scanner wrappers (Nmap, ZAP, etc.)
├── tools/                 # Unified toolset (troubleshoot.py, deduplicator, etc.)
├── ui/                    # Desktop Application (PySide6)
├── main.py                # Application entrypoint
├── setup.sh               # Linux/macOS installer
└── tools/verify_smp.py    # CI/CD integrity testing suite
```

---

## Legal

Use only against systems you have written authorisation to test.  
Maintained by [@mrQhere](https://github.com/mrQhere) · © mrQhere. See [LICENSE](LICENSE).

## About

Built and maintained by mrQhere. This started as a learning project and turned into something I actually care about getting right. The mistakes are in the git history on purpose, not hidden, because I'd rather someone learn from how this got fixed than think it was perfect from the start. If you're using this for real work, read [SECURITY.md](SECURITY.md) first and don't trust anything blindly, including this note. Good luck.
