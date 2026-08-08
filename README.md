# Security Management Platform (SMP) V9.4.2

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-blue)
![Security](https://img.shields.io/badge/security-AES--256-critical)
![Scanners](https://img.shields.io/badge/scanners-30%2B_Integrated-blueviolet)
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
> SMP is a penetration testing orchestration platform that runs ~30 open-source scanners, correlates findings across multiple threat-intelligence sources, and produces compliance-mapped reports — all without sending your client data to a third-party cloud.

> [!TIP]
> **V9.4.2** ships a Neural Correlation Engine (`intelligence/brain.py`) that builds a local heuristics graph from real scan data and the CISA KEV catalog. It includes a force-directed graph UI (`ui/components/neural_graph.py`) to visualise CVE relationships. The CVSS and EPSS values in the graph are populated from live NVD and EPSS API calls — not hardcoded.

**The core pitch is not tool count.** It is:

1. **Correlation depth** — most scanner wrappers report raw CVSS. SMP cross-references each finding against EPSS, GreyNoise, and CISA KEV to produce a single, weighted risk score that reflects real-world exploitability.
2. **Provable local-only operation** — outbound intelligence logs every network call to `logs/egress_audit.log`. Set `SMP_LOCAL_ONLY=1` to block all external calls.
3. **Minimalist UX** — dark aesthetic prioritising raw information density over chrome.
4. **Compliance gap analysis** — maps findings to SOC 2 Type II, ISO 27001, CIS, and PCI-DSS v4.0.
5. **SQLCipher encryption, not optional** — "Encrypted at rest" is unconditionally enforced on all sensitive pentest data. Public CVE models are deliberately unencrypted for maximum I/O performance.

---

## System Architecture

```text
SecurityManagementPlatform/
├── api/                   # REST API backend (FastAPI)
├── config/                # Platform configuration & metadata
├── database/              # SQLite databases (security.db, global_intel.db)
├── intelligence/          # Correlation engine & API connectors (CISA, NVD, EPSS)
├── logs/                  # Unified logging directory
├── scanners/              # 30+ pentesting scanner wrappers (Nmap, ZAP, etc.)
├── tools/                 # Core engine (Scheduler, Database manager, Encryption)
├── ui/                    # Desktop Application (PySide6)
│   ├── components/        # UI widgets (NeuralGraphWidget)
│   ├── views/             # Dashboard and navigation logic
│   └── style.qss          # Global dark theme
├── main.py                # Application entrypoint
├── setup.sh               # Linux/macOS installer
└── tools/verify_smp.py    # CI/CD integrity testing suite
```

---

## Quick Start (Linux / macOS)

```bash
# 1. Clone
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# 2. Install (Python venv + SQLCipher + Go tools — ~2 min)
./setup.sh

# 3. Run GUI
./run.sh

# Run headless REST API instead
python main.py --api
```

> [!NOTE]
> Having installation issues? Check the [Troubleshooting Guides](troubleshooting/).

### Windows

Use Docker (see [USER_GUIDE.md](USER_GUIDE.md#24-docker--all-platforms)):

```bash
docker compose up -d
# API: http://localhost:8000/api/v7/docs
```

### Local-only mode (no outbound calls)

```bash
SMP_LOCAL_ONLY=1 ./run.sh
```

All intelligence API calls will be blocked and logged as `BLOCKED` in `logs/egress_audit.log`.

---

## Encryption At Rest

- Sensitive pentest data (targets, scans, findings) is encrypted at rest using **SQLCipher (AES-256)**.
- Public intelligence databases (`cve.db`, `global_intel.db`) are plaintext SQLite for I/O performance — they contain no client data.

---

## Roadmap

### Near-term (V9.4.2.x.x)
- Neural Graph filtering by CVE correlation weight
- Custom Nuclei/SQLMap payload injection from the UI
- Air-gapped intelligence update via USB import of `global_intel.db`

### Long-term (V10.0)
- Distributed scan agents with mutually authenticated TLS
- Multi-tenant reporting for MSSP client workspaces

---

## Legal

Use only against systems you have written authorisation to test.  
Maintained by [@mrQhere](https://github.com/mrQhere) · © mrQhere. See [LICENSE](LICENSE).


## About

Built and maintained by mrQhere. This started as a learning project
and turned into something I actually care about getting right — the
mistakes are in the git history on purpose, not hidden, because I'd
rather someone learn from how this got fixed than think it was
perfect from the start. If you're using this for real work, read
[SECURITY.md](SECURITY.md) first and don't trust anything blindly, including this
note. Good luck.
