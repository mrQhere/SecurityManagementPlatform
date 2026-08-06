# Security Management Platform (SMP) V9.3.3

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)

**Local-first VAPT platform. Zero cloud. Encrypted at rest.**

Maintained by [@mrQhere](https://github.com/mrQhere).

---

## What it is

SMP is a penetration testing orchestration platform that runs ~30 open-source scanners, correlates findings across multiple threat-intelligence sources, and produces compliance-mapped reports — all without sending your client data to a third-party cloud.

**V9.3.3** ships a Neural Correlation Engine (`intelligence/brain.py`) that builds a local heuristics graph from real scan data and the CISA KEV catalog. It includes a force-directed graph UI (`ui/components/neural_graph.py`) to visualise CVE relationships. The CVSS and EPSS values in the graph are populated from live NVD and EPSS API calls — not hardcoded.

**The core pitch is not tool count.** It is:

1. **Correlation depth** — most scanner wrappers report raw CVSS. SMP cross-references each finding against EPSS, GreyNoise, and CISA KEV to produce a single, weighted risk score that reflects real-world exploitability.
2. **Provable local-only operation** — outbound intelligence logs every network call to `logs/egress_audit.log`. Set `SMP_LOCAL_ONLY=1` to block all external calls.
3. **Minimalist UX** — dark aesthetic prioritising raw information density over chrome.
4. **Compliance gap analysis** — maps findings to SOC 2 Type II, ISO 27001, CIS, and PCI-DSS v9.3.3.
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
- Raw scanner stdout is compressed and encrypted with **Fernet (AES-128-CBC + HMAC-SHA256)** before database storage.
- Public intelligence databases (`cve.db`, `global_intel.db`) are plaintext SQLite for I/O performance — they contain no client data.
- Master password uses PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST 2024 recommendation).

---

## Roadmap

### Near-term (V9.3.3.x)
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
