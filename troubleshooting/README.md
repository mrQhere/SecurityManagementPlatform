# 🛠️ SMP V9.4.3 — Troubleshooting Index

## Step 1: Automated Self-Healing (Do this first)

In V9.4.3, the vast majority of platform errors (missing binaries, locked databases, corrupted Python environments) can be repaired automatically by the SMP Self-Healing Engine. 

Whenever you encounter an error (or a red `SMP-xxxx` code), run the following commands:

```bash
# 1. Activate the Python virtual environment
source venv/bin/activate

# 2. Run the Self-Healing diagnostics and auto-fix script
python3 tools/troubleshoot.py --fix
```

For a detailed breakdown of the `SMP-xxxx` error taxonomy and what actions the `--fix` script takes, read:
👉 **[Auto-Fixes & Error Taxonomy](auto_fixes.md)**

---

## Step 2: Manual Diagnostics

If the automated `--fix` script cannot resolve your issue, consult the manual edge-case guides below. Click the topic that matches your error.

| Category | Directory | Common errors covered |
|----------|------|-----------------------|
| 📦 [Installation](installation/) | `installation/` | pysqlcipher3, libxcb-cursor0 / Qt xcb crash, binary download, Go PATH, WPScan wrapper |
| 🗄️ [Database](database/) | `database/` | DB locked, SQLCipher key mismatch, migration errors, CVE sync |
| 🔬 [Scanner Errors](scanners/) | `scanners/` | Nmap root, Nuclei templates, ffuf false positives, timeouts |
| 🔌 [API Errors](api/) | `api/` | 401/403/429, FastAPI startup, CORS, JWT secrets |
| 📄 [Reports & SBOM](reports/) | `reports/` | PDF generation, SBOM empty, report verification, SMTP |
| 🤖 [Auto Fixes](auto_fixes/) | `auto_fixes/` | Stale locks, temp files cleanup, reset services, flush cache |

---

## Quick Verification

To ensure all 55 components are healthy and the Directed Acyclic Graph (DAG) has no deadlocks:

```bash
source venv/bin/activate
python3 tools/verify_smp.py
```
*(This script runs the full 11-suite testing pipeline and takes ~5 minutes to complete).*
