# 🛠️ SMP V9.4.4 — Troubleshooting Index

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

| Category | File | Common errors covered |
|----------|------|-----------------------|
| 📦 [Installation](installation.md) | `installation.md` | pysqlcipher3, libxcb-cursor0 / Qt xcb crash, binary download, Go PATH, WPScan wrapper |
| 🗄️ [Database](database.md) | `database.md` | DB locked, SQLCipher key mismatch, migration errors, CVE sync |
| 🔬 [Scanner Errors](scanners.md) | `scanners.md` | Nmap root, Nuclei templates, ffuf false positives, timeouts |
| 🔌 [API Errors](api.md) | `api.md` | 401/403/429, FastAPI startup, CORS, JWT secrets |
| 📄 [Reports & SBOM](reports.md) | `reports.md` | PDF generation, SBOM empty, report verification, SMTP |
| 🤖 [Auto Fixes](auto_fixes.md) | `auto_fixes.md` | Stale locks, temp files cleanup, reset services, flush cache |

## V9.4.4 Exploit Frameworks Troubleshooting

With the introduction of 15 advanced exploit frameworks (inspired by DefectDojo/Faraday), you may encounter new edge cases. Reference these fixes if the DAG encounters deadlocks during Phase 2 or Phase 3:

*   **`SMP-4040` Metasploit/Impacket Timeout**: If `msfconsole` or `impacket-psexec` drops a shell, it will block the DAG. Adjust the `timeout` parameter in their respective scanner wrappers to force an exception.
*   **`SMP-4041` OSV-Scanner Binary Incompatibility**: If `osv-scanner` fails to run, ensure Golang is properly installed and the binary was compiled natively for your architecture during `setup.sh`.
*   **`SMP-4042` Responder Port 53 Collision**: `Responder` aggressively binds to UDP port 53. If you run `systemd-resolved` or `dnsmasq`, the scanner will crash. Stop local DNS caching before launching `Responder`.
*   **OpenVAS Signature Loops**: If `OpenVAS` hangs during initialization, run `greenbone-nvt-sync` manually to resolve the blocking feed update.

---

## Quick Verification

To ensure all 90 components are healthy and the Directed Acyclic Graph (DAG) has no deadlocks:

```bash
source venv/bin/activate
python3 tools/verify_smp.py
```
*(This script runs the full 11-suite testing pipeline and takes ~5 minutes to complete).*
