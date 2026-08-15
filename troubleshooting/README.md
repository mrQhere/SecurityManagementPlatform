# 🛠️ SMP V9.5 — Troubleshooting & Diagnostics Reference

This directory contains the operational troubleshooting guides and edge-case resolution manuals for the **Security Management Platform (SMP) V9.5 Security Data Pipeline**.

---

## ⚡ Step 1: Autonomous Self-Healing (Run First)

In SMP V9.5, most common environmental faults (missing directory trees, stale process lock files, SQLite WAL lock contention, missing tool binary links) are resolved automatically by the self-healing engine.

```bash
# 1. Activate Python virtual environment
source venv/bin/activate

# 2. Run automated self-healing diagnostics and repair
python3 tools/troubleshoot.py --fix
```

### Look up any error code directly:
```bash
python3 tools/troubleshoot.py --lookup SMP-3003
```

---

## 📚 Categorized Troubleshooting Guides

When an issue cannot be resolved automatically by `--fix`, consult the domain-specific guide for your error:

| Domain | Guide | Error Code Range | Key Issues Addressed |
|---|---|---|---|
| 🔐 **Authentication & Keys** | [api.md](api.md) | `SMP-1000` – `SMP-1009` | JWT token expiration, KEK derivation, DEK/IEK/EEK unlock, password complexity |
| 🗄️ **Database & SQLCipher** | [database.md](database.md) | `SMP-3000` – `SMP-3007` | PRAGMA key failure, WAL lock deadlock, migration errors, backup recovery |
| 🔬 **Scanners & DAG Engine** | [scanners.md](scanners.md) | `SMP-2000` – `SMP-2010`, `SMP-4040`–`4042` | DAG dependency cycles, Nmap raw capability, timeout budgets, port collisions |
| 🔌 **API & WebSockets** | [api.md](api.md) | `SMP-4000` – `SMP-4002` | FastAPI 401/403/429, SlowAPI rate limiting, CORS preflight, WebSocket disconnects |
| 📄 **Reports & Evidence** | [reports.md](reports.md) | `SMP-4010` – `SMP-4022` | Authenticity hash mismatch, WeasyPrint PDF rendering, evidence tamper alerts |
| 📦 **Installation & Runtime** | [installation.md](installation.md) | `SMP-2002`, `SMP-4041` | `pysqlcipher3` C compilation, Qt XCB GUI crashes, Go/Node toolchains, Docker |
| 🤖 **Autonomous Auto-Fixes** | [auto_fixes.md](auto_fixes.md) | `SMP-9000` – `SMP-9999` | Lock removal recipes, cache flushes, service restarts, emergency factory reset |

---

## 🔍 The V9.5 Diagnostic Flowchart

```
                          ┌────────────────────────┐
                          │     Fault Detected     │
                          │   (UI / API / CLI)     │
                          └───────────┬────────────┘
                                      │
                                      ▼
                          ┌────────────────────────┐
                          │ Run Automated Healing  │
                          │ tools/troubleshoot.py  │
                          │         --fix          │
                          └───────────┬────────────┘
                                      │
                         ┌────────────┴────────────┐
                         │                         │
                   [Resolved ✅]              [Unresolved ❌]
                         │                         │
                         ▼                         ▼
                  Resume Operations       Check Error Code Map
                                          (ERROR_CODES.md)
                                                   │
                                                   ▼
                                        Consult Specific Guide
                                        (e.g., database.md)
```

---

## 🧪 System Health Verification

To run the complete 11-suite end-to-end integration and cryptographic attestation test pipeline:

```bash
source venv/bin/activate
python3 tools/verify_smp.py
```
