# 🤖 Automated Auto-Fixes & Self-Healing Reference — V9.5

This document details the automated self-healing capabilities of the **Security Management Platform (SMP) V9.5 Self-Healing Engine** (`tools/troubleshoot.py`).

---

## ⚡ Running Automated Self-Healing

To run the complete automated diagnostics and apply all safe repairs:

```bash
# Activate environment
source venv/bin/activate

# Execute self-healing repairs
python3 tools/troubleshoot.py --fix
```

To output machine-readable results for automated CI/CD pipelines or monitoring:

```bash
python3 tools/troubleshoot.py --fix --json
```

---

## Automated Fixes Applied by `--fix`

| Category | Error Code | Autonomous Action Taken by `--fix` |
|---|---|---|
| **Directory Tree** | `SMP-5001` | Creates missing platform folders (`data/evidence/`, `database/raw_outputs/`, `database/backups/`, `reports/`, `work/`, `logs/`, `bin/`) |
| **Runtime Locks** | `SMP-9999` | Removes stale `~/.smp_runtime.lock` and orphaned `/tmp/smp_*.lock` files from previous crashed sessions |
| **Config Templates** | `SMP-5001` | Restores missing `config/metadata.json` (V9.5) and default configuration files if corrupted or absent |
| **Security Binaries** | `SMP-2002` | Calls `tools/tool_installer.py` to auto-download and install missing Go/Python security binaries into `./bin/` |
| **Database WAL** | `SMP-3003` | Executes `PRAGMA wal_checkpoint(TRUNCATE)` on SQLite/SQLCipher databases to clear lock contention |
| **Database Schema** | `SMP-3005` | Runs migration schema checks to ensure all required tables and indexes exist |
| **Permissions** | `SMP-2007` | Verifies execution bit permissions on local binaries in `./bin/` |

---

## Manual Copy-Paste Recovery Recipes

When manual intervention is required, use these tested recovery recipes:

### Recipe 1: Emergency Stale Lock Removal

If SMP reports `[FATAL] SMP is already running. Core initialization aborted`:

```bash
# Remove all user and system level lock files
rm -f ~/.smp_runtime.lock /tmp/smp_*.lock /tmp/.smp_runtime.lock
```

---

### Recipe 2: Force Database WAL Truncation & Optimization

If SQLite reports `database is locked` after a hard reboot:

```bash
python3 -c "
from tools.db_manager import get_db_connection
conn = get_db_connection()
conn.execute('PRAGMA wal_checkpoint(TRUNCATE);')
conn.execute('PRAGMA optimize;')
conn.close()
print('Database WAL truncated and optimized.')
"
```

---

### Recipe 3: Rebuild All Security Tool Binaries

If multiple scanner binaries are corrupt or missing:

```bash
# Force fresh rebuild of all local Go, Node, and Python tool wrappers
bash setup.sh --force-rebuild
```

---

### Recipe 4: Clean Workspace Temporary Files

To purge temporary scan directories and evidence cache older than 7 days:

```bash
# Clean temporary scanner workspaces
rm -rf work/* /tmp/smp_test_*

# Prune old logs
find logs/ -name "*.log" -mtime +14 -delete
```

---

### Recipe 5: Emergency Password / Auth Reset (Test & Dev Environments Only)

If the master password is lost on a local testing environment:

```bash
# ⚠️ CAUTION: Deleting auth.json will require setting a new master password
rm -f config/auth.json
python3 -c "print('Master password reset. Re-launch SMP to set a new password.')"
```
