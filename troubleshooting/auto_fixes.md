# 🛡️ Auto-Fixes & Error Taxonomy

The V9.4.3 architecture introduces the **Unified Self-Healing Engine**. This engine standardizes all platform crashes, database locks, and dependency failures into a strict `SMP-xxxx` taxonomy.

Most errors can be resolved instantly by running:
```bash
python3 tools/troubleshoot.py --fix
```

## Error Code Taxonomy & Auto-Recovery Actions

| Error Code | Class | Description | Auto-Recovery (`--fix`) Behavior |
|------------|-------|-------------|------------------------------------|
| **SMP-1000** | `SMPAuthError` | Broad authentication or session failure. | Clears stale session state and prompts for JWT regeneration. |
| **SMP-1001** | `SMPTokenExpiredError`| JWT has expired or signature is invalid. | Flushes API auth cache. |
| **SMP-2000** | `SMPScannerError` | Broad scanner execution failure. | Kills hanging subprocesses. |
| **SMP-2001** | `SMPScannerTimeoutError`| Scanner exceeded configured execution limit. | Resets scanner timeout heuristics in config. |
| **SMP-2002** | `SMPScannerBinaryMissingError`| Missing scanner (e.g., Go/Node tool). | Auto-invokes `tool_installer.py` to fetch missing binaries from GitHub/NPM. |
| **SMP-2003** | `SMPScannerCrashedError`| Subprocess segfaulted or exited non-zero. | No auto-fix. Flags for developer review. |
| **SMP-2004** | `SMPScannerOutputParseError`| Invalid JSON/XML returned by scanner. | Logs raw output for manual review. |
| **SMP-3000** | `SMPDatabaseError` | Broad SQLite / SQLCipher failure. | Validates directory read/write permissions. |
| **SMP-3001** | `SMPDBConnectionError`| Database locked (`database is locked`). | Executes `PRAGMA wal_checkpoint(TRUNCATE)` to flush locked WAL journals. |
| **SMP-3002** | `SMPDBEncryptionError`| Incorrect master password or unencrypted DB. | Instructs user to clear corrupted `database/*.db` and re-initialize. |
| **SMP-4000** | `SMPValidationError` | Internal API payload validation failure. | Clears malformed requests. |
| **SMP-5000** | `SMPConfigError` | Broad configuration or environment issue. | Recreates missing core directories (`reports/`, `logs/`). |
| **SMP-5001** | `SMPConfigMissingError`| `settings.json` is missing or corrupted. | Restores `settings.json` from `config_manager.py` defaults. |
| **SMP-5002** | `SMPIntelSyncError`| NVD/CISA sync failed (offline or rate-limited). | Clears sync lock files and resets sync timestamp. |
| **SMP-9999** | `SMPUnclassifiedError`| Unhandled edge case exception. | Dumps full stack trace to `logs/scan.log`. No auto-fix. |

## Network MAC Changer Constraints (SMP-5001)

If the `mac_changer.py` fails due to lack of `sudo` or `setcap` permissions, the platform deliberately suppresses the crash. It logs an `SMP-5001` warning and **continues scanning using the original MAC address**. This fail-closed design ensures scans complete even in constrained Docker environments.

To manually fix `macchanger` / `Nmap` permissions if you want stealth capabilities:

**Option 1: Set Capabilities (Recommended for Docker/Linux)**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

**Option 2: Sudoers No-Password**
```bash
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/nmap_smp
```
