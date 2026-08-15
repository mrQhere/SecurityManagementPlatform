# 🗄️ Database & SQLCipher Troubleshooting — V9.5

This guide covers operational maintenance, recovery, and encryption troubleshooting for the SMP encrypted-at-rest storage layer (`pysqlcipher3`, SQLite WAL mode, and Hierarchical Key Management).

---

## Error Codes Covered

| Code | Slug | Issue Description |
|---|---|---|
| `SMP-3000` | `db_error` | Generic database driver / execution failure |
| `SMP-3001` | `db_connection_error` | Cannot connect to database / `pysqlcipher3` missing |
| `SMP-3002` | `db_encryption_error` | Database decryption failed / PRAGMA key rejected |
| `SMP-3003` | `db_wal_locked` | SQLite Write-Ahead Log (WAL) deadlock |
| `SMP-3004` | `db_integrity_check_failed` | PRAGMA integrity_check detected corruption |
| `SMP-3005` | `db_migration_error` | Schema migration failed or table version mismatch |
| `SMP-3006` | `raw_output_storage_failed` | Gzip compression / Fernet encryption storage failure |
| `SMP-3007` | `redundancy_db_failed` | Secondary redundancy database failure |

---

## Common Scenarios & Resolutions

### Scenario 1: `pysqlcipher3` Missing or C-Extension Compile Error (`SMP-3001`)

**Symptom:** Application startup halts with `FATAL: pysqlcipher3 is not installed. SMP requires SQLCipher for encrypted-at-rest storage.`

**Root Cause:** The native C SQLCipher development headers (`libsqlcipher-dev`) are not installed on the OS, causing Python binary wheel builds to fail.

**Copy-Paste Solution:**
```bash
# Debian / Ubuntu / Kali:
sudo apt-get update
sudo apt-get install -y libsqlcipher-dev libsqlcipher0 build-essential python3-dev

# Reinstall pysqlcipher3 in virtual environment
source venv/bin/activate
pip install --no-cache-dir pysqlcipher3

# Verify import
python3 -c "from pysqlcipher3 import dbapi2 as sqlite3; print('SQLCipher OK')"
```

---

### Scenario 2: SQLite Write-Ahead Log (WAL) Deadlock (`SMP-3003`)

**Symptom:** Operations fail with `sqlite3.OperationalError: database is locked`.

**Root Cause:** A previous scanner process or API thread terminated abruptly without closing an active write transaction, leaving a locked `-wal` file.

**Copy-Paste Solution:**
```bash
# Option A: Automated fix via troubleshoot engine
python3 tools/troubleshoot.py --fix

# Option B: Manual WAL checkpoint truncation
python3 -c "
from tools.db_manager import get_db_connection
conn = get_db_connection()
conn.execute('PRAGMA wal_checkpoint(TRUNCATE);')
conn.close()
print('WAL checkpoint complete.')
"
```

---

### Scenario 3: Database Decryption / Key Rejection (`SMP-3002`)

**Symptom:** Database queries fail with `file is not a database` or `PRAGMA key` error.

**Root Cause:** The master password supplied does not produce the correct DEK for `database/security.db`, or the database was initialized with a different master key.

**Copy-Paste Solution:**
```bash
# 1. Verify key state with encryption manager
python3 -c "
from tools.encryption_manager import verify_password, is_decryption_ok
pw = input('Enter master password: ')
if verify_password(pw):
 print('Password valid and keys loaded successfully.')
else:
 print('Password invalid.')
"

# 2. If recovering from backup:
cp database/backups/security_latest.db.bak database/security.db
```

---

### Scenario 4: Database Integrity Check Failure (`SMP-3004`)

**Symptom:** `PRAGMA integrity_check` returns non-`ok` results (e.g. `malformed database schema`).

**Root Cause:** Hard power cut, kernel panic, or sudden disk unmount during an active write transaction.

**Copy-Paste Solution:**
```bash
# 1. Check integrity status
python3 -c "
from tools.db_manager import get_db_connection
conn = get_db_connection()
res = conn.execute('PRAGMA integrity_check;').fetchall()
print('Integrity status:', res)
conn.close()
"

# 2. Restore from most recent automated snapshot
python3 -c "
from tools.db_manager import restore_from_backup
ok = restore_from_backup()
print('Restored from backup:', ok)
"
```

---

### Scenario 5: Schema Migration Mismatch (`SMP-3005`)

**Symptom:** Queries fail with `no such table: findings` or missing column error after updating platform code.

**Root Cause:** New database tables or column constraints introduced in V9.5 were not created in an existing database.

**Copy-Paste Solution:**
```bash
# Run schema initializer to apply CREATE TABLE IF NOT EXISTS migrations
python3 -c "
from tools.db_manager import init_db
init_db()
print('Schema migrations applied successfully.')
"
```

---

### Scenario 6: Raw Output Directory Disk Space Full (`SMP-3006`)

**Symptom:** Scans finish but report `SMP-3006: Encryption key unavailable or storage failure`.

**Root Cause:** Partition containing `database/raw_outputs/` has run out of available inodes or disk space.

**Copy-Paste Solution:**
```bash
# 1. Check disk utilization
df -h database/raw_outputs/

# 2. Purge raw output captures older than 30 days
find database/raw_outputs/ -name "raw_*.gz" -mtime +30 -delete

# 3. Trigger database vacuum
python3 -c "
from tools.db_manager import get_db_connection
conn = get_db_connection()
conn.execute('VACUUM;')
conn.close()
print('Vacuum complete.')
"
```
