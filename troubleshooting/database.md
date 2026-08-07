# 🗄️ Database Troubleshooting — SMP V9.4.0

## FATAL: pysqlcipher3 not installed (startup abort)

SMP V9.4.0 exits immediately if SQLCipher is unavailable. See `installation.md`.

---

## Database is locked

```
sqlite3.OperationalError: database is locked
```

**Cause:** Another SMP process holds the connection (crashed scan, zombie process).

```bash
# Find the locking process
fuser database/security.db

# Kill it
kill -9 <PID>

# Or kill all SMP processes
pkill -f "python.*main.py"
pkill -f "python.*run.sh"

# Restart
./run.sh
```

---

## file is not a database (SQLCipher key mismatch)

```
pysqlcipher3.dbapi2.DatabaseError: file is not a database
```

**Cause:** Database was created with a different master password, or is an unencrypted SQLite file.

**Fix (data loss):**
```bash
# Back up first if you want to try to recover data
cp database/security.db database/security.db.bak

# Remove and let SMP recreate
rm -f database/security.db database/redundancy.db
./run.sh
```

**Fix (try to recover with known key):**
```bash
sqlcipher database/security.db.bak
sqlite> PRAGMA key = 'your_known_key';
sqlite> .dump > backup.sql
# Then recreate via SMP and import
```

---

## Database migration error

```
OperationalError: table 'scan_raw_output' already exists
```

All SMP tables use `CREATE TABLE IF NOT EXISTS`. If you see a strict error, force reinitialisation:

```bash
source venv/bin/activate
python3 -c "
from tools.db_manager import init_db
init_db()
print('DB init OK')
"
```

---

## CVE database empty / NVD sync not running

```bash
# Force CVE sync manually
source venv/bin/activate
python3 -c "
from intelligence.nvd import sync_nvd
sync_nvd()
"

# Check sync status
python3 -c "
from tools.db_manager import get_cve_db_connection
conn = get_cve_db_connection()
count = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
conn.close()
print(f'CVE count: {count}')
"
```

---

## EPSS scores not populating

```bash
source venv/bin/activate
python3 -c "
from intelligence.epss import sync_epss
sync_epss()
"
```

If local-only mode is active (`SMP_LOCAL_ONLY=1`), EPSS sync is blocked by design. Disable for enrichment:
```bash
SMP_LOCAL_ONLY=0 python3 -c "from intelligence.epss import sync_epss; sync_epss()"
```

---

## Disk full — database write errors

```
sqlite3.OperationalError: disk I/O error
```

```bash
# Check disk space
df -h database/

# Clean old raw scan outputs (compressed, safe to remove)
find database/ -name "*.raw.gz" -mtime +30 -delete

# Vacuum database to reclaim space
sqlcipher database/security.db
sqlite> PRAGMA key = 'your_key';
sqlite> VACUUM;
sqlite> .quit
```

---

## Database backup / restore

SMP auto-backs up on scan completion via `backup_all_tables()`.

```bash
# Manual backup
cp -r database/ database_backup_$(date +%Y%m%d)/

# Restore
cp database_backup_20260725/security.db database/security.db
```
