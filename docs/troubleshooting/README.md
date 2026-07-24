# 🛠️ SMP V7 — Troubleshooting Index

Quick-find guide. Click the topic that matches your error.

| Category | File | Common errors covered |
|----------|------|-----------------------|
| 📦 [Installation](installation.md) | `installation.md` | pysqlcipher3, binary download, Go PATH, WPScan wrapper |
| 🗄️ [Database](database.md) | `database.md` | DB locked, SQLCipher key mismatch, migration errors, CVE sync |
| 🔬 [Scanner Errors](scanner_errors.md) | `scanner_errors.md` | Nmap root, Nuclei templates, ffuf false positives, timeouts |
| 🔌 [API Errors](api_errors.md) | `api_errors.md` | 401/403/429, FastAPI startup, CORS, JWT secrets |
| 📄 [Reports & SBOM](reports.md) | `reports.md` | PDF generation, SBOM empty, report verification, SMTP |

---

## Quick diagnostics

```bash
# 1. Check SQLCipher is available
python3 -c "from pysqlcipher3 import dbapi2; print('SQLCipher OK')"

# 2. Check all binaries in bin/
ls -la bin/

# 3. Check database health
python3 -c "
from tools.db_manager import get_db_connection
conn = get_db_connection()
tables = conn.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()
conn.close()
print(f'Tables: {[t[0] for t in tables]}')
"

# 4. Check last 50 lines of scan log
tail -50 logs/scan.log

# 5. Check egress audit log
tail -20 logs/egress_audit.log 2>/dev/null || echo "No egress audit log yet"

# 6. Run the built-in verifier
source venv/bin/activate
python3 tools/verify_smp.py -v
```
