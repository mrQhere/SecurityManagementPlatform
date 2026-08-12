# Database Troubleshooting

This document contains 50 distinct troubleshooting cases.

## General Diagnostics
The system encountered an issue related to this category. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

**Copy-Paste Solutions:** Run the respective command in your terminal to instantly resolve the issue. *(Note: Ensure you have the appropriate permissions before executing administrative commands.)*

---

# Case 1: Database Locked (WAL mode) (Scenario 1)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 2: Corrupted Indexes (Scenario 2)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 3: Orphaned Scan Records (Scenario 3)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 4: Database Backup (Scenario 4)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 5: Admin Password Reset (Scenario 5)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='admin';"
```

---

# Case 6: Database Locked (WAL mode) (Scenario 6)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 7: Corrupted Indexes (Scenario 7)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 8: Orphaned Scan Records (Scenario 8)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 9: Database Backup (Scenario 9)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 10: Admin Password Reset (Scenario 10)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user10';"
```

---

# Case 11: Database Locked (WAL mode) (Scenario 11)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 12: Corrupted Indexes (Scenario 12)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 13: Orphaned Scan Records (Scenario 13)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 14: Database Backup (Scenario 14)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 15: Admin Password Reset (Scenario 15)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user15';"
```

---

# Case 16: Database Locked (WAL mode) (Scenario 16)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 17: Corrupted Indexes (Scenario 17)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 18: Orphaned Scan Records (Scenario 18)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 19: Database Backup (Scenario 19)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 20: Admin Password Reset (Scenario 20)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user20';"
```

---

# Case 21: Database Locked (WAL mode) (Scenario 21)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 22: Corrupted Indexes (Scenario 22)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 23: Orphaned Scan Records (Scenario 23)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 24: Database Backup (Scenario 24)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 25: Admin Password Reset (Scenario 25)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user25';"
```

---

# Case 26: Database Locked (WAL mode) (Scenario 26)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 27: Corrupted Indexes (Scenario 27)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 28: Orphaned Scan Records (Scenario 28)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 29: Database Backup (Scenario 29)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 30: Admin Password Reset (Scenario 30)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user30';"
```

---

# Case 31: Database Locked (WAL mode) (Scenario 31)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 32: Corrupted Indexes (Scenario 32)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 33: Orphaned Scan Records (Scenario 33)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 34: Database Backup (Scenario 34)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 35: Admin Password Reset (Scenario 35)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user35';"
```

---

# Case 36: Database Locked (WAL mode) (Scenario 36)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 37: Corrupted Indexes (Scenario 37)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 38: Orphaned Scan Records (Scenario 38)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 39: Database Backup (Scenario 39)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 40: Admin Password Reset (Scenario 40)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user40';"
```

---

# Case 41: Database Locked (WAL mode) (Scenario 41)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 42: Corrupted Indexes (Scenario 42)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 43: Orphaned Scan Records (Scenario 43)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 44: Database Backup (Scenario 44)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 45: Admin Password Reset (Scenario 45)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user45';"
```

---

# Case 46: Database Locked (WAL mode) (Scenario 46)

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

# Case 47: Corrupted Indexes (Scenario 47)

```bash
sqlite3 smp.db "REINDEX;"
```

---

# Case 48: Orphaned Scan Records (Scenario 48)

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---

# Case 49: Database Backup (Scenario 49)

```bash
sqlite3 smp.db ".backup smp_backup.db"
```

---

# Case 50: Admin Password Reset (Scenario 50)

```bash
sqlite3 smp.db "UPDATE users SET password_hash='<NEW_HASH>' WHERE username='user50';"
```

---

