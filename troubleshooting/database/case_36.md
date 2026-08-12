# Case 36: Database Locked (WAL mode) (Scenario 36)

## Problem Description
The system encountered an issue related to database. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
