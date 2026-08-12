# Case 48: Orphaned Scan Records (Scenario 48)

## Problem Description
The system encountered an issue related to database. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
