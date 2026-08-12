# Case 20: Stale Locks Removal (Scenario 20)

## Problem Description
The system encountered an issue related to auto fixes. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
find /tmp -name 'smp_*.lock' -mtime +1 -delete
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
