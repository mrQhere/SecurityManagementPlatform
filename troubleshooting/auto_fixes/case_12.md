# Case 12: Reset All Services (Scenario 12)

## Problem Description
The system encountered an issue related to auto fixes. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api smp-worker smp-dashboard
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
