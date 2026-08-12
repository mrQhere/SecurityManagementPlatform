# Case 22: CORS Preflight Failure (Scenario 22)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
