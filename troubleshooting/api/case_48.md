# Case 48: 502 Bad Gateway (Scenario 48)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
