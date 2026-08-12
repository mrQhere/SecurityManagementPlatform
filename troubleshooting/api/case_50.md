# Case 50: Rate Limit Exceeded (IP Block) (Scenario 50)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.50"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
