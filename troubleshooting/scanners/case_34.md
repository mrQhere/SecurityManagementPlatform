# Case 34: FFUF OOM (Out of Memory) (Scenario 34)

## Problem Description
The system encountered an issue related to scanners. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*
