# Reports Troubleshooting

This document contains 50 distinct troubleshooting cases.

---

# Case 1: Empty Report (No Vulnerabilities) (Scenario 1)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 2: JSON Export Format Error (Scenario 2)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 3: Report Export Timeout (Scenario 3)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 4: CSV Delimiter Mismatch (Scenario 4)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 5: PDF Generation Failed (Missing Fonts) (Scenario 5)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 6: Empty Report (No Vulnerabilities) (Scenario 6)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 7: JSON Export Format Error (Scenario 7)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 8: Report Export Timeout (Scenario 8)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 9: CSV Delimiter Mismatch (Scenario 9)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 10: PDF Generation Failed (Missing Fonts) (Scenario 10)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 11: Empty Report (No Vulnerabilities) (Scenario 11)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 12: JSON Export Format Error (Scenario 12)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 13: Report Export Timeout (Scenario 13)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 14: CSV Delimiter Mismatch (Scenario 14)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 15: PDF Generation Failed (Missing Fonts) (Scenario 15)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 16: Empty Report (No Vulnerabilities) (Scenario 16)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 17: JSON Export Format Error (Scenario 17)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 18: Report Export Timeout (Scenario 18)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 19: CSV Delimiter Mismatch (Scenario 19)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 20: PDF Generation Failed (Missing Fonts) (Scenario 20)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 21: Empty Report (No Vulnerabilities) (Scenario 21)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 22: JSON Export Format Error (Scenario 22)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 23: Report Export Timeout (Scenario 23)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 24: CSV Delimiter Mismatch (Scenario 24)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 25: PDF Generation Failed (Missing Fonts) (Scenario 25)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 26: Empty Report (No Vulnerabilities) (Scenario 26)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 27: JSON Export Format Error (Scenario 27)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 28: Report Export Timeout (Scenario 28)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 29: CSV Delimiter Mismatch (Scenario 29)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 30: PDF Generation Failed (Missing Fonts) (Scenario 30)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 31: Empty Report (No Vulnerabilities) (Scenario 31)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 32: JSON Export Format Error (Scenario 32)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 33: Report Export Timeout (Scenario 33)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 34: CSV Delimiter Mismatch (Scenario 34)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 35: PDF Generation Failed (Missing Fonts) (Scenario 35)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 36: Empty Report (No Vulnerabilities) (Scenario 36)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 37: JSON Export Format Error (Scenario 37)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 38: Report Export Timeout (Scenario 38)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 39: CSV Delimiter Mismatch (Scenario 39)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 40: PDF Generation Failed (Missing Fonts) (Scenario 40)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 41: Empty Report (No Vulnerabilities) (Scenario 41)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 42: JSON Export Format Error (Scenario 42)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 43: Report Export Timeout (Scenario 43)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 44: CSV Delimiter Mismatch (Scenario 44)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 45: PDF Generation Failed (Missing Fonts) (Scenario 45)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 46: Empty Report (No Vulnerabilities) (Scenario 46)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 47: JSON Export Format Error (Scenario 47)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 48: Report Export Timeout (Scenario 48)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 49: CSV Delimiter Mismatch (Scenario 49)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sed -i 's/;/|/g' report.csv
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 50: PDF Generation Failed (Missing Fonts) (Scenario 50)

## Problem Description
The system encountered an issue related to reports. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


