# Reports Troubleshooting

This document contains 50 distinct troubleshooting cases.

## General Diagnostics
The system encountered an issue related to this category. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

**Copy-Paste Solutions:** Run the respective command in your terminal to instantly resolve the issue. *(Note: Ensure you have the appropriate permissions before executing administrative commands.)*

---

# Case 1: Empty Report (No Vulnerabilities) (Scenario 1)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 2: JSON Export Format Error (Scenario 2)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 3: Report Export Timeout (Scenario 3)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 4: CSV Delimiter Mismatch (Scenario 4)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 5: PDF Generation Failed (Missing Fonts) (Scenario 5)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 6: Empty Report (No Vulnerabilities) (Scenario 6)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 7: JSON Export Format Error (Scenario 7)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 8: Report Export Timeout (Scenario 8)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 9: CSV Delimiter Mismatch (Scenario 9)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 10: PDF Generation Failed (Missing Fonts) (Scenario 10)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 11: Empty Report (No Vulnerabilities) (Scenario 11)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 12: JSON Export Format Error (Scenario 12)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 13: Report Export Timeout (Scenario 13)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 14: CSV Delimiter Mismatch (Scenario 14)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 15: PDF Generation Failed (Missing Fonts) (Scenario 15)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 16: Empty Report (No Vulnerabilities) (Scenario 16)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 17: JSON Export Format Error (Scenario 17)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 18: Report Export Timeout (Scenario 18)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 19: CSV Delimiter Mismatch (Scenario 19)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 20: PDF Generation Failed (Missing Fonts) (Scenario 20)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 21: Empty Report (No Vulnerabilities) (Scenario 21)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 22: JSON Export Format Error (Scenario 22)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 23: Report Export Timeout (Scenario 23)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 24: CSV Delimiter Mismatch (Scenario 24)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 25: PDF Generation Failed (Missing Fonts) (Scenario 25)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 26: Empty Report (No Vulnerabilities) (Scenario 26)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 27: JSON Export Format Error (Scenario 27)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 28: Report Export Timeout (Scenario 28)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 29: CSV Delimiter Mismatch (Scenario 29)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 30: PDF Generation Failed (Missing Fonts) (Scenario 30)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 31: Empty Report (No Vulnerabilities) (Scenario 31)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 32: JSON Export Format Error (Scenario 32)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 33: Report Export Timeout (Scenario 33)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 34: CSV Delimiter Mismatch (Scenario 34)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 35: PDF Generation Failed (Missing Fonts) (Scenario 35)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 36: Empty Report (No Vulnerabilities) (Scenario 36)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 37: JSON Export Format Error (Scenario 37)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 38: Report Export Timeout (Scenario 38)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 39: CSV Delimiter Mismatch (Scenario 39)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 40: PDF Generation Failed (Missing Fonts) (Scenario 40)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 41: Empty Report (No Vulnerabilities) (Scenario 41)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 42: JSON Export Format Error (Scenario 42)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 43: Report Export Timeout (Scenario 43)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 44: CSV Delimiter Mismatch (Scenario 44)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 45: PDF Generation Failed (Missing Fonts) (Scenario 45)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

# Case 46: Empty Report (No Vulnerabilities) (Scenario 46)

```bash
sqlite3 smp.db "SELECT count(*) FROM findings WHERE scan_id=123;"
```

---

# Case 47: JSON Export Format Error (Scenario 47)

```bash
python3 tools/report_generator.py --format json --scan-id 123
```

---

# Case 48: Report Export Timeout (Scenario 48)

```bash
export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py
```

---

# Case 49: CSV Delimiter Mismatch (Scenario 49)

```bash
sed -i 's/;/|/g' report.csv
```

---

# Case 50: PDF Generation Failed (Missing Fonts) (Scenario 50)

```bash
sudo apt-get install fonts-liberation && ./run.sh --generate-report
```

---

