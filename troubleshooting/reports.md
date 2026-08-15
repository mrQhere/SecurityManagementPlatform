# 📄 Reports & Evidence Troubleshooting — V9.5

This guide provides technical diagnosis and resolutions for report generation, cryptographic authenticity hashing, PDF rendering (WeasyPrint), and evidence store integrity.

---

## Error Codes Covered

| Code | Slug | Issue Description |
|---|---|---|
| `SMP-4010` | `evidence_storage_error` | AES-256-GCM evidence encryption or write failure |
| `SMP-4011` | `evidence_not_found` | Requested evidence UUID missing from store |
| `SMP-4012` | `evidence_tamper_detected` | Evidence SHA-256 checksum mismatch / tampering detected |
| `SMP-4020` | `report_generation_error` | Report generator failed to compile report document |
| `SMP-4021` | `report_authenticity_failed` | Canonical SHA-256 report authenticity hash mismatch |
| `SMP-4022` | `weasyprint_render_error` | WeasyPrint HTML-to-PDF rendering failed |

---

## Common Scenarios & Resolutions

### Scenario 1: WeasyPrint PDF Rendering Fails (`SMP-4022`)

**Symptom:** Generating a PDF report raises `weasyprint.exceptions.WeasyPrintError` or falls back to Markdown.

**Root Cause:** Missing Pango/Cairo native rendering libraries or Liberation fonts.

**Copy-Paste Solution:**
```bash
# Install required rendering toolchains on Debian/Ubuntu/Kali:
sudo apt-get update
sudo apt-get install -y \
  libpango-1.0-0 \
  libharfbuzz0b \
  libpangoft2-1.0-0 \
  libcairo2 \
  libgdk-pixbuf-2.0-0 \
  libffi-dev \
  fonts-liberation \
  fonts-dejavu-core
```

---

### Scenario 2: Report Authenticity Verification Failed (`SMP-4021`)

**Symptom:** `python3 tools/verify_report.py report.json` returns `❌ Report verification FAILED: Hash mismatch`.

**Root Cause:** The JSON report file was manually modified, pretty-printed with different key sorting, or corrupted after the initial cryptographic signing.

**Copy-Paste Solution:**
```bash
# Inspect authenticity status using verification tool
python3 tools/verify_report.py reports/demo_report.json

# Regenerate a clean signed report from raw database findings
python3 -c "
from tools.report_generator import ReportGenerator
from tools.db_manager import get_findings_for_scan, get_scan
rg = ReportGenerator(version='V9.5')
# Provide scan_id to recompile canonical report
"
```

---

### Scenario 3: Evidence Tamper Detected (`SMP-4012`)

**Symptom:** Evidence retrieval throws `SMP-4012: Evidence SHA-256 checksum mismatch`.

**Root Cause:** The ciphertext file `data/evidence/<eng>/<scan>/<id>/evidence.enc` has been modified, corrupted, or replaced.

**Copy-Paste Solution:**
```bash
# Verify checksum against registered metadata
python3 -c "
import hashlib, json, sys, os
ev_dir = sys.argv[1] if len(sys.argv) > 1 else 'data/evidence/'
for root, dirs, files in os.walk(ev_dir):
    if 'checksum.txt' in files and 'evidence.enc' in files:
        expected = open(os.path.join(root, 'checksum.txt')).read().strip()
        data = open(os.path.join(root, 'evidence.enc'), 'rb').read()
        actual = hashlib.sha256(data).hexdigest()
        print(f'Checking {root}:', 'VALID ✅' if actual == expected else 'TAMPERED ❌')
"
```

---

### Scenario 4: Verify the Report Pipeline Manually

**Symptom:** Verifying that all reporting layers (JSON, Markdown, PDF, Executive Summary) are fully functional.

**Copy-Paste Solution:**
```bash
# Generate complete report using python script
python3 -c "
from tools.report_generator import ReportGenerator
from tools.verify_report import verify_report
rg = ReportGenerator(version='V9.5')
# Generate a JSON report
rg.generate_json_report(scan_id=1, output_file='reports/manual_verification.json')
"

# Inspect output files
ls -lh reports/manual_verification.*
```
