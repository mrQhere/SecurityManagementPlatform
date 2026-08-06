# Contributing to Security Management Platform

> **SMP is a professional VAPT platform used in real security engagements.**  
> Every change you make may affect a penetration tester's workflow or a client's security posture.  
> We hold contributions to a high standard. Please read this fully before opening a PR.

---

## Code of Conduct

Be direct, technical, and professional. No spam, no self-promotion.  
Security tools carry weight — treat this codebase accordingly.

---

## Ways to Contribute

| Type | How |
|------|-----|
| 🐛 Bug fix | Open issue → discuss → PR |
| ➕ New scanner | Follow the scanner guide below |
| 📖 Documentation | Direct PR, no issue needed |
| 🔒 Security vulnerability | **Do NOT open a public issue** — see [SECURITY.md](../SECURITY.md) |

---

## Development Setup

```bash
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform
./setup.sh
source venv/bin/activate
python tools/verify_smp.py -v
```

---

## Adding a Custom Scanner

### 1. Generate the scaffold

```bash
python3 tools/create_scanner.py --name "MyTool" --binary "mytool" --severity High
# Creates: scanners/mytool.py
```

### 2. Implement the scanner

Every scanner must follow this contract:

```python
from scanners.core.registry import register_scanner
import subprocess, logging
from tools.db_manager import add_log_entry
from tools.config_manager import load_settings

logger = logging.getLogger("smp.scan")

MYTOOL_TIMEOUT = 300  # Never reduce power — set a realistic maximum

@register_scanner(
    name="MyTool",
    step_name="Running MyTool",
    depends_on=["HTTPx"],       # DAG phase: what must complete first
    binary_name="mytool",       # checked in PATH and bin/
    needs_binary=True,          # False for pure-Python scanners
    confidence=85,              # 0-100 how reliable your findings are
)
def run_mytool(url: str) -> list[dict] | None:
    """
    Scan url with mytool.
    Returns: list of finding dicts, [] if no findings, None on hard error.
    """
    settings = load_settings()
    bin_path = settings.get("mytool_path", "mytool")
    add_log_entry("INFO", f"MyTool Started: {url}")

    cmd = [bin_path, "--target", url, "--output", "json"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=MYTOOL_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        add_log_entry("WARNING", f"MyTool timed out after {MYTOOL_TIMEOUT}s")
        return []
    except FileNotFoundError:
        add_log_entry("ERROR", "mytool binary not found")
        return None   # None = tool not installed, skip gracefully

    findings = []
    for line in result.stdout.splitlines():
        # Parse your tool's output into SMP findings
        findings.append({
            "severity":    "High",         # Critical|High|Medium|Low|Info
            "title":       "Finding title",
            "description": "Detail …",
            "confidence":  85,
            "template_id": "mytool-001",   # optional, used for deduplication
            "cve_id":      "CVE-XXXX-XXX", # optional
        })

    add_log_entry("INFO", f"MyTool: {len(findings)} findings")
    return findings
```

### 3. Scanner modes — which profile activates your scanner

| Profile | What runs | When activated |
|---------|-----------|----------------|
| `osint` | Passive only — no probing | Recon phase |
| `standard` | Everything except exploitation | Default pentest |
| `full` | Everything including Hydra, Commix, ZAP active | With written permission only |

To restrict to `full` profile only, add a guard:
```python
if settings.get("scan_profile", "standard") != "full":
    return []
```

### 4. DAG dependency reference

```
Phase 0 (always):  Traceroute
Phase 1:           Nmap → (depends_on Traceroute)
Phase 2:           SSL, Security Headers → (depends_on Nmap)
Phase 2:           HTTPx, WhatWeb, Subfinder, theHarvester, Robots
Phase 3:           Nuclei, Nikto, CMS Scanner, ffuf, SQLMap, Gitleaks, Shodan
Phase 4 (cond.):   WPScan (WP detected), Dalfox (XSS surface), Katana (web app),
                   DNSx (subdomains), Arjun (params), JWT Scanner, Cloud Enum
Phase 5 (full):    ZAP, Hydra, Commix
```

Pick your `depends_on` from the phase before yours.

### 5. Register in the profile

Edit `scanners/core/registry.py` to add your scanner to the correct `SCAN_PROFILES` entry.

---

## Pull Request Rules

- [ ] `python tools/verify_smp.py -v` passes
- [ ] No hardcoded credentials, tokens, or real target IPs
- [ ] New scanner includes at least one parsing test in `tests/`
- [ ] Timeout preserved at a realistic maximum (do not set < 120s)
- [ ] PR title: `feat(scanner): add mytool scanner` or `fix(nuclei): ...`

---

## Commit Style

```
feat(scanner): add retire_js scanner for outdated jQuery detection
fix(ffuf): handle empty wordlist gracefully
docs(guide): update custom scanner DAG reference
chore(deps): bump nuclei to v3.3.9
```

© mrQhere — Security Management Platform
