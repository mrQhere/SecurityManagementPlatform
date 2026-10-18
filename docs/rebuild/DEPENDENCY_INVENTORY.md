# Dependency Inventory & Analysis — Part 01

**Date:** 2026-10-18  
**Scope:** Python manifests, system packages, container specifications, and binary installers.

---

## 1. Python Dependencies

### 1.1 Declared Direct Dependencies (`requirements.txt`)

| Package | Specified Version | Purpose in Codebase | Installed in System Python | Issues / Risk |
| :--- | :--- | :--- | :--- | :--- |
| `APScheduler` | `3.11.3` | Periodic scan task scheduler | ❌ No | Background scheduler blocked without venv |
| `Markdown` | `3.10.2` | Report formatting and parsing | ❌ No | Markdown report generation affected |
| `PySide6` | `6.11.1` | Desktop GUI application | ❌ No | GUI mode blocked without venv |
| `cryptography` | `46.0.7` | PBKDF2 HMAC, Fernet, AES-256 | ❌ No | **Causes 1 unit test failure** (`test_encryption_fail_closed`) |
| `fastapi` | `0.141.1` | REST API framework | ❌ No | **Causes 1 unit test failure** (`test_api_database_error_sanitization`) |
| `packaging` | `26.3` | Semantic version parsing | ✔️ Yes (`26.3`) | OK |
| `playwright` | `1.62.0` | Headless browser for DOM scanner | ❌ No | Heavy browser dependency; requires binary drivers |
| `psutil` | `7.2.2` | Process management & termination | ✔️ Yes (`7.0.0`) | Minor version difference (7.0.0 vs 7.2.2) |
| `pydantic` | `2.12.5` | Data validation & schemas | ✔️ Yes (`2.14.1`) | Minor version difference (2.14.1 vs 2.12.5) |
| `pysqlcipher3` | `1.2.0` | Encrypted SQLite storage | ❌ No | Requires C compilation against `libsqlcipher-dev` |
| `pytest` | `9.1.1` | Test framework | ✔️ Yes (`9.1.1`) | OK |
| `python-jose` | `3.5.0` | JWT token encoding/decoding | ❌ No | Causes 10 unit test skips in auth & token tests |
| `python-owasp-zap-v2.4` | `0.1.0` | ZAP scanner API wrapper | ❌ No | Disables ZAP scanner module |
| `reportlab` | `5.0.0` | PDF report engine | ❌ No | Disables PDF generation |
| `requests` | `2.34.2` | HTTP client | ✔️ Yes (`2.31.0`) | Minor version difference (2.31.0 vs 2.34.2) |
| `shodan` | `1.31.0` | Shodan OSINT integration | ❌ No | Disables Shodan scanner |
| `slowapi` | `0.1.10` | Rate limiting on API endpoints | ❌ No | Disables API rate limiting |
| `sqlmap` | `1.10.8` | SQL injection engine | ❌ No | Disables SQLMap runner |
| `sslyze` | `6.3.1` | TLS/SSL scanner | ❌ No | Disables SSLyze scanner |
| `uvicorn` | `0.52.1` | ASGI server for FastAPI | ❌ No | API server cannot start |
| `weasyprint` | `69.0` | HTML to PDF rendering | ❌ No | Requires cairo/pango system libraries |
| `httpx` | *Unpinned* | Modern async HTTP client | ❌ No | Unpinned dependency |
| `httpx2` | *Unpinned* | Undocumented dependency | ❌ No | **Potential typo / phantom package**; unpinned |

---

### 1.2 Manifest Inconsistencies & Lockfile Mismatch

1. **`requirements.lock` vs `requirements.txt` Divergence:**
   - `requirements.lock` was compiled with Python 3.12 (`pip-compile`).
   - `requirements.lock` contains 80+ packages not listed in `requirements.txt` (e.g. `aiodns`, `aiohttp`, `aiosqlite`, `beautifulsoup4`, `tldextract`, `cyclonedx-python-lib`), suggesting historical uncommitted features or stale lock generation.
2. **Unpinned and Invalid Packages:**
   - `requirements.txt` includes unpinned `httpx` and `httpx2`.
   - `httpx2` does not exist as an official HTTP client standard and presents a supply-chain risk if pulled from untrusted indexes.

---

## 2. External Tools & Binary Dependencies

### 2.1 Unpinned Tool Installers (`@latest` Risk)

The following tools are installed using `@latest` tags in `Dockerfile` and `setup.sh`, violating release reproducibility:

| Tool | Installer Source | In Dockerfile | In setup.sh | In scanners/ |
| :--- | :--- | :--- | :--- | :--- |
| **Nuclei** | `github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Line 90 | Pin `v3.3.9` in header, unpinned in script | `scanners/nuclei.py` |
| **Subfinder** | `github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Line 91 | Pin `v2.7.0` in header, unpinned in script | `scanners/subfinder.py` |
| **HTTPx** | `github.com/projectdiscovery/httpx/cmd/httpx@latest` | Line 92 | Pin `v1.7.0` in header, unpinned in script | `scanners/httpx_scanner.py` |
| **Katana** | `github.com/projectdiscovery/katana/cmd/katana@latest` | Line 93 | Pin `v1.1.2` in header, unpinned in script | `scanners/katana.py` |
| **DNSx** | `github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | Line 94 | Pin `v1.2.1` in header, unpinned in script | `scanners/dnsx.py` |
| **ffuf** | `github.com/ffuf/ffuf/v2@latest` | Line 95 | Pin `v2.1.0` in header, unpinned in script | `scanners/ffuf.py` |
| **Dalfox** | `github.com/hahwul/dalfox/v2@latest` | Line 96 | Pin `v2.10.0` in header, unpinned in script | `scanners/dalfox.py` |
| **Gitleaks** | `github.com/zricethezav/gitleaks/v8@latest` | Line 97 | Pin `v8.30.1` in header, unpinned in script | `scanners/gitleaks.py` |
| **Naabu** | `github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | — | Line 830 | `scanners/naabu.py` |
| **Gau** | `github.com/lc/gau/v2/cmd/gau@latest` | — | Line 827 | `scanners/gau_scanner.py` |
| **Hakrawler** | `github.com/hakluke/hakrawler@latest` | — | Line 824 | `scanners/hakrawler.py` |
| **Kube-Bench**| `github.com/aquasecurity/kube-bench@latest` | — | Line 848 | `scanners/kube_bench.py` |

---

## 3. Platform & OS Assumptions

1. **Ubuntu vs Debian Inconsistencies:**
   - CI runs on `ubuntu-24.04` with Python 3.11.
   - `Dockerfile` is based on `ubuntu:22.04` with Go 1.22.4.
   - `setup.sh` hardcodes package names such as `libsqlcipher0t64` (Ubuntu 24.04) vs `libsqlcipher0` (older Ubuntu/Debian).
   - Current host is Debian 13 (trixie) with Python 3.13.5. Debian 13 is not listed in `setup.sh` supported distributions.
2. **Sudo / Root Privileges Requirement:**
   - `setup.sh` and `tools/tool_installer.py` invoke `sudo apt-get` or `sudo make install`. Without passwordless sudo, automated scripts fail.
3. **PEP 668 Virtualenv Restriction:**
   - System Python on Debian 13 blocks `pip install` without `--break-system-packages` or an activated virtual environment.
   - `python3 -m venv` fails without `python3.13-venv` (`ensurepip`), necessitating `--without-pip` or pre-bootstrapped wheels.
