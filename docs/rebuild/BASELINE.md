# Rebuild Baseline — Part 01

**Date:** 2026-10-18  
**Repository:** `SecurityManagementPlatform` (`mrQhere/SecurityManagementPlatform`)  
**Commit Baseline:** `22e2619` (`release: v9.5.13 - Resilient subprocess termination, installer fixes, and security hardening`)  
**Operating System:** Debian GNU/Linux 13 (trixie) x86_64, Linux kernel `6.12.113+deb13-amd64`  
**Host Python Runtime:** Python 3.13.5 (`/usr/bin/python3`)  
**Host Tooling:** Pytest 9.1.1, GCC 14.2.0, GNU Make 4.4.1, Perl 5.40.1, Ruby 3.3.8, Git 2.47.3, Docker 26.1.5 (daemon active, non-root socket access denied)

---

## 1. System & Environment Baseline

| Component | State / Version | Operational Impact |
| :--- | :--- | :--- |
| **OS Distribution** | Debian GNU/Linux 13.7 (trixie) | PEP 668 enforced (`externally-managed-environment`). System-wide `pip install` without `--break-system-packages` is rejected. |
| **Python** | 3.13.5 | Modern Python runtime; `datetime.utcnow()` deprecation warnings observed in Pydantic v2 schemas. |
| **Virtualenv Support** | Missing `python3.13-venv` (`ensurepip`) | Standard `python3 -m venv` fails without `ensurepip`. Creating venv requires `--without-pip` or `--system-site-packages`. |
| **Sudo Privileges** | Password required | Non-interactive background operations cannot execute `sudo apt-get` or modify system files. |
| **Docker** | 26.1.5 installed; `docker compose` missing | `docker compose` is not installed; user `dxt` has no socket access to `/var/run/docker.sock` without elevated permissions. |
| **Network Connectivity** | Active (HTTP 200 via `urllib` to PyPI) | Outbound HTTP/HTTPS is available, but `curl` is not installed in `/usr/bin`. |
| **Security Binaries** | None present in system PATH or `bin/` | External scanners (`nmap`, `nuclei`, `zap`, `sqlmap`, `nikto`, etc.) are not currently in PATH. |

---

## 2. Baseline Check Commands & Real Results

### 2.1 Python Syntax & Bytecode Compilation
- **Command:** `python3 -m compileall -q .`
- **Exit Status:** 0
- **Duration:** < 1s
- **Outcome:** **PASSED**. All Python modules across `api/`, `core/`, `scanners/`, `tools/`, `database/`, `tests/`, and `ui/` compile cleanly without syntax errors under Python 3.13.

### 2.2 Pipeline Verification Suite
- **Command:** `python3 tools/verify_smp.py`
- **Exit Status:** 0
- **Duration:** 0.589s
- **Outcome:** **14 PASSED, 1 SKIPPED**.
  - Passed suites: Suites 01–12, 14–15 (Metadata, Key Hierarchy, DB CRUD, Scope Engine, Observation Taxonomy, Nmap Adapter, DAG Kahn's sort, Scanner State Machine, Evidence Store, Threat Intel, Finding Deduplication, Report Generation, Workflow Validation, API Pydantic v2).
  - Skipped suite: Suite 13 (`test_13_ci_environment_and_lint_gate` skipped: `ruff not installed`).

### 2.3 Unit Test Suite (Pytest)
- **Command:** `pytest tests/ --durations=10 -v`
- **Exit Status:** 1
- **Duration:** 7.60s (414 collected items)
- **Outcome:** **400 PASSED, 12 SKIPPED, 2 FAILED**.
  - **Failures (Environment Missing Modules):**
    1. `tests/test_security.py::test_encryption_fail_closed`: `ModuleNotFoundError: No module named 'cryptography'`
    2. `tests/test_security.py::test_api_database_error_sanitization`: `ModuleNotFoundError: No module named 'fastapi'`
  - **Skipped (Missing Optional Modules):**
    - 6 tests in `tests/test_auth.py` (missing `python-jose`)
    - 1 test in `tests/test_execution_gate.py` (missing `PySide6`)
    - 1 test in `tests/test_execution_gate.py` (missing `fastapi`)
    - 4 tests in `tests/test_token_subject.py` (missing `fastapi` and/or `python-jose`)

### 2.4 Slow & Network-Coupled Tests
- **Test:** `tests/test_troubleshoot_installer.py::test_network_routes_diagnostic`
- **Duration:** 3.93s
- **Cause:** Performs actual live HTTP requests across 4 remote endpoints (`github.com`, `raw.githubusercontent.com`, `pypi.org`, `go.dev`) via `check_network_routes()`.
- **Classification:** **Flaky / Long-Running (Network-Coupled)**. Must be decoupled from unit test runs in later stages.

---

## 3. Version & Contract Inconsistencies

1. **Version Mismatch Across Artifacts:**
   - `config/metadata.json`: `9.5.13`
   - `api/server.py`: Header documents `V9.4.3`, OpenAPI title `SMP API V9.5`, version `6.0`, routes prefixed `/api/v6/`
   - `Makefile`: References `smp:v7` and `/api/v7/health`
   - `Dockerfile`: `LABEL version="9.4.0"` and build tag `smp:v9`
   - `run.sh`: References `http://localhost:8000/api/v6/docs`
   - `docker-compose.yml`: References `/api/v6/health`
2. **Missing Schema Migration Framework:**
   - SQL schema creation is handled imperatively via `CREATE TABLE IF NOT EXISTS` inside `tools/db_manager.py`. There is no versioned migration tracking.
3. **Installer Tool Pinning Discrepancies:**
   - `setup.sh` comments claim pinned GitHub releases for Go tools, but fallback commands and `Dockerfile` use unpinned `@latest` for `nuclei`, `subfinder`, `httpx`, `katana`, `dnsx`, `ffuf`, `dalfox`, `gitleaks`.

---

## 4. Recoverable Checkpoints Established

- **Git Branch Checkpoint:** `checkpoint/pre-rebuild-baseline` pointing to commit `22e2619`.
- **Git Tag Checkpoint:** `checkpoint-pre-rebuild` pointing to commit `22e2619`.
- Clean working directory preserved.
