# Known Limitations, Defects & Environmental Risks — Part 01

**Date:** 2026-10-18  

---

## 1. Environment & Host Limitations

1. **Debian 13 (Trixie) Package Management & PEP 668:**
   - Debian 13 marks the global Python installation as an `externally-managed-environment` under PEP 668. `pip install` without `--break-system-packages` is rejected.
   - The Debian package `python3.13-venv` (`ensurepip`) is not installed on the host. Executing `python3 -m venv <path>` fails unless `--without-pip` is supplied.
2. **Elevated Privileges (Sudo) Barrier:**
   - User `dxt` requires a password for `sudo`. Non-interactive executions of `setup.sh` or `tools/tool_installer.py` attempting `sudo apt-get` will block or fail.
3. **Container Daemon Access & CLI Tooling:**
   - Docker daemon is running, but user `dxt` lacks permissions to access `/var/run/docker.sock` without sudo.
   - Neither `docker compose` (Docker CLI plugin) nor `docker-compose` (standalone binary) is installed in system PATH.
4. **Missing CLI Binaries on Host:**
   - `curl` is missing (`/usr/bin/curl` not found). Python's `urllib` functions normally.
   - None of the external security scanners (`nmap`, `nuclei`, `zap`, `sqlmap`, `nikto`, `subfinder`, `gitleaks`) are installed in the host system PATH or `bin/`.

---

## 2. Product & Codebase Defects

1. **Test Suite Import Fragility (`tests/test_security.py`):**
   - Two tests in `tests/test_security.py` fail immediately with `ModuleNotFoundError` when run in an environment lacking `cryptography` or `fastapi`. Unlike `test_auth.py` and `test_execution_gate.py`, they lack graceful `pytest.importorskip` protections.
2. **Network Coupling in Unit Tests:**
   - `tests/test_troubleshoot_installer.py::test_network_routes_diagnostic` executes real outbound HTTP/TLS requests to `github.com`, `raw.githubusercontent.com`, `pypi.org`, and `go.dev` during unit testing, taking 3.93 seconds and introducing network flakiness.
3. **Phantom / Unpinned Dependencies in `requirements.txt`:**
   - `httpx2` is present in `requirements.txt`. There is no legitimate upstream package by this name; it is likely a typo or placeholder that presents supply-chain ambiguity.
   - `httpx` is completely unpinned.
4. **Supply Chain Non-Reproducibility (`@latest` Tool Installers):**
   - `Dockerfile`, `setup.sh`, and scanner docstrings instruct downloading Go binaries via `@latest` tags (`nuclei@latest`, `subfinder@latest`, `httpx@latest`, `katana@latest`, `dnsx@latest`, `ffuf@latest`, `dalfox@latest`, `gitleaks@latest`).
5. **Version Contract Inconsistencies:**
   - `config/metadata.json` declares version `9.5.13`.
   - `api/server.py` declares OpenAPI version `6.0` with routes under `/api/v6/`.
   - `Makefile` declares targets testing `/api/v7/health` and building image `smp:v7`.
   - `Dockerfile` declares label version `9.4.0` and build tag `smp:v9`.
6. **Database Schema Evolution:**
   - No structured database migration tool (such as Alembic) exists. Schema management is handled exclusively via raw DDL strings with `CREATE TABLE IF NOT EXISTS` in `tools/db_manager.py`.
7. **Python 3.13 Standard Library Deprecations:**
   - `datetime.datetime.utcnow()` is used across Pydantic models in `core/observation.py` and `core/finding.py`, triggering Python 3.13 `DeprecationWarning` notices.
