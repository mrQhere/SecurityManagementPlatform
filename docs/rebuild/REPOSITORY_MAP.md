# Repository Architecture Map — Part 01

**Repository Root:** `/home/dxt/Downloads/SecurityManagementPlatform`  
**Current Architecture:** Modular Monolith with embedded GUI, FastAPI server, dynamic scanner plugin registry, and local SQLite data storage.

---

## 1. Directory Structure Overview

| Path | Purpose | Key Files & Modules |
| :--- | :--- | :--- |
| `api/` | REST API layer (FastAPI, JWT auth, rate limiting) | `api/server.py` (FastAPI app & endpoints), `api/auth.py` (JWT verification & token creation) |
| `bin/` | Local directory for pre-compiled security binaries | Empty by default; dynamically populated by `setup.sh` and `tools/tool_installer.py` |
| `cache/` | Cache directory for intelligence correlation | Stored CVE sync states |
| `config/` | Application configuration and metadata | `config/metadata.json` (platform version), `config/auth.json` (password salts/hashes) |
| `core/` | Core domain logic, policy, and state control | `core/execution_gate.py`, `core/scope_engine.py`, `core/state_machine.py`, `core/url_validator.py`, `core/observation.py`, `core/finding.py`, `core/authorization.py`, `core/evidence.py` |
| `data/` | Persistent application data and evidence store | `data/evidence/` (AES-256-GCM encrypted evidence items) |
| `database/` | SQL databases, schemas, and backups | `database/schema/security_schema.sql`, `database/schema/vulnerability_schema.sql`, `database/raw_outputs/`, pre-existing DBs: `analytics.db`, `cve.db`, `redundancy.db` |
| `docs/` | Documentation assets and thesis | `docs/thesis/`, `docs/rebuild/` |
| `intelligence/`| Threat intelligence connectors & offline mapping | `intelligence/mitre_mapper.py`, `cisa.py`, `epss.py`, `nvd.py`, `greynoise.py`, `brain.py` |
| `logs/` | Runtime application and scan logs | `logs/smp.log` |
| `reports/` | Generated scan reports | Markdown and PDF outputs |
| `scanners/` | Scanner implementations, framework, adapters | 98 modules: 90 auto-discovered scanners, `scanners/scan_runner.py`, `scanners/core/` (DAG, registry), `scanners/adapters/` (Nmap adapter), `scanners/framework/` (execution primitives) |
| `tests/` | Pytest unit and integration test suite | 15 test suites covering auth, gate, scope, observation, subprocess resilience, and reports |
| `tools/` | Platform utilities, installers, and engines | `tools/db_manager.py`, `tools/verify_smp.py`, `tools/tool_installer.py`, `tools/troubleshoot.py`, `tools/encryption_manager.py`, `tools/risk_scorer.py`, `tools/report_generator.py` |
| `troubleshooting/` | Markdown guidance for environment repair | `installation.md`, etc. |
| `ui/` | PySide6 Desktop GUI (Qt) | `ui/dashboard.py`, `ui/views/dashboard_layout.py`, `ui/views/splash_screen.py`, `ui/components/`, `ui/style.qss` |

---

## 2. Entry Points

### 2.1 Main Application Launcher (`main.py`)
- **CLI Options:**
  - `--api`: Starts the headless FastAPI backend server via `api.server.start_server()`.
  - `--operator <name>`: Sets the operator name in UI sessions (default: `Unknown`).
  - `--no-lock`: Disables the `/tmp/.smp_runtime.lock` single-instance check.
- **Default (No flags):** Launches the PySide6 Desktop GUI after authenticating via `PasswordDialog`.

### 2.2 Shell Launcher (`run.sh`)
- Detects virtual environment in `./venv`.
- Verifies `pysqlcipher3` availability (fails hard if missing).
- Checks for `libxcb-cursor0` (auto-falls back to headless if missing).
- Detects headless environment (`$DISPLAY` or `$WAYLAND_DISPLAY` unset) and automatically triggers `--api` mode.

### 2.3 Management & Verification Utilities
- `tools/verify_smp.py`: Self-contained 15-suite pipeline verification runner.
- `tools/troubleshoot.py`: Diagnostic and auto-healing script with 30+ defined error codes (`SMP-1xxx` to `SMP-9xxx`).
- `tools/verify_report.py`: Validates cryptographic signatures, checksums, and structural consistency of generated reports.
- `tools/snapshot.py`: Increments patch version, updates `USER_GUIDE.md`, stages and commits Git changes.
- `tools/bump_version.py`: Replaces version strings across 10+ project files.

---

## 3. API Surface (`api/server.py`)

Current base route prefix: `/api/v6/`

| HTTP Method | Route | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v6/auth/token` | No (Master Pwd) | Exchanges credentials for a 24-hour JWT Bearer token |
| `GET` | `/api/v6/health` | No | Basic JSON service health and timestamp |
| `GET` | `/api/v6/version` | Yes (Bearer) | Platform version metadata from `config/metadata.json` |
| `GET` | `/api/v6/target` | Yes (Bearer) | Lists configured scan targets |
| `POST` | `/api/v6/target` | Yes (Bearer) | Validates destination and adds target to DB |
| `GET` | `/api/v6/scan` | Yes (Bearer) | Lists active and recent scans |
| `POST` | `/api/v6/scan` | Yes (Bearer) | Invokes server-side `execution_gate` and starts scan worker |
| `GET` | `/api/v6/findings` | Yes (Bearer) | Returns deduplicated findings for a given scan ID |
| `GET` | `/api/v6/cve/stats` | Yes (Bearer) | Returns summary metrics from the CVE intelligence database |
| `GET` | `/api/v6/risk/score` | Yes (Bearer) | Calculates and returns risk scores across targets |

---

## 4. Scanner Execution & Worker Subsystem

- **Registry (`scanners/core/registry.py`):**
  - Uses dynamic module discovery via `pkgutil.iter_modules`.
  - Supports `@register_scanner` decorator and `PLUGIN_META` dictionaries.
  - Automatically loads 90 scanner plugins with dependency metadata (`depends_on`).
- **Orchestration (`scanners/scan_runner.py`):**
  - Implements DAG topological sorting via Kahn's algorithm (`scanners/core/dag.py`).
  - Thread-pool and sequential runner executing scanner adapters.
  - Enforces 14-state scanner lifecycle machine (`core/state_machine.py`).
  - Emits telemetry and state changes over internal UDP IPC on port 5005 (`tools/event_bus.py`).
- **Execution Gate (`core/execution_gate.py`):**
  - Validates scan authorization rules (`core/authorization.py`).
  - Enforces destination boundaries (`core/url_validator.py` and `core/scope_engine.py`).
  - Enforces scanner activity level policy (`Passive`, `Active`, `Destructive`).

---

## 5. Storage & Database Schema

- **Encrypted Database Engine:** SQLCipher (`pysqlcipher3`), falling back to standard `sqlite3` when the extension is not compiled.
- **Payload Storage:** Raw scanner outputs are gzip-compressed, encrypted with Fernet (AES-128-CBC + HMAC-SHA256) via `tools/encryption_manager.py`, and stored on disk in `database/raw_outputs/raw_<uuid>.gz`.
- **Database Schema Files:**
  - `database/schema/security_schema.sql`: `users`, `engagements`, `scope_rules`, `targets`, `scans`, `assets`, `services`, `findings`, `audit_log`.
  - `database/schema/vulnerability_schema.sql`: `vulnerabilities`, `aliases`, `cwe`, `cvss`, `cpe`, `cpe_match`, `fixed_version`, `epss`, `kev`, `references`, `intel_import`.
- **Redundancy & Backups:** 3 secondary databases created automatically in `database/backup/`: `active_scans.db`, `cve_secondary.db`, `full_backup.db`.
