# Baseline Test Results & Diagnostic Record — Part 01

**Date:** 2026-10-18  
**Environment:** Debian GNU/Linux 13.7 (trixie), Python 3.13.5, Pytest 9.1.1  

---

## 1. Commands Run, Exit Statuses, and Concise Outcomes

### 1.1 Python Syntax & Compilation Check
- **Exact Command:** `python3 -m compileall -q .`
- **Exit Status:** `0`
- **Duration:** 0.42s
- **Outcome:** **PASSED**. No compilation or syntax errors found in any `.py` file across the entire repository.

### 1.2 SMP Full Pipeline Verification Suite
- **Exact Command:** `python3 tools/verify_smp.py`
- **Exit Status:** `0`
- **Duration:** 0.589s
- **Output Summary:**
  ```text
  Ran 15 tests in 0.589s
  OK (skipped=1)
  ```
  - **Suite Breakdown:**
    - Suite 01: Configuration & Metadata Manager — **PASSED**
    - Suite 02: Cryptographic Key Hierarchy (PBKDF2/Argon2) — **PASSED**
    - Suite 03: Database Pipeline & CRUD Operations — **PASSED**
    - Suite 04: Scope Engine & Authorization Enforcement — **PASSED**
    - Suite 05: Typed Observation Taxonomy & Immutability — **PASSED**
    - Suite 06: Scanner Adapter Framework & Nmap Parser — **PASSED**
    - Suite 07: DAG Orchestration & Topological Scheduling — **PASSED**
    - Suite 08: 14-State Scanner State Machine — **PASSED**
    - Suite 09: Evidence Store & Tamper Detection — **PASSED**
    - Suite 10: Threat Intelligence & Offline CVE Correlation — **PASSED**
    - Suite 11: Finding Deduplication & Risk Scoring Formula — **PASSED**
    - Suite 12: Report Generation & Authenticity Attestation — **PASSED**
    - Suite 13: CI Environment & Lint Gate — **SKIPPED** (`ruff not installed — skipping lint gate`)
    - Suite 14: Workflow Manifest Validation — **PASSED**
    - Suite 15: API Pydantic v2 Compliance — **PASSED**

### 1.3 Full Pytest Suite
- **Exact Command:** `pytest tests/ --durations=10 -v`
- **Exit Status:** `1`
- **Duration:** 7.60s (414 collected test items)
- **Results:** **400 PASSED, 12 SKIPPED, 2 FAILED**

---

## 2. Defect Separation: Repository Defects vs. Environment Deficiencies

### 2.1 Environment Deficiencies (Missing Dependencies)
The 2 failing tests and 12 skipped tests fail exclusively due to missing optional third-party packages in the unmanaged host system Python:

1. **`tests/test_security.py::test_encryption_fail_closed`**
   - **Error:** `ModuleNotFoundError: No module named 'cryptography'` in `tools/encryption_manager.py:13`.
   - **Root Cause:** `cryptography` is listed in `requirements.txt` but not installed in host system Python.
   - **Classification:** **Environment Deficiency** (Missing Dependency).

2. **`tests/test_security.py::test_api_database_error_sanitization`**
   - **Error:** `ModuleNotFoundError: No module named 'fastapi'` in `tests/test_security.py:63`.
   - **Root Cause:** `fastapi` is listed in `requirements.txt` but not installed in host system Python.
   - **Classification:** **Environment Deficiency** (Missing Dependency).

3. **Skipped Tests (Missing `python-jose`, `PySide6`, `fastapi`):**
   - `tests/test_auth.py:101, 121, 158, 181, 211, 258` (skipped: `python-jose not installed`)
   - `tests/test_execution_gate.py:434` (skipped: `PySide6 not installed`)
   - `tests/test_execution_gate.py:466` (skipped: `fastapi not installed`)
   - `tests/test_token_subject.py:144, 179, 231, 270` (skipped: `fastapi and python-jose required`)

### 2.2 Repository Defects & Architecture Risks Identified
1. **Unchecked Direct Imports in `tests/test_security.py`:**
   - While `test_auth.py` and `test_execution_gate.py` implement graceful conditional skips (`pytest.mark.skipif`), `test_security.py` directly executes unhandled top-level imports of `tools.encryption_manager` and `fastapi.testclient.TestClient`.
2. **Deprecation Warnings Under Python 3.13:**
   - `tests/test_new_architecture.py::test_observation_schema`: `DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).`
3. **External Network Coupling in Unit Tests:**
   - See Section 3 below.

---

## 3. Labeled Test Categories: Slow & Flaky Tests

| Test Name | File | Duration | Category | Reason | Next Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `test_network_routes_diagnostic` | `tests/test_troubleshoot_installer.py` | **3.93s** | **Flaky / Network-Coupled** | Calls `check_network_routes()`, which establishes real outbound HTTP/TLS connections to GitHub, RawGitHub, PyPI, and GoDev with 3s timeouts. Fails if network is offline or restricted. | Refactor test in later phase to mock network socket / urllib responses, or move to dedicated external integration suite. |
| `test_setup_sh_syntax_and_functions` | `tests/test_troubleshoot_installer.py` | 0.03s | Fast Unit | Executes `bash -n setup.sh` via subprocess. | Maintain in unit test suite. |
| `test_unknown_scanner_activity_denies_by_default` | `tests/test_activity_level_policy.py` | 0.02s | Fast Unit | Parameterized security boundary test. | Maintain in unit test suite. |
