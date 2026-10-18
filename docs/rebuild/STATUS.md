# Project Status — Rebuild Phase 01

**Current Active Phase:** Part 01 Complete (Repository Baseline and Recoverable Checkpoint)  
**Timestamp:** 2026-10-18  
**Current Git Commit:** `22e2619` (`release: v9.5.13 - Resilient subprocess termination, installer fixes, and security hardening`)  
**Checkpoint References:** Branch `checkpoint/pre-rebuild-baseline`, Tag `checkpoint-pre-rebuild`  

---

## 1. Phase Completion Summary

| Task | Status | Evidence / Notes |
| :--- | :---: | :--- |
| **Map Repository Architecture & Roots** | **DONE** | Documented in `docs/rebuild/REPOSITORY_MAP.md`. Identifies entry points, 90 registered scanners, API routes, SQL schemas. |
| **Preserve Source & Checkpoint Git State** | **DONE** | Created Git branch `checkpoint/pre-rebuild-baseline` and annotated tag `checkpoint-pre-rebuild` on commit `22e2619`. Working tree clean. |
| **Inventory Dependencies & Inconsistencies** | **DONE** | Documented in `docs/rebuild/DEPENDENCY_INVENTORY.md`. Identified `@latest` unpinned tools, `httpx2` phantom entry, lockfile divergence. |
| **Execute Safe Baseline Checks** | **DONE** | Documented in `docs/rebuild/BASELINE_TEST_RESULTS.md`. `compileall` passed (0 syntax errors); `verify_smp.py` 14 passed, 1 skipped; pytest 400 passed, 12 skipped, 2 failed due to missing dependencies. |
| **Identify Flaky & Long-Running Tests** | **DONE** | `test_network_routes_diagnostic` identified as network-coupled (3.93s, live HTTP connections). |
| **Establish Rebuild Tracking Artifacts** | **DONE** | Created all 8 required rebuild documents in `docs/rebuild/`. |

---

## 2. Test Execution Metric Baseline

```text
Suite                     Collected   Passed   Failed   Skipped   Duration
--------------------------------------------------------------------------
compileall (Syntax)       All .py     ALL      0        0         0.42s
tools/verify_smp.py       15 suites   14       0        1         0.589s
pytest tests/             414 items   400      2        12        7.60s
```

- **Environment Failures:** 2 (`cryptography` and `fastapi` absent in unmanaged host Python).
- **Environment Skips:** 12 (`python-jose`, `PySide6`, `fastapi` absent in unmanaged host Python).
- **Flaky / Network Test:** 1 (`test_network_routes_diagnostic`).

---

## 3. Operational Posture

- No application code or scanner modules were modified during this phase, adhering strictly to the Part 01 charter constraints.
- Baseline findings, environment quirks (PEP 668, unprivileged Docker, missing `ensurepip`), and architecture discrepancies are fully cataloged.
