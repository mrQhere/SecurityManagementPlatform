# Architecture Decision Records (ADRs) — Rebuild

## ADR-0001: Recoverable Baseline Checkpoint Strategy

- **Status:** Accepted (2026-10-18)
- **Context:** The repository is under active Git version control on branch `main` at commit `22e2619`. Before executing any rebuild operations, refactoring, or dependency updates, the original unmodified state must be guaranteed recoverable without data loss.
- **Decision:**
  1. Create an annotated Git tag `checkpoint-pre-rebuild` pointing directly to commit `22e2619`.
  2. Create a permanent branch `checkpoint/pre-rebuild-baseline` pointing to commit `22e2619`.
  3. Ensure no local uncommitted files or stashes exist prior to commencing Part 01 documentation.
- **Consequences:** The baseline commit remains immutable and can be checked out or diffed at any point during subsequent phases.

---

## ADR-0002: Strict Separation of Environment Deficiencies from Product Bugs

- **Status:** Accepted (2026-10-18)
- **Context:** The host operating system (Debian GNU/Linux 13 trixie) enforces PEP 668 and lacks packages like `cryptography`, `fastapi`, `python-jose`, and `PySide6` in its global Python 3.13 site-packages. This caused 2 test failures and 12 test skips in `pytest tests/`.
- **Decision:**
  1. Do not weaken, alter, or delete test assertions in `tests/test_security.py` or other test files to artificially produce a green build.
  2. Classify failures originating from missing runtime packages as **Environment Deficiencies** and record them explicitly in `BASELINE_TEST_RESULTS.md` and `KNOWN_LIMITATIONS.md`.
  3. Document the virtualenv bootstrapping mechanism (`--without-pip` + local pip fallback) as the approved remediation path for subsequent parts.
- **Consequences:** The test suite's diagnostic fidelity is preserved, and genuine product defects are not conflated with host setup constraints.

---

## ADR-0003: Deferral of Scanner Repairs and Mass Edits to Assigned Phases

- **Status:** Accepted (2026-10-18)
- **Context:** Multiple issues were discovered during Part 01 inspection (version numbering mismatches across `Dockerfile`, `Makefile`, and `api/server.py`; unpinned `@latest` Go tool downloads; external network calls inside unit tests).
- **Decision:**
  1. Strictly observe Mandatory Work Rule 2 ("Execute only the assigned numbered part. Do not jump ahead to a later part.").
  2. Refrain from editing any scanner implementation or application logic in Part 01.
  3. Catalog all discovered discrepancies in `REPOSITORY_MAP.md`, `DEPENDENCY_INVENTORY.md`, and `KNOWN_LIMITATIONS.md` to be resolved systematically in their corresponding rebuild parts.
- **Consequences:** Changes remain scoped, traceable, and strictly compliant with the Global Operating Charter.
