<!--
FUTURE CONTRIBUTORS:
Every future commit to the main branch MUST add one line to the "Unreleased"
section below in plain English (do not just copy the commit message).
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v9.5.13] - 2026-10-18
### Fixed
- scanners/scan_runner.py: Fixed `ResilientPopen.kill()` and `.terminate()` so process group termination failure in `os.killpg()` no longer raises before standard subprocess fallback is attempted (`super().kill()` / `super().terminate()`).
- scanners/scan_runner.py: Avoided masking process-already-exited conditions (`ProcessLookupError`) as unclassified exceptions, cleanly handling terminated processes and preventing false crash reports.
- scanners/scan_runner.py: Preserved original process group exceptions for diagnostics when both group and standard termination fail (`raise fallback_err from group_err`).
- scanners/scan_runner.py: Added child process reaping (`wait(timeout=...)`) across all termination, kill, and exit paths to eliminate zombie/defunct processes.
- setup.sh: Fixed installer hangs and 12-hour build timeouts. Added 120s command timeouts to `spin()`, safely wrapped piped script installations in `bash -c`, skipped unavailable apt packages (such as `nikto` on modern Debian/Ubuntu) with standalone fallback, prevented interactive sudo hangs, and bypassed incompatible `routersploit` dependencies on Python >= 3.10.
- tests/test_subprocess_resilience.py: Added 11 focused unit and integration tests covering successful group termination, group failure fallback, already-exited processes, chained diagnostic exceptions, Windows bypass, and scanner timeout handling.

## [v9.5.12] - 2026-10-18
### Fixed
- scanners/scan_runner.py: Corrected terminal-state recovery in `resume_interrupted_scans()`. Cancelled scans are centrally defined as terminal states and excluded from startup resumption, remaining cancelled in the database.
- core/state_machine.py: Centrally defined terminal states (`TERMINAL_SCANNER_STATES`, `TERMINAL_SCAN_STATUSES`) and recoverable in-flight states (`RECOVERABLE_IN_FLIGHT_STATUSES`), with fail-closed validation predicates `is_terminal_status()` and `is_recoverable_status()`.
- scanners/scan_runner.py: Replaced negative status exclusion with positive recoverable classification (`is_recoverable_status()`). Scans in unknown, empty, corrupt, or unhandled statuses fail closed and never trigger automatic scanning.
- tests/test_scan_resumption.py: Added 100 database-backed and state-machine tests validating that every terminal state (including `Cancelled`, `Completed`, `Failed`, `Report Pending`, `Timeout`, `Blocked`) never resumes, corrupt statuses fail closed, and only explicitly recoverable in-flight states resume after an unclean shutdown.

## [v9.5.11] - 2026-10-18
### Security
- core/url_validator.py: Replaced prefix-only target URL validation with RFC 3986 standard URL parsing, canonicalization, and destination security gate (`parse_and_canonicalize_url()`, `check_destination_allowed()`, `resolve_and_validate_destination()`, `validate_redirect_destination()`, and `SafeRedirectSession`).
- core/url_validator.py: Enforced strict scheme validation (HTTP/HTTPS only), valid ports (1–65535 with default port normalization), IPv4 dot-decimal without leading zero / octal / hex confusion, RFC 3986 bracketed IPv6 literals, and IDNA domain name conversion (Punycode).
- core/url_validator.py: Fail closed on ASCII control characters (< 32, 127 DEL), userinfo/credentials (`user:pass@`), malformed authorities, internal whitespace, and unsupported schemes (`ftp:`, `file:`, `gopher:`, `javascript:`, `data:`).
- core/url_validator.py: Built policy-governed destination defense against cloud metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`), loopback (`127.0.0.0/8`, `::1`, `localhost`), link-local (`169.254.0.0/16`, `fe80::/10`), unspecified/broadcast (`0.0.0.0`, `::`, `255.255.255.255`), and unauthorized private networks (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`).
- core/url_validator.py: Defended against DNS rebinding attacks by resolving all IP addresses and rejecting requests if any resolved IP belongs to a forbidden destination.
- core/url_validator.py: Created `SafeRedirectSession` and `validate_redirect_destination()` resolving relative paths and enforcing scope and destination safety on initial requests and every redirect hop before network activity.
- core/scope_engine.py: Updated `ScopeEngine.is_allowed()` to extract normalized host and canonical URL, supporting domain, IP, and CIDR rules against full URLs, and updated `check_redirect()` to enforce destination boundaries and scope on every redirect hop.
- core/scan_policy.py: Added destination and rebinding policy fields (`allow_private`, `allow_loopback`, `enforce_dns_rebinding`) to `ScanPolicySchema`.
- core/execution_gate.py: Integrated destination checks and URL canonicalization at execution gate launch time.
- api/server.py: Replaced prefix-only checks in `TargetCreate` and `ScanStartRequest` with `parse_and_canonicalize_url()` and destination gate checks, rejecting malformed and forbidden destinations at validation time with clean HTTP 400 responses.
- tests/test_url_destination_hardening.py: Added 140 table-driven regression tests covering IPv4, IPv6, IDNA, ports, credentials, malformed inputs, destination boundaries, DNS rebinding, and redirect handling with strictly mocked DNS.

## [v9.5.10] - 2026-10-18
### Security
- core/execution_gate.py: Created central server-side scan execution gate (`verify_scan_execution()`) enforcing engagement status, authorization validity, target scope, scanner manifest activity level, user policy allowlist/denylist, and cancellation state immediately before tool execution.
- core/execution_gate.py: Added `get_scanner_activity_level()` mapping scanner tools to manifest activity levels, ensuring manifest activity cannot exceed policy limits.
- scanners/scan_planner.py: ScanPlanner unified with the execution gate; `create_plan()` evaluates `verify_scan_execution()` and fails closed with `ScopeViolationError` or `SMPAuthError`. ScanPlanner is no longer an optional side path.
- scanners/scan_runner.py: Routed all launch entry points (`start_scan_for_target()`, `_run_scan_sequence()`, and `run_with_resilience()`) through `verify_scan_execution()`. Out-of-scope or unauthorized scans fail closed before any tool process or subprocess is spawned.
- scanners/core/plugin.py: `GenericPlugin.execute()` verifies execution permissions through `verify_scan_execution()` immediately prior to running resilient execution routines.
- ui/controllers/dashboard_logic.py: `ScanWorker.run()` enforces execution gate validation before scan sequences begin, emitting UI errors and aborting cleanly on denial.
- api/server.py: Added `POST /api/v6/scan` endpoint with `ScanStartRequest` model validating scans against the execution gate before launching, returning HTTP 403 on denial.
- tests/test_execution_gate.py: Added 20 focused regression tests asserting that out-of-scope, expired, revoked, intrusive-unauthorized, inactive-engagement, or cancelled scans never call `subprocess.Popen` or `subprocess.run`, and proving that valid scope and authorization allow execution.

## [v9.5.9] - 2026-10-18
### Security
- core/scope_engine.py: Enforced scanner activity level against engagement policy maximum activity level. `is_allowed()` now evaluates activity level permissions before target rules and never grants access based solely on a target string match.
- core/scope_engine.py: Added strict, documented ranking for every `ActivityLevel` (`PASSIVE` < `LOW_IMPACT_ACTIVE` < `ACTIVE` < `INTRUSIVE` < `DESTRUCTIVE`). Unknown or malformed scanner activity or policy limits fail closed (denied by default).
- core/scope_engine.py: Updated `ScopeEngine.__init__()` and added `set_policy()` / `set_max_activity_level()` to configure policy limits from `ScanPolicy` instances or direct values, with per-call overrides in `is_allowed()`.
- core/scope_engine.py: Updated `check_redirect()` to respect activity level limits.
- scanners/scan_planner.py: Passed `policy=scan_policy` when initializing `ScopeEngine`.
- tests/test_activity_level_policy.py: Added 70 regression tests covering complete 5x5 activity matrix, unknown activity rejection, non-target-only grant verification, string resolution, and ScanPolicy integration.

## [v9.5.8] - 2026-10-18
### Security
- core/authorization.py: Extracted `is_authorization_currently_valid()` as the single canonical timezone-safe validity gate shared between `AuthorizationTracker` and `ScopeEngine`. Normalizes timestamps to UTC and safely handles naive, offset-aware, missing, and malformed expiry values.
- core/scope_engine.py: Scope rules are now created strictly from authorizations that are active, unexpired, and not revoked, using `is_authorization_currently_valid()`.
- core/scope_engine.py: Database and parse errors during authorization loading fail closed and expose a safe diagnostic (`diagnostic` attribute and error reason) rather than returning an empty success-like policy.
- tests/test_authorization_expiry.py: Added 26 regression tests covering future expiry, expired authorizations, exact boundary timestamps, revoked status, missing expiry, malformed values, timezone offsets, and ScopeEngine database failure diagnostics.

## [v9.5.7] - 2026-10-17
### Security
- api/server.py: Removed caller-controlled JWT subject. The token endpoint previously used `request.username` (caller-supplied) as the JWT `sub` claim after verifying only a shared master password, allowing any authenticated caller to mint a token for any arbitrary identity.
- api/server.py: Added `_ADMIN_SUBJECT = "smp-admin"` server-defined constant. All issued tokens carry this fixed subject, independent of what username the caller sends.
- api/server.py: Token response now returns `subject` (server-resolved) instead of `username` (caller echo-back).
- tests/test_token_subject.py: Eight focused regression tests covering: server constant existence and stability, create_token always called with `_ADMIN_SUBJECT`, arbitrary caller usernames rejected as JWT subject, invalid credentials → 401, response subject always equals server constant, two different callers get identical subject, audit actor derived from JWT sub.
- tests/test_baseline.py: Replaced hard-coded version allowlist with forward-compatible `9.5.x` SemVer check to prevent spurious failures on future patch bumps.

## [v9.5.6] - 2026-10-17
### Security
- api/auth.py: Removed JWT signing key derivation from `config/auth.json` salt (SHA-256 of public password-hashing salt). The signing key is now loaded exclusively from the `SMP_JWT_SECRET` environment variable, making it fully independent of password management.
- api/auth.py: Added minimum key length enforcement (32 characters). Absent or too-short `SMP_JWT_SECRET` raises `RuntimeError` at call-time, refusing to issue tokens (fail-closed).
- api/auth.py: Removed the last-resort path that wrote a generated `jwt_secret` into `config/auth.json`.
- api/auth.py: Added a development/CI escape hatch (`SMP_DEV_ALLOW_INSECURE_JWT=1` or `SMP_CI=1`) that generates a per-process ephemeral random secret with a loud WARNING, never persisted to disk.
- api/auth.py: JWT signing secret value is never written to any log record at any level.
- .env.example: Documented `SMP_JWT_SECRET` as required in production, key rotation procedure, minimum length, independence from password salt, and `SMP_DEV_ALLOW_INSECURE_JWT` dev escape hatch.
- tests/test_auth.py: Nine focused regression tests covering production fail-closed, too-short key, salt independence, secret non-leakage to logs, dev/CI ephemeral mode, and salt-derivation regression.

## [v9.5.5] - 2026-10-17
### Added
- tools/verify_report.py: Deterministic canonical Markdown payload extraction (`get_canonical_markdown_payload`) and digest verification (`compute_markdown_digest`).
- tools/verify_report.py: User-facing verification status distinctly separating payload integrity (tamper/corruption detection) from author authenticity (cryptographic origin attestation).
- tools/verify_report.py: Keyed MAC (HMAC-SHA256) digital signature support with secret key material stored separately from the report payload.
- tools/verify_report.py: Explicit `UNVERIFIABLE_LEGACY` status for older report formats embedding JSON-data hashes instead of canonical Markdown payload digests.
- tests/test_report_verification.py: Focused regression suite verifying valid, one-byte modified, fabricated, missing, malformed, legacy, and keyed HMAC reports.

### Fixed
- tools/verify_report.py: Markdown verification now rejects fabricated 64-hex strings and one-byte modifications by recomputing the digest over the canonical payload rather than accepting any arbitrary 64-hex string.
- tools/report_generator.py: Embed canonical Markdown payload digest (`PAYLOAD-SPEC: canonical-markdown-v1`) and optional HMAC-SHA256 signature in generated Markdown reports.

## [V9.5.1] - 2026-08-16
### Fixed
- tools/scheduler.py: add missing `import os` (resolves ruff F821 — undefined name `os` in nuclei update job)
- api/server.py: migrate Pydantic v1 `@validator` → Pydantic v2 `@field_validator` with `@classmethod` (eliminates PydanticDeprecatedSince20 warnings in CI)
- tools/verify_smp.py: expand from 12 to 15 verification suites — adds Suite 13 (CI environment & ruff lint gate), Suite 14 (CI workflow manifest validation), Suite 15 (API Pydantic v2 compliance)
- database/global_intel.db: remove binary database from git tracking (was accidentally committed; now properly excluded via .gitignore)
- tests/: add test_nuclei_integration.py and test_troubleshoot_installer.py (18 pytest tests total)
### Documentation
- All documentation synchronized to V9.5.1
- docs/thesis/SMP_THESIS_V9.5.pdf: professional PDF thesis added
- GitHub About section updated

## [V9.5.0] - 2026-08-15

### Architecture Overhaul: Security Data Pipeline

- **Security Data Pipeline Model** — Findings are now immutable, evidence-linked records rather than mutable rows.
- **Hierarchical Key Management (KEK/DEK/IEK/EEK)** — Replaced single-key encryption with a four-layer key architecture. Master password derives KEK via PBKDF2-SHA256 (600,000 iterations); KEK wraps DEK (database), IEK (intelligence), and EEK (evidence) independently.
- **Evidence Store** — Per-file AES-256-GCM encryption for all raw scanner outputs, with SHA-256 integrity checksums and JSON metadata sidecars.
- **Typed Observation Model** — Raw scanner outputs parsed into typed, immutable observations: `AssetObservation`, `PortObservation`, `ServiceObservation`, `CPEObservation`, `VulnerabilityObservation`, `SecretObservation`, etc.
- **Fingerprint-Based Finding Deduplication** — SHA-256 canonical fingerprint over `(asset_id, service_id, vulnerability_class, matched_cves)` collapses duplicate observations from overlapping scanners without destroying evidence.
- **ScannerAdapter Framework** — Abstract `ScannerAdapter` base class in `scanners/framework/adapter.py` providing process sandboxing, timeouts, and resource governance.
- **Nmap First-Class Adapter** — `scanners/adapters/nmap_adapter.py` parses Nmap XML into typed observations and candidate vulnerabilities.
- **14-State Scanner State Machine** — Formal state transition engine in `core/state_machine.py` replacing ad-hoc string status values.
- **Scope Engine** — Engagement-scoped authorization engine with CIDR, IP, domain wildcard, and URL regex rule types; default-deny posture when no rules are defined.

### Decoupled UI Rebuild (PySide6)

- **Complete MVC Decoupling** — Separated view layouts (`ui/views/dashboard_layout.py`) from event logic controllers (`ui/controllers/dashboard_logic.py`).
- **10-Page Dashboard Layout** — Overview, Targets, Active Scans, Findings, Intelligence, Assets & Services, Reports, Exporter, Scanners, and Settings.
- **High-Performance UI Components** — Built reusable widgets: `StatCard`, `FindingDetailPanel` (slide-in finding inspector), `ExportGateDialog`, `PasswordDialog`, `ResponsibilityDialog`, and `SystemCheckDialog`.
- **Theme Engine & QSS Style System** — Custom dark-theme engine (`ui/theme.py`, `ui/style.qss`) tailored for cybersecurity operations.

### Enterprise Data Exporter & Legal Gate

- **Multi-Format Enterprise Ticketing Exporter** — `tools/data_exporter.py` supporting Jira JSON, ServiceNow CSV, DefectDojo JSON, Generic JSON, Markdown ZIP, and SARIF 2.1.0 formats.
- **Mandatory Typed Legal Gate** — Enforced typed `"I AGREE"` acknowledgment dialog (`ui/components/export_gate_dialog.py`) for plaintext data exports with permanent non-repudiation audit logging (`SMP-4050`, `SMP-4051`, `SMP-4052`).

### Comprehensive Manual & Academic Thesis

- **Exhaustive User Guide (`USER_GUIDE.md`)** — 1,500+ line technical manual with ASCII SMP header, 11-section table of contents, covering setup, 95-scanner tuning, custom `@register_scanner` development, API reference, and troubleshooting.
- **Academic Thesis (`docs/thesis/SMP_THESIS_V9.5.md`)** — 60+ page academic thesis analyzing V1–V9.5 architectural evolution, DAG topological sort, queuing theory, 4-layer KEK/DEK cryptographic hierarchy, and SHA-256 finding deduplication.

### Cross-Platform Installer & Setup Overhaul (`setup.sh`)

- **Multi-OS / Multi-Arch Support** — Added Darwin/macOS and Linux binary resolution with `_bin_url()` helper for Go security tools (Nuclei, Subfinder, HTTPx, Katana, DNSx, FFUF, Gitleaks, Dalfox).
- **Zero-Friction Pre-Flight Route Verification** — Integrated `verify_network_routes()` to probe outbound HTTPS reachability across key repository mirrors (`github.com`, `raw.githubusercontent.com`, `pypi.org`, `go.dev`) before initiating downloads.
- **Automated Self-Healing in Installer** — Automatically triggers the self-healing engine (`tools/troubleshoot.py --fix` and internal bash routines) upon encountering DPKG locks, stale runtime locks, or network timeouts, with transparent retry mechanisms.
- **Context-Enriched Source-Level Error Dumps** — When unrecoverable faults occur, `report_error_with_code()` outputs a structured terminal error card displaying the official SMP error code (`SMP-9001` through `SMP-9005`, `SMP-2002`, `SMP-3001`), root cause analysis, recent log excerpts, copy-paste remediation steps, and **the entire source code snippet** of the failing function with line numbers.
- **Pre-Compiled Binary Direct Downloads** — Nuclei, Subfinder, HTTPx, Katana, DNSx, FFUF, Gitleaks, and Dalfox download pre-compiled releases with cryptographic SHA-256 validation (reducing installation time from 5–10 minutes down to ~12 seconds).
- **Homebrew & Shell Profile Integration** — Auto-configures `.zprofile` on macOS and `.bashrc` on Linux with PATH exports.
- **Package Repository Hardening** — Fixed Gitleaks naming and automated cleanup of legacy repository artifacts.

### Runtime Connection & Dependency Hardening

- **DAG Dependency Resolution** — Corrected DAG dependency names across `scanners/idor_scanner.py`, `scanners/ppmap.py`, `scanners/race_the_web.py`, and `scanners/wscat_scanner.py` to allow clean topological resolution for all 95 scanners.
- **Database Findings Ingestion Compatibility** — Made `tools/db_manager.py:add_finding` resilient to keyword aliases (`scanner` $\to$ `source_tool`, `remediation` $\to$ `recommendation`).
- **Report Generator Convenience API** — Added flexible default fallbacks and high-level `generate()` convenience method to `tools/report_generator.py`.
- **Airgapped & Offline Resilience** — Hardened `tools/system_checker.py:_check_network` to handle offline/isolated network environments gracefully.
- **Artifact Cleanup** — Removed stale download archives and redundant directories.
- **Verification** — 100% pass across 186 modules, 15/15 `verify_smp.py` suites, and 18/18 `pytest` test suites.

## [V9.5.4] - 2026-08-12

- Scaled DAG Orchestrator to support 95 independent vulnerability scanners.
- Pulled extensive open-source parity from DefectDojo/Faraday, integrating 15 new advanced scanners (Metasploit, OpenVAS, Impacket, SQLNinja, RouterSploit, Responder, Arachni, Bandit, OSV-Scanner, etc.).
- Developed the Enterprise Target Data Exporter: 1-click ZIP export of AES-encrypted database findings, reports, and logs strictly filtered by website target.
- Resolved Trivy APT repository errors (`zena` codename missing) by refactoring `setup.sh` to use the official raw installation binaries, ensuring cross-distro compatibility.
- Auto-cleanup of broken `/etc/apt/sources.list.d/trivy.list` to prevent repeated apt-get failures.
- Expanded Academic Thesis to document the theoretical rationale behind scaling the local-first engine and consolidating disjointed vulnerability management platforms.
- Hardened DAG exception handling (`tools/errors.py`) with specific timeouts (`SMP-4040`), binary mismatches (`SMP-4041`), and port collisions (`SMP-4042`).
- Expanded Troubleshooting guide (`troubleshooting/README.md`) to explicitly cover OpenVAS signature loops and Responder port 53 collisions.

## [V9.5.3] - 2026-08-11

- Implemented 3-Phase Parallel Scanner Architecture with intermediate Brain Intelligence Interleaving (Phase 1 Recon, Phase 2 Active Vuln Testers, Phase 3 Deep Exploitation).
- Added 4 modern web vulnerability scanners with strict semver dependency pinning:
  - `ppmap` (v1.0.0): Prototype Pollution vulnerability tester.
  - `wscat` (V9.5.4): WebSocket endpoint discovery and connection probing.
  - `race-the-web` (v1.0.3): Go binary for TOCTOU and Race Condition vulnerability testing.
  - `idor-scanner`: IDOR/BOLA scanner with optional dual-token (AuthMatrix) session testing capabilities.
- Upgraded Neural Correlation Engine (`intelligence/brain.py`):
  - Enforced authentic findings processing with zero synthetic data or forged CVEs.
  - Built V10 Local LLM foundation (`_query_local_llm()` adapter stub for Ollama/Llama.cpp, falling back safely to TF-IDF heuristics).
- Updated `setup.sh` with Node.js package management (`npm`, `wscat`, `ppmap`) and Go binary releases (`race-the-web`).
- Profile-gated scanner execution (`osint` mode runs purely passive tools, while `standard` and `full` modes run multi-phase parallel scanning with brain interleaving).
- Fixed `scan_id` kwarg crash in `scan_runner.py` that caused scanner plugins to fail.
- Added Scheduler UI integration (Scan schedules and Intel syncs) to the Dashboard Settings.
- Massively expanded Troubleshooting documentation with 300+ copy-paste auto-fix scenarios across API, Database, Installation, Reports, Scanners, and Auto-Fixes.
- Implemented cryptographic SHA-256 binary validation in `setup.sh` to secure all dynamically downloaded external dependencies against supply-chain attacks.
- Updated Academic Thesis to explicitly document the DAG (Directed Acyclic Graph) architecture with instructions for Markdown to PDF generation.
- Added full system wipe/factory reset instructions to the User Guide for recovering from lost master passwords.
- Massively expanded offensive capabilities by adding 20 new vulnerability scanners to the DAG orchestration pipeline (including TruffleHog, Semgrep, Checkov, KubeHunter, XSStrike, Naabu, Hakrawler, SSLyze, CORScanner, and more).

## [V9.5.2] - 2026-08-08

- Fixed `wpscan` installation in `setup.sh` by adding `sudo` to the `gem install` command to prevent file permission errors.
- Added a retry loop in `setup.sh` for `apt update` and `apt install` to handle temporary dpkg lock failures on fresh VMs.
- Added explicit error messages in `setup.sh` and a troubleshooting guide entry for `archive.ubuntu.com` connection failures caused by corporate antivirus or firewall interception.
- Fixed CI test_10 hang: scanner pipeline now skips MAC randomisation, per-tool delays, and tool installs when `SMP_CI=1`.
- Fixed 3-tuple unpack bug in MAC changer call (change_mac_address returns bool, str, str — was being unpacked as 2 values).
- Reduced DAG plugin hang timeout from 3600s to 120s in CI mode.
- Corrected CVSS label in PDF reports from "CVSS V9.5.4" to "CVSS v3.1" (SMP version was leaking into standard label).
- Corrected PCI-DSS label in PDF reports from "PCI-DSS V9.5.4" to "PCI-DSS v4.0".
- Fixed README license badge showing "Proprietary" — now correctly shows "MIT".
- Synchronized all V9.5.x stale version strings to V9.5.4 across tools, scanners, UI, and docs.
- Updated .env.example to document all env vars SMP actually reads (added SMP_CI, QT_LOGGING_RULES, XDG_SESSION_TYPE, NO_PROXY).
