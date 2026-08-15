<!--
FUTURE CONTRIBUTORS:
Every future commit to the main branch MUST add one line to the "Unreleased"
section below in plain English (do not just copy the commit message).
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [V9.5] - 2026-08-15

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

- **Exhaustive User Guide (`USER_GUIDE.md`)** — 1,500+ line technical manual with ASCII SMP header, 11-section table of contents, covering setup, 90-scanner tuning, custom `@register_scanner` development, API reference, and troubleshooting.
- **Academic Thesis (`docs/thesis/SMP_THESIS_V9.5.md`)** — 60+ page academic thesis analyzing V1–V9.5 architectural evolution, DAG topological sort, queuing theory, 4-layer KEK/DEK cryptographic hierarchy, and SHA-256 finding deduplication.

### Cross-Platform Installer & Setup Overhaul (`setup.sh`)

- **Multi-OS / Multi-Arch Support** — Added Darwin/macOS and Linux binary resolution with `_bin_url()` helper for Go security tools (Nuclei, Subfinder, HTTPx, Katana, DNSx, FFUF, Gitleaks, Dalfox).
- **Homebrew & Shell Profile Integration** — Auto-configures `.zprofile` on macOS and `.bashrc` on Linux with PATH exports.
- **Package Repository Hardening** — Fixed Gitleaks naming and automated cleanup of legacy repository artifacts.

### Runtime Connection & Dependency Hardening

- **DAG Dependency Resolution** — Corrected DAG dependency names across `scanners/idor_scanner.py`, `scanners/ppmap.py`, `scanners/race_the_web.py`, and `scanners/wscat_scanner.py` to allow clean topological resolution for all 90 scanners.
- **Database Findings Ingestion Compatibility** — Made `tools/db_manager.py:add_finding` resilient to keyword aliases (`scanner` $\to$ `source_tool`, `remediation` $\to$ `recommendation`).
- **Report Generator Convenience API** — Added flexible default fallbacks and high-level `generate()` convenience method to `tools/report_generator.py`.
- **Airgapped & Offline Resilience** — Hardened `tools/system_checker.py:_check_network` to handle offline/isolated network environments gracefully.
- **Artifact Cleanup** — Removed stale download archives and redundant directories.
- **Verification** — 100% pass across 186 modules, 12/12 `verify_smp.py` suites, and 7/7 `pytest` test suites.

## [V9.5.4] - 2026-08-12

- Scaled DAG Orchestrator to support 90 independent vulnerability scanners.
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
