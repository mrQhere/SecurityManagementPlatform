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

- **Introduced the Security Data Pipeline model** — findings are now immutable evidence-linked records, not mutable database rows.
- **Hierarchical Key Management (KEK/DEK/IEK/EEK)** — replaced single-key encryption with a four-layer key architecture. Master password derives KEK via PBKDF2-SHA256 (600,000 iterations); KEK wraps DEK (database), IEK (intelligence), and EEK (evidence) independently.
- **Evidence Store** — per-file AES-256-GCM encryption for all raw scanner outputs, with SHA-256 integrity checksums and JSON metadata sidecar.
- **Typed Observation Model** — raw scanner outputs now parsed into typed observations: Asset, Port, Service, CPE, HTTP, Technology, VulnerabilityCandidate, Secret, etc.
- **Fingerprint-based Finding Deduplication** — SHA-256 fingerprint over (asset_id, service_id, vulnerability_class, matched_cves) collapses duplicate observations without destroying evidence.
- **ScannerAdapter Framework** — new abstract `ScannerAdapter` base class in `scanners/framework/adapter.py`; all new scanners implement this interface.
- **Nmap First-Class Adapter** — `scanners/adapters/nmap_adapter.py` parses Nmap XML into AssetObservation, PortObservation, ServiceObservation, CPEObservation, and NSE script VulnerabilityCandidate observations.
- **14-state Scanner State Machine** — formal state transition graph replacing ad-hoc string status values.
- **Scope Engine** — engagement-scoped authorization engine with CIDR, IP, domain wildcard, and URL regex rule types; default-deny posture when no rules are defined.
- **Report Generator overhaul** — `tools/report_generator.py` now produces full-length professional VAPT reports in both Markdown (PDF-renderable via weasyprint) and JSON formats, with SHA-256 authenticity hash for tamper evidence.
- **Academic Thesis** — added `docs/thesis/SMP_THESIS_V9.5.md` with formal analysis of the pipeline architecture, cryptographic design, and algorithmic guarantees.
- **README rewrite** — updated for V9.5 data pipeline model, new architecture diagram, and complete feature documentation.
- **UI navigation fix** — fixed `PAGE_NAMES` index mismatch that caused an `IndexError` when navigating to the new Findings and Evidence pages.
- **Version bump** — all version strings synchronized to `V9.5`.

## [V9.4.4] - 2026-08-12

- Scaled DAG Orchestrator to support 90 independent vulnerability scanners.
- Pulled extensive open-source parity from DefectDojo/Faraday, integrating 15 new advanced scanners (Metasploit, OpenVAS, Impacket, SQLNinja, RouterSploit, Responder, Arachni, Bandit, OSV-Scanner, etc.).
- Developed the Enterprise Target Data Exporter: 1-click ZIP export of AES-encrypted database findings, reports, and logs strictly filtered by website target.
- Resolved Trivy APT repository errors (`zena` codename missing) by refactoring `setup.sh` to use the official raw installation binaries, ensuring cross-distro compatibility.
- Auto-cleanup of broken `/etc/apt/sources.list.d/trivy.list` to prevent repeated apt-get failures.
- Expanded Academic Thesis to document the theoretical rationale behind scaling the local-first engine and consolidating disjointed vulnerability management platforms.
- Hardened DAG exception handling (`tools/errors.py`) with specific timeouts (`SMP-4040`), binary mismatches (`SMP-4041`), and port collisions (`SMP-4042`).
- Expanded Troubleshooting guide (`troubleshooting/README.md`) to explicitly cover OpenVAS signature loops and Responder port 53 collisions.

## [V9.4.3] - 2026-08-11

- Implemented 3-Phase Parallel Scanner Architecture with intermediate Brain Intelligence Interleaving (Phase 1 Recon, Phase 2 Active Vuln Testers, Phase 3 Deep Exploitation).
- Added 4 modern web vulnerability scanners with strict semver dependency pinning:
  - `ppmap` (v1.0.0): Prototype Pollution vulnerability tester.
  - `wscat` (v9.4.4): WebSocket endpoint discovery and connection probing.
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

## [V9.4.2] - 2026-08-08

- Fixed `wpscan` installation in `setup.sh` by adding `sudo` to the `gem install` command to prevent file permission errors.
- Added a retry loop in `setup.sh` for `apt update` and `apt install` to handle temporary dpkg lock failures on fresh VMs.
- Added explicit error messages in `setup.sh` and a troubleshooting guide entry for `archive.ubuntu.com` connection failures caused by corporate antivirus or firewall interception.
- Fixed CI test_10 hang: scanner pipeline now skips MAC randomisation, per-tool delays, and tool installs when `SMP_CI=1`.
- Fixed 3-tuple unpack bug in MAC changer call (change_mac_address returns bool, str, str — was being unpacked as 2 values).
- Reduced DAG plugin hang timeout from 3600s to 120s in CI mode.
- Corrected CVSS label in PDF reports from "CVSS v9.4.4" to "CVSS v3.1" (SMP version was leaking into standard label).
- Corrected PCI-DSS label in PDF reports from "PCI-DSS v9.4.4" to "PCI-DSS v4.0".
- Fixed README license badge showing "Proprietary" — now correctly shows "MIT".
- Synchronized all V9.3.x stale version strings to V9.4.4 across tools, scanners, UI, and docs.
- Updated .env.example to document all env vars SMP actually reads (added SMP_CI, QT_LOGGING_RULES, XDG_SESSION_TYPE, NO_PROXY).
