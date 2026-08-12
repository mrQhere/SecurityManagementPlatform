<!--
FUTURE CONTRIBUTORS:
Every future commit to the main branch MUST add one line to the "Unreleased"
section below in plain English (do not just copy the commit message).
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [V9.4.3] - 2026-08-11

- Implemented 3-Phase Parallel Scanner Architecture with intermediate Brain Intelligence Interleaving (Phase 1 Recon, Phase 2 Active Vuln Testers, Phase 3 Deep Exploitation).
- Added 4 modern web vulnerability scanners with strict semver dependency pinning:
  - `ppmap` (v1.0.0): Prototype Pollution vulnerability tester.
  - `wscat` (v5.2.1): WebSocket endpoint discovery and connection probing.
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

## [V9.4.1] - 2026-08-08

- Fixed `wpscan` installation in `setup.sh` by adding `sudo` to the `gem install` command to prevent file permission errors.
- Added a retry loop in `setup.sh` for `apt update` and `apt install` to handle temporary dpkg lock failures on fresh VMs.
- Added explicit error messages in `setup.sh` and a troubleshooting guide entry for `archive.ubuntu.com` connection failures caused by corporate antivirus or firewall interception.
- Fixed CI test_10 hang: scanner pipeline now skips MAC randomisation, per-tool delays, and tool installs when `SMP_CI=1`.
- Fixed 3-tuple unpack bug in MAC changer call (change_mac_address returns bool, str, str — was being unpacked as 2 values).
- Reduced DAG plugin hang timeout from 3600s to 120s in CI mode.
- Corrected CVSS label in PDF reports from "CVSS v9.4.3" to "CVSS v3.1" (SMP version was leaking into standard label).
- Corrected PCI-DSS label in PDF reports from "PCI-DSS v9.4.3" to "PCI-DSS v4.0".
- Fixed README license badge showing "Proprietary" — now correctly shows "MIT".
- Synchronized all V9.3.x stale version strings to V9.4.3 across tools, scanners, UI, and docs.
- Updated .env.example to document all env vars SMP actually reads (added SMP_CI, QT_LOGGING_RULES, XDG_SESSION_TYPE, NO_PROXY).
