<!--
FUTURE CONTRIBUTORS:
Every future commit to the main branch MUST add one line to the "Unreleased"
section below in plain English (do not just copy the commit message).
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Fixed CI test_10 hang: scanner pipeline now skips MAC randomisation, per-tool delays, and tool installs when `SMP_CI=1`.
- Fixed 3-tuple unpack bug in MAC changer call (change_mac_address returns bool, str, str — was being unpacked as 2 values).
- Reduced DAG plugin hang timeout from 3600s to 120s in CI mode.
- Corrected CVSS label in PDF reports from "CVSS v9.4.0" to "CVSS v3.1" (SMP version was leaking into standard label).
- Corrected PCI-DSS label in PDF reports from "PCI-DSS v9.4.0" to "PCI-DSS v4.0".
- Fixed README license badge showing "Proprietary" — now correctly shows "MIT".
- Synchronized all V9.3.x stale version strings to V9.4.0 across tools, scanners, UI, and docs.
- Updated .env.example to document all env vars SMP actually reads (added SMP_CI, QT_LOGGING_RULES, XDG_SESSION_TYPE, NO_PROXY).
