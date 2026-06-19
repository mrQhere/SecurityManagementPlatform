# Security Management Platform (SMP) — Overview

Welcome to the Security Management Platform. This is a cross-platform desktop security monitoring application built to run sequential multi-tool scan pipelines, store results locally, and generate actionable reports.

## Quick Start

### Linux / Ubuntu
```bash
bash setup.sh      # Fully automatic setup
bash run.sh        # Launch the application
```

### Windows
```bat
# Run as Administrator
setup.bat          # Install dependencies
run.bat            # Launch the application
```

## High-Level Architecture

The platform orchestrates multiple open-source security tools in a sequential, rate-limited pipeline to ensure deep vulnerability discovery without causing network disruption. 

**Core Components:**
- **GUI Dashboard**: Built with PySide6 for local management.
- **Scan Runner**: Sequentially executes tools (Nmap, Nuclei, ffuf, SQLMap, Nikto, HTTPx) and free OSINT APIs.
- **Intelligence Engine**: Synchronizes offline databases for NVD CVEs, CISA KEV, GitHub Advisories, and EPSS scores.
- **Reporting Engine**: Generates HTML/PDF situational templates (Executive, Technical, Compliance).
- **Alert Engine**: Dispatches SMTP notifications on critical findings.

## Privacy & Security
- All scan data is stored in a local SQLite database (`database/security.db`).
- Configuration files (`config/settings.json`) containing SMTP credentials are kept strictly local and should never be committed.

> **Note to Developers:** For comprehensive architectural details, historical bug fixes, and pipeline structures, please consult the internal developer diaries.

## [2026-06-18] Platform Enhancements
- **CVE Alert Filtering**: Emails are now only sent if a new CVE matches a technology currently running on an actively monitored ('Enabled') target.
- **Dedicated CVE Logging**: Separated CVE intelligence update errors to `logs/cve.log` using a new `smp.cve` logger.
- **Global Concurrency Control**: The scan runner now limits maximum parallel active scans to 3 globally, preventing excessive network traffic.
- **Scan Resumption**: Added `resume_interrupted_scans()` logic triggered on system boot to resume scans that didn't complete prior to a shutdown.
- **ZAP API Control**: OWASP ZAP is now fully controllable via a toggle in the System Settings UI (disabled by default).
- **Report Generator Expansion**: Integrated Shodan, Wayback Machine, CRT.sh, HackerTarget, and Whois registry info into the generated PDF and HTML reports.
- **UI Redesign**: Overhauled PySide6 stylesheet to an auto-adapting Light/Dark theme with a sleek, professional iOS-inspired aesthetic.
- **UI Performance & UX**: Eliminated GUI lag by implementing state-caching and state-hashing logic across the dashboard refresh cycles. Reversed log display order so newest logs appear at the top.
- **Documentation**: Removed `way.md` from `.gitignore` and documented all recent changes.

## [2026-06-19] UI Complete Ground-Up Redesign
- **Full UI Rewrite**: `ui/dashboard.py` was completely rewritten from scratch (~800 lines). All previous functions preserved, zero regressions.
- **Apple Light Theme**: Implemented genuine Apple-style stylesheet — #F2F2F7 page backgrounds, #FFFFFF card surfaces, #007AFF accent blue, SF Pro/Helvetica Neue typography, 16px border-radius cards, hairline borders.
- **Sidebar**: Replaced QListWidget with stateful QPushButton nav that highlights active page with EAF1FF/007AFF selection — matches macOS sidebar exactly.
- **KPI Strip**: Four cards with 28px bold metric values in brand accent colors.
- **Settings Page**: Scrollable, grouped form sections with 200px-wide labels aligned in a clean grid.
- **Log View**: Terminal-style QTextEdit (dark bg, monospace) — newest log entries at top, with level and search filters.
- **No Lag**: Strict state-hash caching on every refresh function; UI redraws only on actual data change.

## [2026-06-19] UI Fixes & CVE Log Viewer
- **CVE Log Tab**: Added to Audit Logs page — reads `logs/cve.log`, newest entries first, with search filter.
- **Refresh Button**: Dashboard header now has a "↻ Refresh" button that clears all caches and force-redraws the full UI.
- **List Colour Fix**: Removed global `color` on `QListWidget::item` so `setForeground()` per-item colours (red=critical, orange=high, etc.) now render correctly.
