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
