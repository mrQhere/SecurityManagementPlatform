# Security Management Platform (SMP) V6.0

**The Complete Enterprise Security Orchestrator**

Security Management Platform (SMP) V6.0 is an all-in-one vulnerability scanning and intelligence orchestration platform. Maintained by [@mrQhere](https://github.com/mrQhere) at [https://github.com/mrQhere/SecurityManagementPlatform](https://github.com/mrQhere/SecurityManagementPlatform).

It brings together over 30 security tools, CVE intelligence, compliance mapping, and executive reporting into a single dashboard.

## Key Features

* **Adaptive Stage-Feeding Pipeline**: Phase 1 OSINT findings dynamically activate Phase 3 exploit scanners. WordPress detected → WPScan runs. SSH open → Hydra runs. No wasted time on irrelevant tools.
* **Live Narrative Walkthrough**: Every scanner step emits a human-readable explanation — what is being tested, why, and what was found. Persisted per scan and streamed to the dashboard in real time.
* **Docker Deployment**: Full one-command deployment via Docker and Docker Compose. All 30+ tools bundled. No manual dependency installation.
* **Encrypted Database**: AES-256 (Fernet) and PBKDF2 (600,000 iterations).
* **Secured REST API**: Headless operation via FastAPI with JWT Authentication and Rate Limiting.
* **Intelligence and OSINT**: GreyNoise IP intelligence and real-time CVE syncing.
* **Compliance Ready**: Automated mapping to OWASP Top 10 2021, CIS Controls v8, and ISO 27001:2022.
* **SBOM Generation**: Automatic CycloneDX Software Bill of Materials.
* **OPSEC Safe**: Dynamic MAC address changing and port baselining.

## Quick Start — Docker (Recommended)

No dependency installation required. Everything is bundled.

```bash
# Build and run the API server
make docker-build
make docker-run

# Check the API is healthy
make docker-health

# Access the Swagger API docs
open http://localhost:8000/api/v6/docs

# Open a shell inside the container
make docker-shell
```

## Quick Start — Local

```bash
# Install all system and Python dependencies
make install

# Run the desktop GUI
make run

# Run headless API only
make run-api
```

## Adaptive Pipeline

The scanner pipeline is no longer a fixed linear list. It runs in three stages:

| Stage | Scanners | Behaviour |
|-------|----------|-----------|
| Phase 1 — Recon | HTTPx, WhatWeb, Subfinder, CRT.sh, HackerTarget, Whois, Wayback, theHarvester, Traceroute | Always runs. Feeds findings into Phase 3 decision logic. |
| Phase 2 — Active | Nmap, SSL, Headers, CORS, Nikto, Nuclei, ffuf, SQLMap, Shodan, Gitleaks, etc. | Always runs. Findings further refine Phase 3. |
| Phase 3 — Exploit | WPScan, Dalfox, Arjun, DNSx, Katana, Commix, JWT, Masscan, ParamSpider, Cloud Enum, Hydra, ZAP | Conditionally activated based on Phase 1 and 2 results. |

**Example**: If Nmap finds port 22 open, Hydra is automatically added. If WhatWeb detects WordPress, WPScan is triggered. Each branch decision is logged in the Live Narrative.

## Live Narrative

Every scan generates a human-readable walkthrough log at `logs/narrative/scan_<id>.log`:

```
[14:02:01] [STAGE]   [STAGE:RECON]   Stage started — Passive reconnaissance.
[14:02:03] [INFO]    [HTTPX]         Checking whether the target is alive and collecting HTTP metadata.
[14:02:18] [INFO]    [WHATWEB]       Fingerprinting the technology stack — frameworks, CMS, server software.
[14:03:45] [INFO]    [NMAP]          Port and service scanning — identifying open ports and running services.
[14:04:02] [FINDING] [NMAP]          [HIGH] Finding confirmed — Port 22 open — SSH service exposed.
[14:04:02] [BRANCH]  [PIPELINE]      Dynamic branch — NMAP result triggered HYDRA. Reason: SSH port 22 open.
[14:04:02] [BRANCH]  [PIPELINE]      Dynamic branch — CMS result triggered WPSCAN. Reason: WordPress CMS detected.
```

The narrative is also streamed to the GUI dashboard over the real-time IPC bus.

## REST API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/v6/auth/token | No | Obtain JWT token |
| GET | /api/v6/health | No | Health check |
| GET | /api/v6/target | Yes | List all targets |
| POST | /api/v6/target | Yes | Add a target |
| GET | /api/v6/scan | Yes | List scans |
| GET | /api/v6/findings | Yes | Get findings for a scan |
| GET | /api/v6/cve/stats | Yes | CVE database statistics |
| GET | /api/v6/risk/score | Yes | Risk scores per target |
| GET | /api/v6/version | Yes | Platform version |

Full interactive docs at `http://localhost:8000/api/v6/docs`.

## Legal Notice

This software is maintained by [@mrQhere](https://github.com/mrQhere). Unauthorized access, modification, or distribution may be restricted based on the repository license.
