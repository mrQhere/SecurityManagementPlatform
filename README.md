# Security Management Platform (SMP) V7

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)

Local-first VAPT platform. Zero cloud. Encrypted at rest. Runs entirely on your hardware.

Maintained by [@mrQhere](https://github.com/mrQhere).

---

## What it is

SMP is a penetration testing orchestration platform that runs ~30 open-source scanners, correlates findings across multiple threat-intelligence sources, and produces compliance-mapped reports — all without sending your client data to a third-party cloud.

**The core pitch is not tool count.** It is:

1. **Correlation depth** — most scanner wrappers report raw CVSS. SMP cross-references each finding against EPSS (exploitation probability), GreyNoise (active wild scanning), and CISA KEV (known exploited vulnerabilities) to produce a multi-source risk score. See: [`intelligence/`](intelligence/) and [`tools/risk_scorer.py`](tools/risk_scorer.py).

2. **Provable local-only operation** — all four outbound intelligence sources (NVD, EPSS, GreyNoise, CISA KEV) record every network call to `logs/egress_audit.log` with service name, URL, timestamp, and ALLOWED/BLOCKED status. Set `SMP_LOCAL_ONLY=1` to block all external calls at runtime. See: [`tools/egress_auditor.py`](tools/egress_auditor.py).

3. **Two deliverables per scan** — each completed scan produces a pentest report (HTML + PDF) and a CycloneDX SBOM automatically. See: [`tools/sbom_generator.py`](tools/sbom_generator.py), wired into [`tools/report_generator.py`](tools/report_generator.py).

4. **Compliance gap analysis** — findings are mapped to OWASP Top 10, CIS Controls v8, ISO 27001:2022, SOC 2 Type II, and PCI-DSS v7.0.7 control IDs. The output distinguishes between "here are 40 vulnerabilities" and "here is what is blocking your SOC 2 audit." See: [`tools/compliance_mapper.py`](tools/compliance_mapper.py).

5. **SQLCipher encryption, not optional** — SMP will not start if `pysqlcipher3` is missing. "Encrypted at rest" is unconditionally enforced, not a fallback. See: [`tools/db_manager.py`](tools/db_manager.py).

---

## What it is not

- It is not an AI agent. There is no LLM layer.
- It does not compete on tool count. HexStrike and PentAGI have more scanners. That is not the differentiator here.
- It does not require cloud registration, API keys, or telemetry.

---

## Risk correlation stack

When a CVE or finding is identified, SMP enriches it with:

| Source | What it adds | Code |
|--------|-------------|------|
| NVD | CVSS base score, affected products | [`intelligence/nvd.py`](intelligence/nvd.py) |
| EPSS (FIRST.org) | Exploitation probability score (0–1) | [`intelligence/epss.py`](intelligence/epss.py) |
| GreyNoise | Is this IP actively scanning the internet right now? | [`intelligence/greynoise.py`](intelligence/greynoise.py) |
| CISA KEV | Is this CVE on the Known Exploited Vulnerabilities list? | [`intelligence/cisa.py`](intelligence/cisa.py) |
| MITRE ATT&CK | Tactic and technique mapping | [`intelligence/mitre_mapper.py`](intelligence/mitre_mapper.py) |

The composite score is computed in [`tools/risk_scorer.py`](tools/risk_scorer.py).

---

## Scanner pipeline

Three-phase DAG execution. Phase 3 steps activate conditionally based on Phase 1/2 findings:

| Phase | Tools | Trigger |
|-------|-------|---------|
| 1 — Recon | HTTPx, WhatWeb, Subfinder, CRT.sh, HackerTarget, Whois, Wayback, theHarvester, Traceroute | Always |
| 2 — Active | Nmap, SSL, Security Headers, CORS, Nikto, Nuclei, ffuf, SQLMap, Shodan, Gitleaks | Always |
| 3 — Conditional | WPScan, Dalfox, Arjun, DNSx, Katana, Commix, JWT Scanner, Masscan, ParamSpider, Cloud Enum | WordPress detected → WPScan; port 22 open → Hydra; etc. |

Pipeline code: [`scanners/scan_runner.py`](scanners/scan_runner.py), [`scanners/core/dag.py`](scanners/core/dag.py).

---

## Compliance mapping

Every finding is mapped to control IDs across five frameworks:

- OWASP Top 10 2021
- CIS Controls v8
- ISO 27001:2022 Annex A
- SOC 2 Type II (Trust Services Criteria CC6–CC9)
- PCI-DSS v7.0.7 (Requirements 6, 7, 8, 11, 12)

The summary output includes `audit_blocking_findings` — the specific Critical/High findings that directly violate SOC 2 or PCI-DSS controls. Code: [`tools/compliance_mapper.py`](tools/compliance_mapper.py).

---

## Quick start

```bash
# Install dependencies (prebuilt binaries, ~30 seconds for Go tools)
./setup.sh

# Activate venv
source venv/bin/activate

# Run desktop GUI
./run.sh

# Run headless REST API
python main.py --api
```

### Local-only mode (no outbound calls)

```bash
SMP_LOCAL_ONLY=1 ./run.sh
```

All intelligence API calls will be blocked and logged as BLOCKED in `logs/egress_audit.log`.

### Docker

```bash
make docker-build
make docker-run
# API at http://localhost:8000/api/v6/docs
```

---

## REST API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/v6/auth/token | No | Obtain JWT token |
| GET | /api/v6/health | No | Health check |
| GET | /api/v6/target | Yes | List targets |
| POST | /api/v6/target | Yes | Add target |
| GET | /api/v6/scan | Yes | List scans |
| GET | /api/v6/findings | Yes | Findings for scan |
| GET | /api/v6/cve/stats | Yes | CVE database stats |
| GET | /api/v6/risk/score | Yes | Risk scores |
| GET | /api/v6/version | Yes | Platform version |

Interactive docs: `http://localhost:8000/api/v6/docs`

---

## Encryption

- Databases are encrypted at rest using SQLCipher (AES-256). SMP will not start without `pysqlcipher3`.
- Master password: PBKDF2-SHA256 with 600,000 iterations (NIST 2024 recommendation).
- Raw scan outputs are compressed (gzip) and encrypted with Fernet before storage.

---

## Requirements

- Python 3.10+
- `libsqlcipher-dev` + `pysqlcipher3` (hard requirement)
- Linux or macOS

---

## Legal

Use only against systems you have written authorisation to test.  
Maintained by [@mrQhere](https://github.com/mrQhere) · © mrQhere. See [LICENSE](LICENSE).
