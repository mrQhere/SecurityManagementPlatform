# Security Management Platform (SMP) V9.2.4

[![CI](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrQhere/SecurityManagementPlatform/actions/workflows/ci.yml)

**Local-first VAPT platform. Zero cloud. Encrypted at rest. Powered by a Neural Correlation Engine.**

Maintained by [@mrQhere](https://github.com/mrQhere).

---

## What it is

SMP is a penetration testing orchestration platform that runs ~30 open-source scanners, correlates findings across multiple threat-intelligence sources, and produces compliance-mapped reports — all without sending your client data to a third-party cloud.

**The V9.2.4 Awakening**: SMP now features a built-in Neural Correlation Engine (The Brain) which builds a deterministic, crowdsourced global intelligence graph locally without telemetry. It leverages an Obsidian-style physics engine (Force-Directed Graph) built in pure PySide6 to visually correlate over 10,500 real-world threat heuristics in real-time.

**The core pitch is not tool count.** It is:

1. **Correlation depth** — most scanner wrappers report raw CVSS. SMP cross-references each finding against EPSS, GreyNoise, CISA KEV, and the new 10,000+ node Neural Brain.
2. **Provable local-only operation** — outbound intelligence logs every network call to `logs/egress_audit.log`. Set `SMP_LOCAL_ONLY=1` to mathematically isolate the engine.
3. **Beautiful Minimalist UX** — An Obsidian/Ollama-inspired dark aesthetic prioritizing raw information density.
4. **Compliance gap analysis** — maps findings to SOC 2 Type II, ISO 27001, CIS, and PCI-DSS v9.2.4.
5. **SQLCipher encryption, not optional** — "Encrypted at rest" is unconditionally enforced on all sensitive pentest data. Public CVE models are deliberately unencrypted for maximum I/O performance.

---

## System Architecture (Semver Tree)

```text
SecurityManagementPlatform/
├── api/                   # REST API backend (FastAPI)
├── config/                # Platform configuration & metadata
├── database/              # SQLCipher databases (security.db, global_intel.db)
├── intelligence/          # The Brain & API connectors (CISA, NVD, EPSS)
├── logs/                  # Unified logging directory
├── scanners/              # 30+ Pentesting scanner wrappers (Nmap, ZAP, etc.)
├── tools/                 # Core engine mechanics (Scheduler, Database manager, Encryption)
├── ui/                    # Desktop Application (PySide6)
│   ├── components/        # UI Widgets (NeuralGraphWidget)
│   ├── views/             # Dashboard and Navigation logic
│   └── style.qss          # Global Ollama-inspired dark theme
├── main.py                # Application entrypoint
├── setup.sh               # Local installation engine
└── tools/verify_smp.py    # CI/CD integrity testing suite
```

---

## Future Plan (Roadmap)

### Near-term (V9.2.4.x)
- **Neural Graph Filtering**: Allow click-and-drag filtering of the Intelligence Brain based on real-time CVE correlation weights.
- **Custom Payload Injection**: Allow users to define custom Nuclei/SQLMap payloads directly from the Desktop UI.
- **Offline Intelligence Updates**: Enable importing a completely air-gapped `global_intel.db` via USB for classified network scanning.

### Long-term (V10.0 Architecture)
- **Distributed Agents**: Deploy SMP scanning agents on internal networks that phone home to the main encrypted SMP dashboard via mutually authenticated TLS.
- **Multi-Tenant Reporting**: Allow MSSPs to separate target reports by client workspaces inside the database without sacrificing the single-pane-of-glass UI.

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

---

## Encryption At Rest

- Sensitive data (targets, scans, settings) is encrypted at rest using **SQLCipher (AES-256)**.
- Public intelligence models (`cve.db`, `global_intel.db`) are dynamically routed to plaintext logic via `_get_conn(encrypt=False)` to prevent massive I/O bottlenecks without sacrificing security.
- Master password uses PBKDF2-SHA256 with 600,000 iterations (NIST 2024 recommendation).

## Legal

Use only against systems you have written authorisation to test.  
Maintained by [@mrQhere](https://github.com/mrQhere) · © mrQhere. See [LICENSE](LICENSE).
