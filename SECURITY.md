# Security Policy

## Supported Versions

Only the current V9.5.x release line receives security updates.

| Version | Supported |
| -------- | --------- |
| >= V9.5 | ✅ Yes |
| < V9.5 | ❌ No |

## Security Architecture

SMP is designed to handle highly sensitive vulnerability data.

* **Database Encryption (Pentest Data)**: Sensitive databases (`security.db`,
 `redundancy.db`) are encrypted at rest using **SQLCipher (AES-256)**.
 Public intelligence databases (`cve.db`, `global_intel.db`) are plaintext
 SQLite for I/O performance; they contain no client data.
* **Audit Trail**: All intelligence outbound calls are logged to
 `logs/egress_audit.log`. Scan activity is logged to `logs/smp.log`.
* **API Security**: The REST API is secured with JWT Bearer tokens.
* **Single-Instance Lock**: A file-based lock (`/tmp/smp.lock`) prevents
 multiple simultaneous SMP processes from corrupting the database.
* **Air-Gapped & Zero-Exfiltration Brain**: The Neural Correlation Engine and V10 Local LLM adapter operate exclusively on local heuristics and local models (e.g. Ollama). All target findings remain 100% local with zero synthetic data forging or external telemetry.
* **Authentic Findings Integrity**: Scan findings process real tool outputs directly. No simulated or synthetic CVE IDs are generated.
* **Multi-Session Auth Isolation**: IDOR/BOLA session testing utilizes explicit secondary token parameters (`secondary_auth_token`) within isolated scan contexts, ensuring credential boundaries are strictly maintained.

> [!WARNING]
> **Project Disclaimer**
> SMP is a personal project maintained on a best-effort basis. It has not undergone any formal third-party security audits. Use this software at your own risk.

## Reporting a Vulnerability

If you discover a security vulnerability within SMP, please **do not** open a
public issue.

Report it directly by contacting `@mrQhere` or by using **GitHub Security Advisories** on this repository if enabled.

Please include detailed steps to reproduce the issue. Reports are generally acknowledged within 24 hours.
