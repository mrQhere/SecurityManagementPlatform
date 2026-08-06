# Security Policy — SMP V9.2.4

## Supported Versions

Only the current V9.2.x release line receives security updates.

| Version  | Supported |
| -------- | --------- |
| V9.2.x   | ✅ Yes    |
| < V9.2.0 | ❌ No     |

## Security Architecture

SMP is designed to handle highly sensitive vulnerability data. The V9.2.4
architecture enforces the following controls:

* **Database Encryption (Pentest Data)**: All sensitive databases (`security.db`,
  `redundancy.db`) are encrypted at rest using **SQLCipher — AES-256-CBC**.
  Public intelligence databases (`cve.db`, `global_intel.db`) are plaintext
  SQLite for I/O performance; they contain no client data.

* **Raw Output Encryption**: Raw scanner stdout is compressed (gzip) and
  encrypted with **Fernet (AES-128-CBC + HMAC-SHA256)** before being stored
  as a blob in the database.

* **Key Derivation**: The encryption key is derived using **PBKDF2-HMAC-SHA256**
  with 600,000 iterations and a random 32-byte salt (NIST 2024 recommendation).

* **Password Complexity**: Enforced 12+ characters, mixed case, numbers, and
  special characters.

* **Audit Trail**: All intelligence outbound calls are logged to
  `logs/egress_audit.log` (one JSON line per call, with `ALLOWED`/`BLOCKED`
  status). Scan activity is logged to `logs/smp.log`.

* **API Security**: The REST API is secured with short-lived JWT Bearer tokens
  and per-IP rate limiting (60 RPM default).

* **Single-Instance Lock**: A file-based lock (`/tmp/smp.lock`) prevents
  multiple simultaneous SMP processes from corrupting the database.

## Reporting a Vulnerability

If you discover a security vulnerability within SMP, please **do not** open a
public issue.

Report it directly to the maintainer:

* **Repository**: [https://github.com/mrQhere/SecurityManagementPlatform](https://github.com/mrQhere/SecurityManagementPlatform)
* Contact `@mrQhere` directly, or use **GitHub Security Advisories** if enabled.

Please include detailed steps to reproduce the issue. Reports are acknowledged
within 24 hours.
