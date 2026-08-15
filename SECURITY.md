# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| V9.5.x  | ✅ Yes     |
| < V9.5  | ❌ No      |

## Security Architecture

The Security Management Platform (SMP) is built from the ground up with a zero-trust, data sovereignty first approach:

- **Key Management:** Uses a 4-layer key hierarchy (KEK/DEK/IEK/EEK) protected by PBKDF2-SHA256 with 600,000 iterations.
- **Database Encryption:** `security.db` and `redundancy.db` are encrypted using SQLCipher AES-256.
- **Threat Intel:** `cve.db` and `analytics.db` are plaintext but contain **no client data**.
- **Evidence Storage:** All scan evidence in `data/evidence/` is encrypted using AES-256-GCM.
- **Authentication:** The `/api/v6/` API enforces JWT Bearer token authentication.
- **Concurrency & Auditing:** Single-instance file locks (`/tmp/smp.lock`) prevent corruption, and comprehensive audit logs are written to `logs/`.
- **Zero Cloud Dependency:** All data stays local to the executing machine.

## Reporting a Vulnerability

Please do **NOT** open public issues for security vulnerabilities.

If you discover a security vulnerability in SMP, please:
1. Contact `@mrQhere` directly on GitHub, or
2. Use GitHub Security Advisories.

Include detailed reproduction steps. All reports will be acknowledged within 48 hours.

## Scope of Responsible Disclosure

- **In Scope:** Authentication bypass, encryption flaws, command injection in orchestration, authorization issues via API.
- **Out of Scope:** Vulnerabilities in third-party scanner binaries (e.g., nmap, nuclei) unless SMP's wrapper introduces the flaw; physical access attacks; denial of service (DoS) requiring extreme resources.

> **WARNING:** This is a personal/early-stage project and has not been formally audited by a third-party security firm. Use at your own risk.
