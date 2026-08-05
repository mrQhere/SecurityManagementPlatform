# Security Policy for SMP V9.0.3

## Supported Versions

Only the current major release receives security updates.

| Version | Supported |
| ------- | --------- |
| V6.x    | Yes       |
| V5.x    | No        |
| < V9.0.3  | No        |

## Security Architecture

SMP is designed to handle highly sensitive vulnerability data. The V9.0.3 architecture enforces the following controls:

* **Database Encryption**: All databases are encrypted at rest using AES-128-CBC (Fernet) and HMAC-SHA256.
* **Key Derivation**: The encryption key is derived using PBKDF2 with HMAC-SHA256 and 600,000 iterations (NIST 2024 compliance).
* **Password Complexity**: Enforced 12+ characters, mixed case, numbers, and special characters.
* **Audit Trail Integrity**: All audit logs are cryptographically signed using HMAC-SHA256 to prevent tampering.
* **API Security**: The REST API is secured with short-lived JWT Bearer tokens and rate limiting (120 RPM default).
* **Licensing**: Cryptographically verified via RSA-2048 signatures.

## Reporting a Vulnerability

If you discover a security vulnerability within SMP, please DO NOT open a public issue.

Instead, report it directly to the maintainer via the repository:
* **Repository**: [https://github.com/mrQhere/SecurityManagementPlatform.git](https://github.com/mrQhere/SecurityManagementPlatform.git)
* Contact `@mrQhere` directly if sensitive, or use GitHub Security Advisories if enabled.

Please include detailed steps to reproduce the issue. We aim to acknowledge all reports within 24 hours.
