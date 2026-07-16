# 🔒 Security Policy for SMP V6.0

## Supported Versions

Only the current major release receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| V6.x    | :white_check_mark: |
| V5.x    | :x:                |
| < V5.0  | :x:                |

## 🛡️ V6.0 Security Architecture

SMP is designed to handle highly sensitive vulnerability data. The V6.0 architecture enforces the following controls:

*   **Database Encryption**: All databases are encrypted at rest using AES-128-CBC (Fernet) and HMAC-SHA256.
*   **Key Derivation**: The encryption key is derived using PBKDF2 with HMAC-SHA256 and **600,000 iterations** (NIST 2024 compliance).
*   **Password Complexity**: Enforced 12+ chars, mixed case, numbers, and special characters.
*   **Audit Trail Integrity**: All audit logs are cryptographically signed using HMAC-SHA256 to prevent tampering.
*   **API Security**: The REST API is secured with short-lived JWT Bearer tokens and rate limiting (120 RPM default).
*   **Licensing**: Cryptographically verified via RSA-2048 signatures.

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability within SMP, please DO NOT open a public issue.

Instead, report it directly to the Internal Security Team:
*   **Email**: security@megacooperative.local
*   **Subject**: `[SMP V6 Vulnerability] - <Brief Description>`

Please include detailed steps to reproduce the issue. We aim to acknowledge all reports within 24 hours.
