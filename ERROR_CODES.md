# SMP Error Codes Reference

This document outlines the standard error codes returned by the Security Management Platform (SMP).

## 1xxx — Auth/Session
| Code | Slug | Description | Remediation |
|------|------|-------------|-------------|
| **SMP-1000** | `auth_error` | Generic authentication failure. | Check credentials. |
| **SMP-1001** | `token_expired` | JWT token has expired. | Request a new token via `/api/v6/auth/token`. |

## 2xxx — Scanner/Subprocess
| Code | Slug | Description | Remediation |
|------|------|-------------|-------------|
| **SMP-2000** | `scanner_error` | Generic scanner execution failure. | Check scanner logs. |
| **SMP-2001** | `scanner_timeout` | Scanner process timed out. | Increase timeout or check network connectivity. |
| **SMP-2002** | `scanner_binary_missing` | Required scanner binary not found in PATH. | Run `./setup.sh` or install the binary manually. |
| **SMP-2003** | `scanner_crashed` | Scanner process crashed unexpectedly. | Check system resources and scanner compatibility. |
| **SMP-2004** | `scanner_output_parse_error` | Failed to parse scanner output. | Check if the scanner version is supported. |

## 3xxx — Database
| Code | Slug | Description | Remediation |
|------|------|-------------|-------------|
| **SMP-3000** | `db_error` | Generic database error. | Check database logs. |
| **SMP-3001** | `db_connection_error` | Could not connect to the database. | Check if the database file exists and is accessible. |
| **SMP-3002** | `db_encryption_error` | Database decryption failed. | Verify the master password. |

## 4xxx — API/Validation
| Code | Slug | Description | Remediation |
|------|------|-------------|-------------|
| **SMP-4000** | `validation_error` | Generic input validation error. | Check payload format. |
| **SMP-4001** | `invalid_target` | Invalid target URL provided. | Ensure URL is well-formed (e.g., http://...). |
| **SMP-4002** | `invalid_payload` | Malformed API request payload. | Check API documentation. |

## 5xxx — Config/Intelligence
| Code | Slug | Description | Remediation |
|------|------|-------------|-------------|
| **SMP-5000** | `config_error` | Generic configuration error. | Check configuration files. |
| **SMP-5001** | `config_missing` | Required configuration file or key is missing. | Restore default configuration. |
| **SMP-5002** | `intel_sync_error` | Failed to sync intelligence data. | Check internet connection or `SMP_LOCAL_ONLY` mode. |

## 9xxx — Unclassified
| Code | Slug | Description | Remediation |
|------|------|-------------|-------------|
| **SMP-9999** | `unexpected_error` | An unhandled exception occurred. | Check application logs and report the issue. |
