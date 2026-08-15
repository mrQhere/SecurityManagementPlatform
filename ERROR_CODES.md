# SMP Error Codes Reference

The Security Management Platform (SMP) V9.5 uses a strictly categorized, 4-digit error code system. This ensures that every failure across the DAG orchestrator, cryptographic engine, API, and UI has a deterministic root cause and a clear remediation path.

When SMP encounters a fatal exception, the framework dumps a context-enriched error card to the terminal or log file containing the error code, the exact source code snippet, and actionable steps.

---

## 1xxx: Authentication & Cryptography (10 Codes)

The `1xxx` series indicates failures in the 4-layer Key Hierarchy (KEK/DEK/IEK/EEK), JWT Bearer token lifecycle, or SQLCipher master password validation.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-1000` | `ERR_AUTH_GENERIC` | Generic authentication failure. | Unknown credentials provided. | Verify username/password or token. |
| `SMP-1001` | `ERR_INVALID_PASS` | Master password incorrect. | PBKDF2-SHA256 failed to unwrap the KEK. | Retry master password. If lost, database reset required. |
| `SMP-1002` | `ERR_TOKEN_EXPIRED` | JWT token expired. | API bearer token exceeded its lifetime. | Request a new token from `POST /api/v6/auth/token`. |
| `SMP-1003` | `ERR_TOKEN_INVALID` | JWT signature malformed. | Tampered or incorrectly formatted JWT. | Clear client session and re-authenticate. |
| `SMP-1004` | `ERR_KEK_UNWRAP_FAIL` | Failed to unwrap DEK/IEK/EEK. | KEK corruption or keyfile tampering. | Restore key configuration from secure backup. |
| `SMP-1005` | `ERR_SQLCIPHER_DENY` | SQLCipher PRAGMA key rejected. | Incorrect DEK provided to SQLite. | Ensure `security.db` matches the active keyfile. |
| `SMP-1006` | `ERR_SESSION_TIMEOUT` | UI session timeout. | Inactivity timer triggered auto-lock. | Re-enter master password in the PySide6 UI. |
| `SMP-1007` | `ERR_NO_AUTH_HEADER` | Missing Authorization header. | API call made without Bearer token. | Append `Authorization: Bearer <token>` to request. |
| `SMP-1008` | `ERR_ROLE_UNAUTHORIZED`| Insufficient permissions. | Non-admin user attempted admin action. | Elevate privileges or use admin account. |
| `SMP-1009` | `ERR_CRYPTO_INIT_FAIL` | Cryptographic engine init failed. | Missing OpenSSL libraries on host system. | Run `./setup.sh` to install dependencies. |

---

## 2xxx: Scanner & DAG Orchestration (11 Codes)

The `2xxx` series relates to failures within the 95 scanner modules, Kahn's algorithm topological sorting, process sandboxing, and execution timeouts.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-2000` | `ERR_SCAN_GENERIC` | Generic scanner failure. | Scanner adapter encountered unhandled exception. | Check logs for specific Python traceback. |
| `SMP-2001` | `ERR_DAG_CYCLE` | Cyclic dependency detected. | Two scanners mutually depend on each other. | Review `scanners.core.dag` and remove circular links. |
| `SMP-2002` | `ERR_SCANNER_NOT_FOUND`| Scanner binary missing. | System PATH missing required third-party tool. | Rerun `./setup.sh` to download missing binaries. |
| `SMP-2003` | `ERR_PORT_COLLISION` | Scanner port conflict. | Multiple tools attempted to bind the same port. | Allow Kahn's algorithm to separate execution phases. |
| `SMP-2004` | `ERR_SCAN_TIMEOUT` | Tool exceeded time limit. | Scanner hung or network routing blackholed. | Decrease scanner timeout or exclude target host. |
| `SMP-2005` | `ERR_PARSER_FAIL` | Observation parser failed. | Tool output format changed unexpectedly. | Update SMP to latest version or check tool version. |
| `SMP-2006` | `ERR_STATE_TRANSITION` | 14-State machine invalid move. | Attempted to jump from INIT directly to FINISHED. | Restart scan job from UI to reset state. |
| `SMP-2007` | `ERR_OUT_OF_MEMORY` | Process exceeded RAM limit. | Java/Go scanner consumed too much memory. | Increase swap or reduce parallel scanner count. |
| `SMP-2008` | `ERR_ZOMBIE_PROCESS` | Orphaned scanner detected. | Parent adapter died but child binary persisted. | Run `pkill -f smp_scanner` to clean up. |
| `SMP-2009` | `ERR_INVALID_ARGS` | Malformed scanner arguments. | CLI flags passed to tool were rejected. | Review scanner configuration in Dashboard UI. |
| `SMP-2010` | `ERR_NMAP_ROOT_REQD` | Nmap requires root privileges. | SYN scan attempted without sudo permissions. | Run SMP with elevated permissions or use TCP connect. |

---

## 3xxx: Database Operations (8 Codes)

The `3xxx` series encompasses SQLite/SQLCipher lock contention, constraint violations, and schema migrations.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-3000` | `ERR_DB_GENERIC` | Generic database error. | Unhandled SQL exception during query. | Review application logs for raw SQL error. |
| `SMP-3001` | `ERR_DB_LOCKED` | SQLITE_BUSY lock detected. | High concurrency caused a WAL lock timeout. | System will auto-retry. Reduce concurrent API calls. |
| `SMP-3002` | `ERR_MIGRATION_FAIL` | Schema migration failed. | V9.4 to V9.5 database upgrade encountered error. | Restore `security.db` from backup and retry. |
| `SMP-3003` | `ERR_CONSTRAINT_FAIL` | Foreign key or unique failure. | Attempted to insert duplicate or orphaned record. | Verify target and scan IDs exist before insertion. |
| `SMP-3004` | `ERR_DISK_FULL` | SQLITE_FULL error. | Host machine partition exhausted free space. | Clear logs and `data/evidence/` or expand disk. |
| `SMP-3005` | `ERR_CORRUPTION` | Database file corrupted. | Hard power loss during WAL checkpointing. | Restore from `redundancy.db` immediately. |
| `SMP-3006` | `ERR_MISSING_TABLE` | Requested table not found. | Schema initialization was incomplete. | Run `tools/db_manager.py --init` to rebuild. |
| `SMP-3007` | `ERR_REDUNDANCY_FAIL`| Sync to redundancy.db failed. | Write permissions lost on backup directory. | Fix permissions on `database/` folder recursively. |

---

## 4xxx: Evidence & Reporting (13 Codes)

The `4xxx` series handles file operations, AES-256-GCM evidence processing, PDF generation, and strict legal data export gates.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-4000` | `ERR_REPORT_GENERIC` | Report generation failed. | Unknown error in `ReportGenerator`. | Check console for Jinja2 or WeasyPrint errors. |
| `SMP-4001` | `ERR_PDF_ENGINE_FAIL`| WeasyPrint crashed. | Missing system fonts or GTK dependencies. | Install required fonts via `./setup.sh`. |
| `SMP-4002` | `ERR_EVIDENCE_MISSING`| Raw output file not found. | Scanner completed but failed to write output. | Ensure scanner has write access to `/tmp`. |
| `SMP-4003` | `ERR_EVIDENCE_DECRYPT`| AES-GCM decryption failed. | EEK mismatch or file tampering detected. | Do not trust evidence file. Delete and rescan. |
| `SMP-4004` | `ERR_JSON_EXPORT_FAIL`| JSON serialization error. | Unserializable object passed to exporter. | Update Pydantic v2 schemas. |
| `SMP-4005` | `ERR_MARKDOWN_FAIL` | Markdown render error. | Template variable missing in Jinja2. | Validate custom templates in `ui/templates/`. |
| `SMP-4006` | `ERR_SARIF_SCHEMA` | SARIF format violation. | Exported data did not match SARIF 2.1.0 schema. | File bug report on GitHub with error trace. |
| `SMP-4007` | `ERR_HASH_MISMATCH` | Report signature invalid. | SHA-256 authenticity hash failed verification. | Report has been tampered with post-generation. |
| `SMP-4008` | `ERR_JIRA_FORMAT` | Jira exporter mapping fail. | Missing mandatory fields for Jira JSON. | Map required vulnerability severity levels. |
| `SMP-4009` | `ERR_CSV_WRITE_FAIL` | CSV permission denied. | Output directory is read-only. | Change export path or grant write permissions. |
| `SMP-4050` | `ERR_LEGAL_GATE_DENY`| Export gate unacknowledged. | User rejected the "I AGREE" plaintext prompt. | Must type "I AGREE" to export unencrypted data. |
| `SMP-4051` | `ERR_LEGAL_TYPO` | Gate signature mistyped. | User typed incorrect string in ExportGateDialog. | Carefully type exact phrase requested. |
| `SMP-4052` | `ERR_AUDIT_LOG_FAIL` | Non-repudiation log failed. | Unable to write legal acknowledgment to disk. | Restore write access to `logs/audit.log`. |

---

## 5xxx: Configuration & Intelligence (8 Codes)

The `5xxx` series covers `.env` parsing, configuration loading, and CVE intelligence correlation engines.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-5000` | `ERR_CONF_GENERIC` | Configuration error. | Malformed syntax in configuration file. | Review `.env` or settings JSON for typos. |
| `SMP-5001` | `ERR_ENV_MISSING` | Missing required `.env` var. | Critical environment variable not defined. | Copy `.env.example` to `.env` and configure. |
| `SMP-5002` | `ERR_INTEL_SYNC_FAIL`| CVE database update failed. | Unable to reach NVD or Threat Intel API. | Check network connection and proxy settings. |
| `SMP-5003` | `ERR_INVALID_CVE` | Malformed CVE string. | Scanner returned non-standard CVE format. | Ignore or write custom parser filter. |
| `SMP-5004` | `ERR_RATE_LIMIT` | Intel API rate limit hit. | Too many requests to external threat feeds. | Wait 15 minutes or configure API key in `.env`. |
| `SMP-5005` | `ERR_CORRELATION_FAIL`| Risk scoring engine failed. | Could not calculate CVSS v3.1 vector. | Check `intelligence/brain.py` logs. |
| `SMP-5006` | `ERR_LLM_ADAPTER` | Local LLM connection failed. | Ollama/Llama.cpp not running on localhost. | Start local LLM server or disable feature. |
| `SMP-5007` | `ERR_TFIDF_FAIL` | TF-IDF heuristic engine fail. | Insufficient data to perform correlation. | Run more scans to build intelligence corpus. |

---

## 6xxx: Target Scope Engine (7 Codes)

The `6xxx` series represents failures related to the strict engagement boundaries and domain parsing.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-6000` | `ERR_SCOPE_GENERIC` | Scope engine failure. | Unhandled exception during boundary check. | Review target configuration. |
| `SMP-6001` | `ERR_OUT_OF_SCOPE` | Target rejected by scope. | Scanner attempted to hit unapproved asset. | Add asset to Scope Rules or investigate scanner. |
| `SMP-6002` | `ERR_INVALID_CIDR` | Malformed CIDR notation. | e.g., 192.168.1.0/99 provided as scope. | Correct network notation (e.g., /24). |
| `SMP-6003` | `ERR_DNS_RESOLVE` | Unresolvable domain name. | Target domain does not have A/AAAA records. | Check DNS configuration or remove dead target. |
| `SMP-6004` | `ERR_WILDCARD_REJECT`| Domain wildcard too broad. | Refused to scope `*.com` or `*.org`. | Provide a specific top-level domain. |
| `SMP-6005` | `ERR_REGEX_COMPILE` | URL regex compilation fail. | Malformed regular expression in scope rules. | Validate regex syntax. |
| `SMP-6006` | `ERR_DEFAULT_DENY` | Global default deny hit. | No scope rules defined for engagement. | You must explicitly allow-list targets first. |

---

## 9xxx: Installer & System Check (5 Codes)

The `9xxx` series defines early-stage faults during the `./setup.sh` pre-flight checks and cross-platform installation.

| Code | Slug | Description | Root Cause | Remediation Action |
|------|------|-------------|------------|--------------------|
| `SMP-9001` | `ERR_OS_UNSUPPORTED` | Operating System unsupported. | OS is not Linux or macOS (Darwin). | Install on a supported POSIX environment. |
| `SMP-9002` | `ERR_DPKG_LOCKED` | APT/DPKG is locked. | Another package manager is running (unattended-upgrades). | Wait for completion or run troubleshoot tool. |
| `SMP-9003` | `ERR_NETWORK_OFFLINE`| Pre-flight network check fail. | Cannot reach GitHub/PyPI/Go repositories. | Fix internet connection, corporate firewall, or DNS. |
| `SMP-9004` | `ERR_SHA256_MISMATCH`| Binary signature invalid. | Downloaded tool (e.g., Nuclei) failed checksum. | Network tampering or proxy interception. Retry. |
| `SMP-9005` | `ERR_ENV_CREATE_FAIL`| Python venv creation failed. | Missing `python3-venv` package on host. | Install base python utilities via `apt-get`. |

---

## Automated Error Resolution

The Security Management Platform includes an advanced, self-healing diagnostic engine to resolve the most common runtime and installation faults autonomously. 

When encountering structural faults (such as `SMP-3001` database locks, `SMP-9002` dpkg locks, or `SMP-2008` zombie processes), you do not necessarily need to intervene manually. Instead, leverage the built-in troubleshooting suite:

```bash
# Execute the self-healing engine
python3 tools/troubleshoot.py --fix
```

**How it works:**
1. **State Analysis:** The engine will parse `logs/audit.log` to identify the most recent error codes triggered in the last 15 minutes.
2. **Process Cleansing:** If `SMP-2008` is detected, it will safely send `SIGTERM` followed by `SIGKILL` to orphaned scanner binaries without corrupting the DAG orchestrator.
3. **Database Recovery:** For `SMP-3001` and `SMP-3005`, it will attempt to safely flush the SQLite Write-Ahead Log (WAL) or transparently restore the latest checkpoint from `redundancy.db`.
4. **Environment Repair:** For dependency or checksum failures (`SMP-9004`, `SMP-9002`), it flushes the local artifact cache (`/tmp/smp_cache`) and forcibly releases orphaned package manager locks via safe `fuser` commands.

If the automated resolution engine cannot rectify the fault, it will dump a comprehensive JSON diagnostic report to `/tmp/smp_diagnostic.json`. Please attach this file when seeking assistance from the core development team or when opening an issue.
