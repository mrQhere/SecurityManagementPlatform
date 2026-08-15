# SMP Error Codes Reference — V9.5 Security Data Pipeline

This document defines the canonical `SMP-xxxx` error taxonomy for the **Security Management Platform (SMP)** V9.5.

All REST API endpoints, CLI diagnostics (`tools/troubleshoot.py`), DAG orchestrators, and database managers emit structured exceptions conforming to this taxonomy.

---

## Quick Reference Summary

| Category | Range | Domain | Primary Recovery Mechanism |
|---|---|---|---|
| **1xxx** | `SMP-1000` – `SMP-1009` | Authentication, Session & Key Hierarchy | Password re-entry, Token refresh, KEK recovery |
| **2xxx** | `SMP-2000` – `SMP-2010` | Scanner Execution, DAG & State Machine | Binary auto-install, DAG re-evaluation, Timeout increase |
| **3xxx** | `SMP-3000` – `SMP-3007` | Database, SQLCipher & Storage Pipeline | WAL checkpoint, Schema migration, Backup restoration |
| **4xxx** | `SMP-4000` – `SMP-4042` | Evidence Store, Reporting & Verification | Evidence EEK loading, Hash verification, Font install |
| **5xxx** | `SMP-5000` – `SMP-5007` | Threat Intelligence, CVE & Deduplication | Offline DB sync, CPE normalization, Local-only mode check |
| **6xxx** | `SMP-6000` – `SMP-6006` | Scope Engine & Scan Policy | Scope rule adjustment, Rate limit ceiling change, Auth attestation |
| **9xxx** | `SMP-9000` – `SMP-9999` | Unclassified / System Errors | Log analysis, System diagnostic report, Bug report |

---

## 1xxx — Authentication, Session & Cryptographic Key Hierarchy

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-1000** | `auth_error` | Generic authentication failure | Missing or unparseable credentials in request header or CLI | Provide valid username/password or Authorization Bearer header. |
| **SMP-1001** | `token_expired` | JWT bearer token expired | Bearer token generated > 24 hours ago | Request fresh token via `POST /api/v6/auth/token`. |
| **SMP-1002** | `invalid_credentials` | Master password / login credentials incorrect | Failed PBKDF2 hash verification against `config/auth.json` | Verify master password or perform emergency recovery via `tools/troubleshoot.py --fix`. |
| **SMP-1003** | `password_policy_violation` | Master password rejected by policy | Password < 12 characters or missing upper/lower/digit/special chars | Choose a password meeting minimum 12 chars, mixed case, digit, special character. |
| **SMP-1004** | `kek_derivation_failed` | KEK key derivation failed | OpenSSL / PBKDF2 HMAC-SHA256 computational failure | Check `cryptography` Python package installation (`pip install cryptography`). |
| **SMP-1005** | `dek_unavailable` | Database Encryption Key (DEK) not loaded | Database accessed while application is in locked state | Unlock application via GUI password prompt or authenticate API session. |
| **SMP-1006** | `iek_unavailable` | Intelligence Encryption Key (IEK) not loaded | Threat intel database accessed before master key unlock | Provide master password to decrypt the local `vulnerability.db`. |
| **SMP-1007** | `eek_unavailable` | Evidence Encryption Key (EEK) not loaded | Evidence store accessed without active unlocked EEK | Ensure application is unlocked before storing or retrieving raw evidence files. |
| **SMP-1008** | `key_rotation_failed` | Master password / subkey rotation failed | Old password mismatch or partial key write error | Re-verify current master password before attempting key rotation. |
| **SMP-1009** | `auth_file_corrupt` | Master auth metadata `config/auth.json` corrupted | Interrupted disk write or invalid JSON formatting in `auth.json` | Restore `config/auth.json` from backup or run `python3 tools/troubleshoot.py --fix`. |

---

## 2xxx — Scanner Execution, DAG Orchestration & State Machine

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-2000** | `scanner_error` | Generic scanner execution failure | Subprocess crash, non-zero exit code, or unhandled exception | Check `logs/smp.log` and raw output file in `database/raw_outputs/`. |
| **SMP-2001** | `scanner_timeout` | Scanner exceeded maximum execution time | Target host unresponsive, large network subnet, or aggressive rate limit | Increase scanner timeout in Scan Policy or switch profile to `standard` / `fast`. |
| **SMP-2002** | `scanner_binary_missing` | Required security binary not found in PATH | Tool not installed during `./setup.sh` or missing from `./bin/` | Run `python3 tools/troubleshoot.py --fix` or `./setup.sh` to auto-install tool. |
| **SMP-2003** | `scanner_crashed` | Scanner process terminated unexpectedly | Segfault, out-of-memory kill, or missing native shared library (`.so`) | Check system memory (`free -m`) and verify binary dependencies (`ldd $(which <tool>)`). |
| **SMP-2004** | `scanner_output_parse_error` | Observation parser failed to decode output | Unexpected tool output format or incompatible tool version | Verify tool semver matches manifest; check regex/JSON parser in `scanners/adapters/`. |
| **SMP-2005** | `dag_cycle_detected` | Scanner dependency graph contains cycle | Circular dependency declared between scanner plugins | Run `python3 tools/verify_smp.py` to validate DAG topological ordering (Kahn's algorithm). |
| **SMP-2006** | `invalid_state_transition` | State machine transition rule violated | Scanner attempted illegal state jump (e.g. `NOT_STARTED` → `COMPLETED`) | Ensure scanner wrapper transitions through `STARTED` → `RUNNING` before terminal states. |
| **SMP-2007** | `sandbox_isolation_violation` | Scanner process attempted sandbox escape | Attempted write outside designated temporary workspace | Check `scanners/framework/sandbox.py` permissions and target directory boundaries. |
| **SMP-2008** | `missing_dependency_tool` | Upstream parent scanner failed or skipped | Required parent scanner (e.g. Nmap) did not produce required observations | Re-run parent scanner or remove strict dependency from scan policy profile. |
| **SMP-2009** | `resource_limit_exceeded` | Process CPU/Memory concurrency limit reached | Concurrency ceiling exceeded during heavy multi-scanner Phase 2 | Reduce `max_concurrency` in scan policy or increase system worker limits. |
| **SMP-2010** | `adapter_manifest_invalid` | Scanner adapter manifest validation failed | Manifest missing required fields (id, category, parser, timeout) | Validate adapter manifest against `core/scanner_manifest.py` schema. |

---

## 3xxx — Database, SQLCipher & Storage Pipeline

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-3000** | `db_error` | Generic database error | Low-level SQLite/SQLCipher driver failure | Inspect `logs/smp.log` for SQL query and parameter traceback. |
| **SMP-3001** | `db_connection_error` | Cannot connect to database | `pysqlcipher3` missing, permission denied on database file, or lock contention | Run `sudo apt install libsqlcipher-dev && pip install pysqlcipher3`. |
| **SMP-3002** | `db_encryption_error` | SQLCipher database decryption failed | Incorrect passphrase supplied to `PRAGMA key` | Verify master password or restore encrypted backup snapshot. |
| **SMP-3003** | `db_wal_locked` | SQLite Write-Ahead Log (WAL) deadlock | Stale lock from crashed or ungracefully killed scan process | Run `python3 tools/troubleshoot.py --fix` to execute `PRAGMA wal_checkpoint(TRUNCATE)`. |
| **SMP-3004** | `db_integrity_check_failed` | PRAGMA integrity_check failed | File corruption from sudden power loss or process kill | Restore from automated snapshot in `database/backups/`. |
| **SMP-3005** | `db_migration_error` | Schema migration failed | Incompatible schema version upgrade | Run `python3 tools/db_manager.py --migrate` or inspect `database/schema/`. |
| **SMP-3006** | `raw_output_storage_failed` | Gzip compression / Fernet encryption failed | Disk full or missing active encryption key | Free disk space (`df -h`) and confirm encryption keys are initialized. |
| **SMP-3007** | `redundancy_db_failed` | Redundancy secondary database error | SQLite fallback in-memory or secondary file failure | Clear secondary lock or recreate `database/redundancy.db`. |

---

## 4xxx — Evidence Store, Reporting & Authenticity Verification

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-4000** | `validation_error` | Generic request validation error | Request body or argument failed type constraint | Review endpoint schema documentation at `/api/v6/docs`. |
| **SMP-4001** | `invalid_target` | Invalid target IP, URL, or domain | URL missing scheme (e.g. missing `http://`), or invalid IPv4/IPv6 address | Ensure target is well-formed (e.g. `https://example.com` or `192.168.1.1/24`). |
| **SMP-4002** | `invalid_payload` | Malformed API request payload | Non-JSON body or missing required fields | Verify JSON structure and mandatory parameter keys. |
| **SMP-4010** | `evidence_storage_error` | AES-256-GCM evidence encryption error | Disk write failure or EEK missing during evidence capture | Verify `data/evidence` directory write permissions and ensure EEK is in memory. |
| **SMP-4011** | `evidence_not_found` | Evidence record UUID not found | Evidence was pruned or invalid UUID requested | Verify evidence ID exists in `core/evidence.py` index for the engagement. |
| **SMP-4012** | `evidence_tamper_detected` | Evidence SHA-256 checksum mismatch | Raw encrypted evidence file modified externally | Treat as security incident: file integrity compromise detected. Check audit logs. |
| **SMP-4020** | `report_generation_error` | Report generator failed to compile report | Missing findings data, template render error, or write permission denied | Run `python3 tools/generate_demo_report.py` to verify report generator engine. |
| **SMP-4021** | `report_authenticity_failed` | Canonical SHA-256 authenticity hash mismatch | Report JSON was altered after initial cryptographic signing | Run `python3 tools/verify_report.py <report.json>` to inspect mismatch details. |
| **SMP-4022** | `weasyprint_render_error` | Headless PDF rendering failure | `weasyprint` or system fonts (Pango, Cairo, Liberation) missing | Run `sudo apt install fonts-liberation libpango-1.0-0 libcairo2`. |
| **SMP-4040** | `exploit_timeout` | Interactive shell or exploit stalled | `msfconsole`, `impacket`, or `sqlmap` waiting for user input | Set non-interactive flags or decrease timeout in scanner configuration. |
| **SMP-4041** | `binary_incompatibility` | Native binary architecture mismatch | x86_64 binary executed on ARM64 / Apple Silicon system | Compile binary natively using `setup.sh` or run inside Docker container. |
| **SMP-4042** | `port_collision` | Local privileged port conflict | Tool (e.g. `Responder`) attempted binding to occupied port (UDP 53) | Stop conflicting service (`sudo systemctl stop systemd-resolved dnsmasq`). |

---

## 5xxx — Threat Intelligence, CVE Correlation & Deduplication

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-5000** | `config_error` | Generic configuration error | Malformed JSON in `config/settings.json` | Validate JSON syntax in `config/settings.json` with `jq . config/settings.json`. |
| **SMP-5001** | `config_missing` | Required configuration file missing | Missing `config/settings.json` or `config/metadata.json` | Run `python3 tools/troubleshoot.py --fix` to restore defaults from template. |
| **SMP-5002** | `intel_sync_error` | CISA KEV / NVD / EPSS feed sync error | Outbound network failure, proxy block, or remote API rate limiting | Check network connectivity, verify proxy settings, or enable `SMP_LOCAL_ONLY=1`. |
| **SMP-5003** | `vulnerability_db_missing` | Offline vulnerability intelligence database missing | `database/global_intel.db` not found or uninitialized | Run `python3 intelligence/nvd.py --init` or restore `global_intel.db`. |
| **SMP-5004** | `cpe_parsing_error` | CPE 2.3 URI string malformed | Non-standard CPE format emitted by scanner | Check CPE normalization logic in `intelligence/matching.py`. |
| **SMP-5005** | `deduplication_engine_error` | Finding deduplication fingerprint collision | Hash calculation failure on observation attributes | Verify SHA-256 components in `core/finding_engine.py`. |
| **SMP-5006** | `mitre_mapping_error` | MITRE ATT&CK taxonomy lookup failed | Unknown CWE ID or corrupted MITRE mapping table | Check `intelligence/mitre_mapper.py` for missing technique mappings. |
| **SMP-5007** | `local_only_violation` | Network call attempted while `SMP_LOCAL_ONLY=1` | Component attempted external DNS/HTTP request in air-gapped mode | Disable external sync or unset `SMP_LOCAL_ONLY` if internet access is intended. |

---

## 6xxx — Scope Engine & Scan Policy

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-6000** | `scope_violation` | Target out of authorized engagement scope | Target IP/domain not matched by allow rules (default deny) | Add target to scope rules in Engagement settings or check CIDR boundary. |
| **SMP-6001** | `scope_rule_syntax_error` | Invalid scope rule format | Malformed CIDR subnet, invalid wildcard, or broken regex pattern | Correct rule syntax (e.g. `192.168.1.0/24`, `*.example.com`, `^https://.*`). |
| **SMP-6002** | `scan_policy_restricted` | Scanner disallowed by scan policy | Scanner is on denylist or not in allowlist for the engagement | Update `scanner_allowlist` in scan policy configuration. |
| **SMP-6003** | `rate_limit_exceeded` | Request rate ceiling reached | Exceeded requests-per-second limit configured in scan policy | Increase `requests_per_second` in scan policy or configure slower scanner delay. |
| **SMP-6004** | `intrusive_scan_denied` | Intrusive scanner attempted on passive profile | Active/Intrusive scanner queued during `osint` / `passive` scan | Change scan profile to `standard` or `full` to enable active testing. |
| **SMP-6005** | `time_window_closed` | Scan triggered outside allowed hours | Current time outside authorized schedule in Scan Policy | Adjust `time_windows` in scan policy or wait for authorized testing window. |
| **SMP-6006** | `responsibility_attestation_missing` | Operator authorization attestation missing | Active scan initiated without signed operator responsibility checkbox | Check the authorization attestation box in GUI or pass `attestation=true` in API. |

---

## 9xxx — Installation, Bootstrap & System Failures

| Code | Slug | Description | Root Cause | Remediation Action |
|---|---|---|---|---|
| **SMP-9000** | `unclassified_error` | Base unclassified internal exception | Uncaught exception in core engine | Check `logs/smp.log` for full Python traceback. |
| **SMP-9001** | `network_route_unreachable` | Pre-flight network route / mirror unreachable | Outbound HTTPS blocked by firewall/proxy or DNS failure | Check internet connectivity, configure `https_proxy`, or use `./setup.sh --skip-tools`. |
| **SMP-9002** | `pkg_manager_lock_contention` | Package manager (dpkg/apt/dnf) lock held | Background updater / unattended-upgrades holding lock | Wait for background updater or run `sudo killall apt apt-get dpkg && sudo dpkg --configure -a`. |
| **SMP-9003** | `tool_bootstrap_failure` | Security binary bootstrap / extraction failed | Corrupt download, network interruption, or disk full | Run `python3 tools/troubleshoot.py --fix` or manually place binary in `./bin/`. |
| **SMP-9004** | `preflight_check_failure` | Pre-flight environment preconditions unmet | Unsupported architecture or non-root permissions | Ensure required build dependencies are installed and user has sudo access. |
| **SMP-9005** | `python_env_bootstrap_failure` | Python venv or dependency installation failed | Missing `python3-venv`/`python3-dev` or pip error | Run `sudo apt install python3-dev python3-venv build-essential` and rerun `./setup.sh`. |
| **SMP-9999** | `unexpected_error` | Fatal system runtime crash | Kernel signal, unhandled exception, or unexpected environment fault | Run `python3 tools/troubleshoot.py --fix` and review `logs/key_audit.log`. |

---

## Automated Error Resolution

To automatically diagnose and heal any error:

```bash
# Run comprehensive diagnostic scan
python3 tools/troubleshoot.py

# Automatically fix all repairable issues (DB locks, missing binaries, directory trees)
python3 tools/troubleshoot.py --fix

# Look up specific error code resolution
python3 tools/troubleshoot.py --lookup SMP-3003
```
