# Appendix B: Database Schemas and Data Dictionaries

To ensure localized data sovereignty and high-performance querying, the Security Management Platform (SMP) persists state across three discrete SQLite databases. This appendix documents the formal Data Definition Language (DDL) and schema architecture utilized in V9.4.0.

## B.1 The Encrypted Pentest Database (`security.db`)

This database contains all highly sensitive topological and vulnerability data collected during a VAPT engagement. It is encrypted at rest using SQLCipher (AES-256 in CBC mode) with a PBKDF2 HMAC-SHA256 derived key (600,000 iterations).

### `targets` Table
Stores the primary domain or IP scope parameters for an engagement.

```sql
CREATE TABLE targets (
    target_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scanned DATETIME,
    attestation_signed BOOLEAN DEFAULT 0,
    scan_profile TEXT DEFAULT 'standard'
);
```

### `findings` Table
The core relational table mapping vulnerability telemetry to the target scope.

```sql
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    tool TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    confidence INTEGER DEFAULT 50,
    cve_id TEXT,
    epss_score REAL,
    centrality_score REAL DEFAULT 0.0,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
```

### `system_secrets` Table
Stores the internally generated cryptographic keys (e.g., Fernet keys) required to decrypt the unstructured evidence blobs stored on the host filesystem.

```sql
CREATE TABLE system_secrets (
    secret_id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_name TEXT NOT NULL UNIQUE,
    key_value TEXT NOT NULL, -- The Base64 encoded Fernet Key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## B.2 The Public Intelligence Database (`global_intel.db`)

This database powers the "Neural Brain" heuristic engine. Because it contains exclusively public, mathematical models (and zero client-specific data), it is intentionally unencrypted to maximize concurrent `SELECT` query performance.

### `cve_cache` Table
A localized cache of the National Vulnerability Database (NVD) to prevent redundant outbound API calls and rate-limiting.

```sql
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    cvss_v3_score REAL,
    cvss_vector TEXT,
    description TEXT,
    published_date DATETIME,
    last_modified DATETIME
);
```

### `epss_metrics` Table
The Exploit Prediction Scoring System parameters, updated daily.

```sql
CREATE TABLE epss_metrics (
    cve_id TEXT PRIMARY KEY,
    epss_probability REAL NOT NULL, -- Range: 0.0 to 1.0
    percentile REAL,
    date_fetched DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `cisa_kev` Table
The US Cybersecurity and Infrastructure Security Agency's Known Exploited Vulnerabilities catalog.

```sql
CREATE TABLE cisa_kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATETIME,
    due_date DATETIME,
    known_ransomware_campaign_use TEXT
);
```

## B.3 The Operational Redundancy Database (`redundancy.db`)

Also encrypted via SQLCipher, this database acts as a localized transaction log to recover state in the event of a catastrophic system failure (e.g., power loss during a 6-hour scan).

### `dag_state` Table
Tracks the topological sorting queue and completion status of the current scan.

```sql
CREATE TABLE dag_state (
    scan_id INTEGER NOT NULL,
    node_name TEXT NOT NULL,
    in_degree INTEGER NOT NULL,
    status TEXT DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
    start_time DATETIME,
    end_time DATETIME,
    PRIMARY KEY (scan_id, node_name)
);
```

### `blob_pointers` Table
Maintains the mapping between relational `findings_id` and the encrypted Fernet flat-files residing in `reports/evidence/`.

```sql
CREATE TABLE blob_pointers (
    pointer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL, -- SHA-256 for integrity verification
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);
```
