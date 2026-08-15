-- Users table (single admin for now, extensible for multi-user)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,  -- Argon2id
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL,
    last_login TEXT,
    enabled INTEGER DEFAULT 1
);

-- Engagements table (project/grouping)
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    start_date TEXT NOT NULL,
    end_date TEXT,
    status TEXT NOT NULL DEFAULT 'active',  -- active, completed, archived
    created_by INTEGER NOT NULL,  -- user_id
    created_at TEXT NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Scope rules (authorization boundaries)
CREATE TABLE IF NOT EXISTS scope_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,  -- domain, subdomain, ip, cidr, url, port
    rule_value TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'allow',  -- allow, deny
    priority INTEGER DEFAULT 100,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

-- Targets table
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    target TEXT NOT NULL,  -- URL, IP, domain
    target_type TEXT NOT NULL,  -- url, ip, domain, cidr
    status TEXT NOT NULL DEFAULT 'enabled',
    added_date TEXT NOT NULL,
    last_scan TEXT,
    notes TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,  -- standard, osint, full, custom
    profile TEXT NOT NULL,     -- scanner profile configuration
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL,  -- using new state machine
    scanned_by INTEGER NOT NULL,  -- user_id
    report_hash TEXT,
    scanner_count INTEGER DEFAULT 0,
    completed_scanners INTEGER DEFAULT 0,
    failed_scanners INTEGER DEFAULT 0,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (scanned_by) REFERENCES users(id)
);

-- Assets table (from Nmap service discovery)
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    engagement_id INTEGER NOT NULL,
    asset_type TEXT NOT NULL,  -- host, ip, domain, subdomain
    asset_value TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    discovered_at TEXT NOT NULL,
    source_scanner TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

-- Services table (from Nmap)
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,  -- tcp, udp
    state TEXT NOT NULL,    -- open, closed, filtered
    service_name TEXT,
    product TEXT,
    version TEXT,
    banner TEXT,
    confidence REAL DEFAULT 0.95,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Observations table (THE CORE DATA CONTRACT)
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT UNIQUE NOT NULL,  -- UUID
    scan_id INTEGER NOT NULL,
    asset_id INTEGER,
    service_id INTEGER,
    scanner_id TEXT NOT NULL,
    scanner_version TEXT,
    observation_type TEXT NOT NULL,  -- asset, port, service, technology, vulnerability_candidate, etc.
    title TEXT NOT NULL,
    raw_value TEXT,                  -- JSON string of raw data
    normalized_value TEXT,           -- JSON string of normalized data
    confidence REAL DEFAULT 0.5,
    observed_at TEXT NOT NULL,
    raw_output_hash TEXT,
    parser_version TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

-- Findings table (correlated security statements)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT UNIQUE NOT NULL,  -- UUID
    engagement_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    vulnerability_class TEXT,
    cwe_id TEXT,
    cve_id TEXT,
    asset_id INTEGER,
    service_id INTEGER,
    endpoint TEXT,
    parameter TEXT,
    severity TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    status TEXT NOT NULL DEFAULT 'open',  -- open, in_progress, resolved, risk_accepted, false_positive
    risk_score REAL,
    remediation TEXT,
    validation TEXT,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    provenance TEXT,  -- JSON string of source information
    FOREIGN KEY (engagement_id) REFERENCES engagements(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

-- Finding evidence mapping
CREATE TABLE IF NOT EXISTS finding_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    correlation_strength REAL DEFAULT 1.0,
    mapped_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (observation_id) REFERENCES observations(observation_id)
);

-- Scanner execution status (new state machine)
CREATE TABLE IF NOT EXISTS scan_scanner_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    scanner_name TEXT NOT NULL,
    status TEXT NOT NULL,  -- NOT_STARTED, BLOCKED, DEPENDENCY_MISSING, STARTED, RUNNING, COMPLETED, COMPLETED_WITH_FINDINGS, COMPLETED_NO_FINDINGS, FAILED, TIMEOUT, CANCELLED, PARSE_FAILED, PARTIAL, SKIPPED
    start_time TEXT,
    end_time TEXT,
    exit_code INTEGER,
    timeout_reason TEXT,
    retry_count INTEGER DEFAULT 0,
    binary_version TEXT,
    command_hash TEXT,
    raw_output_path TEXT,
    error_message TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Audit log for security-sensitive transitions
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    old_value TEXT,
    new_value TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
