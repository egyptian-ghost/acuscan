"""SQLite schema for AcuScan v6.5."""

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ═══════════════════════════════════════════════════════════════════════
--  Scans
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uuid TEXT UNIQUE NOT NULL,
    targets TEXT NOT NULL,
    config TEXT,
    status TEXT NOT NULL,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    duration_seconds REAL,
    request_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    verified_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════════
--  Findings
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT,
    detail TEXT,
    evidence TEXT,
    confidence REAL,
    cve TEXT,
    cwe TEXT,
    cvss REAL,
    cvss_vector TEXT,
    category TEXT,
    check_name TEXT,
    payload TEXT,
    verification_methods TEXT,
    verification_steps TEXT,
    all_evidence TEXT,
    extracted_info TEXT,
    request_raw TEXT,
    response_raw TEXT,
    remediation TEXT,
    verified INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    type TEXT,
    data TEXT,
    payload TEXT,
    request TEXT,
    response TEXT,
    confidence REAL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

-- ═══════════════════════════════════════════════════════════════════════
--  Schedules
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    cron_expression TEXT,
    targets TEXT NOT NULL,
    config TEXT,
    enabled INTEGER DEFAULT 1,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════════
--  Users
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════════
--  NEW: Crawl Map (v6.5)
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_crawl_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status INTEGER DEFAULT 0,
    content_type TEXT,
    content_length INTEGER DEFAULT 0,
    depth INTEGER DEFAULT 0,
    parent_url TEXT,
    title TEXT,
    parameters TEXT,
    forms TEXT,
    links_found INTEGER DEFAULT 0,
    response_time_ms REAL DEFAULT 0,
    is_external INTEGER DEFAULT 0,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ═══════════════════════════════════════════════════════════════════════
--  NEW: Server Info (v6.5)
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_server_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE,
    url TEXT,
    host TEXT,
    ip_addresses TEXT,
    server TEXT,
    powered_by TEXT,
    aspnet_version TEXT,
    operating_system TEXT,
    hosting_provider TEXT,
    cdn TEXT,
    reverse_proxy TEXT,
    port INTEGER DEFAULT 0,
    protocol TEXT,
    response_time_ms REAL DEFAULT 0,
    headers TEXT,
    security_headers TEXT,
    ssl_enabled INTEGER DEFAULT 0,
    ssl_issuer TEXT,
    ssl_subject TEXT,
    ssl_expires TEXT,
    ssl_protocol TEXT,
    ssl_cipher TEXT,
    technologies TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ═══════════════════════════════════════════════════════════════════════
--  NEW: Login Test Results (v6.5)
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_login_test (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE,
    success INTEGER DEFAULT 0,
    confidence REAL DEFAULT 0,
    reason TEXT,
    request_url TEXT,
    request_method TEXT,
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER DEFAULT 0,
    response_headers TEXT,
    response_body_snippet TEXT,
    cookies_before TEXT,
    cookies_after TEXT,
    cookies_added TEXT,
    redirect_chain TEXT,
    errors TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS active_scan_targets (
    target TEXT PRIMARY KEY,
    scan_uuid TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_active_targets_created 
ON active_scan_targets(created_at);
-- ═══════════════════════════════════════════════════════════════════════
--  Indexes
-- ═══════════════════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_crawl_map_scan ON scan_crawl_map(scan_id);
CREATE INDEX IF NOT EXISTS idx_crawl_map_url ON scan_crawl_map(url);
CREATE INDEX IF NOT EXISTS idx_server_info_scan ON scan_server_info(scan_id);
CREATE INDEX IF NOT EXISTS idx_login_test_scan ON scan_login_test(scan_id);
"""