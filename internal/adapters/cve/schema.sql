-- CVE Database Schema for SQLite
-- Stores Common Vulnerabilities and Exposures records for WiFi/networking devices

CREATE TABLE IF NOT EXISTS cve_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    
    -- Matching Fields
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version_start TEXT,
    version_end TEXT,
    version_exact TEXT,
    
    -- Metadata
    description TEXT,
    severity REAL DEFAULT 0.0,  -- CVSS Score 0-10
    cvss_vector TEXT,
    published_date TEXT,
    last_modified TEXT,
    
    -- Classification
    cwe_id TEXT,
    attack_vector TEXT,  -- NETWORK, ADJACENT, LOCAL, PHYSICAL
    
    -- References (JSON array) - quoted because 'references' is a SQL keyword
    refs TEXT,
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_vendor_product ON cve_records(vendor, product);
CREATE INDEX IF NOT EXISTS idx_severity ON cve_records(severity DESC);
CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_records(cve_id);

-- Keywords table for fuzzy matching
CREATE TABLE IF NOT EXISTS cve_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    keyword TEXT NOT NULL,
    
    FOREIGN KEY (cve_id) REFERENCES cve_records(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_keyword ON cve_keywords(keyword);

-- Sync status tracking
CREATE TABLE IF NOT EXISTS cve_sync_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton table
    last_sync_time DATETIME,
    record_count INTEGER DEFAULT 0,
    error_message TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial sync status
INSERT OR IGNORE INTO cve_sync_status (id, last_sync_time, record_count) 
VALUES (1, '1970-01-01 00:00:00', 0);
