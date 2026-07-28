-- Migration 0005: Unified scanner_jobs table for all scanner plugins

CREATE TABLE IF NOT EXISTS scanner_jobs (
    id VARCHAR PRIMARY KEY,
    scanner_name VARCHAR NOT NULL, -- e.g. 'trivy', 'semgrep', 'snyk', 'helm'
    asset_id VARCHAR,
    target_url VARCHAR NOT NULL,
    target_type VARCHAR NOT NULL DEFAULT 'repo',
    git_ref VARCHAR,
    product_id VARCHAR,
    credential_id VARCHAR,
    status VARCHAR NOT NULL DEFAULT 'queued',
    results_json TEXT,
    error_message TEXT,
    resolved_commit VARCHAR,
    resolved_tags VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scanner_jobs_status ON scanner_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_scanner_jobs_commit ON scanner_jobs(scanner_name, resolved_commit);
CREATE INDEX IF NOT EXISTS idx_scanner_jobs_asset ON scanner_jobs(asset_id, created_at DESC);
