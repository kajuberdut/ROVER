-- Migration 0004: Add snyk_jobs table for Snyk OSS & SAST scan queue and caching
CREATE TABLE IF NOT EXISTS snyk_jobs (
    id VARCHAR PRIMARY KEY,
    target_url VARCHAR NOT NULL,
    git_ref VARCHAR DEFAULT NULL,
    resolved_commit VARCHAR DEFAULT NULL,
    status VARCHAR NOT NULL,
    results_json VARCHAR DEFAULT NULL,
    resolved_tags VARCHAR DEFAULT NULL,
    error_message VARCHAR DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_snyk_jobs_status ON snyk_jobs(status);
CREATE INDEX IF NOT EXISTS idx_snyk_jobs_commit ON snyk_jobs(resolved_commit);
