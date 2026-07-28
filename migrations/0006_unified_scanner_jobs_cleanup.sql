-- Migration 0006: Clean up legacy scan tables and add duration tracking to scanner_jobs

-- 1. Migrate legacy scan_jobs to scanner_jobs if scanner_jobs is missing records
INSERT INTO scanner_jobs (id, scanner_name, target_url, target_type, git_ref, status, results_json, error_message, resolved_commit, resolved_tags, created_at, updated_at)
SELECT id, 'trivy', target_url, target_type, git_ref, status, results_json, error_message, resolved_commit, resolved_tags, created_at, updated_at
FROM scan_jobs
ON CONFLICT (id) DO NOTHING;

INSERT INTO scanner_jobs (id, scanner_name, target_url, target_type, git_ref, status, results_json, error_message, resolved_commit, resolved_tags, created_at, updated_at)
SELECT id, 'semgrep', target_url, 'repo', git_ref, status, results_json, error_message, resolved_commit, resolved_tags, created_at, updated_at
FROM semgrep_jobs
ON CONFLICT (id) DO NOTHING;

INSERT INTO scanner_jobs (id, scanner_name, target_url, target_type, git_ref, status, results_json, error_message, resolved_commit, resolved_tags, created_at, updated_at)
SELECT id, 'snyk', target_url, 'repo', git_ref, status, results_json, error_message, resolved_commit, resolved_tags, created_at, updated_at
FROM snyk_jobs
ON CONFLICT (id) DO NOTHING;

-- 2. Drop legacy tables
DROP TABLE IF EXISTS snyk_jobs;
DROP TABLE IF EXISTS semgrep_jobs;
DROP TABLE IF EXISTS scan_jobs;

-- 3. Add duration tracking columns to scanner_jobs
ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMP DEFAULT NULL;
ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP DEFAULT NULL;
ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS duration_seconds INTEGER DEFAULT NULL;
