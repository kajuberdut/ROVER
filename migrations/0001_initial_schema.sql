-- ROVER Complete Initial Database Schema
-- Standardized PostgreSQL Schema using JSONB for plugin-neutral flexibility

-- 1. Repositories Ledger
CREATE TABLE IF NOT EXISTS repositories (
    id VARCHAR(64) PRIMARY KEY,
    url VARCHAR(512) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Container Images Ledger
CREATE TABLE IF NOT EXISTS images (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(512) UNIQUE NOT NULL,
    image_hash VARCHAR(128) DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Major Software Components Ledger
CREATE TABLE IF NOT EXISTS major_components (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_major_components_name_version UNIQUE (name, version)
);

-- 4. End-of-Life (EOL) Cache Ledger
CREATE TABLE IF NOT EXISTS eol_cache (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    response_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    cached_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_eol_cache_name_version UNIQUE (name, version)
);

-- 5. Products Registry
CREATE TABLE IF NOT EXISTS products (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 6. Product Releases
CREATE TABLE IF NOT EXISTS releases (
    id VARCHAR(64) PRIMARY KEY,
    product_id VARCHAR(64) REFERENCES products(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    is_end_of_life BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_releases_name_version UNIQUE (name, version)
);

-- 7. Release Assets Mapping
CREATE TABLE IF NOT EXISTS release_assets (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    asset_type VARCHAR(50) NOT NULL, -- 'repo', 'image', 'major_component'
    asset_id VARCHAR(64) NOT NULL,
    git_ref VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rel_asset_unique
    ON release_assets (release_id, asset_type, asset_id, COALESCE(git_ref, ''));

-- 8. Unified Plugin-Neutral Scanner Execution Jobs
CREATE TABLE IF NOT EXISTS scanner_jobs (
    id VARCHAR(64) PRIMARY KEY,
    scanner_name VARCHAR(50) NOT NULL, -- 'trivy', 'semgrep', 'snyk', 'helm', etc.
    asset_id VARCHAR(64),
    target_url VARCHAR(1024) NOT NULL,
    target_type VARCHAR(50) NOT NULL DEFAULT 'repo',
    git_ref VARCHAR(255),
    product_id VARCHAR(64),
    credential_id VARCHAR(64),
    status VARCHAR(50) NOT NULL DEFAULT 'queued',
    results_json JSONB DEFAULT NULL, -- Flexible plugin-neutral JSONB payload
    error_message TEXT DEFAULT NULL,
    resolved_commit VARCHAR(128) DEFAULT NULL,
    resolved_tags TEXT DEFAULT NULL,
    started_at TIMESTAMPTZ DEFAULT NULL,
    finished_at TIMESTAMPTZ DEFAULT NULL,
    duration_seconds INTEGER DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scanner_jobs_status ON scanner_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_scanner_jobs_commit ON scanner_jobs(scanner_name, resolved_commit);
CREATE INDEX IF NOT EXISTS idx_scanner_jobs_asset ON scanner_jobs(asset_id, created_at DESC);

-- 9. User Accounts & OIDC Identity Registry
CREATE TABLE IF NOT EXISTS users (
    sub VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255),
    name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'viewer', -- 'system_admin', 'viewer', 'email_only'
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash TEXT DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ DEFAULT NULL
);

-- 10. Product-Level Access Control (RBAC)
CREATE TABLE IF NOT EXISTS product_users (
    user_sub VARCHAR(255) NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
    product_id VARCHAR(64) NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL, -- 'product_admin', 'viewer'
    PRIMARY KEY (user_sub, product_id)
);

-- 11. User API Tokens
CREATE TABLE IF NOT EXISTS api_tokens (
    id VARCHAR(64) PRIMARY KEY,
    user_sub VARCHAR(255) NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    permission VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ DEFAULT NULL
);

-- 12. CI Container Image Signatures & Build Metadata
CREATE TABLE IF NOT EXISTS ci_image_metadata (
    image_hash VARCHAR(128) PRIMARY KEY,
    repo_uri VARCHAR(1024) NOT NULL,
    commit_hash VARCHAR(128) NOT NULL,
    metadata_json JSONB DEFAULT '{}'::jsonb,
    image_tags JSONB DEFAULT '[]'::jsonb,
    ci_job_url VARCHAR(1024) DEFAULT NULL,
    created_by_user_sub VARCHAR(255) DEFAULT NULL,
    created_by_token_id VARCHAR(64) DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 13. Scheduled Recurring Scan Jobs
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    product_id VARCHAR(64) NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    release_id VARCHAR(64) REFERENCES releases(id) ON DELETE CASCADE,
    cron_expression VARCHAR(100) NOT NULL DEFAULT '0 2 * * *',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ DEFAULT NULL,
    next_run_at TIMESTAMPTZ DEFAULT NULL,
    last_status VARCHAR(50) DEFAULT 'idle',
    created_by_user_sub VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_product ON scheduled_scans(product_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run_at) WHERE enabled = true;

-- 14. Schedule Execution Audit Logs
CREATE TABLE IF NOT EXISTS schedule_execution_logs (
    id VARCHAR(64) PRIMARY KEY,
    schedule_id VARCHAR(64) NOT NULL REFERENCES scheduled_scans(id) ON DELETE CASCADE,
    triggered_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL,
    jobs_created_count INTEGER DEFAULT 0,
    details_json JSONB DEFAULT NULL,
    error_message TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_schedule_execution_logs_schedule ON schedule_execution_logs(schedule_id, triggered_at DESC);

-- 15. System Administration Notifications
CREATE TABLE IF NOT EXISTS admin_notifications (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    category VARCHAR(50) NOT NULL DEFAULT 'scanner_update',
    source_tool VARCHAR(100) NOT NULL,
    metadata_json JSONB DEFAULT '{}'::jsonb,
    is_dismissed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    dismissed_at TIMESTAMPTZ DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_notif_dismissed ON admin_notifications(is_dismissed);

-- 16. OpenBao Vault Credentials Metadata
CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'git_token', 'docker_registry', etc.
    scope VARCHAR(50) NOT NULL, -- 'system', 'product'
    product_id VARCHAR(64) REFERENCES products(id) ON DELETE CASCADE,
    description TEXT DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_scope_product_name 
ON credentials (scope, COALESCE(product_id, ''), name);

-- 17. Notification Channels & Destinations
CREATE TABLE IF NOT EXISTS notification_destinations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'webhook', 'slack', 'smtp', 'aws_ses'
    scope VARCHAR(50) NOT NULL, -- 'system', 'product', 'user'
    user_sub VARCHAR(255) REFERENCES users(sub) ON DELETE CASCADE,
    product_id VARCHAR(64) REFERENCES products(id) ON DELETE CASCADE,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    vault_secret_path VARCHAR(512) DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_destinations_scope 
ON notification_destinations (scope, product_id, user_sub);

-- 18. Notification Dispatch Rules
CREATE TABLE IF NOT EXISTS notification_rules (
    id VARCHAR(64) PRIMARY KEY,
    destination_id VARCHAR(64) NOT NULL REFERENCES notification_destinations(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    min_severity VARCHAR(50) NOT NULL DEFAULT 'ALL',
    eol_warning_days INTEGER DEFAULT NULL,
    scope VARCHAR(50) NOT NULL,
    user_sub VARCHAR(255) REFERENCES users(sub) ON DELETE CASCADE,
    product_id VARCHAR(64) REFERENCES products(id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_rules_dest ON notification_rules (destination_id);
CREATE INDEX IF NOT EXISTS idx_notification_rules_event_scope ON notification_rules (event_type, scope, is_enabled);

-- 19. Notification Rule Additional Recipients
CREATE TABLE IF NOT EXISTS notification_rule_recipients (
    id VARCHAR(64) PRIMARY KEY,
    rule_id VARCHAR(64) NOT NULL REFERENCES notification_rules(id) ON DELETE CASCADE,
    recipient_type VARCHAR(20) NOT NULL DEFAULT 'user',
    user_sub VARCHAR(255) REFERENCES users(sub) ON DELETE CASCADE,
    email VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rule_recipients_rule_id ON notification_rule_recipients (rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_recipients_user_sub ON notification_rule_recipients (user_sub);

-- 20. Notification Audit Logs
CREATE TABLE IF NOT EXISTS notification_logs (
    id VARCHAR(64) PRIMARY KEY,
    rule_id VARCHAR(64) REFERENCES notification_rules(id) ON DELETE SET NULL,
    destination_id VARCHAR(64) REFERENCES notification_destinations(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    http_status_code INTEGER DEFAULT NULL,
    error_message TEXT DEFAULT NULL,
    payload_json JSONB DEFAULT NULL,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_logs_destination ON notification_logs (destination_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_logs_rule ON notification_logs (rule_id, created_at DESC);

-- 21. User Invitation Tokens & Tracking
CREATE TABLE IF NOT EXISTS user_invites (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) DEFAULT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    token VARCHAR(128) NOT NULL UNIQUE,
    invited_by_sub VARCHAR(255) REFERENCES users(sub) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at TIMESTAMPTZ DEFAULT NULL,
    accepted_by_sub VARCHAR(255) REFERENCES users(sub) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_user_invites_token ON user_invites(token);
CREATE INDEX IF NOT EXISTS idx_user_invites_status ON user_invites(status);
