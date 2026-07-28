-- Migration 0007: Scheduled Scans & Execution Audit Logs

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    product_id VARCHAR(36) NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    release_id VARCHAR(36) REFERENCES releases(id) ON DELETE CASCADE,
    cron_expression VARCHAR(100) NOT NULL DEFAULT '0 2 * * *',
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    last_status VARCHAR(50) DEFAULT 'idle',
    created_by_user_sub VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_product ON scheduled_scans(product_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run_at) WHERE enabled = true;

CREATE TABLE IF NOT EXISTS schedule_execution_logs (
    id VARCHAR(36) PRIMARY KEY,
    schedule_id VARCHAR(36) NOT NULL REFERENCES scheduled_scans(id) ON DELETE CASCADE,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL,
    jobs_created_count INTEGER DEFAULT 0,
    details_json TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_schedule_execution_logs_schedule ON schedule_execution_logs(schedule_id, triggered_at DESC);
