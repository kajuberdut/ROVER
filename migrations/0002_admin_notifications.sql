-- Migration 0002: Add admin_notifications table for system update alerts and admin notifications queue
CREATE TABLE IF NOT EXISTS admin_notifications (
    id VARCHAR PRIMARY KEY,
    title VARCHAR NOT NULL,
    message VARCHAR NOT NULL,
    category VARCHAR NOT NULL DEFAULT 'scanner_update',
    source_tool VARCHAR NOT NULL,
    metadata_json VARCHAR DEFAULT '{}',
    is_dismissed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dismissed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_admin_notif_dismissed ON admin_notifications(is_dismissed);
