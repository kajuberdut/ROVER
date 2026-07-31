-- Migration 0008: Notifications System (Destinations, Rules, Recipients, and Audit Logs)

CREATE TABLE IF NOT EXISTS notification_destinations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    scope VARCHAR(50) NOT NULL,
    user_sub VARCHAR(255) REFERENCES users(sub) ON DELETE CASCADE,
    product_id VARCHAR(36) REFERENCES products(id) ON DELETE CASCADE,
    is_system BOOLEAN NOT NULL DEFAULT false,
    is_default BOOLEAN NOT NULL DEFAULT false,
    config_json TEXT NOT NULL DEFAULT '{}',
    vault_secret_path VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_destinations_scope 
ON notification_destinations (scope, product_id, user_sub);

CREATE TABLE IF NOT EXISTS notification_rules (
    id VARCHAR(36) PRIMARY KEY,
    destination_id VARCHAR(36) NOT NULL REFERENCES notification_destinations(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    min_severity VARCHAR(50) NOT NULL DEFAULT 'ALL',
    eol_warning_days INTEGER DEFAULT NULL,
    scope VARCHAR(50) NOT NULL,
    user_sub VARCHAR(255) REFERENCES users(sub) ON DELETE CASCADE,
    product_id VARCHAR(36) REFERENCES products(id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_rules_dest ON notification_rules (destination_id);
CREATE INDEX IF NOT EXISTS idx_notification_rules_event_scope ON notification_rules (event_type, scope, is_enabled);

CREATE TABLE IF NOT EXISTS notification_rule_recipients (
    id VARCHAR(36) PRIMARY KEY,
    rule_id VARCHAR(36) NOT NULL REFERENCES notification_rules(id) ON DELETE CASCADE,
    recipient_type VARCHAR(20) NOT NULL DEFAULT 'user',
    user_sub VARCHAR(255) REFERENCES users(sub) ON DELETE CASCADE,
    email VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rule_recipients_rule_id ON notification_rule_recipients (rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_recipients_user_sub ON notification_rule_recipients (user_sub);

CREATE TABLE IF NOT EXISTS notification_logs (
    id VARCHAR(36) PRIMARY KEY,
    rule_id VARCHAR(36) REFERENCES notification_rules(id) ON DELETE SET NULL,
    destination_id VARCHAR(36) REFERENCES notification_destinations(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    http_status_code INTEGER DEFAULT NULL,
    error_message TEXT DEFAULT NULL,
    payload_json TEXT DEFAULT NULL,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_logs_destination ON notification_logs (destination_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_logs_rule ON notification_logs (rule_id, created_at DESC);
