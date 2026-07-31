-- 0010_user_invites.sql — User Invitation Tokens and Tracking Schema

CREATE TABLE IF NOT EXISTS user_invites (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    token VARCHAR(128) NOT NULL UNIQUE,
    invited_by_sub VARCHAR(255) NULL REFERENCES users(sub) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMP WITH TIME ZONE NULL,
    accepted_by_sub VARCHAR(255) NULL REFERENCES users(sub) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_user_invites_token ON user_invites(token);
CREATE INDEX IF NOT EXISTS idx_user_invites_status ON user_invites(status);
