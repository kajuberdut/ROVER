-- Migration 0011: Email Verification, Password Hash & User Roles
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR;
ALTER TABLE notification_destinations ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;
