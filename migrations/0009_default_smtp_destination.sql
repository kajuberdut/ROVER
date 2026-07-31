-- Migration 0009: Add is_default column to notification_destinations

ALTER TABLE notification_destinations ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;
