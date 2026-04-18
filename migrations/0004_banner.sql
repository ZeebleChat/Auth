-- Migration 0004: Add profile banner support (premium feature)
ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_attachment_id BIGINT REFERENCES attachments(id);
