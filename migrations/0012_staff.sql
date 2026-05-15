-- Staff columns on users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_staff   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS staff_role TEXT;    -- e.g. 'admin', 'moderator', 'support'
ALTER TABLE users ADD COLUMN IF NOT EXISTS staff_note TEXT;    -- internal note about the staff member
ALTER TABLE users ADD COLUMN IF NOT EXISTS staff_added_at TEXT;

CREATE INDEX IF NOT EXISTS idx_users_is_staff ON users(is_staff) WHERE is_staff = TRUE;

-- Platform bans table (separate from per-server bans)
CREATE TABLE IF NOT EXISTS platform_bans (
    id          BIGSERIAL PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    reason      TEXT NOT NULL DEFAULT '',
    banned_by   TEXT NOT NULL,  -- beam_identity of staff who issued the ban (from JWT, never trusted from body)
    expires_at  BIGINT,         -- NULL = permanent
    created_at  TEXT NOT NULL DEFAULT (NOW()::TEXT)
);
CREATE INDEX IF NOT EXISTS idx_platform_bans_user ON platform_bans(user_id);

-- Platform broadcasts
CREATE TABLE IF NOT EXISTS platform_broadcasts (
    id          BIGSERIAL PRIMARY KEY,
    message     TEXT NOT NULL,
    sent_by     TEXT NOT NULL,  -- beam_identity from JWT
    sent_at     TEXT NOT NULL DEFAULT (NOW()::TEXT),
    target      TEXT NOT NULL DEFAULT 'all'  -- 'all' or specific audience
);
