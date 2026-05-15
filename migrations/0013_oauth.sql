ALTER TABLE users ADD COLUMN IF NOT EXISTS steam_id TEXT UNIQUE;

CREATE TABLE IF NOT EXISTS oauth_states (
    state         TEXT PRIMARY KEY,
    provider      TEXT    NOT NULL,
    mode          TEXT    NOT NULL,  -- 'link' | 'login'
    uid           TEXT,              -- set for link mode; filled after login callback
    session_token TEXT,              -- access token once ready; 'linked' for link mode
    refresh_token TEXT,
    beam_identity TEXT,
    error         TEXT,
    expires_at    BIGINT  NOT NULL,
    created_at    BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_states_expires ON oauth_states (expires_at);
