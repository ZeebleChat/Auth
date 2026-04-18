-- Users table (no avatar FK yet — added after attachments is created)
CREATE TABLE IF NOT EXISTS users (
    id                   TEXT PRIMARY KEY,
    display_name         TEXT NOT NULL,
    beam_tag             TEXT NOT NULL,
    account_type         TEXT NOT NULL DEFAULT 'primary',
    parent_id            TEXT REFERENCES users(id),
    password_hash        TEXT,
    totp_secret          TEXT,
    totp_backup_codes    TEXT,
    passkey_credential   TEXT,
    auth_methods         BIGINT,
    refresh_token_hash   TEXT,
    bot_token_version    BIGINT,
    locked               BOOLEAN NOT NULL DEFAULT FALSE,
    discord_id           TEXT UNIQUE,
    email_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    premium              BOOLEAN NOT NULL DEFAULT FALSE,
    verified             BOOLEAN NOT NULL DEFAULT FALSE,
    alt_count            BIGINT NOT NULL DEFAULT 0,
    bot_count            BIGINT NOT NULL DEFAULT 0,
    child_count          BIGINT NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (NOW()::TEXT),
    avatar_attachment_id BIGINT,
    UNIQUE(display_name, beam_tag)
);

CREATE INDEX IF NOT EXISTS idx_discord_id   ON users(discord_id);
CREATE INDEX IF NOT EXISTS idx_parent_id    ON users(parent_id);
CREATE INDEX IF NOT EXISTS idx_display_name ON users(display_name);

CREATE TABLE IF NOT EXISTS user_servers (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_url  TEXT NOT NULL,
    server_name TEXT,
    is_owner    BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at   TEXT NOT NULL DEFAULT (NOW()::TEXT),
    PRIMARY KEY (user_id, server_url)
);
CREATE INDEX IF NOT EXISTS idx_user_servers_user ON user_servers(user_id);

CREATE TABLE IF NOT EXISTS server_registry (
    server_url          TEXT PRIMARY KEY,
    owner_beam_identity TEXT NOT NULL,
    jwt_secret          TEXT
);

-- DM messages (sender_id/recipient_id reference users but are nullable)
CREATE TABLE IF NOT EXISTS dm_messages (
    id             BIGSERIAL PRIMARY KEY,
    sender_beam    TEXT NOT NULL,
    recipient_beam TEXT NOT NULL,
    sender_id      TEXT,
    recipient_id   TEXT,
    content        TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (NOW()::TEXT)
);
CREATE INDEX IF NOT EXISTS idx_dm_recipient_created    ON dm_messages(recipient_beam, created_at);
CREATE INDEX IF NOT EXISTS idx_dm_conversation         ON dm_messages(sender_beam, recipient_beam);
CREATE INDEX IF NOT EXISTS idx_dm_sender_recipient     ON dm_messages(sender_id, recipient_id);
CREATE INDEX IF NOT EXISTS idx_dm_recipient_created_id ON dm_messages(recipient_id, created_at);

CREATE TABLE IF NOT EXISTS attachments (
    id            BIGSERIAL PRIMARY KEY,
    message_id    BIGINT,
    dm_message_id BIGINT REFERENCES dm_messages(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    mime_type     TEXT NOT NULL,
    file_size     BIGINT NOT NULL,
    file_data     BYTEA NOT NULL,
    uploaded_by   TEXT NOT NULL DEFAULT '',
    uploaded_at   TEXT NOT NULL DEFAULT (NOW()::TEXT),
    CHECK (
        (message_id IS NOT NULL AND dm_message_id IS NULL) OR
        (message_id IS NULL AND dm_message_id IS NOT NULL) OR
        (message_id IS NULL AND dm_message_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_attachments_dm ON attachments(dm_message_id);

-- Add avatar FK now that attachments exists
ALTER TABLE users
    ADD CONSTRAINT fk_users_avatar
    FOREIGN KEY (avatar_attachment_id) REFERENCES attachments(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS friendships (
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TEXT NOT NULL DEFAULT (NOW()::TEXT),
    PRIMARY KEY (user_id, friend_user_id)
);
CREATE INDEX IF NOT EXISTS idx_friendships_user   ON friendships(user_id);
CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_user_id);

CREATE TABLE IF NOT EXISTS sessions (
    token         TEXT PRIMARY KEY,
    uid           TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id),
    expires_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_uid     ON sessions(uid);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS channels (
    id    TEXT PRIMARY KEY,
    name  TEXT NOT NULL,
    topic TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id            BIGSERIAL PRIMARY KEY,
    channel_id    TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    beam_identity TEXT NOT NULL,
    content       TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (NOW()::TEXT),
    edited_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_channel    ON messages(channel_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);

CREATE TABLE IF NOT EXISTS promo_codes (
    code                  TEXT PRIMARY KEY,
    uses_max              BIGINT,
    uses_count            BIGINT NOT NULL DEFAULT 0,
    expires_at            BIGINT,
    created_by_server_url TEXT,
    created_at            BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);
CREATE INDEX IF NOT EXISTS idx_promo_expires ON promo_codes(expires_at);

CREATE TABLE IF NOT EXISTS user_promos (
    user_id     TEXT NOT NULL REFERENCES users(id),
    promo_code  TEXT NOT NULL REFERENCES promo_codes(code),
    redeemed_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    server_url  TEXT,
    PRIMARY KEY (user_id, promo_code)
);
CREATE INDEX IF NOT EXISTS idx_user_promos_user ON user_promos(user_id);
