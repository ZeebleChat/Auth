CREATE TABLE IF NOT EXISTS email_verifications (
    id         BIGSERIAL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT    NOT NULL,
    pin_hash   TEXT    NOT NULL,
    expires_at BIGINT  NOT NULL,
    created_at BIGINT  NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id);
