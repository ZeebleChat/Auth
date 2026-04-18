CREATE TABLE IF NOT EXISTS password_reset_verifications (
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT    NOT NULL,
    pin_hash   TEXT    NOT NULL,
    expires_at BIGINT  NOT NULL,
    created_at BIGINT  NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE INDEX IF NOT EXISTS idx_password_reset_email ON password_reset_verifications(email);
