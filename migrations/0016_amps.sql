-- Amps: Radiant (premium) subscribers receive 5 Amps to apply to self-hosted servers.
-- Applied Amps unlock server discovery listing and emoji pack uploads.

CREATE TABLE user_amps (
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amps_available  INTEGER NOT NULL DEFAULT 5 CHECK (amps_available >= 0),
    PRIMARY KEY (user_id)
);

CREATE TABLE server_amps (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_url  TEXT        NOT NULL,
    applied_at  BIGINT      NOT NULL,
    UNIQUE (user_id, server_url)
);

CREATE INDEX idx_server_amps_server_url ON server_amps (server_url);
