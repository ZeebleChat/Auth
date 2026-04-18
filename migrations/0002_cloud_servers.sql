-- Add cloud server support to zbeam's server registry.
-- server_type:     'self_hosted' (default) or 'cloud'
-- cloud_server_id: the UUID assigned by zcloud when a cloud server is created

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS server_type TEXT NOT NULL DEFAULT 'self_hosted';

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS cloud_server_id TEXT;

COMMENT ON COLUMN server_registry.server_type IS
    'self_hosted = user-run PhaseLink instance; cloud = managed zcloud instance';

COMMENT ON COLUMN server_registry.cloud_server_id IS
    'UUID of the corresponding cloud_servers record in zcloud (NULL for self-hosted)';
