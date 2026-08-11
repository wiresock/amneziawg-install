-- Optional UTC expiration plus a stable lifecycle identity for managed client
-- configurations. Existing rows receive NULL and therefore remain permanent.
ALTER TABLE peers ADD COLUMN expires_at TEXT;
ALTER TABLE peers ADD COLUMN managed_client_name TEXT;

CREATE INDEX IF NOT EXISTS idx_peers_expires_at ON peers (expires_at);
