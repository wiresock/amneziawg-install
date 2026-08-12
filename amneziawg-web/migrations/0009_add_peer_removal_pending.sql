-- Durable retry state for a managed-user removal that may already have
-- changed the server config, live interface, or client config. Stale cleanup
-- must not discard the row until the lifecycle path completes successfully.
ALTER TABLE peers
    ADD COLUMN removal_pending INTEGER NOT NULL DEFAULT 0
    CHECK (removal_pending IN (0, 1));
