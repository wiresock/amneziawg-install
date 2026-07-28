-- Track newly-created peers until they have been observed on the live AWG
-- interface. This lets stale-peer cleanup preserve only creation attempts that
-- still need reconciliation, without retaining ordinary config-linked peers.
ALTER TABLE peers
    ADD COLUMN sync_pending INTEGER NOT NULL DEFAULT 0
    CHECK (sync_pending IN (0, 1));
