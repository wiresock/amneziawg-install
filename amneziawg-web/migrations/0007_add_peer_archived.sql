-- Keep disabled peer tombstones after their panel metadata and traffic history
-- have been cleared. Archived peers remain available to the disabled-key
-- enforcement path but are hidden from normal peer listings.
ALTER TABLE peers
    ADD COLUMN archived INTEGER NOT NULL DEFAULT 0
    CHECK (archived IN (0, 1));

CREATE INDEX IF NOT EXISTS idx_peers_archived ON peers (archived);
