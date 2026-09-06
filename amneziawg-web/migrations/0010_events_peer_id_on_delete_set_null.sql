-- Rebuild events table to add ON DELETE SET NULL to peer_id foreign key.
-- This ensures deleting a peer row automatically nulls events.peer_id,
-- preventing FOREIGN KEY constraint failures while preserving full audit history.

CREATE TABLE events_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT    NOT NULL DEFAULT 'system',
    action      TEXT    NOT NULL,
    target_key  TEXT,
    detail      TEXT,
    created_at  TEXT    NOT NULL DEFAULT (DATETIME('now')),
    peer_id     INTEGER REFERENCES peers(id) ON DELETE SET NULL
);

INSERT INTO events_new (id, actor, action, target_key, detail, created_at, peer_id)
SELECT id, actor, action, target_key, detail, created_at, peer_id FROM events;

DROP TABLE events;

ALTER TABLE events_new RENAME TO events;

CREATE INDEX IF NOT EXISTS idx_events_target_key ON events (target_key);
CREATE INDEX IF NOT EXISTS idx_events_peer_id ON events (peer_id);
