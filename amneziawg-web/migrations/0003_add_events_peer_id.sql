-- Add a typed peer_id integer FK to the events table so that
-- events can be efficiently filtered by the integer peer id returned
-- by the API, in addition to the existing target_key (public key) lookup.
ALTER TABLE events ADD COLUMN peer_id INTEGER REFERENCES peers(id);

CREATE INDEX IF NOT EXISTS idx_events_peer_id ON events (peer_id);
