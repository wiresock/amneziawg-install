-- Add friendly_name column to the peers table.
-- friendly_name: human-readable name derived from the config filename.
-- For "awg0-client-gramm.conf", this would be "gramm".
ALTER TABLE peers ADD COLUMN friendly_name TEXT;
