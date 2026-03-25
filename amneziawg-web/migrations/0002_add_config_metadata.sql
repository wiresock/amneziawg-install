-- Add config-discovery metadata columns to the peers table.
-- config_name: stem of the matching *.conf filename (no extension), e.g. "ivan-iphone"
-- config_path: absolute path to the *.conf file on disk
ALTER TABLE peers ADD COLUMN config_name TEXT;
ALTER TABLE peers ADD COLUMN config_path TEXT;
