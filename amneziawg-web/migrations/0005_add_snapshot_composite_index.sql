-- Add a composite index on (public_key, captured_at, id) to support
-- bulk usage queries that ORDER BY public_key, captured_at ASC, id ASC
-- and baseline lookups that PARTITION BY public_key ORDER BY captured_at DESC, id DESC.
-- Without this, those queries fall back to a full scan + sort on larger tables.

CREATE INDEX IF NOT EXISTS idx_snapshots_pk_captured_id
    ON snapshots (public_key, captured_at, id);
