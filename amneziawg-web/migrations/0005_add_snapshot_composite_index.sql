-- Add a composite index on (public_key, captured_at, id) to support
-- bulk usage queries that ORDER BY public_key, captured_at ASC, id ASC
-- and baseline lookups implemented as GROUP BY public_key with MAX(captured_at)
-- (and id as a tie-breaker) rather than window functions. Without this, those
-- queries fall back to a full scan plus sort/aggregate on larger tables.

CREATE INDEX IF NOT EXISTS idx_snapshots_pk_captured_id
    ON snapshots (public_key, captured_at, id);
