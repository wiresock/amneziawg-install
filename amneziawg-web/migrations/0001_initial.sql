-- Initial schema for amneziawg-web.
-- All timestamps are stored as Unix epoch integers (INTEGER) or ISO-8601 text
-- depending on how sqlx maps them.  We use TEXT for datetimes that sqlx
-- DateTime<Utc> maps via its TEXT affinity.

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    password    TEXT    NOT NULL,   -- bcrypt hash
    role        TEXT    NOT NULL DEFAULT 'viewer',  -- 'admin' | 'viewer'
    created_at  TEXT    NOT NULL DEFAULT (DATETIME('now')),
    updated_at  TEXT    NOT NULL DEFAULT (DATETIME('now'))
);

-- ---------------------------------------------------------------------------
-- interfaces
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS interfaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    public_key  TEXT    NOT NULL,
    listen_port INTEGER,
    created_at  TEXT    NOT NULL DEFAULT (DATETIME('now')),
    updated_at  TEXT    NOT NULL DEFAULT (DATETIME('now'))
);

-- ---------------------------------------------------------------------------
-- peers
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key          TEXT    NOT NULL UNIQUE,
    display_name        TEXT,
    comment             TEXT,
    endpoint            TEXT,
    allowed_ips         TEXT    NOT NULL DEFAULT '',   -- comma-separated
    last_handshake_at   INTEGER,                       -- Unix epoch
    rx_bytes            INTEGER NOT NULL DEFAULT 0,
    tx_bytes            INTEGER NOT NULL DEFAULT 0,
    disabled            INTEGER NOT NULL DEFAULT 0,    -- boolean 0/1
    has_config          INTEGER NOT NULL DEFAULT 0,    -- boolean 0/1
    created_at          TEXT    NOT NULL DEFAULT (DATETIME('now')),
    updated_at          TEXT    NOT NULL DEFAULT (DATETIME('now'))
);

CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers (public_key);

-- ---------------------------------------------------------------------------
-- snapshots
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS snapshots (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key          TEXT    NOT NULL,
    captured_at         TEXT    NOT NULL DEFAULT (DATETIME('now')),
    endpoint            TEXT,
    last_handshake_at   INTEGER,
    rx_bytes            INTEGER NOT NULL DEFAULT 0,
    tx_bytes            INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_snapshots_public_key ON snapshots (public_key);
CREATE INDEX IF NOT EXISTS idx_snapshots_captured_at ON snapshots (captured_at);

-- ---------------------------------------------------------------------------
-- events  (audit log)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT    NOT NULL DEFAULT 'system',
    action      TEXT    NOT NULL,   -- e.g. 'peer.renamed', 'peer.disabled'
    target_key  TEXT,               -- public_key of affected peer (if any)
    detail      TEXT,               -- JSON blob with action-specific context
    created_at  TEXT    NOT NULL DEFAULT (DATETIME('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_target_key ON events (target_key);
