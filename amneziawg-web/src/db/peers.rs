//! Database query layer for the `peers` and `snapshots` tables.

use sqlx::SqlitePool;

/// A row fetched from the `peers` table.
///
/// Timestamps are stored as Unix-epoch integers; boolean flags as 0/1 integers.
/// Use the conversion helpers in this module to get typed values.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PeerRow {
    pub id: i64,
    pub public_key: String,
    pub display_name: Option<String>,
    pub comment: Option<String>,
    pub endpoint: Option<String>,
    /// Comma-separated list of allowed CIDRs, e.g. `"10.8.0.2/32,fd00::2/128"`.
    pub allowed_ips: String,
    /// Unix epoch of the last observed WireGuard handshake, or `NULL`.
    pub last_handshake_at: Option<i64>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    /// `1` if peer is administratively disabled, `0` otherwise.
    pub disabled: i64,
    /// `1` if a matching client config file has been discovered, `0` otherwise.
    pub has_config: i64,
    /// Stem of the matching config filename (no `.conf` extension).
    pub config_name: Option<String>,
    /// Absolute path to the matching config file.
    pub config_path: Option<String>,
    /// Human-readable name derived from config filename (e.g. `"gramm"`
    /// from `"awg0-client-gramm.conf"`).
    pub friendly_name: Option<String>,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub updated_at: String,
}

/// A row fetched from the `snapshots` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SnapshotRow {
    pub id: i64,
    #[allow(dead_code)]
    pub public_key: String,
    /// ISO-8601 / RFC-3339 timestamp when this snapshot was captured.
    pub captured_at: String,
    pub endpoint: Option<String>,
    pub last_handshake_at: Option<i64>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

/// Narrower snapshot row used by the usage-summary endpoints.
///
/// Contains only the columns needed for traffic delta computation, avoiding the
/// I/O and allocation overhead of fetching unused fields like `endpoint` and
/// `last_handshake_at`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UsageSnapshotRow {
    pub public_key: String,
    /// ISO-8601 / RFC-3339 timestamp when this snapshot was captured.
    #[allow(dead_code)]
    pub captured_at: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

/// Return all peers ordered by their integer ID.
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<PeerRow>, sqlx::Error> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT id, public_key, display_name, comment, endpoint, allowed_ips,
                last_handshake_at, rx_bytes, tx_bytes, disabled, has_config,
                config_name, config_path, friendly_name, created_at, updated_at
         FROM   peers
         ORDER  BY id",
    )
    .fetch_all(pool)
    .await
}

/// Return a single peer by its integer primary key, or `None` if not found.
pub async fn find_by_id(pool: &SqlitePool, id: i64) -> Result<Option<PeerRow>, sqlx::Error> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT id, public_key, display_name, comment, endpoint, allowed_ips,
                last_handshake_at, rx_bytes, tx_bytes, disabled, has_config,
                config_name, config_path, friendly_name, created_at, updated_at
         FROM   peers
         WHERE  id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Return a single peer by its public key, or `None` if not found.
pub async fn find_by_public_key(
    pool: &SqlitePool,
    public_key: &str,
) -> Result<Option<PeerRow>, sqlx::Error> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT id, public_key, display_name, comment, endpoint, allowed_ips,
                last_handshake_at, rx_bytes, tx_bytes, disabled, has_config,
                config_name, config_path, friendly_name, created_at, updated_at
         FROM   peers
         WHERE  public_key = ?",
    )
    .bind(public_key)
    .fetch_optional(pool)
    .await
}

/// Return the set of public keys for all administratively disabled peers.
///
/// Used by the poller to remove disabled peers from the running AWG
/// interface.
pub async fn list_disabled_public_keys(
    pool: &SqlitePool,
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT public_key FROM peers WHERE disabled = 1")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(pk,)| pk).collect())
}

/// Return snapshots for a peer captured on or after `since_rfc3339`, ordered
/// by `captured_at` **ascending** (oldest first).
///
/// Used by the traffic-history endpoint to feed `domain::history::compute_history`.
pub async fn find_snapshots_since(
    pool: &SqlitePool,
    public_key: &str,
    since_rfc3339: &str,
) -> Result<Vec<SnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, SnapshotRow>(
        "SELECT id, public_key, captured_at, endpoint, last_handshake_at, rx_bytes, tx_bytes
         FROM   snapshots
         WHERE  public_key = ?
           AND  captured_at >= ?
         ORDER  BY captured_at ASC",
    )
    .bind(public_key)
    .bind(since_rfc3339)
    .fetch_all(pool)
    .await
}

/// Return snapshots for **all** peers captured on or after `since_rfc3339`,
/// ordered by `public_key` then `captured_at` **ascending** (oldest first).
///
/// Returns the narrower [`UsageSnapshotRow`] (only `public_key`, `captured_at`,
/// `rx_bytes`, `tx_bytes`) to avoid fetching unused columns.
///
/// Used by the traffic-usage endpoint to compute per-peer deltas in bulk.
pub async fn find_all_snapshots_since(
    pool: &SqlitePool,
    since_rfc3339: &str,
) -> Result<Vec<UsageSnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, UsageSnapshotRow>(
        "SELECT public_key, captured_at, rx_bytes, tx_bytes
         FROM   snapshots
         WHERE  captured_at >= ?
         ORDER  BY public_key, captured_at ASC",
    )
    .bind(since_rfc3339)
    .fetch_all(pool)
    .await
}

pub async fn find_snapshots(
    pool: &SqlitePool,
    public_key: &str,
    limit: i64,
) -> Result<Vec<SnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, SnapshotRow>(
        "SELECT id, public_key, captured_at, endpoint, last_handshake_at, rx_bytes, tx_bytes
         FROM   snapshots
         WHERE  public_key = ?
         ORDER  BY captured_at DESC
         LIMIT  ?",
    )
    .bind(public_key)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Update the human-editable metadata fields (`display_name`, `comment`) for a
/// single peer.
///
/// Pass `None` for a field to store `NULL` (clear the value).  The caller
/// should normalise the values with `domain::normalize_display_name` and
/// `domain::normalize_comment` before calling this function.
///
/// Returns the updated `PeerRow`, or `None` if no peer with the given `id`
/// exists.
pub async fn update_peer_metadata(
    pool: &SqlitePool,
    id: i64,
    display_name: Option<&str>,
    comment: Option<&str>,
) -> Result<Option<PeerRow>, sqlx::Error> {
    sqlx::query(
        "UPDATE peers
         SET    display_name = ?, comment = ?, updated_at = CURRENT_TIMESTAMP
         WHERE  id = ?",
    )
    .bind(display_name)
    .bind(comment)
    .bind(id)
    .execute(pool)
    .await?;

    find_by_id(pool, id).await
}

/// Delete a peer row by integer ID.
///
/// Returns `true` if a row was deleted, `false` if no peer with that ID exists.
pub async fn delete_by_id(pool: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM peers WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Update the `disabled` flag for a single peer.
///
/// Returns the updated `PeerRow`, or `None` if no peer with the given `id`
/// exists.
pub async fn update_peer_disabled(
    pool: &SqlitePool,
    id: i64,
    disabled: bool,
) -> Result<Option<PeerRow>, sqlx::Error> {
    sqlx::query(
        "UPDATE peers
         SET    disabled = ?, updated_at = CURRENT_TIMESTAMP
         WHERE  id = ?",
    )
    .bind(disabled as i64)
    .bind(id)
    .execute(pool)
    .await?;

    find_by_id(pool, id).await
}

///
/// Call this at the start of every config-mapping step so that peers whose
/// config files have been removed are correctly unmarked.  The subsequent
/// `apply_config_mapping` calls will re-mark only the peers that still have
/// a matching config file.
pub async fn clear_all_config_mappings(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE peers SET has_config = 0, config_name = NULL, config_path = NULL, friendly_name = NULL",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark one peer as having a discovered config file.
///
/// Sets `has_config = 1`, `config_name`, `config_path`, and `friendly_name`
/// for the peer identified by `public_key`.  Returns `true` if a matching
/// peer was found and updated, `false` if no peer with that public key
/// exists (the config file may reference a key that does not correspond to
/// any known peer — for example the server's own public key).
pub async fn apply_config_mapping(
    pool: &SqlitePool,
    public_key: &str,
    config_name: &str,
    config_path: &str,
    friendly_name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE peers
         SET    has_config = 1, config_name = ?, config_path = ?, friendly_name = ?
         WHERE  public_key = ?",
    )
    .bind(config_name)
    .bind(config_path)
    .bind(friendly_name)
    .bind(public_key)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> crate::db::Database {
        let db = crate::db::Database::connect_for_test()
            .await
            .expect("connect");
        db
    }

    async fn insert_peer(pool: &SqlitePool, public_key: &str, display_name: Option<&str>) -> i64 {
        sqlx::query("INSERT INTO peers (public_key, display_name, allowed_ips) VALUES (?, ?, ?)")
            .bind(public_key)
            .bind(display_name)
            .bind("10.8.0.2/32")
            .execute(pool)
            .await
            .expect("insert peer")
            .last_insert_rowid()
    }

    async fn insert_snapshot(pool: &SqlitePool, public_key: &str, captured_at: &str) {
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes)
             VALUES (?, ?, 100, 200)",
        )
        .bind(public_key)
        .bind(captured_at)
        .execute(pool)
        .await
        .expect("insert snapshot");
    }

    #[tokio::test]
    async fn list_all_empty_db() {
        let db = test_db().await;
        let rows = list_all(&db.pool).await.expect("list_all");
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn list_all_returns_peers() {
        let db = test_db().await;
        insert_peer(&db.pool, "KEY_A=", Some("Alice")).await;
        insert_peer(&db.pool, "KEY_B=", None).await;

        let rows = list_all(&db.pool).await.expect("list_all");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].public_key, "KEY_A=");
        assert_eq!(rows[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(rows[1].public_key, "KEY_B=");
    }

    #[tokio::test]
    async fn find_by_id_not_found() {
        let db = test_db().await;
        let row = find_by_id(&db.pool, 9999).await.expect("find");
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn find_by_id_found() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_FIND=", Some("Bob")).await;

        let row = find_by_id(&db.pool, id).await.expect("find");
        assert!(row.is_some());
        let row = row.unwrap();
        assert_eq!(row.id, id);
        assert_eq!(row.public_key, "KEY_FIND=");
        assert_eq!(row.display_name.as_deref(), Some("Bob"));
    }

    #[tokio::test]
    async fn find_by_public_key_not_found() {
        let db = test_db().await;
        let row = find_by_public_key(&db.pool, "NO_SUCH_KEY=")
            .await
            .expect("find");
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn find_by_public_key_found() {
        let db = test_db().await;
        insert_peer(&db.pool, "KEY_PK=", Some("PkLookup")).await;

        let row = find_by_public_key(&db.pool, "KEY_PK=").await.expect("find");
        assert!(row.is_some());
        let row = row.unwrap();
        assert_eq!(row.public_key, "KEY_PK=");
        assert_eq!(row.display_name.as_deref(), Some("PkLookup"));
    }

    #[tokio::test]
    async fn find_snapshots_empty() {
        let db = test_db().await;
        let rows = find_snapshots(&db.pool, "UNKNOWN_KEY=", 50)
            .await
            .expect("snapshots");
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn find_snapshots_ordered_most_recent_first() {
        let db = test_db().await;
        insert_snapshot(&db.pool, "KEY_SNAP=", "2026-01-01T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_SNAP=", "2026-01-03T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_SNAP=", "2026-01-02T00:00:00Z").await;

        let rows = find_snapshots(&db.pool, "KEY_SNAP=", 50)
            .await
            .expect("snapshots");
        assert_eq!(rows.len(), 3);
        // Most recent first
        assert!(rows[0].captured_at > rows[1].captured_at);
        assert!(rows[1].captured_at > rows[2].captured_at);
    }

    #[tokio::test]
    async fn find_snapshots_respects_limit() {
        let db = test_db().await;
        for i in 0..10 {
            let ts = format!("2026-01-{:02}T00:00:00Z", i + 1);
            insert_snapshot(&db.pool, "KEY_LIM=", &ts).await;
        }
        let rows = find_snapshots(&db.pool, "KEY_LIM=", 3)
            .await
            .expect("snapshots");
        assert_eq!(rows.len(), 3);
    }

    // ── find_snapshots_since ─────────────────────────────────────────────────

    #[tokio::test]
    async fn find_snapshots_since_empty() {
        let db = test_db().await;
        let rows = find_snapshots_since(&db.pool, "NO_SUCH_KEY=", "2026-01-01T00:00:00Z")
            .await
            .expect("snapshots_since");
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn find_snapshots_since_filters_by_time() {
        let db = test_db().await;
        insert_snapshot(&db.pool, "KEY_SINCE=", "2026-01-01T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_SINCE=", "2026-01-05T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_SINCE=", "2026-01-10T00:00:00Z").await;

        // Request snapshots on or after Jan 5 – should return Jan 5 and Jan 10
        let rows = find_snapshots_since(&db.pool, "KEY_SINCE=", "2026-01-05T00:00:00Z")
            .await
            .expect("snapshots_since");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].captured_at, "2026-01-05T00:00:00Z");
        assert_eq!(rows[1].captured_at, "2026-01-10T00:00:00Z");
    }

    #[tokio::test]
    async fn find_snapshots_since_ordered_ascending() {
        let db = test_db().await;
        // Insert out-of-order
        insert_snapshot(&db.pool, "KEY_ASC=", "2026-01-10T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_ASC=", "2026-01-01T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_ASC=", "2026-01-05T00:00:00Z").await;

        let rows = find_snapshots_since(&db.pool, "KEY_ASC=", "2026-01-01T00:00:00Z")
            .await
            .expect("snapshots_since");
        assert_eq!(rows.len(), 3);
        // Ascending: oldest first
        assert!(rows[0].captured_at < rows[1].captured_at);
        assert!(rows[1].captured_at < rows[2].captured_at);
    }

    // ── find_all_snapshots_since ─────────────────────────────────────────────

    #[tokio::test]
    async fn find_all_snapshots_since_empty() {
        let db = test_db().await;
        let rows = find_all_snapshots_since(&db.pool, "2026-01-01T00:00:00Z")
            .await
            .expect("all_snapshots_since");
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn find_all_snapshots_since_returns_multiple_peers() {
        let db = test_db().await;
        insert_snapshot(&db.pool, "KEY_ALL_A=", "2026-01-05T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_ALL_A=", "2026-01-10T00:00:00Z").await;
        insert_snapshot(&db.pool, "KEY_ALL_B=", "2026-01-06T00:00:00Z").await;
        // One snapshot before the cutoff – should be excluded.
        insert_snapshot(&db.pool, "KEY_ALL_A=", "2026-01-01T00:00:00Z").await;

        let rows = find_all_snapshots_since(&db.pool, "2026-01-05T00:00:00Z")
            .await
            .expect("all_snapshots_since");
        assert_eq!(rows.len(), 3);
        // Grouped by public_key, ordered by captured_at ASC within each group.
        assert_eq!(rows[0].public_key, "KEY_ALL_A=");
        assert_eq!(rows[0].captured_at, "2026-01-05T00:00:00Z");
        assert_eq!(rows[1].public_key, "KEY_ALL_A=");
        assert_eq!(rows[1].captured_at, "2026-01-10T00:00:00Z");
        assert_eq!(rows[2].public_key, "KEY_ALL_B=");
        assert_eq!(rows[2].captured_at, "2026-01-06T00:00:00Z");
    }

    // ── Config mapping ───────────────────────────────────────────────────────

    async fn insert_peer_with_config(pool: &SqlitePool, public_key: &str) -> i64 {
        sqlx::query(
            "INSERT INTO peers (public_key, allowed_ips, has_config, config_name, config_path, friendly_name)
             VALUES (?, '10.0.0.2/32', 1, 'existing-config', '/etc/awg/existing.conf', 'existing')",
        )
        .bind(public_key)
        .execute(pool)
        .await
        .expect("insert peer with config")
        .last_insert_rowid()
    }

    #[tokio::test]
    async fn clear_all_config_mappings_resets_fields() {
        let db = test_db().await;
        insert_peer_with_config(&db.pool, "KEY_CLEAR=").await;

        // Verify the peer has config set
        let row = find_by_id(&db.pool, 1).await.unwrap().unwrap();
        assert_eq!(row.has_config, 1);
        assert!(row.config_name.is_some());
        assert!(row.config_path.is_some());
        assert!(row.friendly_name.is_some());

        // Clear all mappings
        clear_all_config_mappings(&db.pool)
            .await
            .expect("clear mappings");

        // Verify reset
        let row = find_by_id(&db.pool, 1).await.unwrap().unwrap();
        assert_eq!(row.has_config, 0);
        assert!(row.config_name.is_none());
        assert!(row.config_path.is_none());
        assert!(row.friendly_name.is_none());
    }

    #[tokio::test]
    async fn apply_config_mapping_updates_peer() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_MAP=", None).await;

        let matched = apply_config_mapping(
            &db.pool,
            "KEY_MAP=",
            "awg0-client-gramm",
            "/etc/awg/awg0-client-gramm.conf",
            "gramm",
        )
        .await
        .expect("apply mapping");
        assert!(matched, "should match existing peer");

        let row = find_by_id(&db.pool, id).await.unwrap().unwrap();
        assert_eq!(row.has_config, 1);
        assert_eq!(row.config_name.as_deref(), Some("awg0-client-gramm"));
        assert_eq!(
            row.config_path.as_deref(),
            Some("/etc/awg/awg0-client-gramm.conf")
        );
        assert_eq!(row.friendly_name.as_deref(), Some("gramm"));
    }

    #[tokio::test]
    async fn apply_config_mapping_unknown_peer_is_noop() {
        let db = test_db().await;
        // Applying to a non-existent public key should not error but return false
        let matched = apply_config_mapping(
            &db.pool,
            "NO_SUCH_KEY=",
            "ghost",
            "/etc/awg/ghost.conf",
            "ghost",
        )
        .await
        .expect("should not error");
        assert!(!matched, "should not match any peer");
    }

    #[tokio::test]
    async fn clear_then_apply_is_idempotent() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_IDEM=", Some("IdemPeer")).await;

        // Apply twice, clear in between
        for _ in 0..2 {
            clear_all_config_mappings(&db.pool).await.unwrap();
            let matched = apply_config_mapping(
                &db.pool,
                "KEY_IDEM=",
                "idem-config",
                "/etc/awg/idem.conf",
                "idem-config",
            )
            .await
            .unwrap();
            assert!(matched);
        }

        let row = find_by_id(&db.pool, id).await.unwrap().unwrap();
        assert_eq!(row.has_config, 1);
        assert_eq!(row.config_name.as_deref(), Some("idem-config"));
        assert_eq!(row.friendly_name.as_deref(), Some("idem-config"));
    }

    // ── update_peer_metadata ─────────────────────────────────────────────────

    #[tokio::test]
    async fn update_peer_metadata_name_only() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_RENAME=", None).await;

        let row = update_peer_metadata(&db.pool, id, Some("Alice"), None)
            .await
            .expect("update")
            .expect("row");
        assert_eq!(row.display_name.as_deref(), Some("Alice"));
        assert!(row.comment.is_none());
    }

    #[tokio::test]
    async fn update_peer_metadata_comment_only() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_COMMENT=", Some("ExistingName")).await;

        let row = update_peer_metadata(&db.pool, id, Some("ExistingName"), Some("Main phone"))
            .await
            .expect("update")
            .expect("row");
        assert_eq!(row.display_name.as_deref(), Some("ExistingName"));
        assert_eq!(row.comment.as_deref(), Some("Main phone"));
    }

    #[tokio::test]
    async fn update_peer_metadata_both_fields() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_BOTH=", None).await;

        let row = update_peer_metadata(&db.pool, id, Some("Bob"), Some("Primary device"))
            .await
            .expect("update")
            .expect("row");
        assert_eq!(row.display_name.as_deref(), Some("Bob"));
        assert_eq!(row.comment.as_deref(), Some("Primary device"));
    }

    #[tokio::test]
    async fn update_peer_metadata_clears_name_with_none() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_CLEAR_NAME=", Some("ToBeCleared")).await;

        let row = update_peer_metadata(&db.pool, id, None, None)
            .await
            .expect("update")
            .expect("row");
        assert!(row.display_name.is_none());
    }

    #[tokio::test]
    async fn update_peer_metadata_invalid_id_returns_none() {
        let db = test_db().await;
        // No peers inserted – ID 9999 must not exist.
        let result = update_peer_metadata(&db.pool, 9999, Some("Ghost"), None)
            .await
            .expect("no db error");
        assert!(result.is_none());
    }

    // ── update_peer_disabled ─────────────────────────────────────────────────

    #[tokio::test]
    async fn update_peer_disabled_sets_flag() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_DIS=", None).await;

        // Initially disabled = 0.
        let row = find_by_id(&db.pool, id).await.unwrap().unwrap();
        assert_eq!(row.disabled, 0);

        // Disable.
        let row = update_peer_disabled(&db.pool, id, true)
            .await
            .expect("update")
            .expect("row");
        assert_eq!(row.disabled, 1);

        // Re-enable.
        let row = update_peer_disabled(&db.pool, id, false)
            .await
            .expect("update")
            .expect("row");
        assert_eq!(row.disabled, 0);
    }

    #[tokio::test]
    async fn update_peer_disabled_invalid_id_returns_none() {
        let db = test_db().await;
        let result = update_peer_disabled(&db.pool, 9999, true)
            .await
            .expect("no db error");
        assert!(result.is_none());
    }

    // ── delete_by_id ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_by_id_existing_peer_removes_row() {
        let db = test_db().await;
        let id = insert_peer(&db.pool, "KEY_DEL=", Some("ToRemove")).await;

        let deleted = delete_by_id(&db.pool, id).await.expect("delete");
        assert!(deleted);

        let row = find_by_id(&db.pool, id).await.expect("find");
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn delete_by_id_missing_peer_returns_false() {
        let db = test_db().await;
        let deleted = delete_by_id(&db.pool, 9999).await.expect("delete");
        assert!(!deleted);
    }

    // ── list_disabled_public_keys ───────────────────────────────────────

    #[tokio::test]
    async fn list_disabled_public_keys_empty_db() {
        let db = test_db().await;
        let keys = list_disabled_public_keys(&db.pool).await.expect("query");
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn list_disabled_public_keys_returns_only_disabled() {
        let db = test_db().await;
        insert_peer(&db.pool, "KEY_ENABLED=", None).await;
        let id_b = insert_peer(&db.pool, "KEY_DISABLED_1=", None).await;
        let id_c = insert_peer(&db.pool, "KEY_DISABLED_2=", None).await;

        // Disable peers B and C
        update_peer_disabled(&db.pool, id_b, true).await.unwrap();
        update_peer_disabled(&db.pool, id_c, true).await.unwrap();

        let keys = list_disabled_public_keys(&db.pool).await.expect("query");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("KEY_DISABLED_1="));
        assert!(keys.contains("KEY_DISABLED_2="));
        assert!(!keys.contains("KEY_ENABLED="));

        // Re-enable B — should now only contain C
        update_peer_disabled(&db.pool, id_b, false).await.unwrap();
        let keys = list_disabled_public_keys(&db.pool).await.expect("query");
        assert_eq!(keys.len(), 1);
        assert!(keys.contains("KEY_DISABLED_2="));
    }
}
