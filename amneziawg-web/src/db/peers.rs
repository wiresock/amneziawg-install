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

/// Narrower snapshot row used by the all-peers usage endpoint (`GET /api/usage`).
///
/// Contains only the columns needed for traffic delta computation, avoiding the
/// I/O and allocation overhead of fetching unused fields like `endpoint`,
/// `last_handshake_at`, and `captured_at` (ordering by `captured_at` is enforced
/// in the SQL query).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UsageSnapshotRow {
    pub public_key: String,
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
         ORDER  BY captured_at ASC, id ASC",
    )
    .bind(public_key)
    .bind(since_rfc3339)
    .fetch_all(pool)
    .await
}

/// Return snapshots for **all** peers captured on or after `since_rfc3339`,
/// ordered by `public_key` then `captured_at` **ascending** (oldest first),
/// with `id ASC` as a deterministic tie-breaker for same-timestamp rows.
///
/// Returns the narrower [`UsageSnapshotRow`] (only `public_key`, `rx_bytes`,
/// `tx_bytes`) to avoid fetching unused columns.  The `ORDER BY captured_at`
/// clause ensures chronological ordering without needing the column in the
/// result set.
///
/// This is the non-streaming (fully-materialized) counterpart of
/// [`stream_all_snapshots_since`].  Production code uses the streaming
/// variant; this function is retained for tests.
#[cfg(test)]
pub async fn find_all_snapshots_since(
    pool: &SqlitePool,
    since_rfc3339: &str,
) -> Result<Vec<UsageSnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, UsageSnapshotRow>(
        "SELECT public_key, rx_bytes, tx_bytes
         FROM   snapshots
         WHERE  captured_at >= ?
         ORDER  BY public_key, captured_at ASC, id ASC",
    )
    .bind(since_rfc3339)
    .fetch_all(pool)
    .await
}

/// Stream snapshots for **all** peers captured on or after `since_rfc3339`,
/// ordered by `public_key` then `captured_at ASC`, `id ASC`.
///
/// Unlike [`find_all_snapshots_since`] (which materializes the full `Vec`),
/// this returns a [`futures_util::Stream`] so the caller can process rows
/// incrementally without holding the entire result set in memory.
pub fn stream_all_snapshots_since<'a>(
    pool: &'a SqlitePool,
    since_rfc3339: &'a str,
) -> impl futures_util::Stream<Item = Result<UsageSnapshotRow, sqlx::Error>> + 'a {
    sqlx::query_as::<_, UsageSnapshotRow>(
        "SELECT public_key, rx_bytes, tx_bytes
         FROM   snapshots
         WHERE  captured_at >= ?
         ORDER  BY public_key, captured_at ASC, id ASC",
    )
    .bind(since_rfc3339)
    .fetch(pool)
}

/// Return the last snapshot for `public_key` captured **before** `before_rfc3339`.
///
/// Used as a "baseline" so that delta computation includes the traffic
/// between the last pre-window snapshot and the first in-window snapshot.
pub async fn find_baseline_snapshot(
    pool: &SqlitePool,
    public_key: &str,
    before_rfc3339: &str,
) -> Result<Option<SnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, SnapshotRow>(
        "SELECT id, public_key, captured_at, endpoint, last_handshake_at, rx_bytes, tx_bytes
         FROM   snapshots
         WHERE  public_key = ?
           AND  captured_at < ?
         ORDER  BY captured_at DESC, id DESC
         LIMIT  1",
    )
    .bind(public_key)
    .bind(before_rfc3339)
    .fetch_optional(pool)
    .await
}

/// Return the last snapshot before `before_rfc3339` for **every** peer that has
/// one.  Uses a `ROW_NUMBER()` window function partitioned by `public_key` and
/// ordered by `captured_at DESC, id DESC` to guarantee exactly one row per peer,
/// correctly handling clock skew or backfilled snapshots.
///
/// Used to seed per-peer baseline counters when computing all-peers usage so
/// that the delta for the first in-window snapshot of each peer is included.
pub async fn find_all_baseline_snapshots(
    pool: &SqlitePool,
    before_rfc3339: &str,
) -> Result<Vec<UsageSnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, UsageSnapshotRow>(
        "SELECT public_key, rx_bytes, tx_bytes
         FROM (
             SELECT
                 public_key,
                 rx_bytes,
                 tx_bytes,
                 ROW_NUMBER() OVER (
                     PARTITION BY public_key
                     ORDER BY captured_at DESC, id DESC
                 ) AS row_num
             FROM snapshots
             WHERE captured_at < ?
         )
         WHERE row_num = 1",
    )
    .bind(before_rfc3339)
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

/// Delete non-disabled peers whose public keys are **not** in `active_keys`.
///
/// This removes "stale" peers that were deleted outside the web panel (e.g.
/// via the install script's `--remove-client` flag).  Disabled peers are
/// preserved because they were intentionally marked via the UI and may be
/// re-enabled later.
///
/// Returns the list of `(id, public_key)` pairs that were deleted so the
/// caller can perform follow-up cleanup (e.g. clearing event references).
pub async fn delete_stale_peers(
    pool: &SqlitePool,
    active_keys: &std::collections::HashSet<String>,
) -> Result<Vec<(i64, String)>, sqlx::Error> {
    // Fetch non-disabled peers first, then filter in Rust because SQLite
    // does not support binding a set parameter.
    let all: Vec<(i64, String, i64)> =
        sqlx::query_as("SELECT id, public_key, disabled FROM peers")
            .fetch_all(pool)
            .await?;

    let stale: Vec<(i64, String)> = all
        .into_iter()
        .filter(|(_, pk, disabled)| *disabled == 0 && !active_keys.contains(pk))
        .map(|(id, pk, _)| (id, pk))
        .collect();

    for (id, _) in &stale {
        sqlx::query("DELETE FROM peers WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
    }

    Ok(stale)
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

    async fn insert_snapshot_with_rx(
        pool: &SqlitePool,
        public_key: &str,
        captured_at: &str,
        rx_bytes: i64,
    ) {
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes)
             VALUES (?, ?, ?, 200)",
        )
        .bind(public_key)
        .bind(captured_at)
        .bind(rx_bytes)
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
        // Use distinct rx_bytes to verify ordering (captured_at is not in UsageSnapshotRow).
        insert_snapshot_with_rx(&db.pool, "KEY_ALL_A=", "2026-01-05T00:00:00Z", 10).await;
        insert_snapshot_with_rx(&db.pool, "KEY_ALL_A=", "2026-01-10T00:00:00Z", 20).await;
        insert_snapshot_with_rx(&db.pool, "KEY_ALL_B=", "2026-01-06T00:00:00Z", 30).await;
        // One snapshot before the cutoff – should be excluded.
        insert_snapshot_with_rx(&db.pool, "KEY_ALL_A=", "2026-01-01T00:00:00Z", 1).await;

        let rows = find_all_snapshots_since(&db.pool, "2026-01-05T00:00:00Z")
            .await
            .expect("all_snapshots_since");
        assert_eq!(rows.len(), 3);
        // Grouped by public_key, ordered by captured_at ASC within each group.
        assert_eq!(rows[0].public_key, "KEY_ALL_A=");
        assert_eq!(rows[0].rx_bytes, 10); // 2026-01-05
        assert_eq!(rows[1].public_key, "KEY_ALL_A=");
        assert_eq!(rows[1].rx_bytes, 20); // 2026-01-10
        assert_eq!(rows[2].public_key, "KEY_ALL_B=");
        assert_eq!(rows[2].rx_bytes, 30); // 2026-01-06
    }

    // ── Config mapping ───────────────────────────────────────────────────────

    // ── find_baseline_snapshot ───────────────────────────────────────────────

    #[tokio::test]
    async fn find_baseline_snapshot_no_data() {
        let db = test_db().await;
        let row = find_baseline_snapshot(&db.pool, "NO_KEY=", "2026-01-01T00:00:00Z")
            .await
            .expect("baseline");
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn find_baseline_snapshot_returns_last_before_cutoff() {
        let db = test_db().await;
        insert_snapshot_with_rx(&db.pool, "KEY_BASE=", "2026-01-01T00:00:00Z", 10).await;
        insert_snapshot_with_rx(&db.pool, "KEY_BASE=", "2026-01-03T00:00:00Z", 30).await;
        // After cutoff – should not be returned.
        insert_snapshot_with_rx(&db.pool, "KEY_BASE=", "2026-01-05T00:00:00Z", 50).await;

        let row = find_baseline_snapshot(&db.pool, "KEY_BASE=", "2026-01-05T00:00:00Z")
            .await
            .expect("baseline")
            .expect("should find a baseline");
        assert_eq!(row.rx_bytes, 30); // last before cutoff
    }

    // ── find_all_baseline_snapshots ─────────────────────────────────────────

    #[tokio::test]
    async fn find_all_baseline_snapshots_empty() {
        let db = test_db().await;
        let rows = find_all_baseline_snapshots(&db.pool, "2026-01-01T00:00:00Z")
            .await
            .expect("all_baselines");
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn find_all_baseline_snapshots_returns_last_per_peer() {
        let db = test_db().await;
        // Peer A: two snapshots before cutoff
        insert_snapshot_with_rx(&db.pool, "KEY_BL_A=", "2026-01-01T00:00:00Z", 10).await;
        insert_snapshot_with_rx(&db.pool, "KEY_BL_A=", "2026-01-03T00:00:00Z", 30).await;
        // Peer B: one snapshot before cutoff
        insert_snapshot_with_rx(&db.pool, "KEY_BL_B=", "2026-01-02T00:00:00Z", 20).await;
        // Both peers also have snapshots after cutoff – should be ignored.
        insert_snapshot_with_rx(&db.pool, "KEY_BL_A=", "2026-01-10T00:00:00Z", 100).await;
        insert_snapshot_with_rx(&db.pool, "KEY_BL_B=", "2026-01-10T00:00:00Z", 200).await;

        let rows = find_all_baseline_snapshots(&db.pool, "2026-01-05T00:00:00Z")
            .await
            .expect("all_baselines");
        assert_eq!(rows.len(), 2);
        // Should return the last snapshot before cutoff for each peer.
        let a = rows.iter().find(|r| r.public_key == "KEY_BL_A=").unwrap();
        assert_eq!(a.rx_bytes, 30); // 2026-01-03
        let b = rows.iter().find(|r| r.public_key == "KEY_BL_B=").unwrap();
        assert_eq!(b.rx_bytes, 20); // 2026-01-02
    }

    // ── Config mapping (continued) ──────────────────────────────────────────

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

    // ── delete_stale_peers ────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_stale_peers_removes_non_active() {
        let db = test_db().await;
        let id_a = insert_peer(&db.pool, "KEY_A=", None).await;
        let _id_b = insert_peer(&db.pool, "KEY_B=", None).await;

        // Only KEY_A is active on the interface
        let active: std::collections::HashSet<String> =
            ["KEY_A=".to_string()].into_iter().collect();

        let stale = delete_stale_peers(&db.pool, &active).await.expect("delete");
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].1, "KEY_B=");

        // KEY_A should still exist
        assert!(find_by_id(&db.pool, id_a).await.unwrap().is_some());
        // KEY_B should be gone
        assert!(find_by_public_key(&db.pool, "KEY_B=").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_stale_peers_preserves_disabled() {
        let db = test_db().await;
        let id_a = insert_peer(&db.pool, "KEY_ACTIVE=", None).await;
        let id_d = insert_peer(&db.pool, "KEY_DISABLED=", None).await;
        update_peer_disabled(&db.pool, id_d, true).await.unwrap();

        // Neither peer is on the interface
        let active: std::collections::HashSet<String> = std::collections::HashSet::new();

        let stale = delete_stale_peers(&db.pool, &active).await.expect("delete");
        // Only the non-disabled peer should be removed
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, id_a);

        // Disabled peer should still exist
        assert!(find_by_id(&db.pool, id_d).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_stale_peers_empty_db_is_noop() {
        let db = test_db().await;
        let active: std::collections::HashSet<String> = std::collections::HashSet::new();
        let stale = delete_stale_peers(&db.pool, &active).await.expect("delete");
        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn delete_stale_peers_all_active_is_noop() {
        let db = test_db().await;
        insert_peer(&db.pool, "KEY_X=", None).await;
        insert_peer(&db.pool, "KEY_Y=", None).await;

        let active: std::collections::HashSet<String> =
            ["KEY_X=".to_string(), "KEY_Y=".to_string()].into_iter().collect();

        let stale = delete_stale_peers(&db.pool, &active).await.expect("delete");
        assert!(stale.is_empty());

        // Both peers should still exist
        assert_eq!(list_all(&db.pool).await.unwrap().len(), 2);
    }
}
