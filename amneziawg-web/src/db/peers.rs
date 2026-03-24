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

/// Return all peers ordered by their integer ID.
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<PeerRow>, sqlx::Error> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT id, public_key, display_name, comment, endpoint, allowed_ips,
                last_handshake_at, rx_bytes, tx_bytes, disabled, has_config,
                config_name, config_path, created_at, updated_at
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
                config_name, config_path, created_at, updated_at
         FROM   peers
         WHERE  id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Return the `limit` most-recent snapshots for a given peer `public_key`.
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
}
