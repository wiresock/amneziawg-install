//! Database access layer (SQLite via sqlx).

pub mod events;
pub mod peers;

use std::str::FromStr;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tracing::info;

/// Wrapper around the SQLite connection pool.
#[derive(Clone, Debug)]
pub struct Database {
    pub(crate) pool: SqlitePool,
}

impl Database {
    /// Open (or create) the SQLite database.
    ///
    /// `path_or_url` may be:
    /// - a plain filesystem path: `/var/lib/amneziawg-web/awg-web.db`
    /// - a relative path: `awg-web.db`
    /// - a SQLite URL: `sqlite:///var/lib/amneziawg-web/awg-web.db`
    /// - an in-memory URL: `sqlite::memory:`
    ///
    /// For file-based databases, the file is created if it does not exist.
    pub async fn connect(path_or_url: &str) -> anyhow::Result<Self> {
        let options = parse_db_options(path_or_url)
            .with_context(|| format!("invalid database path: {path_or_url}"))?;

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .with_context(|| format!("cannot open database at {path_or_url}"))?;
        Ok(Self { pool })
    }

    /// Run pending sqlx migrations from the embedded `migrations/` directory.
    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("sqlx migrate failed")?;
        info!("migrations applied");
        Ok(())
    }

    /// Create an in-memory database suitable for unit tests.
    ///
    /// Uses `max_connections(1)` so that all operations on the pool share the
    /// same SQLite in-memory database.
    #[cfg(test)]
    pub(crate) async fn connect_for_test() -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::from_str("sqlite::memory:").context("parse memory url")?,
            )
            .await
            .context("connect test db")?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }
}

/// Parse a database path or URL into [`SqliteConnectOptions`].
///
/// Rules:
/// - `sqlite::memory:` or `:memory:` → in-memory database (no `create_if_missing`)
/// - `sqlite:…` → parsed as a SQLite URL with `create_if_missing(true)`
/// - anything else → treated as a filesystem path with `create_if_missing(true)`
fn parse_db_options(input: &str) -> anyhow::Result<SqliteConnectOptions> {
    if input == "sqlite::memory:" || input == ":memory:" {
        return SqliteConnectOptions::from_str("sqlite::memory:").context("parse in-memory url");
    }

    if input.starts_with("sqlite:") {
        return Ok(SqliteConnectOptions::from_str(input)
            .with_context(|| format!("parse sqlite url: {input}"))?
            .create_if_missing(true));
    }

    // Plain filesystem path – use SqliteConnectOptions::new().filename()
    // which handles both absolute and relative paths correctly.
    Ok(SqliteConnectOptions::new()
        .filename(input)
        .create_if_missing(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_db_options unit tests ──────────────────────────────────────

    #[test]
    fn parse_in_memory_url() {
        let opts = parse_db_options("sqlite::memory:").expect("parse");
        // Should not panic; we can't easily inspect the filename but
        // the connect test below validates the full round-trip.
        drop(opts);
    }

    #[test]
    fn parse_bare_memory() {
        let opts = parse_db_options(":memory:").expect("parse");
        drop(opts);
    }

    #[test]
    fn parse_absolute_path() {
        let opts = parse_db_options("/tmp/test-awg.db").expect("parse");
        drop(opts);
    }

    #[test]
    fn parse_relative_path() {
        let opts = parse_db_options("awg-web.db").expect("parse");
        drop(opts);
    }

    #[test]
    fn parse_sqlite_url_absolute() {
        let opts = parse_db_options("sqlite:///var/lib/amneziawg-web/awg-web.db").expect("parse");
        drop(opts);
    }

    #[test]
    fn parse_sqlite_url_relative() {
        let opts = parse_db_options("sqlite:awg-web.db").expect("parse");
        drop(opts);
    }

    // ── Database integration-style tests ────────────────────────────────

    #[tokio::test]
    async fn connect_and_migrate_in_memory() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect failed");
        db.migrate().await.expect("migrate failed");
    }

    #[tokio::test]
    async fn connect_for_test_helper() {
        let db = Database::connect_for_test()
            .await
            .expect("connect_for_test failed");
        // Verify migrations ran: peers table must exist
        let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM peers")
            .fetch_one(&db.pool)
            .await
            .expect("query");
    }

    #[tokio::test]
    async fn connect_creates_file_absolute_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.db");

        // File must not exist yet
        assert!(!db_path.exists());

        let db = Database::connect(db_path.to_str().unwrap())
            .await
            .expect("connect with absolute path failed");
        db.migrate().await.expect("migrate failed");

        // File should now exist
        assert!(db_path.exists(), "database file was not created");
    }

    #[tokio::test]
    async fn connect_creates_file_sqlite_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("url-test.db");

        let url = format!("sqlite://{}", db_path.display());

        let db = Database::connect(&url)
            .await
            .expect("connect with sqlite: URL failed");
        db.migrate().await.expect("migrate failed");

        assert!(db_path.exists(), "database file was not created via URL");
    }

    #[tokio::test]
    async fn connect_relative_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orig_dir = std::env::current_dir().expect("cwd");

        // Change to the temp directory so relative path resolves there
        std::env::set_current_dir(dir.path()).expect("chdir");

        let db = Database::connect("rel-test.db")
            .await
            .expect("connect with relative path failed");
        db.migrate().await.expect("migrate failed");

        let created = dir.path().join("rel-test.db");
        assert!(
            created.exists(),
            "database file was not created for relative path"
        );

        // Restore original directory
        std::env::set_current_dir(orig_dir).expect("restore cwd");
    }

    #[tokio::test]
    async fn migration_0010_preserves_existing_events_and_enables_set_null() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect");

        // Manually execute schemas 0001 through 0009
        sqlx::query(include_str!("../../migrations/0001_initial.sql"))
            .execute(&pool)
            .await
            .expect("0001");
        sqlx::query(include_str!(
            "../../migrations/0002_add_config_metadata.sql"
        ))
        .execute(&pool)
        .await
        .expect("0002");
        sqlx::query(include_str!("../../migrations/0003_add_events_peer_id.sql"))
            .execute(&pool)
            .await
            .expect("0003");
        sqlx::query(include_str!("../../migrations/0004_add_friendly_name.sql"))
            .execute(&pool)
            .await
            .expect("0004");
        sqlx::query(include_str!(
            "../../migrations/0005_add_snapshot_composite_index.sql"
        ))
        .execute(&pool)
        .await
        .expect("0005");
        sqlx::query(include_str!(
            "../../migrations/0006_add_peer_sync_pending.sql"
        ))
        .execute(&pool)
        .await
        .expect("0006");
        sqlx::query(include_str!("../../migrations/0007_add_peer_archived.sql"))
            .execute(&pool)
            .await
            .expect("0007");
        sqlx::query(include_str!(
            "../../migrations/0008_add_peer_expiration.sql"
        ))
        .execute(&pool)
        .await
        .expect("0008");
        sqlx::query(include_str!(
            "../../migrations/0009_add_peer_removal_pending.sql"
        ))
        .execute(&pool)
        .await
        .expect("0009");

        // Insert peer and event under pre-0010 schema
        sqlx::query("INSERT INTO peers (id, public_key, allowed_ips) VALUES (42, 'MIGRATE_KEY=', '10.0.0.1/32')")
            .execute(&pool)
            .await
            .expect("insert peer");
        sqlx::query("INSERT INTO events (actor, action, target_key, detail, peer_id) VALUES ('admin', 'peer.created', 'MIGRATE_KEY=', '{\"test\":true}', 42)")
            .execute(&pool)
            .await
            .expect("insert event");

        // Now run migration 0010
        sqlx::query(include_str!(
            "../../migrations/0010_events_peer_id_on_delete_set_null.sql"
        ))
        .execute(&pool)
        .await
        .expect("0010");

        // Verify data was preserved after 0010
        let event_row: (i64, Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT id, peer_id, target_key FROM events WHERE target_key = 'MIGRATE_KEY='",
        )
        .fetch_one(&pool)
        .await
        .expect("query event");
        assert_eq!(event_row.1, Some(42));
        assert_eq!(event_row.2.as_deref(), Some("MIGRATE_KEY="));

        // Delete peer row directly - ON DELETE SET NULL must automatically null peer_id without error!
        sqlx::query("DELETE FROM peers WHERE id = 42")
            .execute(&pool)
            .await
            .expect("delete peer");

        let event_after: (Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT peer_id, target_key FROM events WHERE target_key = 'MIGRATE_KEY='",
        )
        .fetch_one(&pool)
        .await
        .expect("query event after delete");
        assert_eq!(event_after.0, None);
        assert_eq!(event_after.1.as_deref(), Some("MIGRATE_KEY="));
    }
}
