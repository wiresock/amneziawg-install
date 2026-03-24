//! Database access layer (SQLite via sqlx).

pub mod events;
pub mod peers;

use anyhow::Context;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tracing::info;

/// Wrapper around the SQLite connection pool.
#[derive(Clone, Debug)]
pub struct Database {
    pub(crate) pool: SqlitePool,
}

impl Database {
    /// Open (or create) the SQLite database at `url`.
    ///
    /// `url` should be of the form `sqlite:/path/to/file.db` or
    /// `sqlite::memory:` for tests.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await
            .with_context(|| format!("cannot open database at {url}"))?;
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
            .connect("sqlite::memory:")
            .await
            .context("connect test db")?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
