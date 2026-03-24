//! Database access layer (SQLite via sqlx).

use anyhow::Context;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
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
}
