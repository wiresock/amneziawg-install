//! amneziawg-web – main entry point
//!
//! Starts the HTTP server, initialises the database, and launches the background poller.

mod admin;
mod awg;
mod config_store;
mod db;
mod domain;
mod poller;
mod web;

use anyhow::Context;
use clap::Parser;
use tracing::info;

use crate::db::Database;
use crate::poller::Poller;
use crate::web::router;

/// CLI arguments / environment variable configuration.
#[derive(Parser, Debug)]
#[command(author, version, about = "AmneziaWG web management panel")]
pub struct Config {
    /// TCP address the HTTP server will listen on.
    #[arg(long, env = "AWG_WEB_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: std::net::SocketAddr,

    /// Path to the SQLite database file.
    #[arg(long, env = "AWG_WEB_DB", default_value = "awg-web.db")]
    pub database_url: String,

    /// Directory where AWG client configs are stored.
    #[arg(long, env = "AWG_CONFIG_DIR", default_value = "/etc/amneziawg/clients")]
    pub config_dir: std::path::PathBuf,

    /// Polling interval in seconds.
    #[arg(long, env = "AWG_POLL_INTERVAL", default_value_t = 30)]
    pub poll_interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise logging from RUST_LOG env-var (defaults to info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "amneziawg_web=info,tower_http=debug".into()),
        )
        .init();

    let config = Config::parse();
    info!(listen = %config.listen, db = %config.database_url, "starting amneziawg-web");

    // --- Database -----------------------------------------------------------
    let db_url = if config.database_url.starts_with("sqlite:") {
        config.database_url.clone()
    } else {
        format!("sqlite:{}", config.database_url)
    };
    let db = Database::connect(&db_url)
        .await
        .context("failed to open database")?;
    db.migrate().await.context("database migration failed")?;
    info!("database ready");

    // --- Background poller --------------------------------------------------
    let poller = Poller::new(db.clone(), config.poll_interval);
    tokio::spawn(async move {
        poller.run().await;
    });

    // --- HTTP server --------------------------------------------------------
    let app = router(db);
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("failed to bind TCP listener")?;
    info!(addr = %config.listen, "HTTP server listening");
    axum::serve(listener, app)
        .await
        .context("HTTP server error")?;

    Ok(())
}
