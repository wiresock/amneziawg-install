//! amneziawg-web – main entry point
//!
//! Starts the HTTP server, initialises the database, and launches the background poller.

mod admin;
mod auth;
mod awg;
mod config_store;
mod db;
mod domain;
mod poller;
mod web;

use anyhow::Context;
use clap::Parser;
use tracing::info;

use crate::auth::AuthConfig;
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

    // ── Authentication ────────────────────────────────────────────────────
    /// Enable authentication. When false, all requests are allowed through
    /// without credentials. **Do not disable in production.**
    #[arg(long, env = "AUTH_ENABLED", default_value_t = false)]
    pub auth_enabled: bool,

    /// Username for the single admin account. Required when AUTH_ENABLED=true.
    #[arg(long, env = "AUTH_USERNAME", default_value = "admin")]
    pub auth_username: String,

    /// Argon2id PHC string of the admin password.
    /// Generate with: `python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"`
    /// Required when AUTH_ENABLED=true.
    #[arg(long, env = "AUTH_PASSWORD_HASH", default_value = "")]
    pub auth_password_hash: String,

    /// Optional static bearer token for headless API access.
    /// Accepted in the `Authorization: Bearer <token>` header.
    #[arg(long, env = "AUTH_API_TOKEN")]
    pub auth_api_token: Option<String>,

    /// Set the Secure flag on the session cookie.
    /// Enable when serving over HTTPS.
    #[arg(long, env = "AUTH_SECURE_COOKIE", default_value_t = false)]
    pub auth_secure_cookie: bool,
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

    if config.auth_enabled {
        if config.auth_password_hash.is_empty() {
            anyhow::bail!(
                "AUTH_ENABLED=true but AUTH_PASSWORD_HASH is not set. \
                 Generate a hash with: python3 -c \"import argon2; print(argon2.PasswordHasher().hash('yourpassword'))\""
            );
        }
        info!(username = %config.auth_username, "authentication enabled");
    } else {
        tracing::warn!("authentication is DISABLED – do not expose this panel on a public network");
    }

    let auth = AuthConfig {
        enabled: config.auth_enabled,
        username: config.auth_username.clone(),
        password_hash: config.auth_password_hash.clone(),
        api_token: config.auth_api_token.clone(),
        secure_cookie: config.auth_secure_cookie,
    };

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
    let poller = Poller::new(db.clone(), config.poll_interval, config.config_dir);
    tokio::spawn(async move {
        poller.run().await;
    });

    // --- HTTP server --------------------------------------------------------
    let app = router(db, auth);
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("failed to bind TCP listener")?;
    info!(addr = %config.listen, "HTTP server listening");
    axum::serve(listener, app)
        .await
        .context("HTTP server error")?;

    Ok(())
}
