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
use tracing::{info, warn};

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

    /// Session lifetime in seconds.
    /// Default is 86400 (24 hours).
    #[arg(long, env = "AUTH_SESSION_TTL_SECS", default_value_t = 86_400)]
    pub auth_session_ttl_secs: u64,

    /// Path to the amneziawg-install.sh script used for user lifecycle actions.
    #[arg(
        long,
        env = "AWG_INSTALL_SCRIPT",
        default_value = crate::admin::script_bridge::DEFAULT_SCRIPT_PATH
    )]
    pub install_script: std::path::PathBuf,
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

    // --- Validate install-script path early --------------------------------
    // The script path is security-critical: it is invoked via sudo and must
    // be an absolute path, free of whitespace/commas (sudoers can't handle
    // those).  If the file doesn't exist yet (e.g. mid-install or
    // deployments that don't use user lifecycle), we warn instead of failing
    // so the rest of the service can still start.
    {
        let p = &config.install_script;
        if !p.is_absolute() {
            anyhow::bail!(
                "AWG_INSTALL_SCRIPT must be an absolute path, got: {}",
                p.display()
            );
        }
        let s = p.to_string_lossy();
        if s.contains(char::is_whitespace) || s.contains(',') {
            anyhow::bail!(
                "AWG_INSTALL_SCRIPT must not contain whitespace or commas, got: {}",
                p.display()
            );
        }
        if !p.is_file() {
            warn!(
                path = %p.display(),
                "AWG_INSTALL_SCRIPT not found; user lifecycle features will fail until the script is installed"
            );
        } else {
            // Best-effort executable check on Unix.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(p)
                    .with_context(|| format!("cannot stat AWG_INSTALL_SCRIPT: {}", p.display()))?;
                if meta.permissions().mode() & 0o111 == 0 {
                    anyhow::bail!(
                        "AWG_INSTALL_SCRIPT is not executable: {}",
                        p.display()
                    );
                }
            }
        }
        info!(path = %p.display(), "install script validated");
    }

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
        session_ttl: std::time::Duration::from_secs(config.auth_session_ttl_secs),
    };

    // --- Database -----------------------------------------------------------
    let db = Database::connect(&config.database_url)
        .await
        .context("failed to open database")?;
    db.migrate().await.context("database migration failed")?;
    info!("database ready");

    // --- Background poller --------------------------------------------------
    let config_dir = config.config_dir.clone();
    let poller = Poller::new(db.clone(), config.poll_interval, config.config_dir);
    tokio::spawn(async move {
        poller.run().await;
    });

    // --- HTTP server --------------------------------------------------------
    let app = router(db, auth, config_dir, config.install_script);
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("failed to bind TCP listener")?;
    info!(addr = %config.listen, "HTTP server listening");
    axum::serve(listener, app)
        .await
        .context("HTTP server error")?;

    Ok(())
}
