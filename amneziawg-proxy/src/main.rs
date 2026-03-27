use std::path::PathBuf;

use amneziawg_proxy::config;
use amneziawg_proxy::proxy;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(false)
        .init();

    // Determine config path
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("proxy.toml"));

    info!(path = %config_path.display(), "loading configuration");

    let cfg = config::load_config(&config_path)?;
    info!(
        listen = %cfg.listen,
        backend = %cfg.backend,
        protocol = %cfg.imitate_protocol,
        session_ttl = cfg.session_ttl_secs,
        rate_limit = cfg.rate_limit_per_sec,
        "configuration loaded"
    );

    let proxy = proxy::Proxy::bind(cfg).await?;
    let shutdown = proxy.shutdown_handle();

    // Set up graceful shutdown on SIGINT / SIGTERM
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {
                    info!("received SIGINT");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.expect("failed to listen for ctrl-c");
            info!("received ctrl-c");
        }
        shutdown_signal.notify_one();
    });

    if let Err(e) = proxy.run().await {
        error!(error = %e, "proxy exited with error");
        std::process::exit(1);
    }

    info!("proxy shut down gracefully");
    Ok(())
}
