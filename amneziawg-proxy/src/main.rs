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

    // Load AWG config if specified
    let awg_params = if let Some(ref awg_path) = cfg.awg_config {
        let path = PathBuf::from(awg_path);
        info!(path = %path.display(), "loading AmneziaWG configuration");
        let params = config::load_awg_config(&path)?;
        info!(
            jc = params.jc,
            jmin = params.jmin,
            jmax = params.jmax,
            s1 = params.s1,
            s2 = params.s2,
            s3 = params.s3,
            s4 = params.s4,
            h1_min = params.h1.min,
            h1_max = params.h1.max,
            h2_min = params.h2.min,
            h2_max = params.h2.max,
            h3_min = params.h3.min,
            h3_max = params.h3.max,
            h4_min = params.h4.min,
            h4_max = params.h4.max,
            "AWG parameters loaded"
        );
        Some(params)
    } else {
        info!("no AWG config specified, running without packet classification");
        None
    };

    let proxy = proxy::Proxy::bind(cfg, awg_params).await?;
    let shutdown = proxy.shutdown_handle();

    // Set up graceful shutdown on SIGINT / SIGTERM
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to register SIGTERM handler");
                    // Fall back to ctrl-c only.
                    match tokio::signal::ctrl_c().await {
                        Ok(()) => info!("received SIGINT"),
                        Err(e) => error!(error = %e, "failed to listen for SIGINT"),
                    }
                    shutdown_signal.notify_one();
                    return;
                }
            };
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    match result {
                        Ok(()) => info!("received SIGINT"),
                        Err(e) => error!(error = %e, "failed to listen for SIGINT"),
                    }
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
            }
        }
        #[cfg(not(unix))]
        {
            match tokio::signal::ctrl_c().await {
                Ok(()) => info!("received ctrl-c"),
                Err(e) => error!(error = %e, "failed to listen for ctrl-c"),
            }
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
