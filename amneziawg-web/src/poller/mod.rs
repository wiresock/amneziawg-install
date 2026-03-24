//! Background polling task.
//!
//! Every `interval` seconds the poller runs a full cycle:
//!
//! 1. Calls `awg::show_all_dump()` – reads current AWG state.
//! 2. Writes a snapshot row per peer into `snapshots`.
//! 3. Upserts each peer into the `peers` table.
//! 4. Scans the config directory for `*.conf` files.
//! 5. Applies config-to-peer mapping (sets `has_config`, `config_name`,
//!    `config_path` on matching peers).
//!
//! Errors within a single cycle step are logged and the cycle continues;
//! the overall polling loop never stops due to a single-cycle failure.

use std::path::PathBuf;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::awg;
use crate::config_store;
use crate::db::Database;
use crate::domain::PublicKey;

pub struct Poller {
    db: Database,
    interval: Duration,
    /// Directory to scan for `*.conf` client config files.
    config_dir: PathBuf,
}

impl Poller {
    pub fn new(db: Database, interval_secs: u64, config_dir: PathBuf) -> Self {
        Self {
            db,
            interval: Duration::from_secs(interval_secs),
            config_dir,
        }
    }

    /// Run the polling loop forever.  Errors within a single cycle are logged
    /// and the loop continues with the next scheduled tick.
    pub async fn run(&self) {
        info!(
            interval_secs = self.interval.as_secs(),
            config_dir = %self.config_dir.display(),
            "poller started"
        );
        loop {
            if let Err(e) = self.poll_once().await {
                error!(error = %e, "poll cycle failed");
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn poll_once(&self) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        debug!("poll cycle starting");

        // ── Step 1–3: AWG data ───────────────────────────────────────────────
        let interfaces = match awg::show_all_dump() {
            Ok(ifaces) => ifaces,
            Err(awg::AwgError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("awg binary not found at /usr/bin/awg – skipping poll cycle");
                return Ok(());
            }
            Err(e) => {
                error!(error = %e, "awg show all dump failed");
                return Err(e.into());
            }
        };

        let peer_count: usize = interfaces.iter().map(|i| i.peers.len()).sum();
        info!(
            interface_count = interfaces.len(),
            peer_count, "awg data retrieved"
        );

        let now = chrono::Utc::now();
        let mut snapshots_written: usize = 0;

        for iface in &interfaces {
            for peer in &iface.peers {
                match self.store_snapshot(&peer.public_key, peer, now).await {
                    Ok(()) => snapshots_written += 1,
                    Err(e) => {
                        error!(
                            public_key = %peer.public_key,
                            error = %e,
                            "failed to write snapshot – continuing"
                        );
                    }
                }
                if let Err(e) = self.upsert_peer(&peer.public_key, peer).await {
                    error!(
                        public_key = %peer.public_key,
                        error = %e,
                        "failed to upsert peer – continuing"
                    );
                }
            }
        }

        info!(
            snapshots_written,
            elapsed_ms = start.elapsed().as_millis(),
            "awg poll step complete"
        );

        // ── Step 4–5: Config mapping ─────────────────────────────────────────
        if let Err(e) = self.apply_config_mapping_step().await {
            error!(error = %e, "config mapping step failed – continuing");
        }

        info!(
            elapsed_ms = start.elapsed().as_millis(),
            "poll cycle complete"
        );
        Ok(())
    }

    /// Scan the config directory and update `has_config`, `config_name`, and
    /// `config_path` on every peer.
    ///
    /// This operation is idempotent:
    /// 1. All config-mapping fields are first reset to NULL / 0 for every peer.
    /// 2. Each discovered config file is then matched to a peer by `public_key`
    ///    and the relevant fields are set.
    ///
    /// If the config directory cannot be read, a warning is logged and the
    /// step returns `Ok(())` (peers remain with `has_config = 0`).
    async fn apply_config_mapping_step(&self) -> anyhow::Result<()> {
        let configs = match config_store::scan(&self.config_dir) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    config_dir = %self.config_dir.display(),
                    error = %e,
                    "config scan failed – skipping config mapping"
                );
                return Ok(());
            }
        };

        debug!(
            total_configs = configs.len(),
            config_dir = %self.config_dir.display(),
            "config scan complete"
        );

        // Reset all mapping fields so that removed configs don't persist.
        crate::db::peers::clear_all_config_mappings(&self.db.pool).await?;

        let mut mapped: usize = 0;
        for config in &configs {
            let pk = match &config.peer_public_key {
                Some(k) => k,
                None => {
                    debug!(
                        config = %config.name,
                        "config has no [Peer] PublicKey – skipping"
                    );
                    continue;
                }
            };

            let path_str = config.path.to_string_lossy();
            match crate::db::peers::apply_config_mapping(
                &self.db.pool,
                &pk.0,
                &config.name,
                &path_str,
            )
            .await
            {
                Ok(()) => mapped += 1,
                Err(e) => {
                    warn!(
                        config = %config.name,
                        public_key = %pk,
                        error = %e,
                        "failed to apply config mapping – skipping"
                    );
                }
            }
        }

        info!(
            total_configs = configs.len(),
            mapped, "config mapping applied"
        );
        Ok(())
    }

    async fn store_snapshot(
        &self,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()> {
        let endpoint = peer.endpoint.as_deref();
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = peer.rx_bytes as i64;
        let tx = peer.tx_bytes as i64;
        let captured_str = captured_at.to_rfc3339();

        sqlx::query(
            "INSERT INTO snapshots \
             (public_key, captured_at, endpoint, last_handshake_at, rx_bytes, tx_bytes) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&public_key.0)
        .bind(&captured_str)
        .bind(endpoint)
        .bind(last_handshake)
        .bind(rx)
        .bind(tx)
        .execute(&self.db.pool)
        .await?;

        Ok(())
    }

    async fn upsert_peer(&self, public_key: &PublicKey, peer: &awg::AwgPeer) -> anyhow::Result<()> {
        let endpoint = peer.endpoint.as_deref();
        let allowed_ips = peer.allowed_ips.join(",");
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = peer.rx_bytes as i64;
        let tx = peer.tx_bytes as i64;

        sqlx::query(
            "INSERT INTO peers (public_key, endpoint, allowed_ips, last_handshake_at, rx_bytes, tx_bytes) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(public_key) DO UPDATE SET \
                 endpoint            = excluded.endpoint, \
                 allowed_ips         = excluded.allowed_ips, \
                 last_handshake_at   = excluded.last_handshake_at, \
                 rx_bytes            = excluded.rx_bytes, \
                 tx_bytes            = excluded.tx_bytes, \
                 updated_at          = CURRENT_TIMESTAMP",
        )
        .bind(&public_key.0)
        .bind(endpoint)
        .bind(&allowed_ips)
        .bind(last_handshake)
        .bind(rx)
        .bind(tx)
        .execute(&self.db.pool)
        .await?;

        Ok(())
    }
}
