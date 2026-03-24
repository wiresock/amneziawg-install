//! Background polling task.
//!
//! Every `interval` seconds the poller:
//! 1. Calls `awg::show_all_dump()` (reads current AWG state).
//! 2. Writes a snapshot row per peer into `snapshots`.
//! 3. Upserts each peer into the `peers` table (creates new rows for unknown peers).
//! 4. Handles counter resets: if `rx_bytes` or `tx_bytes` decreased since the
//!    last snapshot, the value is treated as a reset and stored as-is.

use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::awg;
use crate::db::Database;
use crate::domain::PublicKey;

pub struct Poller {
    db: Database,
    interval: Duration,
}

impl Poller {
    pub fn new(db: Database, interval_secs: u64) -> Self {
        Self {
            db,
            interval: Duration::from_secs(interval_secs),
        }
    }

    /// Run the polling loop forever.  Errors within a single cycle are logged
    /// and the loop continues with the next scheduled tick.
    pub async fn run(&self) {
        info!(interval_secs = self.interval.as_secs(), "poller started");
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
            "poll cycle complete"
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
