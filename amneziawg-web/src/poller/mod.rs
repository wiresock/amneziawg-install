//! Background polling task.
//!
//! Uses `tokio::time::interval` so that cycles are tick-aligned: the period
//! between the *start* of consecutive cycles is `interval` seconds, regardless
//! of how long each cycle takes.
//!
//! 1. Calls `awg::show_all_dump()` on a blocking thread – reads current AWG state.
//! 2. Writes a snapshot row per peer into `snapshots`.
//! 3. Upserts each peer into the `peers` table.
//!    3b. Removes disabled peers from the running AWG interface
//!    (`awg set <iface> peer <key> remove`).  This is a self-healing
//!    safety net; immediate removal also happens at toggle time.
//! 4. Scans the config directory for `*.conf` files.
//! 5. Applies config-to-peer mapping (sets `has_config`, `config_name`,
//!    `config_path` on matching peers).
//! 6. Removes stale peers – DB rows for non-disabled peers whose public
//!    keys no longer appear on any AWG interface.  This cleans up
//!    artifacts left when peers are removed outside the web panel.
//!
//! Errors within a single cycle step are logged and the cycle continues;
//! the overall polling loop never stops due to a single-cycle failure.
//! Expired managed users are removed before each AWG snapshot, including the
//! poller's immediate first cycle at process startup.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use chrono::SecondsFormat;
use tokio::sync::{Mutex, MutexGuard};
use tracing::{debug, error, info, warn};

use crate::awg;
use crate::config_store;
use crate::db::Database;
use crate::domain::PublicKey;

/// Serializes access to the clear-all + re-map sequence so that concurrent
/// calls from the poller and on-demand `rescan_configs` cannot interleave, and
/// archive eligibility checks cannot observe the transient cleared state.
static CONFIG_MAPPING_LOCK: Mutex<()> = Mutex::const_new(());

/// Serialize config discovery/mapping with newly-created peer persistence and
/// peer archival eligibility checks.
///
/// The guard deliberately covers the directory scan as well as the database
/// clear-and-remap sequence, so a scan cannot apply a pre-creation snapshot
/// after creation metadata has been stored.
pub(crate) async fn acquire_config_mapping_lock() -> MutexGuard<'static, ()> {
    CONFIG_MAPPING_LOCK.lock().await
}

#[derive(Clone)]
pub struct Poller {
    db: Database,
    interval: Duration,
    /// Directory to scan for `*.conf` client config files.
    config_dir: PathBuf,
    /// Persistent directory whose descriptor serializes client lifecycle work.
    lifecycle_lock_dir: PathBuf,
    /// Maximum age of snapshots in days before cleanup (0 = disabled).
    snapshot_retention_days: u32,
}

impl Poller {
    #[cfg(test)]
    pub fn new(db: Database, interval_secs: u64, config_dir: PathBuf) -> Self {
        Self::new_full(db, interval_secs, config_dir.clone(), config_dir, 0)
    }

    pub fn new_full(
        db: Database,
        interval_secs: u64,
        config_dir: PathBuf,
        lifecycle_lock_dir: PathBuf,
        snapshot_retention_days: u32,
    ) -> Self {
        Self {
            db,
            interval: Duration::from_secs(interval_secs),
            config_dir,
            lifecycle_lock_dir,
            snapshot_retention_days,
        }
    }

    #[cfg(test)]
    pub fn with_retention_days(mut self, days: u32) -> Self {
        self.snapshot_retention_days = days;
        self
    }

    /// Run the polling loop and independent retention task forever.
    pub async fn run(&self) {
        if self.snapshot_retention_days > 0 {
            info!(
                interval_secs = self.interval.as_secs(),
                snapshot_retention_days = self.snapshot_retention_days,
                config_dir = %self.config_dir.display(),
                "poller started (snapshot retention enabled)"
            );
        } else {
            info!(
                interval_secs = self.interval.as_secs(),
                config_dir = %self.config_dir.display(),
                "poller started (snapshot retention disabled)"
            );
        }

        tokio::join!(self.run_poll_loop(), self.run_retention_loop());
    }

    async fn run_poll_loop(&self) {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.poll_once().await {
                error!(error = %e, "poll cycle failed");
            }
        }
    }

    /// Independent retention loop that runs snapshot cleanup on startup and
    /// subsequently every hour. If a deletable (non-baseline) snapshot backlog
    /// remains, continues draining in bounded chunks with a 1-second pause
    /// between steps until fully cleared. AWG dump collection runs on the
    /// blocking pool, so a slow `awg` command does not stall this timer.
    pub async fn run_retention_loop(&self) {
        self.run_retention_loop_with_intervals(Duration::from_secs(3600), Duration::from_secs(1))
            .await;
    }

    pub async fn run_retention_loop_with_intervals(
        &self,
        interval: Duration,
        backlog_delay: Duration,
    ) {
        if self.snapshot_retention_days == 0 {
            return;
        }

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;

            let mut more_remaining = self.cleanup_expired_snapshots_step().await;
            while more_remaining {
                tokio::time::sleep(backlog_delay).await;
                more_remaining = self.cleanup_expired_snapshots_step().await;
            }

            ticker.reset();
        }
    }

    async fn poll_once(&self) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        debug!("poll cycle starting");

        // ── Step 0: Expired-user cleanup ────────────────────────────────────
        // The first interval tick fires immediately, so this also catches
        // expirations missed while the web service was stopped. Running it
        // before AWG discovery means cleanup is still attempted if AWG status
        // collection fails later in the cycle.
        match crate::admin::cleanup_expired_users(
            &self.db,
            &self.config_dir,
            &self.lifecycle_lock_dir,
        )
        .await
        {
            Ok(removed) if removed > 0 => {
                info!(removed, "expired-user cleanup complete");
            }
            Ok(_) => {}
            Err(e) => {
                error!(error = %e, "expired-user cleanup query failed – continuing");
            }
        }

        // ── Step 1–3: AWG data ───────────────────────────────────────────────
        // `awg show all dump` is a blocking process; run it off the async
        // executor so the independent retention timer (and HTTP tasks) can
        // still be polled while the command is in flight.
        let interfaces = match collect_awg_dump().await {
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
        let snapshots_written = match self.record_poll_batch(&interfaces, now).await {
            Ok(count) => count,
            Err(e) => {
                error!(error = %e, "failed to record poll batch – continuing");
                0
            }
        };

        info!(
            snapshots_written,
            elapsed_ms = start.elapsed().as_millis(),
            "awg poll step complete"
        );

        // ── Step 3b: Enforce disabled peers ──────────────────────────────────
        // Remove peers that are flagged as disabled in the DB but still present
        // on the running AWG interface.  This is a self-healing safety net:
        // immediate removal also happens at toggle time (web/admin handlers),
        // but the poller ensures eventual consistency (e.g. after an AWG
        // restart that re-reads the on-disk config).
        if let Err(e) = self.enforce_disabled_peers(&interfaces).await {
            error!(error = %e, "enforce-disabled step failed – continuing");
        }

        // ── Step 4–5: Config mapping ─────────────────────────────────────────
        if let Err(e) = self.apply_config_mapping_step().await {
            error!(error = %e, "config mapping step failed – continuing");
        }

        // ── Step 6: Remove stale peers ───────────────────────────────────────
        // Delete DB peers that no longer appear on any AWG interface and are
        // not administratively disabled.  This cleans up artifacts left when
        // a peer is removed outside the web panel (e.g. via the install
        // script's --remove-client flag).
        if let Err(e) = self.remove_stale_peers(&interfaces).await {
            error!(error = %e, "stale-peer cleanup failed – continuing");
        }

        info!(
            elapsed_ms = start.elapsed().as_millis(),
            "poll cycle complete"
        );
        Ok(())
    }

    /// Remove peers that are disabled in the database but still present on the
    /// running AWG interface.
    ///
    /// Iterates over every peer reported by `awg show all dump`.  If a peer's
    /// public key is marked `disabled = 1` in the DB, it is removed from the
    /// interface via `awg set <iface> peer <pubkey> remove`.
    ///
    /// The actual removal commands are blocking (`std::process::Command`) and
    /// are offloaded to `tokio::task::spawn_blocking` so the poller task stays
    /// responsive.
    ///
    /// Errors on individual peer removals are logged but do not abort the
    /// remaining removals.
    async fn enforce_disabled_peers(&self, interfaces: &[awg::AwgInterface]) -> anyhow::Result<()> {
        let disabled_keys = crate::db::peers::list_disabled_public_keys(&self.db.pool).await?;

        if disabled_keys.is_empty() {
            return Ok(());
        }

        // Collect (interface_name, public_key) pairs that need removal.
        let to_remove: Vec<(String, String)> = interfaces
            .iter()
            .flat_map(|iface| {
                iface
                    .peers
                    .iter()
                    .filter(|p| disabled_keys.contains(&p.public_key.0))
                    .map(|p| (iface.name.clone(), p.public_key.0.clone()))
            })
            .collect();

        if to_remove.is_empty() {
            return Ok(());
        }

        // Offload the blocking awg commands to a dedicated thread.
        let result = tokio::task::spawn_blocking(move || {
            let mut removed: usize = 0;
            for (iface_name, public_key) in &to_remove {
                info!(
                    interface = %iface_name,
                    public_key = %public_key,
                    "removing disabled peer from interface"
                );
                match awg::remove_peer(iface_name, public_key) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        error!(
                            interface = %iface_name,
                            public_key = %public_key,
                            error = %e,
                            "failed to remove disabled peer – continuing"
                        );
                    }
                }
            }
            removed
        })
        .await;

        match result {
            Ok(removed) if removed > 0 => {
                info!(removed, "disabled peers removed from interface");
            }
            Err(e) if e.is_panic() => {
                error!(error = %e, "spawn_blocking for peer removal panicked");
            }
            Err(e) if e.is_cancelled() => {
                warn!(error = %e, "spawn_blocking for peer removal was cancelled");
            }
            Err(e) => {
                error!(error = %e, "spawn_blocking for peer removal failed");
            }
            _ => {}
        }
        Ok(())
    }

    /// Scan the config directory and update `has_config`, `config_name`,
    /// `config_path`, and `friendly_name` on every peer.
    ///
    /// This operation is idempotent:
    /// 1. All config-mapping fields are first reset to NULL / 0 for every peer.
    /// 2. Each discovered config file is matched to a peer by `public_key`
    ///    first; if no key match is found, a fallback match via AllowedIPs
    ///    is attempted.
    ///
    /// If the config directory cannot be read, a warning is logged and the
    /// step returns `Ok(())` — existing config-mapping fields are **not**
    /// cleared (they retain whatever values they had from the previous cycle).
    async fn apply_config_mapping_step(&self) -> anyhow::Result<()> {
        let _guard = acquire_config_mapping_lock().await;
        let config_dir = self.config_dir.clone();
        let configs =
            match tokio::task::spawn_blocking(move || config_store::scan(&config_dir)).await {
                Ok(scan_result) => scan_result,
                Err(e) => {
                    warn!(
                        config_dir = %self.config_dir.display(),
                        error = %e,
                        "config scan task failed – skipping config mapping"
                    );
                    return Ok(());
                }
            };

        let configs = match configs {
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

        apply_config_mappings(&self.db, &configs).await
    }

    /// Purge snapshots older than `snapshot_retention_days` (if configured > 0).
    ///
    /// Each peer keeps its newest pre-cutoff snapshot as a usage baseline.
    /// Returns the number of snapshots deleted.
    #[cfg(test)]
    pub async fn cleanup_expired_snapshots(&self) -> anyhow::Result<u64> {
        if self.snapshot_retention_days == 0 {
            return Ok(0);
        }

        let retention_duration = match chrono::Duration::try_days(
            self.snapshot_retention_days as i64,
        ) {
            Some(dur) if self.snapshot_retention_days <= 36_500 => dur,
            _ => {
                warn!(
                    days = self.snapshot_retention_days,
                    "snapshot retention days exceeds maximum supported range (36500); skipping cleanup"
                );
                return Ok(0);
            }
        };

        let cutoff = chrono::Utc::now() - retention_duration;
        let cutoff_str = cutoff.to_rfc3339_opts(SecondsFormat::Secs, true);
        let res =
            crate::db::peers::delete_expired_snapshots(&self.db.pool, &cutoff_str, 5000, None)
                .await?;
        Ok(res.deleted)
    }

    pub async fn cleanup_expired_snapshots_step(&self) -> bool {
        if self.snapshot_retention_days == 0 {
            return false;
        }

        let retention_duration = match chrono::Duration::try_days(
            self.snapshot_retention_days as i64,
        ) {
            Some(dur) if self.snapshot_retention_days <= 36_500 => dur,
            _ => {
                warn!(
                    days = self.snapshot_retention_days,
                    "snapshot retention days exceeds maximum supported range (36500); skipping cleanup"
                );
                return false;
            }
        };

        let cutoff = chrono::Utc::now() - retention_duration;
        let cutoff_str = cutoff.to_rfc3339_opts(SecondsFormat::Secs, true);

        // Cap to 2 batches (up to 10,000 rows) per step with 25ms pause between batches,
        // preventing prolonged lock contention and yielding the SQLite write lock.
        match crate::db::peers::delete_expired_snapshots(&self.db.pool, &cutoff_str, 5000, Some(2))
            .await
        {
            Ok(result) => {
                if result.deleted > 0 {
                    info!(
                        deleted = result.deleted,
                        more_remaining = result.more_remaining,
                        retention_days = self.snapshot_retention_days,
                        "expired snapshot cleanup progress"
                    );
                }
                result.more_remaining
            }
            Err(e) => {
                error!(error = %e, "expired snapshot cleanup failed – continuing");
                false
            }
        }
    }

    async fn record_poll_batch(
        &self,
        interfaces: &[awg::AwgInterface],
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<usize> {
        let mut tx = self
            .db
            .pool
            .begin()
            .await
            .context("begin poll batch transaction")?;
        let mut snapshots_written = 0;

        for iface in interfaces {
            for peer in &iface.peers {
                match self
                    .store_snapshot_tx(&mut tx, &peer.public_key, peer, now)
                    .await
                {
                    Ok(true) => snapshots_written += 1,
                    Ok(false) => {
                        debug!(
                            public_key = %peer.public_key,
                            "snapshot skipped for archived peer"
                        );
                    }
                    Err(e) => {
                        error!(
                            public_key = %peer.public_key,
                            error = %e,
                            "failed to write snapshot in batch"
                        );
                        return Err(e);
                    }
                }

                if let Err(e) = self.upsert_peer_tx(&mut tx, &peer.public_key, peer).await {
                    error!(
                        public_key = %peer.public_key,
                        error = %e,
                        "failed to upsert peer in batch"
                    );
                    return Err(e);
                }
            }
        }

        tx.commit().await.context("commit poll batch transaction")?;
        Ok(snapshots_written)
    }

    async fn store_snapshot_tx(
        &self,
        tx: &mut sqlx::SqliteConnection,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let endpoint = peer.endpoint.as_deref();
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = saturating_u64_to_i64(peer.rx_bytes);
        let tx_bytes = saturating_u64_to_i64(peer.tx_bytes);
        let captured_str = captured_at.to_rfc3339_opts(SecondsFormat::Secs, true);

        let result = sqlx::query(
            "INSERT INTO snapshots \
             (public_key, captured_at, endpoint, last_handshake_at, rx_bytes, tx_bytes) \
             SELECT ?, ?, ?, ?, ?, ? \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM peers WHERE public_key = ? AND archived = 1 \
             )",
        )
        .bind(&public_key.0)
        .bind(&captured_str)
        .bind(endpoint)
        .bind(last_handshake)
        .bind(rx)
        .bind(tx_bytes)
        .bind(&public_key.0)
        .execute(tx)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    #[cfg(test)]
    async fn store_snapshot(
        &self,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let mut tx = self.db.pool.begin().await?;
        let res = self
            .store_snapshot_tx(&mut tx, public_key, peer, captured_at)
            .await?;
        tx.commit().await?;
        Ok(res)
    }

    async fn upsert_peer_tx(
        &self,
        tx: &mut sqlx::SqliteConnection,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
    ) -> anyhow::Result<()> {
        let endpoint = peer.endpoint.as_deref();
        let allowed_ips = peer.allowed_ips.join(",");
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = saturating_u64_to_i64(peer.rx_bytes);
        let tx_bytes = saturating_u64_to_i64(peer.tx_bytes);

        sqlx::query(
            "INSERT INTO peers (public_key, endpoint, allowed_ips, last_handshake_at, rx_bytes, tx_bytes) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(public_key) DO UPDATE SET \
                 endpoint            = excluded.endpoint, \
                 allowed_ips         = excluded.allowed_ips, \
                 last_handshake_at   = excluded.last_handshake_at, \
                 rx_bytes            = excluded.rx_bytes, \
                 tx_bytes            = excluded.tx_bytes, \
                 sync_pending        = 0, \
                 updated_at          = CURRENT_TIMESTAMP \
             WHERE peers.archived = 0",
        )
        .bind(&public_key.0)
        .bind(endpoint)
        .bind(&allowed_ips)
        .bind(last_handshake)
        .bind(rx)
        .bind(tx_bytes)
        .execute(tx)
        .await?;

        Ok(())
    }

    #[cfg(test)]
    async fn upsert_peer(&self, public_key: &PublicKey, peer: &awg::AwgPeer) -> anyhow::Result<()> {
        let mut tx = self.db.pool.begin().await?;
        self.upsert_peer_tx(&mut tx, public_key, peer).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete DB peers that no longer appear on any AWG interface and are not
    /// administratively disabled.
    ///
    /// This cleans up artifacts left when a peer is removed outside the web
    /// panel (e.g. via the install script's `--remove-client` flag).  Disabled
    /// peers are preserved because they were intentionally marked via the UI.
    async fn remove_stale_peers(&self, interfaces: &[awg::AwgInterface]) -> anyhow::Result<()> {
        // If no interfaces were returned we cannot tell whether all peers are
        // truly gone or AWG is simply down / not configured.  Skip cleanup to
        // avoid accidentally deleting every non-disabled peer.
        if interfaces.is_empty() {
            warn!("no AWG interfaces found – skipping stale-peer cleanup");
            return Ok(());
        }

        let active_keys: std::collections::HashSet<String> = interfaces
            .iter()
            .flat_map(|iface| iface.peers.iter().map(|p| p.public_key.0.clone()))
            .collect();

        let now = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let stale = crate::db::peers::delete_stale_peers(&self.db.pool, &active_keys, &now).await?;

        if !stale.is_empty() {
            info!(removed = stale.len(), "stale peers removed from database");
        }

        Ok(())
    }
}

/// Run blocking `awg show all dump` off the async executor.
///
/// A hung or slow AWG command still occupies a blocking-pool thread until it
/// returns, but it must not stall the Tokio worker that drives the retention
/// timer and HTTP tasks.
async fn collect_awg_dump() -> Result<Vec<awg::AwgInterface>, awg::AwgError> {
    collect_awg_dump_with(awg::show_all_dump).await
}

#[allow(clippy::io_other_error)] // Error::other requires Rust 1.83; crate MSRV is 1.75
async fn collect_awg_dump_with<F>(dump: F) -> Result<Vec<awg::AwgInterface>, awg::AwgError>
where
    F: FnOnce() -> Result<Vec<awg::AwgInterface>, awg::AwgError> + Send + 'static,
{
    match tokio::task::spawn_blocking(dump).await {
        Ok(result) => result,
        Err(e) if e.is_panic() => {
            error!(error = %e, "spawn_blocking for awg dump panicked");
            Err(awg::AwgError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "awg dump task panicked",
            )))
        }
        Err(e) if e.is_cancelled() => {
            error!(error = %e, "spawn_blocking for awg dump was cancelled");
            Err(awg::AwgError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "awg dump task was cancelled",
            )))
        }
        Err(e) => {
            error!(error = %e, "spawn_blocking for awg dump failed");
            Err(awg::AwgError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "awg dump task failed",
            )))
        }
    }
}

/// Perform a one-shot AWG peer snapshot into the `peers` table.
///
/// Unlike the full poller cycle, this helper does not write traffic snapshots
/// and does not touch config mapping; it only upserts the latest peer rows so
/// UI pages can reflect lifecycle changes immediately.
pub async fn sync_peers_from_awg(db: &crate::db::Database) -> anyhow::Result<()> {
    let interfaces = match collect_awg_dump().await {
        Ok(ifaces) => ifaces,
        Err(awg::AwgError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("awg binary not found at /usr/bin/awg – skipping one-shot peer sync");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let mut tx = db.pool.begin().await.context("begin sync_peers tx")?;
    for iface in &interfaces {
        for peer in &iface.peers {
            let endpoint = peer.endpoint.as_deref();
            let allowed_ips = peer.allowed_ips.join(",");
            let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
            let rx = saturating_u64_to_i64(peer.rx_bytes);
            let tx_bytes = saturating_u64_to_i64(peer.tx_bytes);

            sqlx::query(
                "INSERT INTO peers (public_key, endpoint, allowed_ips, last_handshake_at, rx_bytes, tx_bytes) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(public_key) DO UPDATE SET \
                     endpoint            = excluded.endpoint, \
                     allowed_ips         = excluded.allowed_ips, \
                     last_handshake_at   = excluded.last_handshake_at, \
                     rx_bytes            = excluded.rx_bytes, \
                     tx_bytes            = excluded.tx_bytes, \
                     updated_at          = CURRENT_TIMESTAMP \
                 WHERE peers.archived = 0",
            )
            .bind(&peer.public_key.0)
            .bind(endpoint)
            .bind(&allowed_ips)
            .bind(last_handshake)
            .bind(rx)
            .bind(tx_bytes)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await.context("commit sync_peers tx")?;

    Ok(())
}

/// Convert a `u64` counter to `i64`, capping at [`i64::MAX`] instead of
/// silently wrapping.  Traffic counters from `awg show` can theoretically
/// exceed `i64::MAX` (~9.2 EiB), but saturating avoids writing incorrect
/// negative values into SQLite.
fn saturating_u64_to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Extract the base IP address from a CIDR string (e.g. `"10.8.0.2/32"` → `"10.8.0.2"`).
fn base_ip(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or(cidr)
}

/// Shared config-to-peer mapping logic used by both the poller cycle and
/// on-demand rescan.  Resets all mappings, then applies Strategy 1 (public-key)
/// and Strategy 2 (AllowedIPs fallback) for each config.
///
/// Callers hold [`CONFIG_MAPPING_LOCK`] across both their directory scan and
/// this clear-and-remap sequence.
async fn apply_config_mappings(
    db: &crate::db::Database,
    configs: &[config_store::ClientConfig],
) -> anyhow::Result<()> {
    // Reset all mapping fields so that removed configs don't persist.
    crate::db::peers::clear_all_config_mappings(&db.pool).await?;

    // Load all peers from the DB for AllowedIPs fallback matching.
    let all_peers = crate::db::peers::list_visible(&db.pool).await?;

    let mut mapped: usize = 0;
    let mut mapped_by_ip: usize = 0;
    for config in configs {
        let path_str = config.path.to_string_lossy();
        let managed_client_name = crate::admin::script_bridge::managed_client_name_from_config(
            &config.name,
            &config.friendly_name,
        );

        // ── Strategy 1: exact public-key match ──────────────────
        //
        // The `[Peer] PublicKey` in a client config refers to the
        // *server's* key, so it will only match a peer whose public
        // key happens to equal that value (i.e. if the config dir
        // also contains server-side configs).  If no peer matches,
        // we fall through to Strategy 2 instead of giving up.
        if let Some(pk) = &config.peer_public_key {
            match crate::db::peers::apply_config_mapping(
                &db.pool,
                &pk.0,
                &config.name,
                &path_str,
                &config.friendly_name,
                managed_client_name,
            )
            .await
            {
                Ok(true) => {
                    mapped += 1;
                    debug!(
                        config = %config.name,
                        friendly_name = %config.friendly_name,
                        public_key = %pk,
                        "config linked by public key"
                    );
                    continue;
                }
                Ok(false) => {
                    // No peer matched this public key (common: the key
                    // in a client config is normally the server's key).
                    // Fall through to AllowedIPs matching.
                    debug!(
                        config = %config.name,
                        public_key = %pk,
                        "no peer matched [Peer] PublicKey – trying AllowedIPs fallback"
                    );
                }
                Err(e) => {
                    warn!(
                        config = %config.name,
                        public_key = %pk,
                        error = %e,
                        "failed to apply config mapping – skipping"
                    );
                    continue;
                }
            }
        }

        // ── Strategy 2: AllowedIPs fallback ─────────────────────
        // Attempt to match by comparing the config's Address field
        // with peer AllowedIPs.  Only match if unambiguous (exactly one).
        if !config.addresses.is_empty() {
            let candidates: Vec<_> = all_peers
                .iter()
                .filter(|p| {
                    config.addresses.iter().any(|addr| {
                        let addr_base = base_ip(addr);
                        p.allowed_ips
                            .split(',')
                            .any(|a| base_ip(a.trim()) == addr_base)
                    })
                })
                .collect();

            if candidates.len() == 1 {
                let peer = candidates[0];
                match crate::db::peers::apply_config_mapping(
                    &db.pool,
                    &peer.public_key,
                    &config.name,
                    &path_str,
                    &config.friendly_name,
                    managed_client_name,
                )
                .await
                {
                    Ok(true) => {
                        mapped_by_ip += 1;
                        info!(
                            config = %config.name,
                            friendly_name = %config.friendly_name,
                            public_key = %peer.public_key,
                            "config linked by AllowedIPs fallback"
                        );
                    }
                    Ok(false) => {
                        warn!(
                            config = %config.name,
                            public_key = %peer.public_key,
                            "AllowedIPs candidate peer vanished between query and update"
                        );
                    }
                    Err(e) => {
                        warn!(
                            config = %config.name,
                            error = %e,
                            "failed to apply AllowedIPs config mapping – skipping"
                        );
                    }
                }
            } else if candidates.len() > 1 {
                warn!(
                    config = %config.name,
                    candidate_count = candidates.len(),
                    "ambiguous AllowedIPs match – skipping config mapping"
                );
            } else {
                debug!(
                    config = %config.name,
                    "no [Peer] PublicKey and no AllowedIPs match – skipping"
                );
            }
        } else {
            debug!(
                config = %config.name,
                "config has no [Peer] PublicKey and no addresses – skipping"
            );
        }
    }

    info!(
        total_configs = configs.len(),
        mapped_by_key = mapped,
        mapped_by_ip = mapped_by_ip,
        "config mapping applied"
    );
    Ok(())
}

/// Perform a one-shot config-directory rescan and update peer mappings.
///
/// Uses `spawn_blocking` for the filesystem scan to avoid blocking the
/// Tokio runtime, then delegates to the shared `apply_config_mappings`
/// helper (same logic the poller uses every cycle).
pub async fn rescan_configs(
    db: &crate::db::Database,
    config_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let _guard = acquire_config_mapping_lock().await;
    let dir = config_dir.to_path_buf();
    let configs = match tokio::task::spawn_blocking(move || config_store::scan(&dir)).await {
        Ok(scan_result) => scan_result,
        Err(e) => {
            warn!(
                config_dir = %config_dir.display(),
                error = %e,
                "config scan task failed during rescan"
            );
            return Ok(());
        }
    };

    let configs = match configs {
        Ok(c) => c,
        Err(e) => {
            warn!(
                config_dir = %config_dir.display(),
                error = %e,
                "config scan failed during rescan"
            );
            return Ok(());
        }
    };

    apply_config_mappings(db, &configs).await?;
    info!("on-demand config rescan complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn collect_awg_dump_propagates_success() {
        let result = collect_awg_dump_with(|| Ok(Vec::new())).await;
        assert!(result.expect("success").is_empty());
    }

    #[tokio::test]
    async fn collect_awg_dump_propagates_awg_error() {
        let result = collect_awg_dump_with(|| Err(awg::AwgError::Parse("bad dump".into()))).await;
        assert!(matches!(result, Err(awg::AwgError::Parse(_))));
    }

    #[tokio::test]
    async fn collect_awg_dump_propagates_blocking_panic() {
        let result = collect_awg_dump_with(|| panic!("awg dump panicked")).await;
        match result {
            Err(awg::AwgError::Io(err)) => {
                assert!(err.to_string().contains("panicked"));
            }
            other => panic!("expected Io panic error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn collect_awg_dump_does_not_starve_async_work() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let dump = tokio::spawn(async move {
            collect_awg_dump_with(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
                Ok(Vec::new())
            })
            .await
        });

        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .expect("blocking dump should start without occupying the async worker")
            .expect("oneshot");

        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::time::sleep(Duration::from_millis(30)),
        )
        .await
        .expect("retention/HTTP timers must fire while AWG collection is blocked");

        release_tx.send(()).expect("release blocking dump");
        dump.await.expect("join dump task").expect("dump result");
    }

    #[tokio::test]
    async fn poller_writes_cannot_repopulate_an_archived_peer() {
        let db = Database::connect_for_test().await.expect("test database");
        let public_key = PublicKey("KEY_ARCHIVED_POLLER=".to_string());
        let id = sqlx::query(
            "INSERT INTO peers (public_key, display_name, comment, allowed_ips, disabled) \
             VALUES (?, 'Old name', 'Old comment', '10.8.0.2/32', 1)",
        )
        .bind(&public_key.0)
        .execute(&db.pool)
        .await
        .expect("insert peer")
        .last_insert_rowid();

        let outcome = crate::db::peers::archive_peer_data(&db.pool, id, "admin")
            .await
            .expect("archive peer");
        assert!(matches!(
            outcome,
            crate::db::peers::ArchivePeerOutcome::Archived { .. }
        ));

        let observed = awg::AwgPeer {
            public_key: public_key.clone(),
            endpoint: Some("198.51.100.9:51820".to_string()),
            allowed_ips: vec!["10.8.0.2/32".to_string()],
            last_handshake: Some(Utc::now()),
            rx_bytes: 123,
            tx_bytes: 456,
        };
        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));

        assert!(!poller
            .store_snapshot(&public_key, &observed, Utc::now())
            .await
            .expect("store guarded snapshot"));
        poller
            .upsert_peer(&public_key, &observed)
            .await
            .expect("guarded peer upsert");

        let row = crate::db::peers::find_by_id(&db.pool, id)
            .await
            .expect("find peer")
            .expect("archived tombstone");
        assert_eq!(row.archived, 1);
        assert_eq!(row.disabled, 1);
        assert!(row.display_name.is_none());
        assert!(row.comment.is_none());
        assert!(row.endpoint.is_none());
        assert!(row.allowed_ips.is_empty());
        assert_eq!(row.rx_bytes, 0);
        assert_eq!(row.tx_bytes, 0);

        let snapshots: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM snapshots WHERE public_key = ?")
                .bind(&public_key.0)
                .fetch_one(&db.pool)
                .await
                .expect("count snapshots");
        assert_eq!(snapshots, 0);
    }

    #[tokio::test]
    async fn record_poll_batch_writes_snapshots_and_upserts_peers() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk1 = PublicKey("KEY_BATCH_1=".to_string());
        let pk2 = PublicKey("KEY_BATCH_2=".to_string());

        let peer1 = awg::AwgPeer {
            public_key: pk1.clone(),
            endpoint: Some("198.51.100.10:51820".to_string()),
            allowed_ips: vec!["10.8.0.2/32".to_string()],
            last_handshake: Some(Utc::now()),
            rx_bytes: 1000,
            tx_bytes: 2000,
        };
        let peer2 = awg::AwgPeer {
            public_key: pk2.clone(),
            endpoint: Some("198.51.100.11:51820".to_string()),
            allowed_ips: vec!["10.8.0.3/32".to_string()],
            last_handshake: Some(Utc::now()),
            rx_bytes: 3000,
            tx_bytes: 4000,
        };

        let iface = awg::AwgInterface {
            name: "awg0".to_string(),
            public_key: PublicKey("SERVER_PUBKEY=".to_string()),
            listen_port: Some(51820),
            peers: vec![peer1, peer2],
        };

        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));
        let written = poller
            .record_poll_batch(&[iface], Utc::now())
            .await
            .expect("record batch");
        assert_eq!(written, 2);

        let row1 = crate::db::peers::find_by_public_key(&db.pool, &pk1.0)
            .await
            .expect("find peer1")
            .expect("peer1 exists");
        assert_eq!(row1.rx_bytes, 1000);
        assert_eq!(row1.tx_bytes, 2000);

        let snaps1 = crate::db::peers::find_snapshots(&db.pool, &pk1.0, 10)
            .await
            .expect("find snapshots");
        assert_eq!(snaps1.len(), 1);
        assert_eq!(snaps1[0].rx_bytes, 1000);
        assert_eq!(snaps1[0].tx_bytes, 2000);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_respects_retention_days() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_RETENTION=";

        // Insert older snapshot (40 days ago) and newer snapshot (10 days ago)
        let old_ts =
            (Utc::now() - chrono::Duration::days(40)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let new_ts =
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339_opts(SecondsFormat::Secs, true);

        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
        )
        .bind(pk)
        .bind(&old_ts)
        .execute(&db.pool)
        .await
        .expect("insert old snapshot");

        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 30, 40)",
        )
        .bind(pk)
        .bind(&new_ts)
        .execute(&db.pool)
        .await
        .expect("insert new snapshot");

        // Poller with 30-day retention: the 40-day row is the sparse baseline
        // and must be kept so 30-day usage can still compute a delta.
        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(30);
        let deleted = poller.cleanup_expired_snapshots().await.expect("cleanup");
        assert_eq!(deleted, 0);

        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 10)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().any(|row| row.captured_at == old_ts));
        assert!(remaining.iter().any(|row| row.captured_at == new_ts));
    }

    #[tokio::test]
    async fn cleanup_preserves_sparse_baseline_for_thirty_day_usage() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_SPARSE_USAGE=";
        let old_ts =
            (Utc::now() - chrono::Duration::days(40)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let new_ts =
            (Utc::now() - chrono::Duration::days(5)).to_rfc3339_opts(SecondsFormat::Secs, true);

        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 1000, 2000)",
        )
        .bind(pk)
        .bind(&old_ts)
        .execute(&db.pool)
        .await
        .expect("insert old snapshot");
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 5000, 8000)",
        )
        .bind(pk)
        .bind(&new_ts)
        .execute(&db.pool)
        .await
        .expect("insert new snapshot");

        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(31);
        let deleted = poller.cleanup_expired_snapshots().await.expect("cleanup");
        assert_eq!(deleted, 0);

        let window_start =
            (Utc::now() - chrono::Duration::days(30)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let baseline = crate::db::peers::find_baseline_snapshot(&db.pool, pk, &window_start)
            .await
            .expect("baseline")
            .expect("40-day snapshot must remain as the 30-day baseline");
        let in_window = crate::db::peers::find_snapshots_since(&db.pool, pk, &window_start)
            .await
            .expect("in-window");
        let mut inputs = vec![crate::domain::history::SnapshotInput {
            captured_at: baseline.captured_at,
            rx_bytes: baseline.rx_bytes as u64,
            tx_bytes: baseline.tx_bytes as u64,
        }];
        inputs.extend(
            in_window
                .into_iter()
                .map(|row| crate::domain::history::SnapshotInput {
                    captured_at: row.captured_at,
                    rx_bytes: row.rx_bytes as u64,
                    tx_bytes: row.tx_bytes as u64,
                }),
        );
        let summary = crate::domain::history::compute_usage_summary(&inputs);
        assert_eq!(summary.rx_total_delta, 4_000);
        assert_eq!(summary.tx_total_delta, 6_000);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_disabled_when_zero() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_RETENTION_ZERO=";

        let old_ts =
            (Utc::now() - chrono::Duration::days(100)).to_rfc3339_opts(SecondsFormat::Secs, true);
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
        )
        .bind(pk)
        .bind(&old_ts)
        .execute(&db.pool)
        .await
        .expect("insert old snapshot");

        // Poller with retention_days = 0 (disabled)
        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(0);
        let deleted = poller.cleanup_expired_snapshots().await.expect("cleanup");
        assert_eq!(deleted, 0);

        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 10)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_handles_overflow_gracefully() {
        let db = Database::connect_for_test().await.expect("test database");

        // Poller with overflow retention_days (e.g. 200,000 days or u32::MAX)
        let poller_huge =
            Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(200_000);
        let deleted = poller_huge
            .cleanup_expired_snapshots()
            .await
            .expect("must not panic on huge retention days");
        assert_eq!(deleted, 0);

        let poller_max =
            Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(u32::MAX);
        let deleted_max = poller_max
            .cleanup_expired_snapshots()
            .await
            .expect("must not panic on u32::MAX");
        assert_eq!(deleted_max, 0);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_step_retains_newest_pre_cutoff_snapshot() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_STEP_THROTTLE=";

        // Insert 12 old snapshots (50 days ago)
        for i in 1..=12 {
            let ts = (Utc::now() - chrono::Duration::days(50 + i))
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            sqlx::query(
                "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
            )
            .bind(pk)
            .bind(&ts)
            .execute(&db.pool)
            .await
            .expect("insert snapshot");
        }

        // Poller with 31 days retention
        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(31);
        poller.cleanup_expired_snapshots_step().await;

        // Cleanup was executed: 11 older rows go away, the newest pre-cutoff
        // snapshot is retained as the usage baseline.
        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 20)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn run_retention_loop_runs_on_startup_and_interval() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_RETENTION_LOOP=";

        // Insert 10 old snapshots (50 days ago)
        for i in 1..=10 {
            let ts = (Utc::now() - chrono::Duration::days(50 + i))
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            sqlx::query(
                "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
            )
            .bind(pk)
            .bind(&ts)
            .execute(&db.pool)
            .await
            .expect("insert snapshot");
        }

        // Create poller with 31 days retention and a 7200s poller interval (to verify it doesn't wait on poller)
        let poller = Poller::new(db.clone(), 7200, PathBuf::from(".")).with_retention_days(31);

        // Spawn retention loop with 50ms interval and 10ms backlog delay
        let poller_clone = poller.clone();
        let handle = tokio::spawn(async move {
            poller_clone
                .run_retention_loop_with_intervals(
                    Duration::from_millis(50),
                    Duration::from_millis(10),
                )
                .await;
        });

        // Give it a moment to run the startup cleanup
        tokio::time::sleep(Duration::from_millis(25)).await;

        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 20)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 1);

        // Insert more expired snapshots and verify the loop picks them up on the next tick
        for i in 1..=5 {
            let ts = (Utc::now() - chrono::Duration::days(50 + i))
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            sqlx::query(
                "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
            )
            .bind(pk)
            .bind(&ts)
            .execute(&db.pool)
            .await
            .expect("insert snapshot");
        }

        // Wait for the next 50ms tick
        tokio::time::sleep(Duration::from_millis(60)).await;

        let remaining_after = crate::db::peers::find_snapshots(&db.pool, pk, 20)
            .await
            .expect("find snapshots");
        assert_eq!(remaining_after.len(), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn concurrency_stress_test_file_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("stress_concurrency.db");
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let peer_count = 30;
        let mut pks = Vec::new();
        for i in 0..peer_count {
            let pk = format!("CONCURRENT_PK_{:03}=", i);
            sqlx::query("INSERT INTO peers (public_key, allowed_ips) VALUES (?, ?)")
                .bind(&pk)
                .bind(format!("10.8.0.{}/32", i + 2))
                .execute(&db.pool)
                .await
                .expect("seed peer");
            pks.push(pk);
        }

        // Seed expired snapshots (40 days old) crossing the 5,000-row batch boundary (6,000 rows)
        // to thoroughly exercise concurrent chunk deletion, inter-batch sleep, and lock yielding.
        let expired_count = 6000;
        let expired_ts =
            (Utc::now() - chrono::Duration::days(40)).to_rfc3339_opts(SecondsFormat::Secs, true);
        {
            let mut tx = db.pool.begin().await.expect("seed tx");
            for i in 0..expired_count {
                let pk = &pks[i % pks.len()];
                sqlx::query(
                    "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, ?, ?)",
                )
                .bind(pk)
                .bind(&expired_ts)
                .bind(100)
                .bind(200)
                .execute(&mut *tx)
                .await
                .expect("seed snapshot");
            }
            tx.commit().await.expect("commit seed tx");
        }

        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(31);

        // Writer task 1: Poller writing batches of snapshots and upserting peers
        let poller1 = poller.clone();
        let pks1 = pks.clone();
        let writer_task = tokio::spawn(async move {
            for round in 0..15 {
                let mut peers = Vec::new();
                for pk in &pks1 {
                    peers.push(awg::AwgPeer {
                        public_key: PublicKey(pk.clone()),
                        endpoint: Some("198.51.100.1:51820".to_string()),
                        allowed_ips: vec!["10.8.0.2/32".to_string()],
                        last_handshake: Some(Utc::now()),
                        rx_bytes: (round + 1) * 1000,
                        tx_bytes: (round + 1) * 2000,
                    });
                }
                let iface = awg::AwgInterface {
                    name: "awg0".to_string(),
                    public_key: PublicKey("SERVER_KEY=".to_string()),
                    listen_port: Some(51820),
                    peers,
                };
                poller1
                    .record_poll_batch(&[iface], Utc::now())
                    .await
                    .expect("record_poll_batch in writer task");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        // Writer task 2: Snapshot retention cleaner running concurrently
        let poller2 = poller.clone();
        let cleaner_task = tokio::spawn(async move {
            let mut total_deleted = 0u64;
            for _ in 0..10 {
                let deleted = poller2
                    .cleanup_expired_snapshots()
                    .await
                    .expect("cleanup in cleaner task");
                total_deleted += deleted;
                tokio::time::sleep(Duration::from_millis(8)).await;
            }
            total_deleted
        });

        // Reader task 1: API listing visible peers
        let db_r1 = db.clone();
        let reader_visible = tokio::spawn(async move {
            for _ in 0..30 {
                let peers = crate::db::peers::list_visible(&db_r1.pool)
                    .await
                    .expect("list_visible in reader");
                assert_eq!(peers.len(), peer_count);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        });

        // Reader task 2: Traffic history queries
        let db_r2 = db.clone();
        let pks2 = pks.clone();
        let reader_history = tokio::spawn(async move {
            for _ in 0..30 {
                for pk in pks2.iter().take(5) {
                    let _ = crate::db::peers::find_snapshots(&db_r2.pool, pk, 10)
                        .await
                        .expect("find_snapshots in reader");
                }
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        });

        // Writer task 3: Web handler updating metadata / disabling peers
        let db_w3 = db.clone();
        let pks3 = pks.clone();
        let web_updater = tokio::spawn(async move {
            for i in 0..15 {
                let target_pk = &pks3[i % pks3.len()];
                let row = crate::db::peers::find_by_public_key(&db_w3.pool, target_pk)
                    .await
                    .expect("find peer")
                    .expect("peer exists");
                let updated =
                    crate::db::peers::update_peer_disabled(&db_w3.pool, row.id, i % 2 == 1)
                        .await
                        .expect("update disabled");
                assert!(updated.is_some());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let (r1, r2, r3, r4, r5) = tokio::join!(
            writer_task,
            cleaner_task,
            reader_visible,
            reader_history,
            web_updater
        );
        r1.expect("writer task");
        let cleaner_deleted = r2.expect("cleaner task");
        r3.expect("reader visible task");
        r4.expect("reader history task");
        r5.expect("web updater task");

        // Each of the 30 peers keeps one pre-cutoff baseline; the rest of the
        // 6,000 expired rows are deleted across batch boundaries.
        assert_eq!(cleaner_deleted, (expired_count - peer_count) as u64);

        let expired_remaining: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE captured_at = ?")
                .bind(&expired_ts)
                .fetch_one(&db.pool)
                .await
                .expect("count expired snapshots");
        assert_eq!(expired_remaining.0, peer_count as i64);

        let fresh_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE captured_at > ?")
                .bind(&expired_ts)
                .fetch_one(&db.pool)
                .await
                .expect("count fresh snapshots");
        assert!(fresh_count.0 > 0);
    }
}
