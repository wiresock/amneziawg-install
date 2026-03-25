//! Background polling task.
//!
//! Uses `tokio::time::interval` so that cycles are tick-aligned: the period
//! between the *start* of consecutive cycles is `interval` seconds, regardless
//! of how long each cycle takes.
//!
//! 1. Calls `awg::show_all_dump()` – reads current AWG state.
//! 2. Writes a snapshot row per peer into `snapshots`.
//! 3. Upserts each peer into the `peers` table.
//! 3b. Removes disabled peers from the running AWG interface
//!     (`awg set <iface> peer <key> remove`).  This is a self-healing
//!     safety net; immediate removal also happens at toggle time.
//! 4. Scans the config directory for `*.conf` files.
//! 5. Applies config-to-peer mapping (sets `has_config`, `config_name`,
//!    `config_path` on matching peers).
//!
//! Errors within a single cycle step are logged and the cycle continues;
//! the overall polling loop never stops due to a single-cycle failure.

use std::path::PathBuf;
use std::time::Duration;

use chrono::SecondsFormat;
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

    /// Run the polling loop forever.  Uses `tokio::time::interval` so that
    /// cycles are tick-aligned – the period between the *start* of consecutive
    /// cycles is `interval`, regardless of how long each `poll_once` takes.
    pub async fn run(&self) {
        info!(
            interval_secs = self.interval.as_secs(),
            config_dir = %self.config_dir.display(),
            "poller started"
        );
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.poll_once().await {
                error!(error = %e, "poll cycle failed");
            }
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
    async fn enforce_disabled_peers(
        &self,
        interfaces: &[awg::AwgInterface],
    ) -> anyhow::Result<()> {
        let disabled_keys =
            crate::db::peers::list_disabled_public_keys(&self.db.pool).await?;

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

        // Load all peers from the DB for AllowedIPs fallback matching.
        let all_peers = crate::db::peers::list_all(&self.db.pool).await?;

        let mut mapped: usize = 0;
        let mut mapped_by_ip: usize = 0;
        for config in &configs {
            let path_str = config.path.to_string_lossy();

            // ── Strategy 1: exact public-key match ──────────────────
            //
            // The `[Peer] PublicKey` in a client config refers to the
            // *server's* key, so it will only match a peer whose public
            // key happens to equal that value (i.e. if the config dir
            // also contains server-side configs).  If no peer matches,
            // we fall through to Strategy 2 instead of giving up.
            if let Some(pk) = &config.peer_public_key {
                match crate::db::peers::apply_config_mapping(
                    &self.db.pool,
                    &pk.0,
                    &config.name,
                    &path_str,
                    &config.friendly_name,
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
                        &self.db.pool,
                        &peer.public_key,
                        &config.name,
                        &path_str,
                        &config.friendly_name,
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

    async fn store_snapshot(
        &self,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()> {
        let endpoint = peer.endpoint.as_deref();
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = saturating_u64_to_i64(peer.rx_bytes);
        let tx = saturating_u64_to_i64(peer.tx_bytes);
        let captured_str = captured_at.to_rfc3339_opts(SecondsFormat::Secs, true);

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
        let rx = saturating_u64_to_i64(peer.rx_bytes);
        let tx = saturating_u64_to_i64(peer.tx_bytes);

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
