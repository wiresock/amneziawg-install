//! Core domain types shared across the application.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Public-key fingerprint used as the canonical peer identifier.
/// Private keys are NEVER stored or logged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct PublicKey(pub String);

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Human-readable status for a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Handshake within the last 3 minutes.
    Online,
    /// No recent handshake but a handshake has been seen.
    Inactive,
    /// Administratively disabled (no private config present / flagged).
    Disabled,
    /// Seen in `awg show` but no matching config file found.
    Unlinked,
}

impl PeerStatus {
    /// Derive status from the last handshake timestamp and the disabled flag.
    pub fn derive(last_handshake: Option<DateTime<Utc>>, disabled: bool, has_config: bool) -> Self {
        if disabled {
            return PeerStatus::Disabled;
        }
        if !has_config {
            return PeerStatus::Unlinked;
        }
        match last_handshake {
            Some(ts) => {
                let age = Utc::now() - ts;
                if age.num_seconds() <= 180 {
                    PeerStatus::Online
                } else {
                    PeerStatus::Inactive
                }
            }
            None => PeerStatus::Inactive,
        }
    }
}

/// Peer as known to the web panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub public_key: PublicKey,
    pub display_name: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_handshake: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub status: PeerStatus,
    pub disabled: bool,
    pub comment: Option<String>,
}

/// A point-in-time snapshot of a peer's stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub public_key: PublicKey,
    pub captured_at: DateTime<Utc>,
    pub endpoint: Option<String>,
    pub last_handshake: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_within_3_minutes() {
        let ts = Utc::now() - chrono::Duration::seconds(60);
        assert_eq!(
            PeerStatus::derive(Some(ts), false, true),
            PeerStatus::Online
        );
    }

    #[test]
    fn inactive_after_3_minutes() {
        let ts = Utc::now() - chrono::Duration::seconds(300);
        assert_eq!(
            PeerStatus::derive(Some(ts), false, true),
            PeerStatus::Inactive
        );
    }

    #[test]
    fn disabled_overrides_handshake() {
        let ts = Utc::now() - chrono::Duration::seconds(10);
        assert_eq!(
            PeerStatus::derive(Some(ts), true, true),
            PeerStatus::Disabled
        );
    }

    #[test]
    fn unlinked_when_no_config() {
        assert_eq!(PeerStatus::derive(None, false, false), PeerStatus::Unlinked);
    }

    #[test]
    fn inactive_no_handshake_but_has_config() {
        assert_eq!(PeerStatus::derive(None, false, true), PeerStatus::Inactive);
    }
}
