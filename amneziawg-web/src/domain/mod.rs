//! Core domain types shared across the application.

pub mod history;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Seconds within which a peer is considered "online" based on last handshake.
pub const ONLINE_THRESHOLD_SECS: i64 = 180;

/// Maximum allowed length (in Unicode scalar values) for a peer display name.
pub const MAX_DISPLAY_NAME_LEN: usize = 128;
/// Maximum allowed length (in Unicode scalar values) for a peer comment.
pub const MAX_COMMENT_LEN: usize = 512;

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
    /// Handshake within `online_threshold_secs` seconds.
    Online,
    /// No recent handshake but the peer has a known config.
    Inactive,
    /// Administratively disabled.
    Disabled,
    /// Seen in `awg show` but no matching config file found and no
    /// display name has been assigned.
    Unlinked,
}

impl PeerStatus {
    /// Derive status from the last handshake timestamp, disabled flag,
    /// config-presence flag, and a configurable online threshold.
    ///
    /// Priority order:
    /// 1. `disabled` → `Disabled` (overrides everything)
    /// 2. `!has_config` → `Unlinked`
    /// 3. Recent handshake → `Online`
    /// 4. Otherwise → `Inactive`
    pub fn derive(
        last_handshake: Option<DateTime<Utc>>,
        disabled: bool,
        has_config: bool,
        online_threshold_secs: i64,
    ) -> Self {
        if disabled {
            return PeerStatus::Disabled;
        }
        if !has_config {
            return PeerStatus::Unlinked;
        }
        match last_handshake {
            Some(ts) => {
                let age = Utc::now() - ts;
                if age.num_seconds() <= online_threshold_secs {
                    PeerStatus::Online
                } else {
                    PeerStatus::Inactive
                }
            }
            None => PeerStatus::Inactive,
        }
    }
}

/// Normalize a candidate display name.
///
/// Rules:
/// - Leading/trailing whitespace is stripped.
/// - Empty result → `None` (clears the field).
/// - Truncated to at most `MAX_DISPLAY_NAME_LEN` Unicode scalar values.
pub fn normalize_display_name(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(truncate_chars(trimmed, MAX_DISPLAY_NAME_LEN))
}

/// Normalize a candidate comment string.
///
/// Rules:
/// - Leading/trailing whitespace is stripped.
/// - Empty result → `None` (clears the field).
/// - Truncated to at most `MAX_COMMENT_LEN` Unicode scalar values.
pub fn normalize_comment(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(truncate_chars(trimmed, MAX_COMMENT_LEN))
}

/// Return the first `max_chars` Unicode scalar values of `s`.
///
/// If `s` is already within the limit, returns an owned copy without
/// scanning beyond the required length.  Only iterates up to
/// `max_chars + 1` characters to decide whether truncation is needed.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_owned(),           // within limit – no truncation needed
        Some((idx, _)) => s[..idx].to_owned(), // truncate at byte boundary
    }
}

/// Resolve the human-readable display name for a peer.
///
/// Fallback order:
/// 1. `display_name` – if a user has explicitly set one.
/// 2. `config_name` – stem of the matching `.conf` file (e.g. `"ivan-iphone"`).
/// 3. `peer-<first-8-chars-of-public_key>` – last-resort generated name.
pub fn resolve_display_name(
    display_name: Option<&str>,
    config_name: Option<&str>,
    public_key: &str,
) -> String {
    if let Some(name) = display_name {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    if let Some(name) = config_name {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    let prefix_len = public_key.len().min(8);
    format!("peer-{}", &public_key[..prefix_len])
}

/// Peer as known to the web panel (domain model, not a DB row).
#[allow(dead_code)]
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

/// A point-in-time snapshot of a peer's stats (domain model).
#[allow(dead_code)]
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

    // ── PeerStatus::derive ─────────────────────────────────────────────────

    #[test]
    fn online_within_threshold() {
        let ts = Utc::now() - chrono::Duration::seconds(60);
        assert_eq!(
            PeerStatus::derive(Some(ts), false, true, ONLINE_THRESHOLD_SECS),
            PeerStatus::Online
        );
    }

    #[test]
    fn inactive_after_threshold() {
        let ts = Utc::now() - chrono::Duration::seconds(300);
        assert_eq!(
            PeerStatus::derive(Some(ts), false, true, ONLINE_THRESHOLD_SECS),
            PeerStatus::Inactive
        );
    }

    #[test]
    fn disabled_overrides_recent_handshake() {
        let ts = Utc::now() - chrono::Duration::seconds(10);
        assert_eq!(
            PeerStatus::derive(Some(ts), true, true, ONLINE_THRESHOLD_SECS),
            PeerStatus::Disabled
        );
    }

    #[test]
    fn unlinked_when_no_config() {
        assert_eq!(
            PeerStatus::derive(None, false, false, ONLINE_THRESHOLD_SECS),
            PeerStatus::Unlinked
        );
    }

    #[test]
    fn inactive_no_handshake_with_config() {
        assert_eq!(
            PeerStatus::derive(None, false, true, ONLINE_THRESHOLD_SECS),
            PeerStatus::Inactive
        );
    }

    #[test]
    fn custom_threshold_respected() {
        // With a 10-second threshold, a 15-second-old handshake is inactive.
        let ts = Utc::now() - chrono::Duration::seconds(15);
        assert_eq!(
            PeerStatus::derive(Some(ts), false, true, 10),
            PeerStatus::Inactive
        );
        // But with a 30-second threshold it is online.
        assert_eq!(
            PeerStatus::derive(Some(ts), false, true, 30),
            PeerStatus::Online
        );
    }

    // ── resolve_display_name ───────────────────────────────────────────────

    #[test]
    fn uses_display_name_first() {
        assert_eq!(
            resolve_display_name(Some("Alice"), Some("client1"), "abcdef1234567890"),
            "Alice"
        );
    }

    #[test]
    fn falls_back_to_config_name() {
        assert_eq!(
            resolve_display_name(None, Some("ivan-iphone"), "abcdef1234567890"),
            "ivan-iphone"
        );
    }

    #[test]
    fn falls_back_to_public_key_prefix() {
        assert_eq!(
            resolve_display_name(None, None, "abcdef1234567890"),
            "peer-abcdef12"
        );
    }

    #[test]
    fn short_public_key_uses_full_key() {
        assert_eq!(resolve_display_name(None, None, "abc"), "peer-abc");
    }

    #[test]
    fn empty_display_name_uses_config_name() {
        assert_eq!(
            resolve_display_name(Some(""), Some("ivan-iphone"), "abcdef1234567890"),
            "ivan-iphone"
        );
    }

    #[test]
    fn empty_config_name_uses_key_prefix() {
        assert_eq!(
            resolve_display_name(None, Some(""), "abcdef1234567890"),
            "peer-abcdef12"
        );
    }

    // ── normalize_display_name ─────────────────────────────────────────────

    #[test]
    fn normalize_name_trims_whitespace() {
        assert_eq!(
            normalize_display_name("  Alice  "),
            Some("Alice".to_string())
        );
    }

    #[test]
    fn normalize_name_empty_returns_none() {
        assert_eq!(normalize_display_name(""), None);
        assert_eq!(normalize_display_name("   "), None);
    }

    #[test]
    fn normalize_name_truncates_at_max_len() {
        let long = "a".repeat(200);
        let result = normalize_display_name(&long).unwrap();
        assert_eq!(result.chars().count(), MAX_DISPLAY_NAME_LEN);
    }

    #[test]
    fn normalize_name_short_not_truncated() {
        let s = "Ivan iPhone";
        assert_eq!(normalize_display_name(s), Some(s.to_string()));
    }

    #[test]
    fn normalize_name_unicode_truncated_by_chars_not_bytes() {
        // Each '☃' is 3 bytes; truncation must count chars, not bytes.
        let long: String = "☃".repeat(200);
        let result = normalize_display_name(&long).unwrap();
        assert_eq!(result.chars().count(), MAX_DISPLAY_NAME_LEN);
        assert!(result.is_empty() == false);
    }

    // ── normalize_comment ──────────────────────────────────────────────────

    #[test]
    fn normalize_comment_trims_and_keeps() {
        assert_eq!(
            normalize_comment("  My phone  "),
            Some("My phone".to_string())
        );
    }

    #[test]
    fn normalize_comment_empty_returns_none() {
        assert_eq!(normalize_comment(""), None);
        assert_eq!(normalize_comment("\t\n  "), None);
    }

    #[test]
    fn normalize_comment_truncates_at_max_len() {
        let long = "b".repeat(600);
        let result = normalize_comment(&long).unwrap();
        assert_eq!(result.chars().count(), MAX_COMMENT_LEN);
    }
}
