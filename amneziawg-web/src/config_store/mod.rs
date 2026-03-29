//! Config-file discovery and metadata extraction.
//!
//! Scans a directory for `*.conf` files (AWG client configs), extracts
//! basic metadata, and attempts to map each config to a live peer via its
//! `PublicKey`.
//!
//! ## Discovery rules
//!
//! - Non-recursive: only direct children of the target directory are examined.
//! - Only regular files with the `.conf` extension are processed.
//! - If an individual file cannot be read or parsed, a warning is logged and
//!   that file is skipped; the rest of the scan continues.
//! - If the directory itself cannot be opened, an error is returned to the
//!   caller (the poller logs it and skips the mapping step).

use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;
use tracing::warn;

use crate::domain::PublicKey;

#[derive(Debug, Error)]
pub enum ConfigStoreError {
    #[error("failed to read config directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Metadata extracted from a single client config file.
#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    /// Filename without extension (e.g. `"awg0-client-gramm"`).
    pub name: String,
    /// Human-readable name derived from the filename.
    ///
    /// For files matching the pattern `*-client-<suffix>.conf`, the suffix is
    /// used (e.g. `"awg0-client-gramm.conf"` → `"gramm"`).  Otherwise falls
    /// back to the full filename stem (without `.conf`).
    pub friendly_name: String,
    /// Absolute path to the config file.
    pub path: PathBuf,
    /// Public key extracted from the `[Peer]` section of the config.
    ///
    /// In a split-tunnel AWG client config the `[Peer]` section describes the
    /// **server** endpoint.  The `PublicKey` value there matches what
    /// `awg show` reports for this client peer.
    pub peer_public_key: Option<PublicKey>,
    /// Address(es) from the `[Interface]` `Address` field.
    pub addresses: Vec<String>,
}

/// Derive a human-readable "friendly" name from a config filename stem.
///
/// The AmneziaWG installer creates client configs with names like
/// `awg0-client-gramm.conf`.  This function strips the common
/// `*-client-` prefix pattern to yield `"gramm"`.
///
/// If the filename does not match the pattern, the full stem is returned
/// (e.g. `"custom-name.conf"` → `"custom-name"`).
///
/// The input should be the filename **stem** (without the `.conf` extension).
pub fn friendly_name_from_filename(stem: &str) -> String {
    // Look for the last occurrence of "-client-" and take the suffix.
    if let Some(pos) = stem.rfind("-client-") {
        let suffix = &stem[pos + "-client-".len()..];
        if !suffix.is_empty() {
            return suffix.to_string();
        }
    }
    stem.to_string()
}

/// Scan `dir` for `*.conf` files and return metadata for each.
///
/// Only the top-level entries inside `dir` are examined (no recursion).
/// Entries that are not regular files or do not have a `.conf` extension are
/// silently ignored.  Files that cannot be read are logged as warnings and
/// skipped; the scan continues with the remaining files.
pub fn scan(dir: &Path) -> Result<Vec<ClientConfig>, ConfigStoreError> {
    let entries = std::fs::read_dir(dir).map_err(|e| ConfigStoreError::ReadDir {
        path: dir.to_path_buf(),
        source: e,
    })?;

    let mut configs = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read config file – skipping");
                continue;
            }
        };

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let friendly_name = friendly_name_from_filename(&name);
        let peer_public_key = extract_peer_public_key(&content);
        let addresses = extract_addresses(&content);

        configs.push(ClientConfig {
            name,
            friendly_name,
            path,
            peer_public_key,
            addresses,
        });
    }

    Ok(configs)
}

/// Extract `PublicKey` from the first `[Peer]` section of a WireGuard config.
fn extract_peer_public_key(content: &str) -> Option<PublicKey> {
    let mut in_peer = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("[Peer]") {
            in_peer = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_peer = false;
        }
        if in_peer {
            if let Some(key) = parse_kv(trimmed, "PublicKey") {
                return Some(PublicKey(key.to_string()));
            }
        }
    }
    None
}

/// Extract `Address` values from the `[Interface]` section.
fn extract_addresses(content: &str) -> Vec<String> {
    let mut in_iface = false;
    let mut addrs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("[Interface]") {
            in_iface = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_iface = false;
        }
        if in_iface {
            if let Some(val) = parse_kv(trimmed, "Address") {
                for addr in val.split(',') {
                    let a = addr.trim().to_string();
                    if !a.is_empty() {
                        addrs.push(a);
                    }
                }
            }
        }
    }
    addrs
}

fn parse_kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut parts = line.splitn(2, '=');
    let k = parts.next()?.trim();
    if k.eq_ignore_ascii_case(key) {
        Some(parts.next()?.trim())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = "\
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY=
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
";

    const CONFIG_NO_PEER: &str = "\
[Interface]
PrivateKey = SOME_KEY=
Address = 10.8.0.3/32
";

    #[test]
    fn extracts_peer_public_key() {
        let key = extract_peer_public_key(SAMPLE_CONFIG);
        assert_eq!(key, Some(PublicKey("SERVER_PUBLIC_KEY=".to_string())));
    }

    #[test]
    fn extracts_addresses() {
        let addrs = extract_addresses(SAMPLE_CONFIG);
        assert_eq!(addrs, vec!["10.8.0.2/32", "fd00::2/128"]);
    }

    #[test]
    fn no_peer_section_returns_none_key() {
        let key = extract_peer_public_key(CONFIG_NO_PEER);
        assert!(key.is_none());
    }

    #[test]
    fn scan_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = scan(dir.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn scan_conf_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("client1.conf"), SAMPLE_CONFIG).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

        let result = scan(dir.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "client1");
        assert!(result[0].peer_public_key.is_some());
    }

    #[test]
    fn scan_config_without_peer_section_included_with_none_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("iface-only.conf"), CONFIG_NO_PEER).unwrap();

        let result = scan(dir.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "iface-only");
        assert!(result[0].peer_public_key.is_none());
    }

    #[test]
    fn scan_nonexistent_dir_returns_error() {
        let result = scan(Path::new("/tmp/does-not-exist-amneziawg-test-xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn scan_multiple_configs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("alice.conf"), SAMPLE_CONFIG).unwrap();
        std::fs::write(dir.path().join("bob.conf"), CONFIG_NO_PEER).unwrap();

        let mut result = scan(dir.path()).unwrap();
        // Sort by name for deterministic comparison
        result.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "alice");
        assert_eq!(result[1].name, "bob");
        assert!(result[0].peer_public_key.is_some());
        assert!(result[1].peer_public_key.is_none());
    }

    // ── friendly_name_from_filename ─────────────────────────────────────────

    #[test]
    fn friendly_name_awg0_client_gramm() {
        assert_eq!(friendly_name_from_filename("awg0-client-gramm"), "gramm");
    }

    #[test]
    fn friendly_name_awg0_client_iphone() {
        assert_eq!(friendly_name_from_filename("awg0-client-iphone"), "iphone");
    }

    #[test]
    fn friendly_name_wg0_client_alice() {
        assert_eq!(friendly_name_from_filename("wg0-client-alice"), "alice");
    }

    #[test]
    fn friendly_name_generic_filename() {
        assert_eq!(friendly_name_from_filename("custom-name"), "custom-name");
    }

    #[test]
    fn friendly_name_bare_name() {
        assert_eq!(friendly_name_from_filename("mydevice"), "mydevice");
    }

    #[test]
    fn friendly_name_empty_suffix_uses_full_stem() {
        // Edge case: "-client-" at the end with no suffix
        assert_eq!(friendly_name_from_filename("awg0-client-"), "awg0-client-");
    }

    #[test]
    fn friendly_name_multiple_client_uses_last() {
        // If "-client-" appears multiple times, use the last suffix
        assert_eq!(
            friendly_name_from_filename("awg0-client-nested-client-final"),
            "final"
        );
    }

    #[test]
    fn friendly_name_in_scan_result() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("awg0-client-gramm.conf"), SAMPLE_CONFIG).unwrap();
        std::fs::write(dir.path().join("awg0-client-iphone.conf"), CONFIG_NO_PEER).unwrap();
        std::fs::write(dir.path().join("custom-peer.conf"), SAMPLE_CONFIG).unwrap();

        let mut result = scan(dir.path()).unwrap();
        result.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].name, "awg0-client-gramm");
        assert_eq!(result[0].friendly_name, "gramm");
        assert_eq!(result[1].name, "awg0-client-iphone");
        assert_eq!(result[1].friendly_name, "iphone");
        assert_eq!(result[2].name, "custom-peer");
        assert_eq!(result[2].friendly_name, "custom-peer");
    }
}
