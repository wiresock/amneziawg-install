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
    /// Filename without extension (e.g. `"ivan-iphone"`).
    pub name: String,
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

        let peer_public_key = extract_peer_public_key(&content);
        let addresses = extract_addresses(&content);

        configs.push(ClientConfig {
            name,
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
}
