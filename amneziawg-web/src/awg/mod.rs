//! AWG integration layer.
//!
//! Executes `awg show all dump` via `std::process::Command` (NO shell
//! interpolation) and parses the output into [`AwgInterface`] / [`AwgPeer`]
//! structs.
//!
//! ## Output format assumptions
//!
//! `awg show all dump` produces tab-separated lines with two record types:
//!
//! **Interface line** (5 fields):
//! ```text
//! <interface>  private_key  public_key  listen_port  fwmark
//! ```
//!
//! **Peer line** (9 fields):
//! ```text
//! <interface>  public_key  preshared_key  endpoint  allowed_ips
//!     latest_handshake  transfer_rx  transfer_tx  persistent_keepalive
//! ```
//!
//! TODO: Verify these field counts against the running `awg` binary and adjust
//!       the parser if they differ.

use std::process::Command;

use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::domain::PublicKey;

/// Errors produced by the AWG integration layer.
#[derive(Debug, Error)]
pub enum AwgError {
    #[error("failed to execute awg: {0}")]
    Io(#[from] std::io::Error),

    #[error("awg exited with status {status}: {stderr}")]
    NonZeroExit { status: i32, stderr: String },

    #[error("failed to parse awg output: {0}")]
    Parse(String),
}

/// Parsed representation of a WireGuard / AWG interface.
#[derive(Debug, Clone, Serialize)]
pub struct AwgInterface {
    pub name: String,
    /// Public key of the server interface (private key is NOT stored).
    pub public_key: PublicKey,
    pub listen_port: Option<u16>,
    pub peers: Vec<AwgPeer>,
}

/// Parsed representation of a single peer as reported by `awg show`.
#[derive(Debug, Clone, Serialize)]
pub struct AwgPeer {
    pub public_key: PublicKey,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_handshake: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Execute `awg show all dump` and return parsed interfaces.
///
/// Uses an absolute path to avoid PATH manipulation attacks.
pub fn show_all_dump() -> Result<Vec<AwgInterface>, AwgError> {
    let output = Command::new("/usr/bin/awg")
        .args(["show", "all", "dump"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let code = output.status.code().unwrap_or(-1);
        return Err(AwgError::NonZeroExit {
            status: code,
            stderr,
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dump(&stdout)
}

/// Parse the textual output of `awg show all dump`.
///
/// Exposed publicly for unit testing without requiring a running AWG daemon.
pub fn parse_dump(output: &str) -> Result<Vec<AwgInterface>, AwgError> {
    let mut interfaces: Vec<AwgInterface> = Vec::new();

    for (line_no, line) in output.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();

        match fields.len() {
            // Interface header line: interface  private_key  public_key  listen_port  fwmark
            5 => {
                let iface_name = fields[0].to_string();
                // fields[1] is the private key – we intentionally discard it.
                let public_key = PublicKey(fields[2].to_string());
                let listen_port = fields[3].parse::<u16>().ok();

                interfaces.push(AwgInterface {
                    name: iface_name,
                    public_key,
                    listen_port,
                    peers: Vec::new(),
                });
            }
            // Peer line: interface  public_key  preshared_key  endpoint  allowed_ips
            //            latest_handshake  transfer_rx  transfer_tx  persistent_keepalive
            9 => {
                let iface_name = fields[0];
                let public_key = PublicKey(fields[1].to_string());
                // fields[2] is preshared_key – discarded for security.
                let endpoint = parse_optional(fields[3]);
                let allowed_ips = parse_allowed_ips(fields[4]);
                let last_handshake = parse_timestamp(fields[5]);
                let rx_bytes = fields[6].parse::<u64>().unwrap_or(0);
                let tx_bytes = fields[7].parse::<u64>().unwrap_or(0);

                let peer = AwgPeer {
                    public_key,
                    endpoint,
                    allowed_ips,
                    last_handshake,
                    rx_bytes,
                    tx_bytes,
                };

                if let Some(iface) = interfaces.iter_mut().find(|i| i.name == iface_name) {
                    iface.peers.push(peer);
                } else {
                    return Err(AwgError::Parse(format!(
                        "line {}: peer references unknown interface '{}'",
                        line_no + 1,
                        iface_name
                    )));
                }
            }
            n => {
                return Err(AwgError::Parse(format!(
                    "line {}: unexpected field count {} (expected 5 or 9)",
                    line_no + 1,
                    n
                )));
            }
        }
    }

    Ok(interfaces)
}

fn parse_optional(s: &str) -> Option<String> {
    if s == "(none)" || s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn parse_allowed_ips(s: &str) -> Vec<String> {
    if s == "(none)" || s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(|ip| ip.trim().to_string()).collect()
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    match s.parse::<i64>() {
        Ok(0) | Err(_) => None,
        Ok(ts) => Utc.timestamp_opt(ts, 0).single(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DUMP: &str = "\
awg0\tPRIVATE_KEY_REDACTED\tSERVER_PUBLIC_KEY_BASE64=\t51820\toff\n\
awg0\tCLIENT1_PUBLIC_KEY=\t(none)\t203.0.113.42:12345\t10.8.0.2/32\t1700000000\t1024\t2048\toff\n\
awg0\tCLIENT2_PUBLIC_KEY=\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n\
";

    #[test]
    fn parse_interface_and_peers() {
        let result = parse_dump(SAMPLE_DUMP).expect("parse should succeed");
        assert_eq!(result.len(), 1);
        let iface = &result[0];
        assert_eq!(iface.name, "awg0");
        assert_eq!(iface.listen_port, Some(51820));
        assert_eq!(iface.peers.len(), 2);
    }

    #[test]
    fn peer_with_endpoint() {
        let result = parse_dump(SAMPLE_DUMP).unwrap();
        let peer = &result[0].peers[0];
        assert_eq!(peer.public_key.0, "CLIENT1_PUBLIC_KEY=");
        assert_eq!(peer.endpoint, Some("203.0.113.42:12345".to_string()));
        assert_eq!(peer.allowed_ips, vec!["10.8.0.2/32"]);
        assert_eq!(peer.rx_bytes, 1024);
        assert_eq!(peer.tx_bytes, 2048);
        assert!(peer.last_handshake.is_some());
    }

    #[test]
    fn peer_without_handshake() {
        let result = parse_dump(SAMPLE_DUMP).unwrap();
        let peer = &result[0].peers[1];
        assert!(peer.last_handshake.is_none());
        assert_eq!(peer.rx_bytes, 0);
    }

    #[test]
    fn empty_input_returns_no_interfaces() {
        let result = parse_dump("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn invalid_field_count_returns_error() {
        let bad = "awg0\tonly_two_fields\n";
        assert!(parse_dump(bad).is_err());
    }
}
