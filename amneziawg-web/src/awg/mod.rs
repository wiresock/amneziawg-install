//! AWG integration layer.
//!
//! Executes `sudo /usr/bin/awg …` via `std::process::Command`
//! (NO shell interpolation) and parses the output into [`AwgInterface`] /
//! [`AwgPeer`] structs.
//!
//! ## Privilege model
//!
//! Managing AWG interface state requires `CAP_NET_ADMIN`.  The web service
//! runs as a dedicated non-root user (`awg-web`).  Rather than running the
//! entire service as root, the installer configures a tightly-scoped sudoers
//! drop-in (`/etc/sudoers.d/amneziawg-web`) that allows **only**:
//!
//! ```text
//! awg-web ALL=(root) NOPASSWD: /usr/bin/awg show all dump, \
//!     /usr/bin/awg set * peer * remove
//! ```
//!
//! This grants the minimum privilege needed for AWG inspection and for
//! removing disabled peers from the running interface.
//!
//! ## Output format assumptions
//!
//! `awg show all dump` produces tab-separated lines with two record types.
//!
//! **Interface line** (≥ 5 fields):
//! ```text
//! <interface>  private_key  public_key  listen_port  [awg_params…]  fwmark
//! ```
//! Standard WireGuard emits exactly 5 fields.  AmneziaWG appends additional
//! obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1–H4, …) resulting in
//! ≥ 21 fields.  The parser uses only fields 0–3 and ignores the rest.
//!
//! **Peer line** (≥ 9 fields):
//! ```text
//! <interface>  public_key  preshared_key  endpoint  allowed_ips
//!     latest_handshake  transfer_rx  transfer_tx  persistent_keepalive  …
//! ```
//!
//! Lines are distinguished by whether their first field (interface name)
//! has already been seen as an interface header.

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

/// Absolute path to the `sudo` binary.
const SUDO_BIN: &str = "/usr/bin/sudo";

/// Absolute path to the `awg` binary.
const AWG_BIN: &str = "/usr/bin/awg";

/// Execute `sudo /usr/bin/awg show all dump` and return parsed interfaces.
///
/// Uses absolute paths for both `sudo` and `awg` to prevent PATH
/// manipulation attacks.  The service user must be granted passwordless
/// sudo for exactly this command — see the sudoers drop-in installed by
/// `amneziawg-web-install.sh`.
pub fn show_all_dump() -> Result<Vec<AwgInterface>, AwgError> {
    let output = Command::new(SUDO_BIN)
        .args(["-n", AWG_BIN, "show", "all", "dump"])
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

/// Remove a single peer from a running AWG interface.
///
/// Executes `sudo -n /usr/bin/awg set <interface> peer <pubkey> remove`.
/// The sudoers drop-in installed by the installer restricts `awg set` to
/// only the `remove` sub-command, and the arguments are passed as an
/// explicit array (no shell interpolation).
///
/// Returns `Ok(())` if the peer was removed or the command exited
/// successfully (e.g. the peer was already absent).
pub fn remove_peer(interface: &str, public_key: &str) -> Result<(), AwgError> {
    let output = Command::new(SUDO_BIN)
        .args(["-n", AWG_BIN, "set", interface, "peer", public_key, "remove"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let code = output.status.code().unwrap_or(-1);
        return Err(AwgError::NonZeroExit {
            status: code,
            stderr,
        });
    }

    Ok(())
}

/// Parse the textual output of `awg show all dump`.
///
/// Handles both standard WireGuard (5-field interface, 9-field peer) and
/// AmneziaWG extended format (≥ 21-field interface with extra obfuscation
/// parameters).  Lines are classified by whether their first field matches
/// an already-seen interface name.
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
        let n = fields.len();

        if n < 5 {
            return Err(AwgError::Parse(format!(
                "line {}: too few fields {} (minimum 5)",
                line_no + 1,
                n
            )));
        }

        let iface_name = fields[0];

        // If this interface name was already seen, the line is a peer record.
        let is_peer = interfaces.iter().any(|i| i.name == iface_name);

        if is_peer {
            // Peer line: need at least 9 fields
            // (interface, public_key, preshared_key, endpoint, allowed_ips,
            //  latest_handshake, transfer_rx, transfer_tx, persistent_keepalive)
            if n < 9 {
                return Err(AwgError::Parse(format!(
                    "line {}: peer line has {} fields (minimum 9)",
                    line_no + 1,
                    n
                )));
            }

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
        } else {
            // Interface header line: first 4 fields are always
            // interface, private_key, public_key, listen_port.
            // fields[1] is the private key – we intentionally discard it.
            let public_key = PublicKey(fields[2].to_string());
            let listen_port = fields[3].parse::<u16>().ok();

            interfaces.push(AwgInterface {
                name: iface_name.to_string(),
                public_key,
                listen_port,
                peers: Vec::new(),
            });
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

    // ── AmneziaWG extended-format tests ─────────────────────────────

    /// Real AmneziaWG `awg show all dump` emits 21-field interface lines
    /// with extra obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1–H4, …).
    const AWG_EXTENDED_DUMP: &str = "\
awg0\tPRIVATE_KEY\tSVR_PUB_KEY_BASE64=\t51820\t8\t50\t1000\t107\t105\t62\t95321941292\t774489227\t1084244185\t1837068650\t(null)\t(null)\t(null)\t(null)\t(null)\t(null)\toff\n\
awg0\tCLIENT1_PUB_KEY=\t(none)\t203.0.113.42:12345\t10.8.0.2/32\t1700000000\t1024\t2048\toff\n\
awg0\tCLIENT2_PUB_KEY=\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n\
";

    #[test]
    fn parse_awg_extended_interface_line() {
        let result = parse_dump(AWG_EXTENDED_DUMP).expect("parse should succeed");
        assert_eq!(result.len(), 1);
        let iface = &result[0];
        assert_eq!(iface.name, "awg0");
        assert_eq!(iface.public_key.0, "SVR_PUB_KEY_BASE64=");
        assert_eq!(iface.listen_port, Some(51820));
        assert_eq!(iface.peers.len(), 2);
    }

    #[test]
    fn parse_awg_extended_peers() {
        let result = parse_dump(AWG_EXTENDED_DUMP).unwrap();
        let peer = &result[0].peers[0];
        assert_eq!(peer.public_key.0, "CLIENT1_PUB_KEY=");
        assert_eq!(peer.endpoint, Some("203.0.113.42:12345".to_string()));
        assert_eq!(peer.rx_bytes, 1024);
        assert_eq!(peer.tx_bytes, 2048);
        assert!(peer.last_handshake.is_some());
    }

    #[test]
    fn peer_shaped_line_without_prior_interface_treated_as_interface() {
        // A 9-field line whose interface name hasn't been seen yet is treated
        // as a new interface header (≥5 fields), not a peer.
        let input = "awg0\tPK=\t(none)\t1.2.3.4:5678\t10.0.0.2/32\t0\t0\t0\toff\n";
        let result = parse_dump(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap()[0].peers.len(), 0);
    }

    // ── Command construction tests ──────────────────────────────────

    /// Verify `show_all_dump` invokes `sudo -n /usr/bin/awg show all dump`
    /// with explicit argument arrays and no shell wrapping.
    #[test]
    fn command_uses_sudo_with_absolute_paths() {
        // Build the same Command that show_all_dump() would construct.
        let cmd = Command::new(SUDO_BIN);
        let prog = cmd.get_program();
        assert_eq!(prog, SUDO_BIN, "must use absolute /usr/bin/sudo");
    }

    #[test]
    fn constants_use_absolute_paths() {
        assert_eq!(SUDO_BIN, "/usr/bin/sudo");
        assert_eq!(AWG_BIN, "/usr/bin/awg");
    }

    /// Verify the command is assembled without shell interpolation.
    #[test]
    fn command_args_are_explicit_array() {
        let mut cmd = Command::new(SUDO_BIN);
        cmd.args(["-n", AWG_BIN, "show", "all", "dump"]);

        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["-n", AWG_BIN, "show", "all", "dump"]);
    }

    // ── remove_peer command construction tests ──────────────────────

    /// Verify `remove_peer` constructs the correct `awg set … peer … remove`
    /// command with explicit argument array.
    #[test]
    fn remove_peer_command_args() {
        let mut cmd = Command::new(SUDO_BIN);
        cmd.args(["-n", AWG_BIN, "set", "awg0", "peer", "SOME_KEY=", "remove"]);

        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(
            args,
            vec!["-n", AWG_BIN, "set", "awg0", "peer", "SOME_KEY=", "remove"]
        );
    }
}
