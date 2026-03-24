//! Admin action stubs (rename, disable/enable peer, config download).
//!
//! TODO: Implement admin actions behind an authentication layer.

use crate::domain::PublicKey;

/// Rename or set the display name of a peer.
pub struct RenamePeerCommand {
    pub public_key: PublicKey,
    pub display_name: String,
}

/// Enable or disable a peer (admin action).
pub struct SetPeerEnabledCommand {
    pub public_key: PublicKey,
    pub enabled: bool,
}
