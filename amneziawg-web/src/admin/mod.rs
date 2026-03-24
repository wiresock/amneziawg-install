//! Admin action helpers (disable/enable peer, config download).
//!
//! These functions encapsulate the DB mutations and audit logging so that both
//! the JSON API and the HTML form handler can share the same logic without
//! duplicating validation or event-recording code.

#![allow(dead_code)]

use crate::db::events::{log_event, EVT_PEER_DISABLED};
use crate::db::peers::{find_by_id, update_peer_disabled, PeerRow};
use crate::db::Database;
use crate::domain::PublicKey;

/// Enable or disable a peer (admin action).
pub struct SetPeerEnabledCommand {
    pub public_key: PublicKey,
    pub enabled: bool,
}

/// Execute a [`SetPeerEnabledCommand`], updating the database and recording an
/// audit event if the state actually changed.
///
/// Returns the updated `PeerRow`, or `None` if no peer with the matching
/// public key exists.
pub async fn execute_set_peer_enabled(
    db: &Database,
    cmd: &SetPeerEnabledCommand,
    actor: &str,
) -> Result<Option<PeerRow>, sqlx::Error> {
    // Find the peer by public key.
    let rows = crate::db::peers::list_all(&db.pool).await?;
    let existing = rows.into_iter().find(|r| r.public_key == cmd.public_key.0);
    let existing = match existing {
        Some(r) => r,
        None => return Ok(None),
    };

    let disabled = !cmd.enabled;
    let old_disabled = existing.disabled != 0;

    let updated = update_peer_disabled(&db.pool, existing.id, disabled).await?;

    if disabled != old_disabled {
        let detail = serde_json::json!({
            "old_disabled": old_disabled,
            "new_disabled": disabled,
        })
        .to_string();
        log_event(
            &db.pool,
            EVT_PEER_DISABLED,
            Some(existing.id),
            Some(&existing.public_key),
            Some(&detail),
            actor,
        )
        .await;
    }

    Ok(updated)
}
