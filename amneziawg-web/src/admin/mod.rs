//! Admin action helpers (disable/enable peer, config download, user lifecycle).
//!
//! These functions encapsulate the DB mutations and audit logging so that both
//! the JSON API and the HTML form handler can share the same logic without
//! duplicating validation or event-recording code.

#![allow(dead_code)]

pub mod script_bridge;

use crate::db::events::{
    log_event, EVT_PEER_DISABLED, EVT_USER_CREATED, EVT_USER_CREATE_FAILED,
    EVT_USER_CREATE_REQUESTED, EVT_USER_REMOVED, EVT_USER_REMOVE_FAILED, EVT_USER_REMOVE_REQUESTED,
};
use crate::db::peers::{find_by_public_key, update_peer_disabled, PeerRow};
use crate::db::Database;
use crate::domain::PublicKey;

use self::script_bridge::{ScriptBridge, ScriptError};

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
    let existing = match find_by_public_key(&db.pool, &cmd.public_key.0).await? {
        Some(r) => r,
        None => return Ok(None),
    };

    let disabled = !cmd.enabled;
    let old_disabled = existing.disabled != 0;

    // Short-circuit: skip the UPDATE if the value is already correct.
    if disabled == old_disabled {
        return Ok(Some(existing));
    }

    let updated = update_peer_disabled(&db.pool, existing.id, disabled).await?;

    {
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

// ── User lifecycle (create / remove) ─────────────────────────────────────────

/// Result of a successful user creation.
#[derive(Debug)]
pub struct CreateUserResult {
    /// The config path returned by the install script.
    pub config_path: String,
    /// The client name that was requested.
    pub client_name: String,
}

/// Create a new AmneziaWG user/client via the install script.
///
/// 1. Validates the name.
/// 2. Logs `user_create_requested`.
/// 3. Invokes `--add-client` through the script bridge.
/// 4. Logs `user_created` or `user_create_failed`.
///
/// The caller is responsible for triggering a config rescan after success.
pub async fn execute_create_user(
    db: &Database,
    bridge: &ScriptBridge,
    name: &str,
    actor: &str,
) -> Result<CreateUserResult, ScriptError> {
    // Pre-validate name (the script validates too, but fail fast for the UI).
    script_bridge::validate_client_name(name)?;

    let detail = serde_json::json!({ "name": name }).to_string();
    log_event(
        &db.pool,
        EVT_USER_CREATE_REQUESTED,
        None,
        None,
        Some(&detail),
        actor,
    )
    .await;

    match bridge.add_client(name).await {
        Ok(config_path) => {
            let detail = serde_json::json!({
                "name": name,
                "config_path": &config_path,
            })
            .to_string();
            log_event(&db.pool, EVT_USER_CREATED, None, None, Some(&detail), actor).await;
            Ok(CreateUserResult {
                config_path,
                client_name: name.to_string(),
            })
        }
        Err(e) => {
            let detail = serde_json::json!({
                "name": name,
                "error": e.to_string(),
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_CREATE_FAILED,
                None,
                None,
                Some(&detail),
                actor,
            )
            .await;
            Err(e)
        }
    }
}

/// Remove an existing AmneziaWG user/client via the install script.
///
/// The `client_name` should be the script-side client identifier (the same
/// value used in `### Client <name>` markers in the server config).
///
/// Historical peer data (snapshots, events) is preserved in the database;
/// the peer row itself will become "unlinked" after the next config rescan
/// and will eventually stop appearing in `awg show` output.
pub async fn execute_remove_user(
    db: &Database,
    bridge: &ScriptBridge,
    peer_id: i64,
    client_name: &str,
    actor: &str,
) -> Result<(), ScriptError> {
    script_bridge::validate_client_name(client_name)?;

    let detail = serde_json::json!({
        "peer_id": peer_id,
        "name": client_name,
    })
    .to_string();
    log_event(
        &db.pool,
        EVT_USER_REMOVE_REQUESTED,
        Some(peer_id),
        None,
        Some(&detail),
        actor,
    )
    .await;

    match bridge.remove_client(client_name).await {
        Ok(()) => {
            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_REMOVED,
                Some(peer_id),
                None,
                Some(&detail),
                actor,
            )
            .await;
            Ok(())
        }
        Err(e) => {
            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
                "error": e.to_string(),
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_REMOVE_FAILED,
                Some(peer_id),
                None,
                Some(&detail),
                actor,
            )
            .await;
            Err(e)
        }
    }
}
