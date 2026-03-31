//! Admin action helpers (disable/enable peer, config download, user lifecycle).
//!
//! These functions encapsulate the DB mutations and audit logging so that both
//! the JSON API and the HTML form handler can share the same logic without
//! duplicating validation or event-recording code.

#![allow(dead_code)]

pub mod client_manager;
pub mod script_bridge;

use crate::db::events::{
    log_event, EVT_PEER_DISABLED, EVT_USER_CREATED, EVT_USER_CREATE_FAILED,
    EVT_USER_CREATE_REQUESTED, EVT_USER_REMOVED, EVT_USER_REMOVE_FAILED, EVT_USER_REMOVE_REQUESTED,
};
use crate::db::peers::{find_by_public_key, update_peer_disabled, PeerRow};
use crate::db::Database;
use crate::domain::PublicKey;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use self::client_manager::RemoveClientError;

#[cfg(unix)]
fn acquire_lifecycle_lock(lock_path: &std::path::Path) -> Result<std::fs::File, RemoveClientError> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|err| {
            RemoveClientError::Internal(format!(
                "failed to open lock file for client removal at {lock_path:?}: {err}",
            ))
        })?;

    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                Err(RemoveClientError::LockBusy)
            }
            _ => Err(RemoveClientError::Internal(format!(
                "failed to acquire lock for client removal: {err}"
            ))),
        };
    }

    Ok(f)
}

#[cfg(not(unix))]
fn acquire_lifecycle_lock(lock_path: &std::path::Path) -> Result<std::fs::File, RemoveClientError> {
    let _ = lock_path;
    Err(RemoveClientError::Internal(
        "file locking for add/remove lifecycle is supported only on unix targets".to_string(),
    ))
}

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
    /// Absolute path to the generated client config file.
    pub config_path: String,
    /// The client name that was requested.
    pub client_name: String,
}

/// Create a new AmneziaWG user/client directly, without the external script.
///
/// 1. Validates the name.
/// 2. Logs `user_create_requested`.
/// 3. Reads server params, generates keys, writes configs, and syncs the
///    interface — all natively in Rust using individual AWG commands.
/// 4. Logs `user_created` or `user_create_failed`.
///
/// The caller is responsible for triggering a config rescan after success.
pub async fn execute_create_user(
    db: &Database,
    config_dir: &std::path::Path,
    name: &str,
    actor: &str,
) -> Result<CreateUserResult, client_manager::CreateClientError> {
    // Pre-validate name (fail fast for the UI).
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

    // Fetch disabled keys so the sync step doesn't reactivate disabled peers.
    // Fail closed: if the DB lookup fails, abort the operation so disabled
    // peers are never accidentally reactivated.
    let disabled_keys = match crate::db::peers::list_disabled_public_keys(&db.pool).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, "failed to load disabled peers from database");
            let detail = serde_json::json!({
                "name": name,
                "error": "db_read_failed",
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
            return Err(client_manager::CreateClientError::DbRead(
                "failed to load disabled peers from database".to_string(),
            ));
        }
    };

    let dir = config_dir.to_path_buf();
    let client_name = name.to_string();

    // Run the blocking client-creation logic on a dedicated thread.
    let result = tokio::task::spawn_blocking(move || {
        client_manager::create_client(&dir, &client_name, &disabled_keys)
    })
    .await;

    // Handle JoinError from spawn_blocking (panic or cancellation).
    let result = match result {
        Ok(inner) => inner,
        Err(e) => {
            tracing::error!(error = %e, "client creation task panicked or was cancelled");
            Err(client_manager::CreateClientError::Internal(
                "internal error while running client creation task".to_string(),
            ))
        }
    };

    match result {
        Ok(r) => {
            let detail = serde_json::json!({
                "name": name,
                "config_path": &r.config_path,
            })
            .to_string();
            log_event(&db.pool, EVT_USER_CREATED, None, None, Some(&detail), actor).await;
            Ok(CreateUserResult {
                config_path: r.config_path,
                client_name: r.client_name,
            })
        }
        Err(e) => {
            // Log full error details server-side only; the audit event
            // visible via /api/events uses a fixed/sanitized message to
            // avoid leaking raw stderr, OS errors, or filesystem paths.
            tracing::error!(error = %e, name = name, "client creation failed");
            let sanitized = client_manager::sanitized_create_error_category(&e);
            let is_awg_partial_success = matches!(e, client_manager::CreateClientError::Awg(_));
            let (event_type, detail) = if is_awg_partial_success {
                // Configs were written, but interface sync failed. The HTTP API
                // reports this as a successful creation with `sync_required`.
                // Reflect that in the audit log by recording a created event
                // with an explicit `sync_required` flag instead of a failure.
                (
                    EVT_USER_CREATED,
                    serde_json::json!({
                        "name": name,
                        "error": sanitized,
                        "sync_required": true,
                    })
                    .to_string(),
                )
            } else {
                (
                    EVT_USER_CREATE_FAILED,
                    serde_json::json!({
                        "name": name,
                        "error": sanitized,
                    })
                    .to_string(),
                )
            };
            log_event(
                &db.pool,
                event_type,
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
/// After the script removes the peer block from the server config and deletes
/// the client config from its default location (`/etc/amnezia/amneziawg/clients`),
/// this function also attempts to remove any matching config file from
/// `config_dir` (the web panel's monitored directory) if it differs from
/// the default, so stale configs don't linger after a rescan.
///
/// Historical peer data (snapshots, events) is preserved in the database;
/// the peer row itself will become "unlinked" after the next config rescan
/// and will eventually stop appearing in `awg show` output.
pub async fn execute_remove_user(
    db: &Database,
    config_dir: &std::path::Path,
    peer_id: i64,
    client_name: &str,
    actor: &str,
) -> Result<(), RemoveClientError> {
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

    // Acquire the same exclusive lock used by create_client() to prevent
    // concurrent add/remove operations from corrupting the server config
    // (the remove path uses `sed -i` + rename which can race with `tee -a`).
    // Non-blocking (LOCK_NB) to avoid hanging web requests; returns an error
    // if another operation is in progress, matching create_client() behavior.
    let lock_path = config_dir.join(".create-client.lock");
    let lock_result = acquire_lifecycle_lock(&lock_path);
    let _lock_file = match lock_result {
        Ok(f) => f,
        Err(e) => {
            let error_kind = match &e {
                RemoveClientError::LockBusy => "lock_busy",
                _ => "lock_failed",
            };
            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
                "error": error_kind,
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
            return Err(e);
        }
    };

    let disabled_keys = crate::db::peers::list_disabled_public_keys(&db.pool)
        .await
        .map_err(|e| RemoveClientError::DbRead(e.to_string()))?;
    let dir = config_dir.to_path_buf();
    let name = client_name.to_string();
    let remove_result = tokio::task::spawn_blocking(move || {
        client_manager::remove_client(&dir, &name, &disabled_keys)
    })
    .await;

    let remove_result = match remove_result {
        Ok(inner) => inner,
        Err(e) => {
            tracing::error!(error = %e, "client removal task panicked or was cancelled");
            Err(RemoveClientError::Internal(
                "internal error while running client removal task".to_string(),
            ))
        }
    };

    match remove_result {
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
            tracing::warn!(
                peer_id = %peer_id,
                name = %client_name,
                error = %e,
                "failed to remove client natively"
            );
            let error_kind = client_manager::sanitized_remove_error_category(&e);
            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
                "error": error_kind,
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
