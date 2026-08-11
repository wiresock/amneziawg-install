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
use crate::db::peers::{
    find_by_public_key, update_peer_disabled, upsert_created_peer, CreatedPeerMetadata, PeerRow,
};
use crate::db::Database;
use crate::domain::{normalize_comment, PublicKey};

use self::client_manager::{acquire_lifecycle_lock, RemoveClientError};

/// Serializes expiration edits with creation metadata persistence and
/// automated expiration cleanup. The native lifecycle lock still protects
/// server/config rewrites; this lock closes the smaller in-process races at
/// the database/lifecycle boundary.
static EXPIRATION_STATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn map_lock_error(err: std::io::Error) -> RemoveClientError {
    match err.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
            RemoveClientError::LockBusy
        }
        _ => RemoveClientError::Internal(format!(
            "failed to acquire lock for client removal: {err}"
        )),
    }
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
    if existing.archived != 0 {
        return Ok(None);
    }

    let disabled = !cmd.enabled;
    let old_disabled = existing.disabled != 0;

    // Short-circuit: skip the UPDATE if the value is already correct.
    if disabled == old_disabled {
        return Ok(Some(existing));
    }

    let Some(updated) = update_peer_disabled(&db.pool, existing.id, disabled).await? else {
        return Ok(None);
    };

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

    Ok(Some(updated))
}

// ── User lifecycle (create / remove) ─────────────────────────────────────────

/// Result of a successful user creation.
#[derive(Debug)]
pub struct CreateUserResult {
    /// Absolute path to the generated client config file.
    pub config_path: String,
    /// The client name that was requested.
    pub client_name: String,
    /// Whether the client exists on disk but still needs a live interface sync.
    pub sync_required: bool,
    /// Whether creation-time metadata, including the comment, was saved.
    pub metadata_persisted: bool,
}

fn normalize_create_comment(comment: Option<&str>) -> Option<String> {
    comment.and_then(normalize_comment)
}

async fn persist_created_peer(
    db: &Database,
    result: &client_manager::CreateClientResult,
    comment: Option<&str>,
    expires_at: Option<&str>,
) -> Result<PeerRow, sqlx::Error> {
    let _mapping_guard = crate::poller::acquire_config_mapping_lock().await;
    let metadata = CreatedPeerMetadata {
        public_key: &result.public_key,
        allowed_ips: &result.allowed_ips,
        comment,
        config_name: &result.config_name,
        config_path: &result.config_path,
        friendly_name: &result.friendly_name,
        managed_client_name: &result.client_name,
        expires_at,
    };
    upsert_created_peer(&db.pool, &metadata).await
}

async fn run_native_client_creation(
    dir: std::path::PathBuf,
    client_name: String,
    disabled_keys: std::collections::HashSet<String>,
    ip_override: client_manager::IpOverride,
) -> Result<client_manager::CreateClientResult, client_manager::CreateClientError> {
    match tokio::task::spawn_blocking(move || {
        client_manager::create_client_with_lifecycle_lock(
            &dir,
            &client_name,
            &disabled_keys,
            &ip_override,
        )
    })
    .await
    {
        Ok(inner) => inner,
        Err(e) => {
            tracing::error!(error = %e, "client creation task panicked or was cancelled");
            Err(client_manager::CreateClientError::Internal(
                "internal error while running client creation task".to_string(),
            ))
        }
    }
}

/// Fetch the next available IP addresses for client creation.
///
/// This is a read-only operation that can be used to pre-populate the
/// "Add user" form with suggested addresses.
pub async fn execute_suggest_ips(
) -> Result<client_manager::SuggestedIps, client_manager::CreateClientError> {
    tokio::task::spawn_blocking(client_manager::suggest_next_ips)
        .await
        .map_err(|e| {
            client_manager::CreateClientError::Internal(format!(
                "suggest_next_ips task panicked: {e}"
            ))
        })?
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
// Test-only native-result and lock-acquisition injections extend this
// boundary; production retains the lifecycle transaction parameters.
#[allow(clippy::too_many_arguments)]
pub async fn execute_create_user(
    db: &Database,
    config_dir: &std::path::Path,
    lifecycle_lock_dir: &std::path::Path,
    name: &str,
    comment: Option<&str>,
    expires_at: Option<&str>,
    actor: &str,
    ip_override: &client_manager::IpOverride,
    #[cfg(test)] create_result_override: Option<client_manager::CreateClientResult>,
    #[cfg(test)] expiration_lock_acquired: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(test)] expiration_lock_release: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<CreateUserResult, client_manager::CreateClientError> {
    let task = tokio::spawn(execute_create_user_transaction(
        db.clone(),
        config_dir.to_path_buf(),
        lifecycle_lock_dir.to_path_buf(),
        name.to_string(),
        comment.map(str::to_string),
        expires_at.map(str::to_string),
        actor.to_string(),
        ip_override.clone(),
        #[cfg(test)]
        create_result_override,
        #[cfg(test)]
        expiration_lock_acquired,
        #[cfg(test)]
        expiration_lock_release,
    ));

    match task.await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "client creation transaction panicked or was cancelled");
            Err(client_manager::CreateClientError::Internal(
                "internal error while running client creation transaction".to_string(),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_create_user_transaction(
    db: Database,
    config_dir: std::path::PathBuf,
    lifecycle_lock_dir: std::path::PathBuf,
    name: String,
    comment: Option<String>,
    expires_at: Option<String>,
    actor: String,
    ip_override: client_manager::IpOverride,
    #[cfg(test)] create_result_override: Option<client_manager::CreateClientResult>,
    #[cfg(test)] expiration_lock_acquired: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(test)] expiration_lock_release: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<CreateUserResult, client_manager::CreateClientError> {
    // Pre-validate name (fail fast for the UI).
    script_bridge::validate_client_name(&name)?;
    // Defensively enforce the domain boundary for all current and future
    // callers, even if the HTTP layer already normalized the value.
    let comment = normalize_create_comment(comment.as_deref());

    let detail = serde_json::json!({ "name": name }).to_string();
    log_event(
        &db.pool,
        EVT_USER_CREATE_REQUESTED,
        None,
        None,
        Some(&detail),
        &actor,
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
                &actor,
            )
            .await;
            return Err(client_manager::CreateClientError::DbRead(
                "failed to load disabled peers from database".to_string(),
            ));
        }
    };

    // Expiration state always precedes the native lifecycle lock. Keep both
    // held through metadata persistence so an edit cannot land on a
    // poller-created row and then be overwritten by the creation upsert.
    let _expiration_guard = EXPIRATION_STATE_LOCK.lock().await;
    #[cfg(test)]
    if let Some(acquired) = expiration_lock_acquired {
        let _ = acquired.send(());
    }
    #[cfg(test)]
    if let Some(release) = expiration_lock_release {
        let _ = release.await;
    }

    // Keep a single lifecycle lock held across native creation and metadata
    // persistence. If the database write fails, rollback runs under the same
    // lock, so no concurrent add/remove can strand or replace this client.
    #[cfg(test)]
    let lifecycle_lock_result = if create_result_override.is_some() {
        Ok(None)
    } else {
        client_manager::acquire_creation_lifecycle_lock(&config_dir, &lifecycle_lock_dir).map(Some)
    };
    #[cfg(not(test))]
    let lifecycle_lock_result =
        client_manager::acquire_creation_lifecycle_lock(&config_dir, &lifecycle_lock_dir).map(Some);
    let _lifecycle_lock = match lifecycle_lock_result {
        Ok(lock) => lock,
        Err(e) => {
            tracing::error!(error = %e, name = name, "failed to acquire client lifecycle lock");
            let detail = serde_json::json!({
                "name": name,
                "error": client_manager::sanitized_create_error_category(&e),
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_CREATE_FAILED,
                None,
                None,
                Some(&detail),
                &actor,
            )
            .await;
            return Err(e);
        }
    };

    let dir = config_dir.clone();
    let client_name = name.clone();
    let ip_ovr = ip_override.clone();
    let native_disabled_keys = disabled_keys.clone();

    // Run the blocking client-creation logic on a dedicated thread. Tests can
    // inject the native result at this boundary while still exercising the
    // real validation, persistence, auditing, and HTTP response flow.
    #[cfg(test)]
    let result = match create_result_override {
        Some(result) => Ok(result),
        None => run_native_client_creation(dir, client_name, native_disabled_keys, ip_ovr).await,
    };
    #[cfg(not(test))]
    let result = run_native_client_creation(dir, client_name, native_disabled_keys, ip_ovr).await;

    match result {
        Ok(r) => {
            let metadata_persisted = match persist_created_peer(
                &db,
                &r,
                comment.as_deref(),
                expires_at.as_deref(),
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        name = name,
                        public_key = %r.public_key,
                        "client was created but peer metadata could not be persisted"
                    );
                    // Permanent clients retain the historical partial-success
                    // behavior. An expiring client must fail closed so a lost
                    // deadline can never silently turn it into a permanent one.
                    if expires_at.is_some() {
                        let rollback =
                            rollback_created_expiring_client(&db, &config_dir, &r, &disabled_keys)
                                .await;
                        if let Err(rollback_error) = &rollback {
                            tracing::error!(
                                error = %rollback_error,
                                name = name,
                                public_key = %r.public_key,
                                "failed to roll back expiring client after metadata failure"
                            );
                        }
                        let detail = serde_json::json!({
                            "name": name,
                            "error": "expiration_metadata_persistence_failed",
                            "rollback_succeeded": rollback.is_ok(),
                        })
                        .to_string();
                        log_event(
                            &db.pool,
                            EVT_USER_CREATE_FAILED,
                            None,
                            Some(&r.public_key),
                            Some(&detail),
                            &actor,
                        )
                        .await;
                        return Err(client_manager::CreateClientError::DbRead(
                            if rollback.is_ok() {
                                "expiration could not be saved; client creation was rolled back"
                                    .to_string()
                            } else {
                                "expiration could not be saved and client rollback failed; manual cleanup is required"
                                    .to_string()
                            },
                        ));
                    }
                    false
                }
            };

            let detail = serde_json::json!({
                "name": name,
                "config_path": &r.config_path,
                "sync_required": r.sync_required,
                "metadata_persisted": metadata_persisted,
                "expires_at": expires_at,
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_CREATED,
                None,
                Some(&r.public_key),
                Some(&detail),
                &actor,
            )
            .await;
            Ok(CreateUserResult {
                config_path: r.config_path,
                client_name: r.client_name,
                sync_required: r.sync_required,
                metadata_persisted,
            })
        }
        Err(e) => {
            // Log full error details server-side only; the audit event
            // visible via /api/events uses a fixed/sanitized message to
            // avoid leaking raw stderr, OS errors, or filesystem paths.
            tracing::error!(error = %e, name = name, "client creation failed");
            let sanitized = client_manager::sanitized_create_error_category(&e);
            let detail = serde_json::json!({
                "name": name,
                "error": sanitized,
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_CREATE_FAILED,
                None,
                None,
                Some(&detail),
                &actor,
            )
            .await;
            Err(e)
        }
    }
}

/// Remove an existing AmneziaWG user/client via the native Rust client manager.
///
/// The `client_name` should be the client identifier used in
/// `### Client <name>` markers in the server config.
///
/// This function delegates to the resumable native removal path, which rewrites
/// the server config to remove the peer block, removes matching client config
/// files from `config_dir`, and syncs the running interface.
///
/// Historical snapshots/events are preserved; the peer row itself is deleted
/// from the `peers` table on successful removal.
pub async fn execute_remove_user(
    db: &Database,
    config_dir: &std::path::Path,
    lifecycle_lock_dir: &std::path::Path,
    peer_id: i64,
    client_name: &str,
    actor: &str,
) -> Result<(), RemoveClientError> {
    execute_remove_user_inner(
        db,
        config_dir,
        lifecycle_lock_dir,
        peer_id,
        client_name,
        actor,
        "manual",
        None,
        true,
    )
    .await
    .map(|_| ())
}

/// Set or clear a peer expiration while serialized with automated cleanup.
pub async fn execute_update_peer_expiration(
    db: &Database,
    peer_id: i64,
    expires_at: Option<&str>,
    managed_client_name: Option<&str>,
) -> Result<Option<PeerRow>, sqlx::Error> {
    let _guard = EXPIRATION_STATE_LOCK.lock().await;
    crate::db::peers::update_peer_expiration(
        &db.pool,
        peer_id,
        expires_at,
        managed_client_name,
    )
    .await
}

/// Update metadata and an optional expiration as one guarded database change.
pub async fn execute_update_peer_details(
    db: &Database,
    peer_id: i64,
    display_name: Option<&str>,
    comment: Option<&str>,
    expiration_update: Option<Option<&str>>,
    managed_client_name: Option<&str>,
) -> Result<Option<PeerRow>, sqlx::Error> {
    let _guard = EXPIRATION_STATE_LOCK.lock().await;
    crate::db::peers::update_peer_details(
        &db.pool,
        peer_id,
        display_name,
        comment,
        expiration_update,
        managed_client_name,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_remove_user_inner(
    db: &Database,
    config_dir: &std::path::Path,
    lifecycle_lock_dir: &std::path::Path,
    peer_id: i64,
    client_name: &str,
    actor: &str,
    reason: &str,
    expected_expires_at: Option<&str>,
    persist_attempt_events: bool,
) -> Result<bool, RemoveClientError> {
    let task = tokio::spawn(execute_remove_user_transaction(
        db.clone(),
        config_dir.to_path_buf(),
        lifecycle_lock_dir.to_path_buf(),
        peer_id,
        client_name.to_string(),
        actor.to_string(),
        reason.to_string(),
        expected_expires_at.map(str::to_string),
        persist_attempt_events,
    ));

    match task.await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "client removal transaction panicked or was cancelled");
            Err(RemoveClientError::Internal(
                "internal error while running client removal transaction".to_string(),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_remove_user_transaction(
    db: Database,
    config_dir: std::path::PathBuf,
    lifecycle_lock_dir: std::path::PathBuf,
    peer_id: i64,
    client_name: String,
    actor: String,
    reason: String,
    expected_expires_at: Option<String>,
    persist_attempt_events: bool,
) -> Result<bool, RemoveClientError> {
    script_bridge::validate_client_name(&client_name)?;

    // Expiration revalidation and any following native/database cleanup must
    // remain serialized even if the poller is cancelled during shutdown.
    let _expiration_guard = if expected_expires_at.is_some() {
        Some(EXPIRATION_STATE_LOCK.lock().await)
    } else {
        None
    };

    if persist_attempt_events {
        let detail = serde_json::json!({
            "peer_id": peer_id,
            "name": client_name,
            "reason": reason,
        })
        .to_string();
        log_event(
            &db.pool,
            EVT_USER_REMOVE_REQUESTED,
            Some(peer_id),
            None,
            Some(&detail),
            &actor,
        )
        .await;
    }

    // Acquire the same exclusive lock used by create_client() to prevent
    // concurrent add/remove operations from racing while rewriting the server
    // config and syncing the interface.
    // Non-blocking (LOCK_NB) to avoid hanging web requests; returns an error
    // if another operation is in progress, matching create_client() behavior.
    let lock_result = acquire_lifecycle_lock(&lifecycle_lock_dir).map_err(map_lock_error);
    let _lock_file = match lock_result {
        Ok(f) => f,
        Err(e) => {
            let error_kind = match &e {
                RemoveClientError::LockBusy => "lock_busy",
                _ => "lock_failed",
            };
            if persist_attempt_events {
                let detail = serde_json::json!({
                    "peer_id": peer_id,
                    "name": client_name,
                    "reason": reason,
                    "error": error_kind,
                })
                .to_string();
                log_event(
                    &db.pool,
                    EVT_USER_REMOVE_FAILED,
                    Some(peer_id),
                    None,
                    Some(&detail),
                    &actor,
                )
                .await;
            }
            return Err(e);
        }
    };

    // Expiration cleanup revalidates the exact timestamp while holding the
    // lifecycle lock. If an administrator extended or cleared the expiration
    // after the candidate list was read, the client is left untouched.
    if let Some(expected) = expected_expires_at.as_deref() {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let still_due = crate::db::peers::expiration_is_due(
            &db.pool,
            peer_id,
            expected,
            &now,
        )
        .await
        .map_err(|e| RemoveClientError::DbRead(e.to_string()))?;
        if !still_due {
            tracing::info!(
                peer_id,
                name = %client_name,
                "expiration changed before cleanup; skipping removal"
            );
            return Ok(false);
        }
    }

    let expected_public_key = crate::db::peers::find_by_id(&db.pool, peer_id)
        .await
        .map_err(|e| RemoveClientError::DbRead(e.to_string()))?
        .ok_or_else(|| {
            RemoveClientError::DbRead(
                "peer disappeared before native removal could start".to_string(),
            )
        })?
        .public_key;

    let disabled_keys = match crate::db::peers::list_disabled_public_keys(&db.pool).await {
        Ok(keys) => keys,
        Err(e) => {
            let err = RemoveClientError::DbRead(e.to_string());
            if persist_attempt_events {
                let detail = serde_json::json!({
                    "peer_id": peer_id,
                    "name": client_name,
                    "reason": reason,
                    "error": "db_read_failed",
                })
                .to_string();
                log_event(
                    &db.pool,
                    EVT_USER_REMOVE_FAILED,
                    Some(peer_id),
                    None,
                    Some(&detail),
                    &actor,
                )
                .await;
            }
            return Err(err);
        }
    };

    // From this point onward the native path may partially remove the server
    // block, live peer, or client config. Persist retry ownership before the
    // first external mutation so poller stale cleanup cannot discard the row.
    let removal_marked = crate::db::peers::mark_removal_pending(&db.pool, peer_id)
        .await
        .map_err(|e| RemoveClientError::DbRead(e.to_string()))?;
    if !removal_marked {
        return Err(RemoveClientError::DbRead(
            "peer disappeared before native removal could start".to_string(),
        ));
    }

    let dir = config_dir.clone();
    let name = client_name.clone();
    let remove_result = tokio::task::spawn_blocking(move || {
        client_manager::remove_client_resumable(
            &dir,
            &name,
            &expected_public_key,
            &disabled_keys,
        )
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
            if let Err(e) = crate::db::events::clear_peer_id_references(&db.pool, peer_id).await {
                tracing::error!(
                    peer_id = %peer_id,
                    error = %e,
                    "failed to clear event peer_id references after client removal"
                );
                if persist_attempt_events {
                    let detail = serde_json::json!({
                        "peer_id": peer_id,
                        "name": client_name,
                        "reason": reason,
                        "error": "db_cleanup_failed",
                    })
                    .to_string();
                    log_event(
                        &db.pool,
                        EVT_USER_REMOVE_FAILED,
                        Some(peer_id),
                        None,
                        Some(&detail),
                        &actor,
                    )
                    .await;
                }
                return Err(RemoveClientError::Internal(format!(
                    "client removed from WireGuard but database cleanup failed: {e}"
                )));
            }

            let delete_result = crate::db::peers::delete_by_id(&db.pool, peer_id).await;
            if !matches!(&delete_result, Ok(true)) {
                tracing::error!(
                    peer_id = %peer_id,
                    result = ?delete_result,
                    "failed to delete removed peer row from database"
                );
                if persist_attempt_events {
                    let detail = serde_json::json!({
                        "peer_id": peer_id,
                        "name": client_name,
                        "reason": reason,
                        "error": "db_cleanup_failed",
                    })
                    .to_string();
                    log_event(
                        &db.pool,
                        EVT_USER_REMOVE_FAILED,
                        Some(peer_id),
                        None,
                        Some(&detail),
                        &actor,
                    )
                    .await;
                }
                return Err(RemoveClientError::Internal(format!(
                    "client removed from WireGuard but failed to delete peer row: {delete_result:?}"
                )));
            }

            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
                "reason": reason,
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_REMOVED,
                None,
                None,
                Some(&detail),
                &actor,
            )
            .await;
            Ok(true)
        }
        Err(e) => {
            tracing::warn!(
                peer_id = %peer_id,
                name = %client_name,
                error = %e,
                "failed to remove client natively"
            );
            let error_kind = client_manager::sanitized_remove_error_category(&e);
            if persist_attempt_events {
                let detail = serde_json::json!({
                    "peer_id": peer_id,
                    "name": client_name,
                    "reason": reason,
                    "error": error_kind,
                })
                .to_string();
                log_event(
                    &db.pool,
                    EVT_USER_REMOVE_FAILED,
                    Some(peer_id),
                    None,
                    Some(&detail),
                    &actor,
                )
                .await;
            }
            Err(e)
        }
    }
}

async fn delete_rolled_back_peer_state(
    db: &Database,
    public_key: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = db.pool.begin().await?;
    sqlx::query(
        "UPDATE events
         SET peer_id = NULL
         WHERE peer_id IN (SELECT id FROM peers WHERE public_key = ?)",
    )
    .bind(public_key)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM peers WHERE public_key = ? AND archived = 0")
        .bind(public_key)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

#[cfg(not(test))]
async fn rollback_created_expiring_client(
    db: &Database,
    config_dir: &std::path::Path,
    result: &client_manager::CreateClientResult,
    disabled_keys: &std::collections::HashSet<String>,
) -> Result<(), String> {
    let dir = config_dir.to_path_buf();
    let name = result.client_name.clone();
    let public_key = result.public_key.clone();
    let disabled_keys = disabled_keys.clone();
    tokio::task::spawn_blocking(move || {
        client_manager::remove_client_resumable(&dir, &name, &public_key, &disabled_keys)
    })
    .await
    .map_err(|error| format!("rollback task failed: {error}"))?
    .map_err(|error| format!("native rollback failed: {error}"))?;
    delete_rolled_back_peer_state(db, &result.public_key)
        .await
        .map_err(|error| format!("database rollback cleanup failed: {error}"))
}

// Native creation is injected in unit tests, so there is no server/config
// state to undo. Keep the database half of rollback real and testable.
#[cfg(test)]
async fn rollback_created_expiring_client(
    db: &Database,
    _config_dir: &std::path::Path,
    result: &client_manager::CreateClientResult,
    _disabled_keys: &std::collections::HashSet<String>,
) -> Result<(), String> {
    delete_rolled_back_peer_state(db, &result.public_key)
        .await
        .map_err(|error| format!("database rollback cleanup failed: {error}"))
}

/// Remove every managed peer whose expiration is due.
///
/// This intentionally calls the same native removal path as an administrator:
/// server peer block removal, client-config deletion, live-interface sync,
/// event reference cleanup, and peer-row deletion all remain centralized.
/// Failures are logged and left in the database so a later periodic pass can
/// retry them. Automated attempts are emitted to the service log rather than
/// persisted as audit events on every poll; the final successful removal still
/// records `user_removed` through the shared path.
pub async fn cleanup_expired_users(
    db: &Database,
    config_dir: &std::path::Path,
    lifecycle_lock_dir: &std::path::Path,
) -> Result<usize, sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let expired = crate::db::peers::list_expired(&db.pool, &now).await?;
    let mut removed = 0usize;

    for peer in expired {
        let Some(expires_at) = peer.expires_at.as_deref() else {
            continue;
        };
        let Some(client_name) = peer
            .managed_client_name
            .as_deref()
            .filter(|name| script_bridge::validate_client_name(name).is_ok())
        else {
            tracing::error!(
                peer_id = peer.id,
                public_key = %peer.public_key,
                "expired peer has no stable installer-managed client name; cleanup will retry"
            );
            continue;
        };

        match execute_remove_user_inner(
            db,
            config_dir,
            lifecycle_lock_dir,
            peer.id,
            client_name,
            "system",
            "expiration",
            Some(expires_at),
            false,
        )
        .await
        {
            Ok(true) => {
                removed += 1;
                tracing::info!(peer_id = peer.id, name = %client_name, "expired user removed");
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    peer_id = peer.id,
                    name = %client_name,
                    error = %e,
                    "failed to remove expired user; cleanup will retry"
                );
            }
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn created_client_result(sync_required: bool) -> client_manager::CreateClientResult {
        client_manager::CreateClientResult {
            config_path: "/etc/amnezia/amneziawg/clients/awg0-client-alice.conf".to_string(),
            config_name: "awg0-client-alice".to_string(),
            client_name: "alice".to_string(),
            friendly_name: "alice".to_string(),
            public_key: "CREATED_PUBLIC_KEY=".to_string(),
            allowed_ips: "10.66.66.2/32,fd42:42:42::2/128".to_string(),
            sync_required,
        }
    }

    #[test]
    fn create_comment_boundary_trims_blanks_and_limits_length() {
        assert_eq!(
            normalize_create_comment(Some("  Main phone  ")).as_deref(),
            Some("Main phone")
        );
        assert!(normalize_create_comment(Some(" \t\n ")).is_none());
        assert!(normalize_create_comment(None).is_none());

        let long = "☃".repeat(crate::domain::MAX_COMMENT_LEN + 10);
        let normalized = normalize_create_comment(Some(&long)).expect("normalized comment");
        assert_eq!(normalized.chars().count(), crate::domain::MAX_COMMENT_LEN);
    }

    #[tokio::test]
    async fn persist_created_peer_stores_comment_during_partial_sync() {
        let db = Database::connect_for_test().await.expect("connect");
        let result = created_client_result(true);

        let row = persist_created_peer(
            &db,
            &result,
            Some("Main phone"),
            Some("2026-08-18T12:00:00Z"),
        )
            .await
            .expect("persist created peer");

        assert_eq!(row.public_key, result.public_key);
        assert_eq!(row.comment.as_deref(), Some("Main phone"));
        assert_eq!(row.allowed_ips, result.allowed_ips);
        assert_eq!(row.has_config, 1);
        assert_eq!(row.sync_pending, 1);
        assert_eq!(row.config_name.as_deref(), Some("awg0-client-alice"));
        assert_eq!(row.friendly_name.as_deref(), Some("alice"));
        assert_eq!(row.expires_at.as_deref(), Some("2026-08-18T12:00:00Z"));
    }

    #[tokio::test]
    async fn persist_created_peer_accepts_no_comment() {
        let db = Database::connect_for_test().await.expect("connect");
        let result = created_client_result(false);

        let row = persist_created_peer(&db, &result, None, None)
            .await
            .expect("persist created peer");

        assert!(row.comment.is_none());
        assert_eq!(row.has_config, 1);
        assert_eq!(row.sync_pending, 1);
    }

    #[tokio::test]
    async fn durable_creation_reports_metadata_persistence_failure_as_partial_success() {
        let db = Database::connect_for_test().await.expect("connect");
        sqlx::query(
            "CREATE TRIGGER fail_created_peer_insert
             BEFORE INSERT ON peers
             BEGIN
               SELECT RAISE(FAIL, 'forced peer metadata failure');
             END",
        )
        .execute(&db.pool)
        .await
        .expect("install failure trigger");

        let dir = tempfile::tempdir().expect("tempdir");
        let outcome = execute_create_user(
            &db,
            dir.path(),
            dir.path(),
            "alice",
            Some("Main phone"),
            None,
            "test-admin",
            &client_manager::IpOverride::default(),
            Some(created_client_result(true)),
            None,
            None,
        )
        .await
        .expect("durable creation must remain a success");

        assert!(outcome.sync_required);
        assert!(!outcome.metadata_persisted);
        assert!(find_by_public_key(&db.pool, "CREATED_PUBLIC_KEY=")
            .await
            .expect("query peer")
            .is_none());

        let created_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events
             WHERE action = ? AND detail LIKE '%\"metadata_persisted\":false%'",
        )
        .bind(EVT_USER_CREATED)
        .fetch_one(&db.pool)
        .await
        .expect("count created events");
        let failed_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE action = ?")
            .bind(EVT_USER_CREATE_FAILED)
            .fetch_one(&db.pool)
            .await
            .expect("count failed events");
        assert_eq!(created_events, 1);
        assert_eq!(failed_events, 0);
    }

    #[tokio::test]
    async fn expiring_creation_rolls_back_when_deadline_cannot_be_persisted() {
        let db = Database::connect_for_test().await.expect("connect");
        sqlx::query(
            "INSERT INTO peers (public_key, allowed_ips)
             VALUES ('CREATED_PUBLIC_KEY=', '10.66.66.2/32')",
        )
        .execute(&db.pool)
        .await
        .expect("seed poller-created peer");
        sqlx::query(
            "CREATE TRIGGER fail_created_peer_update
             BEFORE UPDATE ON peers
             WHEN OLD.public_key = 'CREATED_PUBLIC_KEY='
             BEGIN
               SELECT RAISE(FAIL, 'forced peer metadata failure');
             END",
        )
        .execute(&db.pool)
        .await
        .expect("install failure trigger");

        let dir = tempfile::tempdir().expect("tempdir");
        let outcome = execute_create_user(
            &db,
            dir.path(),
            dir.path(),
            "alice",
            Some("Main phone"),
            Some("2026-08-18T12:00:00Z"),
            "test-admin",
            &client_manager::IpOverride::default(),
            Some(created_client_result(true)),
            None,
            None,
        )
        .await;

        assert!(matches!(
            outcome,
            Err(client_manager::CreateClientError::DbRead(_))
        ));
        assert!(find_by_public_key(&db.pool, "CREATED_PUBLIC_KEY=")
            .await
            .expect("query peer")
            .is_none());
        let created_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE action = ?")
                .bind(EVT_USER_CREATED)
                .fetch_one(&db.pool)
                .await
                .expect("count created events");
        let failed_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events
             WHERE action = ? AND detail LIKE '%\"rollback_succeeded\":true%'",
        )
        .bind(EVT_USER_CREATE_FAILED)
        .fetch_one(&db.pool)
        .await
        .expect("count failed events");
        assert_eq!(created_events, 0);
        assert_eq!(failed_events, 1);
    }

    #[tokio::test]
    async fn expiration_retries_do_not_append_attempt_audit_events() {
        let db = Database::connect_for_test().await.expect("connect");
        sqlx::query(
            "INSERT INTO peers (
                 public_key, allowed_ips, managed_client_name, expires_at
             ) VALUES (
                 'EXPIRED_RETRY_KEY=', '10.66.66.9/32', 'retry-user',
                 '2000-01-01T00:00:00Z'
             )",
        )
        .execute(&db.pool)
        .await
        .expect("seed expired peer");

        let state_dir = tempfile::tempdir().expect("state tempdir");
        let missing_config_dir = state_dir.path().join("missing-clients");
        for _ in 0..2 {
            assert_eq!(
                cleanup_expired_users(&db, &missing_config_dir, state_dir.path())
                    .await
                    .expect("cleanup pass"),
                0
            );
        }

        let attempt_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events
             WHERE action IN (?, ?)",
        )
        .bind(EVT_USER_REMOVE_REQUESTED)
        .bind(EVT_USER_REMOVE_FAILED)
        .fetch_one(&db.pool)
        .await
        .expect("count removal attempt events");
        assert_eq!(attempt_events, 0);
    }

    #[tokio::test]
    async fn creation_persistence_waits_for_config_mapping_snapshot() {
        let db = Database::connect_for_test().await.expect("connect");
        let mapping_guard = crate::poller::acquire_config_mapping_lock().await;
        let task_db = db.clone();
        let task = tokio::spawn(async move {
            persist_created_peer(
                &task_db,
                &created_client_result(false),
                Some("Serialized comment"),
                None,
            )
            .await
        });

        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "creation metadata must wait for an in-progress config snapshot"
        );

        crate::db::peers::clear_all_config_mappings(&db.pool)
            .await
            .expect("apply stale empty mapping");
        drop(mapping_guard);

        let row = task
            .await
            .expect("persistence task")
            .expect("persist after mapping");
        let removed =
            crate::db::peers::delete_stale_peers(
                &db.pool,
                &std::collections::HashSet::new(),
                "2026-08-11T12:00:00Z",
            )
                .await
                .expect("stale cleanup");
        assert!(removed.is_empty());

        let persisted = find_by_public_key(&db.pool, &row.public_key)
            .await
            .expect("query peer")
            .expect("pending created peer must survive");
        assert_eq!(persisted.comment.as_deref(), Some("Serialized comment"));
        assert_eq!(persisted.has_config, 1);
        assert_eq!(persisted.sync_pending, 1);
    }

    #[tokio::test]
    async fn expiration_edit_waits_for_creation_metadata_persistence() {
        let db = Database::connect_for_test().await.expect("connect");
        sqlx::query(
            "INSERT INTO peers (public_key, allowed_ips)
             VALUES ('CREATED_PUBLIC_KEY=', '10.66.66.2/32')",
        )
        .execute(&db.pool)
        .await
        .expect("seed poller-created peer");
        let peer = find_by_public_key(&db.pool, "CREATED_PUBLIC_KEY=")
            .await
            .expect("query peer")
            .expect("seeded peer");

        let task_db = db.clone();
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        let (lock_acquired_tx, lock_acquired_rx) = tokio::sync::oneshot::channel();
        let (lock_release_tx, lock_release_rx) = tokio::sync::oneshot::channel();
        let create_task = tokio::spawn(async move {
            let ip_override = client_manager::IpOverride::default();
            execute_create_user(
                &task_db,
                &dir_path,
                &dir_path,
                "alice",
                None,
                None,
                "test-admin",
                &ip_override,
                Some(created_client_result(false)),
                Some(lock_acquired_tx),
                Some(lock_release_rx),
            )
            .await
        });

        lock_acquired_rx
            .await
            .expect("creation must acquire the expiration lock before persistence");

        let update_db = db.clone();
        let update_task = tokio::spawn(async move {
            execute_update_peer_expiration(
                &update_db,
                peer.id,
                Some("2026-08-18T12:00:00Z"),
                Some("alice"),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(
            !update_task.is_finished(),
            "expiration edit must wait until creation metadata is durable"
        );

        lock_release_tx
            .send(())
            .expect("release creation persistence");
        create_task
            .await
            .expect("creation task")
            .expect("create user");
        update_task
            .await
            .expect("expiration task")
            .expect("update expiration")
            .expect("updated peer");

        let persisted = find_by_public_key(&db.pool, "CREATED_PUBLIC_KEY=")
            .await
            .expect("query peer")
            .expect("persisted peer");
        assert_eq!(
            persisted.expires_at.as_deref(),
            Some("2026-08-18T12:00:00Z")
        );
    }

    #[tokio::test]
    async fn creation_transaction_survives_caller_cancellation() {
        let db = Database::connect_for_test().await.expect("connect");
        let task_db = db.clone();
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        let (lock_acquired_tx, lock_acquired_rx) = tokio::sync::oneshot::channel();
        let (lock_release_tx, lock_release_rx) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(async move {
            let ip_override = client_manager::IpOverride::default();
            execute_create_user(
                &task_db,
                &dir_path,
                &dir_path,
                "alice",
                None,
                Some("2026-08-18T12:00:00Z"),
                "test-admin",
                &ip_override,
                Some(created_client_result(false)),
                Some(lock_acquired_tx),
                Some(lock_release_rx),
            )
            .await
        });

        lock_acquired_rx
            .await
            .expect("creation transaction must acquire its lock");
        caller.abort();
        let _ = caller.await;
        lock_release_tx
            .send(())
            .expect("owned creation transaction must survive caller cancellation");

        let persisted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(peer) = find_by_public_key(&db.pool, "CREATED_PUBLIC_KEY=")
                    .await
                    .expect("query peer")
                {
                    break peer;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached creation transaction must finish persistence");

        assert_eq!(
            persisted.expires_at.as_deref(),
            Some("2026-08-18T12:00:00Z")
        );
        assert_eq!(persisted.managed_client_name.as_deref(), Some("alice"));
    }
}
