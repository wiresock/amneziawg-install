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
) -> Result<PeerRow, sqlx::Error> {
    let _mapping_guard = crate::poller::acquire_config_mapping_lock().await;
    let metadata = CreatedPeerMetadata {
        public_key: &result.public_key,
        allowed_ips: &result.allowed_ips,
        comment,
        config_name: &result.config_name,
        config_path: &result.config_path,
        friendly_name: &result.friendly_name,
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
        client_manager::create_client(&dir, &client_name, &disabled_keys, &ip_override)
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
pub async fn execute_create_user(
    db: &Database,
    config_dir: &std::path::Path,
    name: &str,
    comment: Option<&str>,
    actor: &str,
    ip_override: &client_manager::IpOverride,
    #[cfg(test)] create_result_override: Option<client_manager::CreateClientResult>,
) -> Result<CreateUserResult, client_manager::CreateClientError> {
    // Pre-validate name (fail fast for the UI).
    script_bridge::validate_client_name(name)?;
    // Defensively enforce the domain boundary for all current and future
    // callers, even if the HTTP layer already normalized the value.
    let comment = normalize_create_comment(comment);

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
    let ip_ovr = ip_override.clone();

    // Run the blocking client-creation logic on a dedicated thread. Tests can
    // inject the native result at this boundary while still exercising the
    // real validation, persistence, auditing, and HTTP response flow.
    #[cfg(test)]
    let result = match create_result_override {
        Some(result) => Ok(result),
        None => run_native_client_creation(dir, client_name, disabled_keys, ip_ovr).await,
    };
    #[cfg(not(test))]
    let result = run_native_client_creation(dir, client_name, disabled_keys, ip_ovr).await;

    match result {
        Ok(r) => {
            // Once create_client returns, the client and server configs are
            // durable. A later DB failure is therefore a partial success, not
            // a retry-safe creation failure.
            let metadata_persisted = match persist_created_peer(db, &r, comment.as_deref()).await {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        name = name,
                        public_key = %r.public_key,
                        "client was created but peer metadata could not be persisted"
                    );
                    false
                }
            };

            let detail = serde_json::json!({
                "name": name,
                "config_path": &r.config_path,
                "sync_required": r.sync_required,
                "metadata_persisted": metadata_persisted,
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_CREATED,
                None,
                Some(&r.public_key),
                Some(&detail),
                actor,
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
                actor,
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
/// This function delegates to `client_manager::remove_client`, which rewrites
/// the server config to remove the peer block, removes matching client config
/// files from `config_dir`, and syncs the running interface.
///
/// Historical snapshots/events are preserved; the peer row itself is deleted
/// from the `peers` table on successful removal.
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
    // concurrent add/remove operations from racing while rewriting the server
    // config and syncing the interface.
    // Non-blocking (LOCK_NB) to avoid hanging web requests; returns an error
    // if another operation is in progress, matching create_client() behavior.
    let lock_path = config_dir.join(".create-client.lock");
    let lock_result = acquire_lifecycle_lock(&lock_path).map_err(map_lock_error);
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

    let disabled_keys = match crate::db::peers::list_disabled_public_keys(&db.pool).await {
        Ok(keys) => keys,
        Err(e) => {
            let err = RemoveClientError::DbRead(e.to_string());
            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
                "error": "db_read_failed",
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
            return Err(err);
        }
    };
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
            if let Err(e) = crate::db::events::clear_peer_id_references(&db.pool, peer_id).await {
                tracing::error!(
                    peer_id = %peer_id,
                    error = %e,
                    "failed to clear event peer_id references after client removal"
                );
                let detail = serde_json::json!({
                    "peer_id": peer_id,
                    "name": client_name,
                    "error": "db_cleanup_failed",
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
                let detail = serde_json::json!({
                    "peer_id": peer_id,
                    "name": client_name,
                    "error": "db_cleanup_failed",
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
                return Err(RemoveClientError::Internal(format!(
                    "client removed from WireGuard but failed to delete peer row: {delete_result:?}"
                )));
            }

            let detail = serde_json::json!({
                "peer_id": peer_id,
                "name": client_name,
            })
            .to_string();
            log_event(
                &db.pool,
                EVT_USER_REMOVED,
                None,
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

        let row = persist_created_peer(&db, &result, Some("Main phone"))
            .await
            .expect("persist created peer");

        assert_eq!(row.public_key, result.public_key);
        assert_eq!(row.comment.as_deref(), Some("Main phone"));
        assert_eq!(row.allowed_ips, result.allowed_ips);
        assert_eq!(row.has_config, 1);
        assert_eq!(row.sync_pending, 1);
        assert_eq!(row.config_name.as_deref(), Some("awg0-client-alice"));
        assert_eq!(row.friendly_name.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn persist_created_peer_accepts_no_comment() {
        let db = Database::connect_for_test().await.expect("connect");
        let result = created_client_result(false);

        let row = persist_created_peer(&db, &result, None)
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
            "alice",
            Some("Main phone"),
            "test-admin",
            &client_manager::IpOverride::default(),
            Some(created_client_result(true)),
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
    async fn creation_persistence_waits_for_config_mapping_snapshot() {
        let db = Database::connect_for_test().await.expect("connect");
        let mapping_guard = crate::poller::acquire_config_mapping_lock().await;
        let task_db = db.clone();
        let task = tokio::spawn(async move {
            persist_created_peer(
                &task_db,
                &created_client_result(false),
                Some("Serialized comment"),
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
            crate::db::peers::delete_stale_peers(&db.pool, &std::collections::HashSet::new())
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
}
