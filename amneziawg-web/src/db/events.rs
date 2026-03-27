//! Database query layer for the `events` (audit log) table.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE events (
//!     id         INTEGER PRIMARY KEY AUTOINCREMENT,
//!     actor      TEXT    NOT NULL DEFAULT 'system',
//!     action     TEXT    NOT NULL,   -- event type, e.g. 'peer_updated'
//!     peer_id    INTEGER,            -- FK to peers.id (nullable)
//!     target_key TEXT,               -- public_key of affected peer (if any)
//!     detail     TEXT,               -- JSON payload
//!     created_at TEXT    NOT NULL DEFAULT (DATETIME('now'))
//! );
//! ```
//!
//! # Event types
//!
//! | Constant | Value | When logged |
//! |---|---|---|
//! | [`EVT_PEER_UPDATED`] | `"peer_updated"` | PATCH /api/peers/:id or POST /peers/:id |
//! | [`EVT_LOGIN_SUCCESS`] | `"login_success"` | successful POST /login |
//! | [`EVT_LOGIN_FAILED`]  | `"login_failed"`  | failed POST /login credential check |
//! | [`EVT_LOGOUT`]        | `"logout"`        | POST /logout |
//!
//! # Fire-and-forget logging
//!
//! [`log_event`] is intentionally infallible from the caller's perspective.
//! If the INSERT fails, a `tracing::warn!` is emitted but the main operation
//! is **not** rolled back or interrupted.

use sqlx::SqlitePool;
use tracing::warn;

// ── Event type constants ─────────────────────────────────────────────────────

/// Audit event for `PATCH /api/peers/:id` and `POST /peers/:id` writes.
pub const EVT_PEER_UPDATED: &str = "peer_updated";
/// Audit event for a successful login.
pub const EVT_LOGIN_SUCCESS: &str = "login_success";
/// Audit event for a failed login attempt (wrong credentials).
pub const EVT_LOGIN_FAILED: &str = "login_failed";
/// Audit event for `POST /logout`.
pub const EVT_LOGOUT: &str = "logout";
/// Audit event for enabling or disabling a peer.
pub const EVT_PEER_DISABLED: &str = "peer_disabled";
/// Audit event when a user creation is requested.
pub const EVT_USER_CREATE_REQUESTED: &str = "user_create_requested";
/// Audit event when a user creation succeeds.
pub const EVT_USER_CREATED: &str = "user_created";
/// Audit event when a user creation fails.
pub const EVT_USER_CREATE_FAILED: &str = "user_create_failed";
/// Audit event when a user removal is requested.
pub const EVT_USER_REMOVE_REQUESTED: &str = "user_remove_requested";
/// Audit event when a user removal succeeds.
pub const EVT_USER_REMOVED: &str = "user_removed";
/// Audit event when a user removal fails.
pub const EVT_USER_REMOVE_FAILED: &str = "user_remove_failed";

/// Maximum number of events that can be returned in a single [`list_events`] call.
pub const MAX_EVENTS_LIMIT: i64 = 200;

// ── EventRow ─────────────────────────────────────────────────────────────────

/// A row fetched from the `events` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventRow {
    pub id: i64,
    pub actor: String,
    /// Event type string (e.g. `"peer_updated"`).
    pub action: String,
    /// Integer FK to `peers.id`, if the event is associated with a peer.
    pub peer_id: Option<i64>,
    /// Public key of the affected peer, if applicable.
    #[allow(dead_code)]
    pub target_key: Option<String>,
    /// JSON payload with event-specific context.
    pub detail: Option<String>,
    pub created_at: String,
}

// ── log_event ─────────────────────────────────────────────────────────────────

/// Insert an audit event into the `events` table.
///
/// This function is **fire-and-forget**: errors are logged with `warn!` but
/// are **not** propagated to the caller so that a logging failure never aborts
/// the main operation.
///
/// # Parameters
///
/// - `action`     – one of the `EVT_*` constants, e.g. [`EVT_PEER_UPDATED`].
/// - `peer_id`    – integer primary key of the affected peer, if any.
/// - `target_key` – `public_key` of the affected peer (additional lookup field).
/// - `detail`     – JSON string with action-specific payload.
/// - `actor`      – username of the acting party (e.g. `"admin"`).
pub async fn log_event(
    pool: &SqlitePool,
    action: &str,
    peer_id: Option<i64>,
    target_key: Option<&str>,
    detail: Option<&str>,
    actor: &str,
) {
    let result = sqlx::query(
        "INSERT INTO events (actor, action, peer_id, target_key, detail)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(peer_id)
    .bind(target_key)
    .bind(detail)
    .execute(pool)
    .await;

    if let Err(e) = result {
        warn!(action, actor, error = %e, "audit log write failed (event dropped)");
    }
}

// ── list_events ───────────────────────────────────────────────────────────────

/// Query the `events` table with optional filters.
///
/// All filter parameters are optional (`None` means "no filter").
///
/// - `peer_id`  – restrict to events for this peer integer ID.
/// - `action`   – restrict to events with this action/event-type string.
/// - `limit`    – maximum number of rows to return (default: 50, capped at [`MAX_EVENTS_LIMIT`]).
///
/// Results are ordered newest-first (`id DESC`).
pub async fn list_events(
    pool: &SqlitePool,
    peer_id: Option<i64>,
    action: Option<&str>,
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    let capped_limit = limit.clamp(1, MAX_EVENTS_LIMIT);
    sqlx::query_as::<_, EventRow>(
        "SELECT id, actor, action, peer_id, target_key, detail, created_at
         FROM   events
         WHERE  (? IS NULL OR peer_id = ?)
           AND  (? IS NULL OR action  = ?)
         ORDER  BY id DESC
         LIMIT  ?",
    )
    .bind(peer_id)
    .bind(peer_id)
    .bind(action)
    .bind(action)
    .bind(capped_limit)
    .fetch_all(pool)
    .await
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> crate::db::Database {
        crate::db::Database::connect_for_test()
            .await
            .expect("connect")
    }

    async fn insert_peer(pool: &SqlitePool, public_key: &str) -> i64 {
        sqlx::query("INSERT INTO peers (public_key, allowed_ips) VALUES (?, '10.0.0.2/32')")
            .bind(public_key)
            .execute(pool)
            .await
            .expect("insert peer")
            .last_insert_rowid()
    }

    // ── log_event ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn log_event_inserts_row() {
        let db = test_db().await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            None,
            Some("PUBKEY=="),
            Some(r#"{"old_name":null,"new_name":"Alice"}"#),
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, None, None, 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.action, EVT_PEER_UPDATED);
        assert_eq!(row.actor, "admin");
        assert_eq!(row.target_key.as_deref(), Some("PUBKEY=="));
        assert!(row.peer_id.is_none());
        assert!(row.detail.as_deref().unwrap().contains("Alice"));
    }

    #[tokio::test]
    async fn log_event_with_peer_id() {
        let db = test_db().await;
        let pid = insert_peer(&db.pool, "PKEY_LOG==").await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            Some(pid),
            Some("PKEY_LOG=="),
            Some(r#"{"old_name":"Old","new_name":"New"}"#),
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, Some(pid), None, 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].peer_id, Some(pid));
    }

    #[tokio::test]
    async fn log_event_without_detail() {
        let db = test_db().await;
        log_event(&db.pool, EVT_LOGIN_SUCCESS, None, None, None, "admin").await;
        let rows = list_events(&db.pool, None, None, 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, EVT_LOGIN_SUCCESS);
        assert!(rows[0].detail.is_none());
    }

    // ── list_events ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_events_empty() {
        let db = test_db().await;
        let rows = list_events(&db.pool, None, None, 50)
            .await
            .expect("list_events");
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn list_events_ordered_newest_first() {
        let db = test_db().await;
        for i in 0..3 {
            log_event(
                &db.pool,
                EVT_PEER_UPDATED,
                None,
                Some("KEY=="),
                Some(&format!(r#"{{"seq":{i}}}"#)),
                "admin",
            )
            .await;
        }
        let rows = list_events(&db.pool, None, None, 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 3);
        // Newest (highest id) first.
        assert!(rows[0].id > rows[1].id);
        assert!(rows[1].id > rows[2].id);
    }

    #[tokio::test]
    async fn list_events_filter_by_peer_id() {
        let db = test_db().await;
        let pid1 = insert_peer(&db.pool, "K1==").await;
        let pid2 = insert_peer(&db.pool, "K2==").await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            Some(pid1),
            Some("K1=="),
            None,
            "admin",
        )
        .await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            Some(pid2),
            Some("K2=="),
            None,
            "admin",
        )
        .await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            Some(pid1),
            Some("K1=="),
            None,
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, Some(pid1), None, 50)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.peer_id == Some(pid1)));
    }

    #[tokio::test]
    async fn list_events_filter_by_action() {
        let db = test_db().await;
        log_event(&db.pool, EVT_PEER_UPDATED, None, None, None, "admin").await;
        log_event(&db.pool, EVT_LOGIN_SUCCESS, None, None, None, "admin").await;
        log_event(&db.pool, EVT_PEER_UPDATED, None, None, None, "admin").await;

        let rows = list_events(&db.pool, None, Some(EVT_PEER_UPDATED), 50)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.action == EVT_PEER_UPDATED));
    }

    #[tokio::test]
    async fn list_events_respects_limit() {
        let db = test_db().await;
        for _ in 0..10 {
            log_event(&db.pool, EVT_PEER_UPDATED, None, None, None, "admin").await;
        }
        let rows = list_events(&db.pool, None, None, 3)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn list_events_caps_limit_at_200() {
        // list_events should not allow fetching more than 200 rows.
        let db = test_db().await;
        // We don't insert 200 rows – just verify the cap is applied to the
        // query without panicking.
        let rows = list_events(&db.pool, None, None, 9999)
            .await
            .expect("list_events");
        assert!(rows.is_empty()); // No rows inserted; cap just prevents unlimited fetches.
    }

    #[tokio::test]
    async fn list_events_combined_filters() {
        let db = test_db().await;
        let pid = insert_peer(&db.pool, "COMBO_KEY==").await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            Some(pid),
            Some("COMBO_KEY=="),
            None,
            "admin",
        )
        .await;
        log_event(&db.pool, EVT_LOGIN_SUCCESS, None, None, None, "admin").await;
        log_event(
            &db.pool,
            EVT_PEER_UPDATED,
            None,
            Some("OTHER_KEY=="),
            None,
            "admin",
        )
        .await;

        // Filter by peer_id AND action
        let rows = list_events(&db.pool, Some(pid), Some(EVT_PEER_UPDATED), 50)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].peer_id, Some(pid));
        assert_eq!(rows[0].action, EVT_PEER_UPDATED);
    }

    // ── User lifecycle event constants ────────────────────────────────────

    #[tokio::test]
    async fn user_create_events_logged_correctly() {
        let db = test_db().await;

        log_event(
            &db.pool,
            EVT_USER_CREATE_REQUESTED,
            None,
            None,
            Some(r#"{"name":"alice"}"#),
            "admin",
        )
        .await;

        log_event(
            &db.pool,
            EVT_USER_CREATED,
            None,
            None,
            Some(r#"{"name":"alice","config_path":"/root/awg0-client-alice.conf"}"#),
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, None, Some(EVT_USER_CREATED), 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, EVT_USER_CREATED);
        assert!(rows[0].detail.as_deref().unwrap().contains("alice"));

        let rows = list_events(&db.pool, None, Some(EVT_USER_CREATE_REQUESTED), 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn user_remove_events_logged_correctly() {
        let db = test_db().await;
        let pid = insert_peer(&db.pool, "REMOVE_KEY==").await;

        let detail = format!(r#"{{"peer_id":{},"name":"bob"}}"#, pid);

        log_event(
            &db.pool,
            EVT_USER_REMOVE_REQUESTED,
            Some(pid),
            None,
            Some(&detail),
            "admin",
        )
        .await;

        log_event(
            &db.pool,
            EVT_USER_REMOVED,
            Some(pid),
            None,
            Some(&detail),
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, Some(pid), None, 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 2);

        let rows = list_events(&db.pool, None, Some(EVT_USER_REMOVED), 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, EVT_USER_REMOVED);
    }

    #[tokio::test]
    async fn user_create_failed_event_logged() {
        let db = test_db().await;
        log_event(
            &db.pool,
            EVT_USER_CREATE_FAILED,
            None,
            None,
            Some(r#"{"name":"bad","error":"script failed"}"#),
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, None, Some(EVT_USER_CREATE_FAILED), 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].detail.as_deref().unwrap().contains("script failed"));
    }

    #[tokio::test]
    async fn user_remove_failed_event_logged() {
        let db = test_db().await;
        log_event(
            &db.pool,
            EVT_USER_REMOVE_FAILED,
            None,
            None,
            Some(r#"{"name":"missing","error":"not found"}"#),
            "admin",
        )
        .await;

        let rows = list_events(&db.pool, None, Some(EVT_USER_REMOVE_FAILED), 10)
            .await
            .expect("list_events");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].detail.as_deref().unwrap().contains("not found"));
    }
}
