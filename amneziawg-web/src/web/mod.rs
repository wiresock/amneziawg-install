//! HTTP router and request handlers.
//!
//! All handlers are intentionally thin: they delegate DB queries to
//! `crate::db::peers` and status derivation to `crate::domain`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::json;
use tower_http::trace::TraceLayer;
use tracing::error;

use crate::db::peers::{PeerRow, SnapshotRow};
use crate::db::Database;
use crate::domain::{resolve_display_name, PeerStatus, ONLINE_THRESHOLD_SECS};

// ── Error helper ────────────────────────────────────────────────────────────

type ApiResult<T> = Result<T, ApiError>;

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error!(error = ?self.0, "internal server error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "internal server error" })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

// ── DTOs ────────────────────────────────────────────────────────────────────

/// Summary of one peer, returned by `GET /api/peers`.
#[derive(Debug, Serialize)]
pub struct PeerSummaryDto {
    pub id: i64,
    /// Resolved display name (display_name → config_name → peer-<key prefix>).
    pub name: String,
    pub public_key: String,
    /// Stem of the matching `.conf` filename, if known.
    pub config_name: Option<String>,
    /// Comma-separated list of allowed CIDRs.
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub latest_handshake_at: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub status: PeerStatus,
}

/// Compact snapshot entry used inside `PeerDetailDto`.
#[derive(Debug, Serialize)]
pub struct SnapshotDto {
    pub id: i64,
    pub captured_at: String,
    pub endpoint: Option<String>,
    pub last_handshake_at: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Full peer details, returned by `GET /api/peers/:id`.
#[derive(Debug, Serialize)]
pub struct PeerDetailDto {
    pub id: i64,
    pub name: String,
    pub public_key: String,
    pub display_name: Option<String>,
    pub comment: Option<String>,
    pub config_name: Option<String>,
    pub config_path: Option<String>,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub latest_handshake_at: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub status: PeerStatus,
    pub disabled: bool,
    pub has_config: bool,
    /// The 50 most-recent snapshots, newest first.
    pub recent_snapshots: Vec<SnapshotDto>,
}

// ── Conversion helpers ───────────────────────────────────────────────────────

fn epoch_to_utc(ts: Option<i64>) -> Option<DateTime<Utc>> {
    ts.and_then(|t| Utc.timestamp_opt(t, 0).single())
}

fn peer_row_to_summary(row: PeerRow) -> PeerSummaryDto {
    let last_handshake = epoch_to_utc(row.last_handshake_at);
    let disabled = row.disabled != 0;
    let has_config = row.has_config != 0;
    let status = PeerStatus::derive(last_handshake, disabled, has_config, ONLINE_THRESHOLD_SECS);
    let name = resolve_display_name(
        row.display_name.as_deref(),
        row.config_name.as_deref(),
        &row.public_key,
    );
    PeerSummaryDto {
        id: row.id,
        name,
        public_key: row.public_key,
        config_name: row.config_name,
        allowed_ips: row.allowed_ips,
        endpoint: row.endpoint,
        latest_handshake_at: last_handshake,
        rx_bytes: row.rx_bytes as u64,
        tx_bytes: row.tx_bytes as u64,
        status,
    }
}

fn snapshot_row_to_dto(row: SnapshotRow) -> SnapshotDto {
    SnapshotDto {
        id: row.id,
        captured_at: row.captured_at,
        endpoint: row.endpoint,
        last_handshake_at: epoch_to_utc(row.last_handshake_at),
        rx_bytes: row.rx_bytes as u64,
        tx_bytes: row.tx_bytes as u64,
    }
}

fn peer_row_to_detail(row: PeerRow, snapshots: Vec<SnapshotRow>) -> PeerDetailDto {
    let last_handshake = epoch_to_utc(row.last_handshake_at);
    let disabled = row.disabled != 0;
    let has_config = row.has_config != 0;
    let status = PeerStatus::derive(last_handshake, disabled, has_config, ONLINE_THRESHOLD_SECS);
    let name = resolve_display_name(
        row.display_name.as_deref(),
        row.config_name.as_deref(),
        &row.public_key,
    );
    PeerDetailDto {
        id: row.id,
        name,
        public_key: row.public_key,
        display_name: row.display_name,
        comment: row.comment,
        config_name: row.config_name,
        config_path: row.config_path,
        allowed_ips: row.allowed_ips,
        endpoint: row.endpoint,
        latest_handshake_at: last_handshake,
        rx_bytes: row.rx_bytes as u64,
        tx_bytes: row.tx_bytes as u64,
        status,
        disabled,
        has_config,
        recent_snapshots: snapshots.into_iter().map(snapshot_row_to_dto).collect(),
    }
}

// ── Router ──────────────────────────────────────────────────────────────────

/// Build the application router.
pub fn router(db: Database) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/peers", get(list_peers))
        .route("/api/peers/:id", get(get_peer))
        .with_state(db)
        .layer(TraceLayer::new_for_http())
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/health` – liveness probe.
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/peers` – list all known peers with their current stats.
async fn list_peers(State(db): State<Database>) -> ApiResult<Json<Vec<PeerSummaryDto>>> {
    let rows = crate::db::peers::list_all(&db.pool).await?;
    let dtos: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
    Ok(Json(dtos))
}

/// `GET /api/peers/:id` – return full details for one peer.
///
/// `:id` is the integer primary key from the `peers` table.
/// Returns HTTP 404 if no peer with that ID exists.
async fn get_peer(State(db): State<Database>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let row = crate::db::peers::find_by_id(&db.pool, id).await?;
    match row {
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "peer not found" })),
        )
            .into_response()),
        Some(peer_row) => {
            let public_key = peer_row.public_key.clone();
            let snapshots = crate::db::peers::find_snapshots(&db.pool, &public_key, 50).await?;
            let dto = peer_row_to_detail(peer_row, snapshots);
            Ok(Json(dto).into_response())
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::util::ServiceExt;

    async fn test_db() -> Database {
        Database::connect_for_test().await.expect("connect")
    }

    /// Insert a minimal peer row for testing and return its rowid.
    async fn insert_peer(db: &Database, public_key: &str, display_name: Option<&str>) -> i64 {
        sqlx::query("INSERT INTO peers (public_key, display_name, allowed_ips) VALUES (?, ?, ?)")
            .bind(public_key)
            .bind(display_name)
            .bind("10.8.0.2/32")
            .execute(&db.pool)
            .await
            .expect("insert peer")
            .last_insert_rowid()
    }

    #[tokio::test]
    async fn health_returns_200() {
        let app = router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_peers_empty_db_returns_empty_array() {
        let app = router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_peers_returns_inserted_peer() {
        let db = test_db().await;
        insert_peer(&db, "TESTKEY1234567890ABCDEF==", Some("Alice")).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let peers = json.as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["name"], "Alice");
        assert_eq!(peers[0]["public_key"], "TESTKEY1234567890ABCDEF==");
        // Private key must NOT appear anywhere in the response
        assert!(!body.windows(11).any(|w| w == b"private_key"));
    }

    #[tokio::test]
    async fn get_peer_not_found_returns_404() {
        let app = router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers/9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_peer_returns_detail() {
        let db = test_db().await;
        let id = insert_peer(&db, "DETAILKEY1234567890ABCDEF==", Some("Bob")).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], id);
        assert_eq!(json["name"], "Bob");
        assert_eq!(json["public_key"], "DETAILKEY1234567890ABCDEF==");
        assert!(json["recent_snapshots"].is_array());
        assert_eq!(json["recent_snapshots"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn name_fallback_to_key_prefix() {
        let db = test_db().await;
        // No display_name, no config_name → should fall back to peer-<prefix>
        let id = insert_peer(&db, "ABCDEF1234567890==", None).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Should be peer-ABCDEF12 (first 8 chars)
        assert_eq!(json["name"], "peer-ABCDEF12");
    }
}
