//! HTTP router and request handlers.
//!
//! All handlers are intentionally thin: they delegate DB queries to
//! `crate::db::peers` and status derivation/history to `crate::domain`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::trace::TraceLayer;
use tracing::error;

use crate::db::peers::{PeerRow, SnapshotRow};
use crate::db::Database;
use crate::domain::history::{compute_history, HistoryPoint, HistorySummary, SnapshotInput};
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

/// Traffic history response, returned by `GET /api/peers/:id/history`.
#[derive(Debug, Serialize)]
pub struct PeerHistoryDto {
    pub peer_id: i64,
    pub range: String,
    pub points: Vec<HistoryPoint>,
    pub summary: HistorySummary,
}

/// Query parameters for the history endpoint.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// One of `24h`, `7d`, `30d`.  Defaults to `24h`.
    pub range: Option<String>,
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

fn snapshot_row_to_input(row: SnapshotRow) -> SnapshotInput {
    SnapshotInput {
        captured_at: row.captured_at,
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

/// Parse the `range` query parameter string into a duration in seconds.
///
/// - `"24h"` → 86 400 s
/// - `"7d"`  → 604 800 s
/// - `"30d"` → 2 592 000 s
/// - anything else (or absent) → 86 400 s (default)
fn range_to_secs(range: &str) -> i64 {
    match range {
        "7d" => 7 * 24 * 3600,
        "30d" => 30 * 24 * 3600,
        _ => 24 * 3600, // "24h" or unknown
    }
}

// ── Router ──────────────────────────────────────────────────────────────────

/// Build the application router.
pub fn router(db: Database) -> Router {
    Router::new()
        // HTML pages
        .route("/", get(page_peer_list))
        .route("/peers/:id", get(page_peer_detail))
        // JSON API
        .route("/api/health", get(health))
        .route("/api/peers", get(list_peers))
        .route("/api/peers/:id", get(get_peer))
        .route("/api/peers/:id/history", get(get_peer_history))
        .with_state(db)
        .layer(TraceLayer::new_for_http())
}

// ── API Handlers ─────────────────────────────────────────────────────────────

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

/// `GET /api/peers/:id/history?range=24h|7d|30d`
///
/// Returns RX/TX traffic history for a peer based on `snapshots`.
///
/// Counter-reset handling: if a snapshot's counter is lower than the previous
/// snapshot's counter, the delta for that step is treated as 0 (the counter
/// was reset by an interface restart).  This prevents negative deltas and
/// avoids inflating summary totals.
///
/// Returns HTTP 404 if the peer does not exist.
/// Returns empty `points` and zero totals if the peer has no snapshots in the
/// requested range.
async fn get_peer_history(
    State(db): State<Database>,
    Path(id): Path<i64>,
    Query(params): Query<HistoryQuery>,
) -> Result<Response, ApiError> {
    // Verify the peer exists
    let row = crate::db::peers::find_by_id(&db.pool, id).await?;
    let peer = match row {
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "peer not found" })),
            )
                .into_response())
        }
        Some(r) => r,
    };

    let range_str = params.range.as_deref().unwrap_or("24h");
    let secs = range_to_secs(range_str);
    let since = Utc::now() - chrono::Duration::seconds(secs);
    let since_str = since.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let snapshot_rows =
        crate::db::peers::find_snapshots_since(&db.pool, &peer.public_key, &since_str).await?;

    let inputs: Vec<SnapshotInput> = snapshot_rows
        .into_iter()
        .map(snapshot_row_to_input)
        .collect();
    let (points, summary) = compute_history(&inputs);

    let dto = PeerHistoryDto {
        peer_id: id,
        range: range_str.to_string(),
        points,
        summary,
    };
    Ok(Json(dto).into_response())
}

// ── HTML Handlers ─────────────────────────────────────────────────────────────

/// `GET /` – server-rendered peer list page.
async fn page_peer_list(State(db): State<Database>) -> Result<Response, ApiError> {
    let rows = crate::db::peers::list_all(&db.pool).await?;
    let peers: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
    Ok(Html(render_peer_list(&peers)).into_response())
}

/// `GET /peers/:id` – server-rendered peer detail page.
async fn page_peer_detail(
    State(db): State<Database>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let row = crate::db::peers::find_by_id(&db.pool, id).await?;
    match row {
        None => Ok((
            StatusCode::NOT_FOUND,
            Html("<h1>Peer not found</h1>".to_string()),
        )
            .into_response()),
        Some(peer_row) => {
            let public_key = peer_row.public_key.clone();
            let snapshots = crate::db::peers::find_snapshots(&db.pool, &public_key, 50).await?;
            let dto = peer_row_to_detail(peer_row, snapshots);
            Ok(Html(render_peer_detail(&dto)).into_response())
        }
    }
}

// ── HTML rendering ────────────────────────────────────────────────────────────

/// Escape the five HTML special characters to prevent XSS.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn status_badge(status: &PeerStatus) -> &'static str {
    match status {
        PeerStatus::Online => r#"<span style="color:green">&#x25CF; online</span>"#,
        PeerStatus::Inactive => r#"<span style="color:gray">&#x25CF; inactive</span>"#,
        PeerStatus::Disabled => r#"<span style="color:red">&#x25CF; disabled</span>"#,
        PeerStatus::Unlinked => r#"<span style="color:orange">&#x25CF; unlinked</span>"#,
    }
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn html_head(title: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; color: #222; }}
  h1 {{ margin-bottom: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: .4rem .7rem; text-align: left; }}
  th {{ background: #f0f0f0; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  a {{ color: #0066cc; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .meta {{ font-size: .85rem; color: #666; margin-bottom: 1.5rem; }}
  .back {{ margin-bottom: 1rem; display: block; }}
</style>
</head>
<body>
"#,
        title = esc(title)
    )
}

fn render_peer_list(peers: &[PeerSummaryDto]) -> String {
    let mut buf = html_head("AmneziaWG – Peers");
    buf.push_str("<h1>AmneziaWG Peers</h1>\n");
    buf.push_str(&format!(
        "<p class=\"meta\">{} peer(s) known &nbsp;·&nbsp; <a href=\"/api/peers\">JSON API</a></p>\n",
        peers.len()
    ));

    if peers.is_empty() {
        buf.push_str("<p>No peers found. The poller may not have run yet.</p>\n");
    } else {
        buf.push_str(
            "<table>\n\
             <tr><th>Name</th><th>Status</th><th>Endpoint</th>\
             <th>Last handshake</th><th>RX</th><th>TX</th></tr>\n",
        );
        for p in peers {
            let name_link = format!(
                r#"<a href="/peers/{id}">{name}</a>"#,
                id = p.id,
                name = esc(&p.name)
            );
            let endpoint = p
                .endpoint
                .as_deref()
                .map(esc)
                .unwrap_or_else(|| "–".to_string());
            let handshake = p
                .latest_handshake_at
                .map(|ts| esc(&ts.format("%Y-%m-%d %H:%M:%S UTC").to_string()))
                .unwrap_or_else(|| "never".to_string());
            buf.push_str(&format!(
                "<tr><td>{name_link}</td><td>{status}</td><td>{endpoint}</td>\
                 <td>{handshake}</td><td>{rx}</td><td>{tx}</td></tr>\n",
                status = status_badge(&p.status),
                rx = fmt_bytes(p.rx_bytes),
                tx = fmt_bytes(p.tx_bytes),
            ));
        }
        buf.push_str("</table>\n");
    }

    buf.push_str("</body></html>");
    buf
}

fn render_peer_detail(dto: &PeerDetailDto) -> String {
    let mut buf = html_head(&format!("Peer – {}", dto.name));
    buf.push_str(&format!(
        "<a class=\"back\" href=\"/\">&larr; All peers</a>\n\
         <h1>{name}</h1>\n",
        name = esc(&dto.name)
    ));

    // Identity block
    buf.push_str("<table>\n");
    buf.push_str(&format!(
        "<tr><th>Public key</th><td><code>{}</code></td></tr>\n",
        esc(&dto.public_key)
    ));
    buf.push_str(&format!(
        "<tr><th>Status</th><td>{}</td></tr>\n",
        status_badge(&dto.status)
    ));
    if let Some(ref ep) = dto.endpoint {
        buf.push_str(&format!("<tr><th>Endpoint</th><td>{}</td></tr>\n", esc(ep)));
    }
    let handshake = dto
        .latest_handshake_at
        .map(|ts| ts.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "never".to_string());
    buf.push_str(&format!(
        "<tr><th>Last handshake</th><td>{}</td></tr>\n",
        esc(&handshake)
    ));
    buf.push_str(&format!(
        "<tr><th>RX</th><td>{}</td></tr>\n",
        fmt_bytes(dto.rx_bytes)
    ));
    buf.push_str(&format!(
        "<tr><th>TX</th><td>{}</td></tr>\n",
        fmt_bytes(dto.tx_bytes)
    ));
    buf.push_str(&format!(
        "<tr><th>Allowed IPs</th><td>{}</td></tr>\n",
        esc(&dto.allowed_ips)
    ));
    if let Some(ref cn) = dto.config_name {
        buf.push_str(&format!(
            "<tr><th>Config name</th><td>{}</td></tr>\n",
            esc(cn)
        ));
    }
    buf.push_str("</table>\n");

    // Recent snapshots
    buf.push_str(&format!(
        "<h2>Recent snapshots ({})</h2>\n",
        dto.recent_snapshots.len()
    ));
    if dto.recent_snapshots.is_empty() {
        buf.push_str("<p>No snapshots recorded yet.</p>\n");
    } else {
        buf.push_str(
            "<table>\n\
             <tr><th>Captured at</th><th>RX</th><th>TX</th><th>Endpoint</th></tr>\n",
        );
        for s in &dto.recent_snapshots {
            let ep = s
                .endpoint
                .as_deref()
                .map(esc)
                .unwrap_or_else(|| "–".to_string());
            buf.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&s.captured_at),
                fmt_bytes(s.rx_bytes),
                fmt_bytes(s.tx_bytes),
                ep,
            ));
        }
        buf.push_str("</table>\n");
    }

    buf.push_str(&format!(
        "<p class=\"meta\"><a href=\"/api/peers/{id}/history\">JSON history (24h)</a></p>\n",
        id = dto.id
    ));

    buf.push_str("</body></html>");
    buf
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

    async fn insert_snapshot_with_bytes(
        db: &Database,
        public_key: &str,
        captured_at: &str,
        rx: i64,
        tx: i64,
    ) {
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?,?,?,?)",
        )
        .bind(public_key)
        .bind(captured_at)
        .bind(rx)
        .bind(tx)
        .execute(&db.pool)
        .await
        .expect("insert snapshot");
    }

    // ── Existing tests ─────────────────────────────────────────────────────

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
        assert_eq!(json["name"], "peer-ABCDEF12");
    }

    // ── History endpoint ───────────────────────────────────────────────────

    #[tokio::test]
    async fn history_peer_not_found_returns_404() {
        let app = router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers/9999/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn history_no_snapshots_returns_empty_points() {
        let db = test_db().await;
        let id = insert_peer(&db, "HIST_KEY_EMPTY=", Some("EmptyPeer")).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}/history"))
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
        assert_eq!(json["peer_id"], id);
        assert_eq!(json["range"], "24h");
        assert!(json["points"].as_array().unwrap().is_empty());
        assert_eq!(json["summary"]["rx_total_delta"], 0);
        assert_eq!(json["summary"]["tx_total_delta"], 0);
    }

    #[tokio::test]
    async fn history_with_snapshots_returns_points_and_totals() {
        let db = test_db().await;
        let id = insert_peer(&db, "HIST_KEY_DATA=", Some("DataPeer")).await;

        // Use timestamps in the past 24 hours to stay within the default range.
        let now = Utc::now();
        let t1 =
            (now - chrono::Duration::hours(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let t2 =
            (now - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        insert_snapshot_with_bytes(&db, "HIST_KEY_DATA=", &t1, 0, 0).await;
        insert_snapshot_with_bytes(&db, "HIST_KEY_DATA=", &t2, 1000, 2000).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}/history"))
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
        let points = json["points"].as_array().unwrap();
        assert_eq!(points.len(), 2);
        // Second point should show the delta
        assert_eq!(json["summary"]["rx_total_delta"], 1000);
        assert_eq!(json["summary"]["tx_total_delta"], 2000);
    }

    #[tokio::test]
    async fn history_range_7d_accepted() {
        let db = test_db().await;
        let id = insert_peer(&db, "HIST_7D_KEY=", Some("SevenDayPeer")).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}/history?range=7d"))
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
        assert_eq!(json["range"], "7d");
    }

    // ── HTML pages ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn root_returns_html() {
        let app = router(test_db().await);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        // Must look like HTML
        assert!(body.starts_with(b"<!DOCTYPE html>"));
        assert!(
            body.windows(6).any(|w| w == b"<html>") || body.windows(10).any(|w| w == b"<html lang")
        );
    }

    #[tokio::test]
    async fn root_lists_peers_in_html() {
        let db = test_db().await;
        insert_peer(&db, "HTMLKEY1234567890ABCDEF==", Some("Charlie")).await;

        let app = router(db);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Charlie"));
        // Private key must not appear in the page
        assert!(!html.contains("HTMLKEY1234567890ABCDEF=="));
    }

    #[tokio::test]
    async fn peer_detail_page_not_found_returns_404() {
        let app = router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/peers/9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn peer_detail_page_returns_html() {
        let db = test_db().await;
        let id = insert_peer(&db, "HTMLDETAILKEY1234567890==", Some("Diana")).await;

        let app = router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/peers/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Diana"));
        assert!(html.starts_with("<!DOCTYPE html>"));
    }

    // ── HTML helpers ───────────────────────────────────────────────────────

    #[test]
    fn esc_handles_special_chars() {
        assert_eq!(esc("<script>"), "&lt;script&gt;");
        assert_eq!(esc("a&b"), "a&amp;b");
        assert_eq!(esc("\"hello\""), "&quot;hello&quot;");
    }

    #[test]
    fn fmt_bytes_human_readable() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(2 * 1024 * 1024), "2.0 MiB");
    }

    #[test]
    fn range_to_secs_parses_correctly() {
        assert_eq!(range_to_secs("24h"), 86_400);
        assert_eq!(range_to_secs("7d"), 604_800);
        assert_eq!(range_to_secs("30d"), 2_592_000);
        assert_eq!(range_to_secs(""), 86_400); // default
        assert_eq!(range_to_secs("unknown"), 86_400); // default
    }
}
