//! HTTP router and request handlers.
//!
//! All handlers are intentionally thin: they delegate DB queries to
//! `crate::db::peers` and status derivation/history to `crate::domain`.

use axum::{
    extract::{Path, Query, State},
    http::{header::SET_COOKIE, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::trace::TraceLayer;
use tracing::error;

use crate::auth::{
    add_session, clear_session_cookie, extract_session_token, generate_session_id,
    is_session_valid, make_session_cookie, new_session_store, remove_session, AuthConfig,
    SessionStore,
};
use crate::db::peers::{PeerRow, SnapshotRow};
use crate::db::Database;
use crate::domain::history::{compute_history, HistoryPoint, HistorySummary, SnapshotInput};
use crate::domain::{
    normalize_comment, normalize_display_name, resolve_display_name, PeerStatus,
    ONLINE_THRESHOLD_SECS,
};

// ── App state ────────────────────────────────────────────────────────────────

/// Shared application state passed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub auth: AuthConfig,
    pub sessions: SessionStore,
}

impl AppState {
    fn new(db: Database, auth: AuthConfig) -> Self {
        Self {
            db,
            auth,
            sessions: new_session_store(),
        }
    }
}

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
    /// Whether a matching client config file has been discovered.
    pub has_config: bool,
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

/// Request body for `PATCH /api/peers/:id`.
///
/// Both fields are optional.  If a field is absent the existing value is kept.
/// If a field is provided with an empty or blank string, the value is cleared
/// (set to NULL).
#[derive(Debug, Deserialize)]
pub struct PatchPeerRequest {
    pub display_name: Option<String>,
    pub comment: Option<String>,
}

/// URL-encoded form body submitted by the HTML edit form on `POST /peers/:id`.
#[derive(Debug, Deserialize)]
pub struct PeerEditForm {
    pub display_name: Option<String>,
    pub comment: Option<String>,
}

/// URL-encoded form body submitted by the login page.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
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
        has_config,
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
pub fn router(db: Database, auth: AuthConfig) -> Router {
    let state = AppState::new(db, auth);

    // Protected routes – all require a valid session.
    let protected = Router::new()
        .route("/", get(page_peer_list))
        .route("/peers/:id", get(page_peer_detail).post(post_peer_edit))
        .route("/api/peers", get(list_peers))
        .route("/api/peers/:id", get(get_peer).patch(patch_peer))
        .route("/api/peers/:id/history", get(get_peer_history))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        // Public routes (no auth required)
        .route("/api/health", get(health))
        .route("/login", get(page_login).post(post_login))
        .route("/logout", post(post_logout))
        // Protected routes
        .merge(protected)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

// ── Auth middleware ───────────────────────────────────────────────────────────

/// Axum middleware that enforces authentication on every route it is applied to.
///
/// Behaviour:
/// - When `auth.enabled = false`: always passes through (dev/trusted-network mode).
/// - Session cookie present and valid: passes through.
/// - Bearer token present, matches `auth.api_token`: passes through (API only).
/// - Otherwise:
///   - Paths starting with `/api/` → `401 Unauthorized` JSON.
///   - Other paths → `303 See Other` redirect to `/login`.
async fn require_auth(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !state.auth.enabled {
        return next.run(req).await;
    }

    let is_api = req.uri().path().starts_with("/api/");

    // Check session cookie.
    let cookie_header = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(token) = extract_session_token(cookie_header) {
        if is_session_valid(&state.sessions, &token) {
            return next.run(req).await;
        }
    }

    // Check bearer token (API paths only).
    if is_api {
        if let Some(ref expected) = state.auth.api_token {
            let auth_header = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if let Some(provided) = auth_header.strip_prefix("Bearer ") {
                if provided == expected.as_str() {
                    return next.run(req).await;
                }
            }
        }
    }

    // Unauthenticated.
    if is_api {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "authentication required" })),
        )
            .into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

// ── Auth Handlers ─────────────────────────────────────────────────────────────

/// `GET /login` – render the login form.
async fn page_login() -> impl IntoResponse {
    Html(render_login_page(false))
}

/// `POST /login` – validate credentials and set a session cookie on success.
async fn post_login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    // When auth is disabled, redirect straight to home.
    if !state.auth.enabled {
        return Redirect::to("/").into_response();
    }

    // Validate credentials.  Never log the password.
    let username_ok = form.username == state.auth.username;
    let password_ok = crate::auth::verify_password(&state.auth.password_hash, &form.password);

    if !username_ok || !password_ok {
        // Generic error – do not reveal which field was wrong.
        return Html(render_login_page(true)).into_response();
    }

    // Issue a new session token.
    let token = generate_session_id();
    add_session(&state.sessions, token.clone());

    let cookie = make_session_cookie(&token, state.auth.secure_cookie);
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().expect("valid cookie header value"),
    );
    (headers, Redirect::to("/")).into_response()
}

/// `POST /logout` – invalidate the session and clear the cookie.
async fn post_logout(State(state): State<AppState>, req: Request<axum::body::Body>) -> Response {
    let cookie_header = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(token) = extract_session_token(cookie_header) {
        remove_session(&state.sessions, &token);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        clear_session_cookie()
            .parse()
            .expect("valid cookie header value"),
    );
    (headers, Redirect::to("/login")).into_response()
}

// ── API Handlers ─────────────────────────────────────────────────────────────

/// `GET /api/health` – liveness probe.
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/peers` – list all known peers with their current stats.
async fn list_peers(State(state): State<AppState>) -> ApiResult<Json<Vec<PeerSummaryDto>>> {
    let rows = crate::db::peers::list_all(&state.db.pool).await?;
    let dtos: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
    Ok(Json(dtos))
}

/// `GET /api/peers/:id` – return full details for one peer.
///
/// `:id` is the integer primary key from the `peers` table.
/// Returns HTTP 404 if no peer with that ID exists.
async fn get_peer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let row = crate::db::peers::find_by_id(&state.db.pool, id).await?;
    match row {
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "peer not found" })),
        )
            .into_response()),
        Some(peer_row) => {
            let public_key = peer_row.public_key.clone();
            let snapshots =
                crate::db::peers::find_snapshots(&state.db.pool, &public_key, 50).await?;
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
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<HistoryQuery>,
) -> Result<Response, ApiError> {
    // Verify the peer exists
    let row = crate::db::peers::find_by_id(&state.db.pool, id).await?;
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
        crate::db::peers::find_snapshots_since(&state.db.pool, &peer.public_key, &since_str)
            .await?;

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

/// `PATCH /api/peers/:id` – update a peer's display name and/or comment.
///
/// Both request fields are optional:
/// - If absent, the corresponding DB field is left unchanged.
/// - If present and blank/empty after trimming, the field is cleared (NULL).
///
/// Returns the full peer detail DTO (same as `GET /api/peers/:id`).
/// Returns HTTP 404 if the peer does not exist.
async fn patch_peer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<PatchPeerRequest>,
) -> Result<Response, ApiError> {
    // Load the existing peer so we can apply partial updates.
    let existing = match crate::db::peers::find_by_id(&state.db.pool, id).await? {
        Some(r) => r,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "peer not found" })),
            )
                .into_response())
        }
    };

    // Merge: if the caller provided a field, normalise it; otherwise keep the
    // existing DB value.
    let new_display_name = match body.display_name {
        Some(v) => normalize_display_name(&v),
        None => existing.display_name.clone(),
    };
    let new_comment = match body.comment {
        Some(v) => normalize_comment(&v),
        None => existing.comment.clone(),
    };

    let updated = crate::db::peers::update_peer_metadata(
        &state.db.pool,
        id,
        new_display_name.as_deref(),
        new_comment.as_deref(),
    )
    .await?;

    match updated {
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "peer not found" })),
        )
            .into_response()),
        Some(peer_row) => {
            let public_key = peer_row.public_key.clone();
            let snapshots =
                crate::db::peers::find_snapshots(&state.db.pool, &public_key, 50).await?;
            let dto = peer_row_to_detail(peer_row, snapshots);
            Ok(Json(dto).into_response())
        }
    }
}

// ── HTML Handlers ─────────────────────────────────────────────────────────────

/// `GET /` – server-rendered peer list page.
async fn page_peer_list(State(state): State<AppState>) -> Result<Response, ApiError> {
    let rows = crate::db::peers::list_all(&state.db.pool).await?;
    let peers: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
    Ok(Html(render_peer_list(&peers)).into_response())
}

/// `GET /peers/:id` – server-rendered peer detail page.
async fn page_peer_detail(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let row = crate::db::peers::find_by_id(&state.db.pool, id).await?;
    match row {
        None => Ok((
            StatusCode::NOT_FOUND,
            Html("<h1>Peer not found</h1>".to_string()),
        )
            .into_response()),
        Some(peer_row) => {
            let public_key = peer_row.public_key.clone();
            let snapshots =
                crate::db::peers::find_snapshots(&state.db.pool, &public_key, 50).await?;
            let dto = peer_row_to_detail(peer_row, snapshots);
            Ok(Html(render_peer_detail(&dto)).into_response())
        }
    }
}

/// `POST /peers/:id` – accept the HTML edit form, update the peer, and redirect
/// back to the detail page.
///
/// HTML `<form>` elements do not support `PATCH`, so the UI uses a POST to this
/// page-level route, while the JSON API uses `PATCH /api/peers/:id`.
async fn post_peer_edit(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<PeerEditForm>,
) -> Result<Response, ApiError> {
    // 404 if the peer does not exist.
    if crate::db::peers::find_by_id(&state.db.pool, id)
        .await?
        .is_none()
    {
        return Ok((
            StatusCode::NOT_FOUND,
            Html("<h1>Peer not found</h1>".to_string()),
        )
            .into_response());
    }

    let display_name = form
        .display_name
        .as_deref()
        .and_then(normalize_display_name);
    let comment = form.comment.as_deref().and_then(normalize_comment);

    crate::db::peers::update_peer_metadata(
        &state.db.pool,
        id,
        display_name.as_deref(),
        comment.as_deref(),
    )
    .await?;

    // Redirect back to the detail page (PRG pattern).
    Ok(Redirect::to(&format!("/peers/{id}")).into_response())
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
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * KIB;
    const GIB: f64 = MIB * KIB;
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / KIB)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", b as f64 / MIB)
    } else {
        format!("{:.2} GiB", b as f64 / GIB)
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
  .edit-form {{ margin-top: 2rem; padding: 1rem; border: 1px solid #ddd; border-radius: 4px; background: #f9f9f9; max-width: 480px; }}
  .edit-form h2 {{ margin-top: 0; font-size: 1.1rem; }}
  .edit-form label {{ display: block; font-weight: bold; margin-bottom: .25rem; margin-top: .75rem; }}
  .edit-form input[type=text], .edit-form input[type=password], .edit-form textarea {{ width: 100%; padding: .35rem .5rem; border: 1px solid #ccc; border-radius: 3px; font-family: inherit; font-size: .95rem; box-sizing: border-box; }}
  .edit-form textarea {{ resize: vertical; min-height: 4rem; }}
  .edit-form button[type=submit] {{ margin-top: 1rem; padding: .4rem 1.1rem; background: #0066cc; color: #fff; border: none; border-radius: 3px; cursor: pointer; font-size: .95rem; }}
  .edit-form button[type=submit]:hover {{ background: #0055aa; }}
  .nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding-bottom: .5rem; border-bottom: 1px solid #ddd; }}
  .nav-logout {{ display: inline-block; }}
  .nav-logout button {{ padding: .3rem .8rem; background: #e55; color: #fff; border: none; border-radius: 3px; cursor: pointer; font-size: .85rem; }}
  .nav-logout button:hover {{ background: #c33; }}
  .error {{ color: #c00; margin-top: .5rem; font-size: .95rem; }}
</style>
</head>
<body>
"#,
        title = esc(title)
    )
}

/// Render the top navigation bar with a logout button.
fn nav_bar() -> String {
    r#"<nav class="nav">
  <span><a href="/">AmneziaWG Panel</a></span>
  <form class="nav-logout" method="POST" action="/logout">
    <button type="submit">Log out</button>
  </form>
</nav>
"#
    .to_string()
}

/// Render the login page.
///
/// `show_error`: when `true`, a generic "invalid credentials" message is shown.
fn render_login_page(show_error: bool) -> String {
    let mut buf = html_head("AmneziaWG – Login");
    buf.push_str(
        r#"<div class="edit-form" style="max-width:340px;margin:4rem auto">
<h2>AmneziaWG Login</h2>
<form method="POST" action="/login">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" autocomplete="username" required>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" autocomplete="current-password" required>
"#,
    );
    if show_error {
        buf.push_str(r#"  <p class="error">Invalid username or password.</p>"#);
        buf.push('\n');
    }
    buf.push_str(
        r#"  <button type="submit">Log in</button>
</form>
</div>
</body></html>
"#,
    );
    buf
}

fn render_peer_list(peers: &[PeerSummaryDto]) -> String {
    let mut buf = html_head("AmneziaWG – Peers");
    buf.push_str(&nav_bar());
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
    buf.push_str(&nav_bar());
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
    if let Some(ref cp) = dto.config_path {
        buf.push_str(&format!(
            "<tr><th>Config path</th><td><code>{}</code></td></tr>\n",
            esc(cp)
        ));
    }
    if let Some(ref dn) = dto.display_name {
        buf.push_str(&format!(
            "<tr><th>Display name</th><td>{}</td></tr>\n",
            esc(dn)
        ));
    }
    if let Some(ref cm) = dto.comment {
        buf.push_str(&format!("<tr><th>Comment</th><td>{}</td></tr>\n", esc(cm)));
    }
    buf.push_str("</table>\n");

    // Edit form
    let current_display_name = dto.display_name.as_deref().unwrap_or("");
    let current_comment = dto.comment.as_deref().unwrap_or("");
    buf.push_str(&format!(
        r#"<div class="edit-form">
<h2>Edit peer</h2>
<form method="POST" action="/peers/{id}">
  <label for="display_name">Display name</label>
  <input type="text" id="display_name" name="display_name"
         value="{dn}" maxlength="128" placeholder="e.g. Ivan iPhone">
  <label for="comment">Comment</label>
  <textarea id="comment" name="comment" maxlength="512"
            placeholder="Optional note about this peer">{cm}</textarea>
  <button type="submit">Save</button>
</form>
</div>
"#,
        id = dto.id,
        dn = esc(current_display_name),
        cm = esc(current_comment),
    ));

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

    /// Build a router with auth disabled (used for all pre-auth tests).
    fn test_router(db: Database) -> Router {
        router(db, AuthConfig::disabled())
    }

    /// Build a router with auth enabled and known test credentials.
    fn test_router_with_auth(db: Database) -> (Router, String) {
        let hash = AuthConfig::hash_password_fast("testpassword");
        let auth = AuthConfig {
            enabled: true,
            username: "admin".to_string(),
            password_hash: hash,
            api_token: Some("super-secret-token".to_string()),
            secure_cookie: false,
        };
        (router(db, auth), "testpassword".to_string())
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
        let app = test_router(test_db().await);
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
        let app = test_router(test_db().await);
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

        let app = test_router(db);
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
        let app = test_router(test_db().await);
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

        let app = test_router(db);
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

        let app = test_router(db);
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
        let app = test_router(test_db().await);
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

        let app = test_router(db);
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

        let app = test_router(db);
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

        let app = test_router(db);
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
        let app = test_router(test_db().await);
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

        let app = test_router(db);
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
        // The peer LIST shows names, not raw public keys.  Verify the public key
        // is not exposed in the list HTML (it only appears on the detail page).
        assert!(!html.contains("HTMLKEY1234567890ABCDEF=="));
    }

    #[tokio::test]
    async fn peer_detail_page_not_found_returns_404() {
        let app = test_router(test_db().await);
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

        let app = test_router(db);
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

    // ── PATCH /api/peers/:id ───────────────────────────────────────────────

    #[tokio::test]
    async fn patch_peer_updates_name() {
        let db = test_db().await;
        let id = insert_peer(&db, "PATCHKEY1234567890==", None).await;

        let app = test_router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"Renamed Peer"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["display_name"], "Renamed Peer");
        assert_eq!(json["name"], "Renamed Peer");
    }

    #[tokio::test]
    async fn patch_peer_updates_comment() {
        let db = test_db().await;
        let id = insert_peer(&db, "CMTKEY1234567890==", Some("Alice")).await;

        let app = test_router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"comment":"Main device"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // display_name should be preserved (field absent in request)
        assert_eq!(json["display_name"], "Alice");
        assert_eq!(json["comment"], "Main device");
    }

    #[tokio::test]
    async fn patch_peer_clears_name_with_blank_string() {
        let db = test_db().await;
        let id = insert_peer(&db, "CLEARKEY1234567890==", Some("ToBeCleared")).await;

        let app = test_router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"  "}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Blank name normalises to NULL → falls back to key prefix in "name"
        assert_eq!(json["display_name"], serde_json::Value::Null);
        assert!(json["name"].as_str().unwrap().starts_with("peer-"));
    }

    #[tokio::test]
    async fn patch_peer_not_found_returns_404() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/peers/9999")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"Ghost"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn patch_peer_empty_body_leaves_values_unchanged() {
        let db = test_db().await;
        let id = insert_peer(&db, "EMPTYKEY1234567890==", Some("Unchanged")).await;

        let app = test_router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["display_name"], "Unchanged");
    }

    // ── has_config in peer list ────────────────────────────────────────────

    #[tokio::test]
    async fn list_peers_includes_has_config_field() {
        let db = test_db().await;
        insert_peer(&db, "HCKEY1234567890==", None).await;

        let app = test_router(db);
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
        let peer = &json.as_array().unwrap()[0];
        // has_config should be present and false (no config file linked)
        assert_eq!(peer["has_config"], false);
    }

    // ── HTML detail page shows edit form ───────────────────────────────────

    #[tokio::test]
    async fn peer_detail_page_contains_edit_form() {
        let db = test_db().await;
        let id = insert_peer(&db, "FORMKEY1234567890==", Some("Editable")).await;

        let app = test_router(db);
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
        // Form must be present with correct action
        assert!(html.contains(&format!("action=\"/peers/{id}\"")));
        assert!(html.contains("name=\"display_name\""));
        assert!(html.contains("name=\"comment\""));
        // Existing name must be pre-filled
        assert!(html.contains("Editable"));
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

    // ── Login page rendering ────────────────────────────────────────────────

    #[test]
    fn login_page_renders_form() {
        let html = render_login_page(false);
        assert!(html.contains(r#"action="/login""#));
        assert!(html.contains(r#"name="username""#));
        assert!(html.contains(r#"name="password""#));
        assert!(!html.contains("Invalid username"));
    }

    #[test]
    fn login_page_shows_error() {
        let html = render_login_page(true);
        assert!(html.contains("Invalid username or password"));
    }

    // ── Auth: when auth is disabled, all routes remain accessible ──────────

    #[tokio::test]
    async fn auth_disabled_root_accessible() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_disabled_api_accessible() {
        let app = test_router(test_db().await);
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
    }

    // ── Auth: when auth is enabled, unauthenticated access is blocked ──────

    #[tokio::test]
    async fn auth_enabled_html_redirects_to_login() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap(), "/login");
    }

    #[tokio::test]
    async fn auth_enabled_api_returns_401() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "authentication required");
    }

    #[tokio::test]
    async fn auth_enabled_health_stays_public() {
        let (app, _) = test_router_with_auth(test_db().await);
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

    // ── Auth: login flow ───────────────────────────────────────────────────

    #[tokio::test]
    async fn login_page_returns_200() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.starts_with(b"<!DOCTYPE html>"));
    }

    #[tokio::test]
    async fn login_wrong_password_shows_error_page() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("username=admin&password=wrongpassword"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Should stay on login page (200), not redirect.
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Invalid username or password"));
    }

    #[tokio::test]
    async fn login_correct_credentials_sets_cookie_and_redirects() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("username=admin&password=testpassword"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap(), "/");
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .expect("Set-Cookie header missing")
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("awg_session="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
    }

    #[tokio::test]
    async fn authenticated_session_allows_api_access() {
        let db = test_db().await;
        insert_peer(&db, "AUTH_TEST_KEY1234==", Some("TestPeer")).await;

        let (app, _password) = test_router_with_auth(db);

        // 1. Login to get a session cookie.
        let login_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("username=admin&password=testpassword"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
        let cookie = login_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // Extract just the token from "awg_session=TOKEN; ..."
        let session_value = cookie.split(';').next().unwrap().trim().to_string();

        // 2. Use the session cookie to access the API.
        let api_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .header("cookie", &session_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_clears_session() {
        let db = test_db().await;
        let (app, _) = test_router_with_auth(db);

        // Login.
        let login_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("username=admin&password=testpassword"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = login_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let session_value = cookie.split(';').next().unwrap().trim().to_string();

        // Logout with that session.
        let logout_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header("cookie", &session_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_response.status(), StatusCode::SEE_OTHER);
        // Cookie must be cleared (Max-Age=0).
        let clear_cookie = logout_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(clear_cookie.contains("Max-Age=0"));

        // Subsequent request with same cookie must now be rejected.
        let after_logout = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .header("cookie", &session_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Auth: bearer token ─────────────────────────────────────────────────

    #[tokio::test]
    async fn bearer_token_allows_api_access() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .header("authorization", "Bearer super-secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_bearer_token_returns_401() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_does_not_unlock_html_pages() {
        // Bearer token should only work for /api/ paths; HTML paths still
        // redirect to /login even with a valid bearer token.
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("authorization", "Bearer super-secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    // ── Auth: authenticated PATCH /api/peers/:id ───────────────────────────

    #[tokio::test]
    async fn authenticated_patch_peer_succeeds() {
        let db = test_db().await;
        let id = insert_peer(&db, "AUTHPATCH1234567890==", None).await;
        let (app, _) = test_router_with_auth(db);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("authorization", "Bearer super-secret-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"Auth Peer"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["display_name"], "Auth Peer");
    }
}
