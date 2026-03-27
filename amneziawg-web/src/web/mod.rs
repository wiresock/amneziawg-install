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

use crate::admin::script_bridge::ScriptBridge;
use crate::auth::{
    add_session, check_and_record_login_attempt, clear_session_cookie, consume_login_csrf, csrf_eq,
    extract_session_token, generate_login_csrf, generate_session_id, get_session_csrf,
    is_session_valid, make_session_cookie, new_login_csrf_store, new_login_rate_limiter,
    new_session_store, remove_session, AuthConfig, LoginCsrfStore, LoginRateLimiter, SessionStore,
    RATE_LIMIT_MAX_ATTEMPTS, RATE_LIMIT_WINDOW,
};
use crate::db::events::{
    list_events, log_event, EVT_LOGIN_FAILED, EVT_LOGIN_SUCCESS, EVT_LOGOUT, EVT_PEER_DISABLED,
    EVT_PEER_UPDATED,
};
use crate::db::peers::{PeerRow, SnapshotRow};
use crate::db::Database;
use crate::domain::history::{compute_history, HistoryPoint, HistorySummary, SnapshotInput};
use crate::domain::{
    normalize_comment, normalize_display_name, resolve_display_name, ConnectionStatus,
    IdentityStatus, PeerStatus, ONLINE_THRESHOLD_SECS,
};

// ── App state ────────────────────────────────────────────────────────────────

/// Shared application state passed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub auth: AuthConfig,
    pub sessions: SessionStore,
    /// Short-lived CSRF tokens for the pre-auth login form.
    pub login_csrf: LoginCsrfStore,
    /// Sliding-window login attempt counters keyed by client IP.
    pub rate_limiter: LoginRateLimiter,
    /// Directory where AWG client configs are stored (for rescan).
    pub config_dir: std::path::PathBuf,
    /// Bridge to the install script for user lifecycle actions.
    pub script_bridge: std::sync::Arc<ScriptBridge>,
}

impl AppState {
    fn new(
        db: Database,
        auth: AuthConfig,
        config_dir: std::path::PathBuf,
        install_script: std::path::PathBuf,
    ) -> Self {
        Self {
            db,
            auth,
            sessions: new_session_store(),
            login_csrf: new_login_csrf_store(),
            rate_limiter: new_login_rate_limiter(),
            config_dir,
            script_bridge: std::sync::Arc::new(ScriptBridge::new(install_script)),
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
    /// Resolved display name (display_name → friendly_name → config_name → peer-<key prefix>).
    pub name: String,
    pub public_key: String,
    /// Stem of the matching `.conf` filename, if known.
    pub config_name: Option<String>,
    /// Human-readable name from config filename (e.g. `"gramm"`).
    pub friendly_name: Option<String>,
    /// Whether a matching client config file has been discovered.
    pub has_config: bool,
    /// Comma-separated list of allowed CIDRs.
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub latest_handshake_at: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Legacy combined status (kept for backward compatibility).
    pub status: PeerStatus,
    /// Connection/activity status (online, inactive, never, disabled).
    pub connection_status: ConnectionStatus,
    /// Identity/config mapping status (linked, unlinked).
    pub identity_status: IdentityStatus,
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
    pub friendly_name: Option<String>,
    pub config_path: Option<String>,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub latest_handshake_at: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Legacy combined status (kept for backward compatibility).
    pub status: PeerStatus,
    /// Connection/activity status (online, inactive, never, disabled).
    pub connection_status: ConnectionStatus,
    /// Identity/config mapping status (linked, unlinked).
    pub identity_status: IdentityStatus,
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
    /// When present, enables (`false`) or disables (`true`) the peer.
    pub disabled: Option<bool>,
}

/// URL-encoded form body submitted by the HTML edit form on `POST /peers/:id`.
#[derive(Debug, Deserialize)]
pub struct PeerEditForm {
    pub display_name: Option<String>,
    pub comment: Option<String>,
    /// CSRF token embedded as a hidden field in the edit form.
    pub csrf_token: Option<String>,
    /// Checkbox: present with value `"1"` when checked, absent when unchecked.
    pub disabled: Option<String>,
}

/// URL-encoded form body submitted by the login page.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    /// Pre-login CSRF token embedded as a hidden field in the login form.
    pub csrf_token: Option<String>,
}

/// URL-encoded form body submitted by the logout button.
#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    /// Session CSRF token embedded as a hidden field in the logout form.
    pub csrf_token: Option<String>,
}

/// Query parameters for `GET /api/events`.
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    /// Filter by integer peer ID.
    pub peer_id: Option<i64>,
    /// Filter by event type string (e.g. `"peer_updated"`).
    pub event_type: Option<String>,
    /// Maximum number of events to return (default 50, max 200).
    pub limit: Option<i64>,
}

/// One event entry returned by `GET /api/events`.
#[derive(Debug, Serialize)]
pub struct EventDto {
    pub id: i64,
    pub event_type: String,
    pub peer_id: Option<i64>,
    /// Parsed JSON payload, or `null` if no detail was recorded.
    pub payload: Option<serde_json::Value>,
    pub actor: String,
    pub created_at: String,
}

// ── User lifecycle DTOs ──────────────────────────────────────────────────────

/// JSON request body for `POST /api/admin/users`.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
}

/// HTML form body for `POST /admin/users/add`.
#[derive(Debug, Deserialize)]
pub struct AddUserForm {
    pub name: String,
    pub csrf_token: Option<String>,
}

/// HTML form body for `POST /admin/users/:id/remove`.
#[derive(Debug, Deserialize)]
pub struct RemoveUserForm {
    pub csrf_token: Option<String>,
    /// Confirmation field – must be "yes" to proceed.
    pub confirm: Option<String>,
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
    let connection_status =
        ConnectionStatus::derive(last_handshake, disabled, ONLINE_THRESHOLD_SECS);
    let identity_status = IdentityStatus::derive(has_config);
    let name = resolve_display_name(
        row.display_name.as_deref(),
        row.friendly_name.as_deref(),
        row.config_name.as_deref(),
        &row.public_key,
    );
    PeerSummaryDto {
        id: row.id,
        name,
        public_key: row.public_key,
        config_name: row.config_name,
        friendly_name: row.friendly_name,
        has_config,
        allowed_ips: row.allowed_ips,
        endpoint: row.endpoint,
        latest_handshake_at: last_handshake,
        rx_bytes: row.rx_bytes as u64,
        tx_bytes: row.tx_bytes as u64,
        status,
        connection_status,
        identity_status,
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
    let connection_status =
        ConnectionStatus::derive(last_handshake, disabled, ONLINE_THRESHOLD_SECS);
    let identity_status = IdentityStatus::derive(has_config);
    let name = resolve_display_name(
        row.display_name.as_deref(),
        row.friendly_name.as_deref(),
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
        friendly_name: row.friendly_name,
        config_path: row.config_path,
        allowed_ips: row.allowed_ips,
        endpoint: row.endpoint,
        latest_handshake_at: last_handshake,
        rx_bytes: row.rx_bytes as u64,
        tx_bytes: row.tx_bytes as u64,
        status,
        connection_status,
        identity_status,
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
pub fn router(
    db: Database,
    auth: AuthConfig,
    config_dir: std::path::PathBuf,
    install_script: std::path::PathBuf,
) -> Router {
    let state = AppState::new(db, auth, config_dir, install_script);

    // Protected routes – all require a valid session.
    let protected = Router::new()
        .route("/", get(page_peer_list))
        .route("/peers/:id", get(page_peer_detail).post(post_peer_edit))
        .route("/api/peers", get(list_peers))
        .route("/api/peers/:id", get(get_peer).patch(patch_peer))
        .route("/api/peers/:id/history", get(get_peer_history))
        .route("/api/peers/:id/config", get(get_peer_config))
        .route("/api/events", get(list_events_handler))
        // ── User lifecycle routes ────────────────────────────────
        .route("/api/admin/users", post(api_create_user))
        .route("/api/admin/users/:id/remove", post(api_remove_user))
        .route("/admin/users/add", post(post_add_user_form))
        .route("/admin/users/:id/remove", post(post_remove_user_form))
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
        if is_session_valid(&state.sessions, &token, state.auth.session_ttl) {
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

/// `GET /login` – render the login form with a fresh pre-login CSRF token.
async fn page_login(State(state): State<AppState>) -> impl IntoResponse {
    let csrf = if state.auth.enabled {
        generate_login_csrf(&state.login_csrf)
    } else {
        String::new()
    };
    Html(render_login_page(false, &csrf))
}

/// `POST /login` – validate CSRF, check rate limit, then validate credentials.
async fn post_login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // When auth is disabled, redirect straight to home.
    if !state.auth.enabled {
        return Redirect::to("/").into_response();
    }

    // ── Pre-login CSRF check ─────────────────────────────────────────────
    let submitted_csrf = form.csrf_token.as_deref().unwrap_or("");
    if !consume_login_csrf(&state.login_csrf, submitted_csrf) {
        let new_csrf = generate_login_csrf(&state.login_csrf);
        return (
            StatusCode::FORBIDDEN,
            Html(render_login_page_with_msg(
                "Request validation failed. Please try again.",
                &new_csrf,
            )),
        )
            .into_response();
    }

    // ── Rate limiting ────────────────────────────────────────────────────
    let ip = extract_client_ip(&headers);
    if !check_and_record_login_attempt(
        &state.rate_limiter,
        &ip,
        RATE_LIMIT_MAX_ATTEMPTS,
        RATE_LIMIT_WINDOW,
    ) {
        let new_csrf = generate_login_csrf(&state.login_csrf);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(render_login_page_with_msg(
                "Too many login attempts. Please wait a few minutes and try again.",
                &new_csrf,
            )),
        )
            .into_response();
    }

    // ── Credential check ─────────────────────────────────────────────────
    let username_ok = form.username == state.auth.username;
    let password_ok = crate::auth::verify_password(&state.auth.password_hash, &form.password);

    if !username_ok || !password_ok {
        // Log failed login attempt (does not reveal which field was wrong).
        log_event(
            &state.db.pool,
            EVT_LOGIN_FAILED,
            None,
            None,
            None,
            &state.auth.username,
        )
        .await;
        let new_csrf = generate_login_csrf(&state.login_csrf);
        return Html(render_login_page(true, &new_csrf)).into_response();
    }

    // Issue a new session.
    let session_id = generate_session_id();
    let _csrf = add_session(&state.sessions, session_id.clone());

    // Log successful login.
    log_event(
        &state.db.pool,
        EVT_LOGIN_SUCCESS,
        None,
        None,
        None,
        &state.auth.username,
    )
    .await;

    let cookie = make_session_cookie(
        &session_id,
        state.auth.secure_cookie,
        state.auth.session_ttl,
    );
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        SET_COOKIE,
        cookie.parse().expect("valid cookie header value"),
    );
    (resp_headers, Redirect::to("/")).into_response()
}

/// `POST /logout` – validate session CSRF, invalidate the session, clear cookie.
async fn post_logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Validate CSRF before doing anything (when auth is enabled).
    if state.auth.enabled {
        let submitted = form.csrf_token.as_deref().unwrap_or("");
        if !validate_form_csrf(&state, cookie_header, submitted) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    if let Some(token) = extract_session_token(cookie_header) {
        remove_session(&state.sessions, &token);
    }

    // Log the logout event.
    log_event(
        &state.db.pool,
        EVT_LOGOUT,
        None,
        None,
        None,
        &state.auth.username,
    )
    .await;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        SET_COOKIE,
        clear_session_cookie()
            .parse()
            .expect("valid cookie header value"),
    );
    (resp_headers, Redirect::to("/login")).into_response()
}

// ── API Handlers ─────────────────────────────────────────────────────────────

/// `GET /api/health` – liveness probe.
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/events` – audit event log.
///
/// Accepts optional query parameters:
/// - `peer_id`    – filter by integer peer ID
/// - `event_type` – filter by event type string (e.g. `"peer_updated"`)
/// - `limit`      – max rows to return (default 50, max 200)
async fn list_events_handler(
    State(state): State<AppState>,
    Query(params): Query<EventsQuery>,
) -> ApiResult<Json<Vec<EventDto>>> {
    let limit = params.limit.unwrap_or(50);
    let rows = list_events(
        &state.db.pool,
        params.peer_id,
        params.event_type.as_deref(),
        limit,
    )
    .await?;

    let dtos = rows
        .into_iter()
        .map(|row| EventDto {
            id: row.id,
            event_type: row.action,
            peer_id: row.peer_id,
            payload: row
                .detail
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            actor: row.actor,
            created_at: row.created_at,
        })
        .collect();
    Ok(Json(dtos))
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

/// `GET /api/peers/:id/config` – download the client config file.
///
/// Returns the raw config file content with `Content-Type: text/plain` and a
/// `Content-Disposition: attachment` header so browsers offer a download dialog.
///
/// Returns HTTP 404 if the peer does not exist or has no associated config file.
/// Returns HTTP 404 if the config file cannot be read from disk.
async fn get_peer_config(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
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

    let config_path = match peer.config_path {
        Some(ref p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "no config file associated with this peer" })),
            )
                .into_response())
        }
    };

    // Security: ensure the path is absolute and doesn't contain traversal.
    if !config_path.is_absolute() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "invalid config path" })),
        )
            .into_response());
    }

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "config file not found on disk" })),
            )
                .into_response())
        }
    };

    let filename = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("client.conf")
        // Sanitise for use inside a quoted Content-Disposition filename.
        .replace('\\', "_")
        .replace('"', "_");

    let disposition = format!("attachment; filename=\"{}\"", filename);

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (axum::http::header::CONTENT_DISPOSITION, disposition),
        ],
        content,
    )
        .into_response())
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
        Some(ref v) => normalize_display_name(v),
        None => existing.display_name.clone(),
    };
    let new_comment = match body.comment {
        Some(ref v) => normalize_comment(v),
        None => existing.comment.clone(),
    };

    let updated = crate::db::peers::update_peer_metadata(
        &state.db.pool,
        id,
        new_display_name.as_deref(),
        new_comment.as_deref(),
    )
    .await?;

    // Handle disabled flag if provided.
    if let Some(disabled) = body.disabled {
        crate::db::peers::update_peer_disabled(&state.db.pool, id, disabled).await?;
        let old_disabled = existing.disabled != 0;
        if disabled != old_disabled {
            let detail = serde_json::json!({
                "old_disabled": old_disabled,
                "new_disabled": disabled,
            })
            .to_string();
            log_event(
                &state.db.pool,
                EVT_PEER_DISABLED,
                Some(id),
                Some(&existing.public_key),
                Some(&detail),
                &state.auth.username,
            )
            .await;

            // Immediately remove the peer from the running AWG interface so
            // the client cannot connect until re-enabled.
            if disabled {
                remove_peer_from_interface(&existing.public_key);
            } else {
                // Re-add the peer to the running AWG interface by syncing
                // the on-disk config (with disabled peers pre-filtered so
                // syncconf never reactivates them).
                restore_peer_best_effort(&state.db.pool).await;
            }
        }
    }

    match updated {
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "peer not found" })),
        )
            .into_response()),
        Some(peer_row) => {
            // Fire-and-forget audit log for metadata changes.
            if body.display_name.is_some() || body.comment.is_some() {
                let detail = serde_json::json!({
                    "old_display_name": existing.display_name,
                    "new_display_name": new_display_name,
                    "old_comment": existing.comment,
                    "new_comment": new_comment,
                })
                .to_string();
                log_event(
                    &state.db.pool,
                    EVT_PEER_UPDATED,
                    Some(id),
                    Some(&peer_row.public_key),
                    Some(&detail),
                    &state.auth.username,
                )
                .await;
            }

            // Re-read the peer to include the disabled update.
            let final_row = crate::db::peers::find_by_id(&state.db.pool, id).await?;
            match final_row {
                None => Ok((
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "peer not found" })),
                )
                    .into_response()),
                Some(row) => {
                    let public_key = row.public_key.clone();
                    let snapshots =
                        crate::db::peers::find_snapshots(&state.db.pool, &public_key, 50).await?;
                    let dto = peer_row_to_detail(row, snapshots);
                    Ok(Json(dto).into_response())
                }
            }
        }
    }
}

// ── HTML Handlers ─────────────────────────────────────────────────────────────

/// `GET /` – server-rendered peer list page.
async fn page_peer_list(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let rows = crate::db::peers::list_all(&state.db.pool).await?;
    let peers: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
    let csrf = session_csrf_from_headers(&state, &headers);
    Ok(Html(render_peer_list(&peers, &csrf)).into_response())
}

/// `GET /peers/:id` – server-rendered peer detail page.
async fn page_peer_detail(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
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
            let events = list_events(&state.db.pool, Some(id), None, 20).await?;
            let dto = peer_row_to_detail(peer_row, snapshots);
            let csrf = session_csrf_from_headers(&state, &headers);
            Ok(Html(render_peer_detail(&dto, &csrf, &events)).into_response())
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
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<PeerEditForm>,
) -> Result<Response, ApiError> {
    // CSRF validation (when auth is enabled).
    if state.auth.enabled {
        let cookie_header = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let submitted = form.csrf_token.as_deref().unwrap_or("");
        if !validate_form_csrf(&state, cookie_header, submitted) {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
    }

    // 404 if the peer does not exist.
    let existing = match crate::db::peers::find_by_id(&state.db.pool, id).await? {
        Some(r) => r,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Html("<h1>Peer not found</h1>".to_string()),
            )
                .into_response());
        }
    };

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

    // Handle disabled checkbox: present with value "1" means disabled; absent means enabled.
    let new_disabled = form.disabled.as_deref() == Some("1");
    let old_disabled = existing.disabled != 0;
    if new_disabled != old_disabled {
        crate::db::peers::update_peer_disabled(&state.db.pool, id, new_disabled).await?;
        let detail = serde_json::json!({
            "old_disabled": old_disabled,
            "new_disabled": new_disabled,
        })
        .to_string();
        log_event(
            &state.db.pool,
            EVT_PEER_DISABLED,
            Some(id),
            Some(&existing.public_key),
            Some(&detail),
            &state.auth.username,
        )
        .await;

        // Immediately remove the peer from the running AWG interface so
        // the client cannot connect until re-enabled.
        if new_disabled {
            remove_peer_from_interface(&existing.public_key);
        } else {
            // Re-add the peer to the running AWG interface by syncing
            // the on-disk config (with disabled peers pre-filtered so
            // syncconf never reactivates them).
            restore_peer_best_effort(&state.db.pool).await;
        }
    }

    // Fire-and-forget audit log.
    let detail = serde_json::json!({
        "old_display_name": existing.display_name,
        "new_display_name": display_name,
        "old_comment": existing.comment,
        "new_comment": comment,
    })
    .to_string();
    log_event(
        &state.db.pool,
        EVT_PEER_UPDATED,
        Some(id),
        Some(&existing.public_key),
        Some(&detail),
        &state.auth.username,
    )
    .await;

    // Redirect back to the detail page (PRG pattern).
    Ok(Redirect::to(&format!("/peers/{id}")).into_response())
}

// ── User lifecycle handlers ──────────────────────────────────────────────────

/// `POST /api/admin/users` – JSON API to create a new user/client.
async fn api_create_user(
    State(state): State<AppState>,
    Json(body): Json<CreateUserRequest>,
) -> Result<Response, ApiError> {
    let name = body.name.trim().to_string();
    match crate::admin::execute_create_user(
        &state.db,
        &state.script_bridge,
        &name,
        &state.auth.username,
    )
    .await
    {
        Ok(result) => {
            // Trigger config rescan so new peer appears immediately.
            if let Err(e) = crate::poller::rescan_configs(&state.db, &state.config_dir).await {
                tracing::warn!(error = %e, "post-create config rescan failed");
            }
            Ok((
                StatusCode::CREATED,
                Json(json!({
                    "name": result.client_name,
                    "config_path": result.config_path,
                })),
            )
                .into_response())
        }
        Err(crate::admin::script_bridge::ScriptError::InvalidName(msg)) => {
            Ok((StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to create user via script");
            Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
                .into_response())
        }
    }
}

/// `POST /api/admin/users/:id/remove` – JSON API to remove an existing user/client.
async fn api_remove_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let peer = match crate::db::peers::find_by_id(&state.db.pool, id).await? {
        Some(p) => p,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "peer not found" })),
            )
                .into_response());
        }
    };

    // Determine the script-side client name from the peer's friendly_name
    // (which is extracted from the config filename's `-client-<suffix>` pattern).
    let client_name = match peer.friendly_name.as_deref() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "peer has no associated client name (no config linked)" })),
            )
                .into_response());
        }
    };

    // Only peers whose friendly_name passes installer validation can be removed
    // via the script.  Configs not matching the `*-client-<name>.conf` pattern
    // (or with names that exceed the character/length constraints) are not
    // managed by the installer and would always fail.
    if let Err(e) = crate::admin::script_bridge::validate_client_name(&client_name) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("peer is not managed by installer: {e}") })),
        )
            .into_response());
    }

    match crate::admin::execute_remove_user(
        &state.db,
        &state.script_bridge,
        id,
        &client_name,
        &state.auth.username,
    )
    .await
    {
        Ok(()) => {
            if let Err(e) = crate::poller::rescan_configs(&state.db, &state.config_dir).await {
                tracing::warn!(error = %e, "post-remove config rescan failed");
            }
            Ok(Json(json!({ "ok": true })).into_response())
        }
        Err(crate::admin::script_bridge::ScriptError::InvalidName(msg)) => {
            Ok((StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to remove user via script");
            Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
                .into_response())
        }
    }
}

/// `POST /admin/users/add` – HTML form to add a new user (PRG pattern).
async fn post_add_user_form(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<AddUserForm>,
) -> Result<Response, ApiError> {
    if state.auth.enabled {
        let cookie_header = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let submitted = form.csrf_token.as_deref().unwrap_or("");
        if !validate_form_csrf(&state, cookie_header, submitted) {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
    }

    let name = form.name.trim().to_string();
    match crate::admin::execute_create_user(
        &state.db,
        &state.script_bridge,
        &name,
        &state.auth.username,
    )
    .await
    {
        Ok(_result) => {
            if let Err(e) = crate::poller::rescan_configs(&state.db, &state.config_dir).await {
                tracing::warn!(error = %e, "post-create config rescan failed");
            }
            // Redirect back to the peer list.
            Ok(Redirect::to("/").into_response())
        }
        Err(crate::admin::script_bridge::ScriptError::InvalidName(msg)) => {
            // Show the peer list page with an error message.
            let rows = crate::db::peers::list_all(&state.db.pool).await?;
            let peers: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
            let csrf = session_csrf_from_headers(&state, &headers);
            Ok(Html(render_peer_list_with_error(&peers, &csrf, &msg)).into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to create user via HTML form");
            let rows = crate::db::peers::list_all(&state.db.pool).await?;
            let peers: Vec<PeerSummaryDto> = rows.into_iter().map(peer_row_to_summary).collect();
            let csrf = session_csrf_from_headers(&state, &headers);
            let message = "Failed to create user. Please try again later or contact the administrator.";
            Ok(Html(render_peer_list_with_error(&peers, &csrf, message)).into_response())
        }
    }
}

/// `POST /admin/users/:id/remove` – HTML form to remove a user (PRG pattern).
async fn post_remove_user_form(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<RemoveUserForm>,
) -> Result<Response, ApiError> {
    if state.auth.enabled {
        let cookie_header = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let submitted = form.csrf_token.as_deref().unwrap_or("");
        if !validate_form_csrf(&state, cookie_header, submitted) {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
    }

    // Require explicit confirmation.
    if form.confirm.as_deref() != Some("yes") {
        return Ok(Redirect::to(&format!("/peers/{id}")).into_response());
    }

    let peer = match crate::db::peers::find_by_id(&state.db.pool, id).await? {
        Some(p) => p,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Html("<h1>Peer not found</h1>".to_string()),
            )
                .into_response());
        }
    };

    let client_name = match peer.friendly_name.as_deref() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => {
            return Ok(Redirect::to(&format!("/peers/{id}")).into_response());
        }
    };

    match crate::admin::execute_remove_user(
        &state.db,
        &state.script_bridge,
        id,
        &client_name,
        &state.auth.username,
    )
    .await
    {
        Ok(()) => {
            if let Err(e) = crate::poller::rescan_configs(&state.db, &state.config_dir).await {
                tracing::warn!(error = %e, "post-remove config rescan failed");
            }
            Ok(Redirect::to("/").into_response())
        }
        Err(_e) => Ok(Redirect::to(&format!("/peers/{id}")).into_response()),
    }
}

// ── AWG enforcement helpers ───────────────────────────────────────────────────

/// Best-effort immediate removal of a peer from the running AWG interface.
///
/// Spawns the blocking AWG commands (`show all dump` + `set … peer … remove`)
/// on a dedicated blocking thread via `tokio::task::spawn_blocking` so the
/// calling async handler stays non-blocking.  The task is fire-and-forget:
/// errors are logged but never propagated – the database is already updated,
/// and the poller will retry removal on the next cycle.
fn remove_peer_from_interface(public_key: &str) {
    let pk = public_key.to_owned();
    tokio::task::spawn_blocking(move || {
        let interfaces = match crate::awg::show_all_dump() {
            Ok(ifaces) => ifaces,
            Err(e) => {
                tracing::warn!(
                    public_key = %pk,
                    error = %e,
                    "could not read AWG state for immediate peer removal – poller will retry"
                );
                return;
            }
        };

        for iface in &interfaces {
            if iface.peers.iter().any(|p| p.public_key.0 == pk) {
                match crate::awg::remove_peer(&iface.name, &pk) {
                    Ok(()) => {
                        tracing::info!(
                            interface = %iface.name,
                            public_key = %pk,
                            "disabled peer removed from interface"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            interface = %iface.name,
                            public_key = %pk,
                            error = %e,
                            "failed to remove disabled peer – poller will retry"
                        );
                    }
                }
            }
        }
    });
}

/// Load disabled keys from the DB and attempt a best-effort interface sync.
///
/// Fails closed: if the disabled keys cannot be loaded, the sync is skipped
/// entirely so that disabled peers are never accidentally reactivated.
async fn restore_peer_best_effort(pool: &sqlx::SqlitePool) {
    match crate::db::peers::list_disabled_public_keys(pool).await {
        Ok(disabled_keys) => {
            restore_peer_to_interface(disabled_keys);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not load disabled keys – skipping interface sync to avoid re-adding disabled peers"
            );
        }
    }
}

/// Best-effort immediate reconciliation of the running AWG interface with the
/// on-disk config.
///
/// Spawns blocking AWG commands on a dedicated thread:
/// 1. `awg show all dump` to discover active interfaces.
/// 2. For each interface, `awg-quick strip <iface>` → filter out disabled
///    peers → `awg syncconf <iface>` to fully reconcile the running
///    interface with the (filtered) on-disk config.
///
/// **Important:** `syncconf` performs a full reconciliation — it adds peers
/// present in the config but missing from the interface, removes peers
/// present on the interface but absent from the config (including any
/// runtime-only peers), and updates changed settings.  Disabled peers are
/// filtered from the config *before* it reaches `syncconf`, so they are
/// effectively removed from the running interface as well.
///
/// Like [`remove_peer_from_interface`], this is fire-and-forget: errors are
/// logged but never propagated.  If this best-effort restore fails, the peer
/// will not be auto-synced; it will become active on the next AWG restart.
fn restore_peer_to_interface(disabled_keys: std::collections::HashSet<String>) {
    tokio::task::spawn_blocking(move || {
        let interfaces = match crate::awg::show_all_dump() {
            Ok(ifaces) => ifaces,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not read AWG state for peer restoration – skipping best-effort restore; peer will not be auto-synced"
                );
                return;
            }
        };

        for iface in &interfaces {
            match crate::awg::sync_interface(&iface.name, &disabled_keys) {
                Ok(()) => {
                    tracing::info!(
                        interface = %iface.name,
                        "interface synced from disk after attempting peer restore"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        interface = %iface.name,
                        error = %e,
                        "failed to sync interface – peer will be restored on next AWG restart"
                    );
                }
            }
        }
    });
}

// ── CSRF / IP helpers ─────────────────────────────────────────────────────────

/// Validate a CSRF token submitted in an HTML form against the session's stored
/// token.
///
/// - When `auth.enabled = false`: always returns `true` (CSRF not enforced).
/// - Otherwise: extracts the session ID from `cookie_header`, looks up the
///   expected token, and does a constant-time comparison.
fn validate_form_csrf(state: &AppState, cookie_header: &str, submitted: &str) -> bool {
    if !state.auth.enabled {
        return true;
    }
    let Some(session_id) = extract_session_token(cookie_header) else {
        return false;
    };
    let Some(expected) = get_session_csrf(&state.sessions, &session_id, state.auth.session_ttl)
    else {
        return false;
    };
    csrf_eq(&expected, submitted)
}

/// Extract the CSRF token for the current session from the `Cookie` header.
///
/// Returns an empty string when auth is disabled or the session is not found.
fn session_csrf_from_headers(state: &AppState, headers: &axum::http::HeaderMap) -> String {
    if !state.auth.enabled {
        return String::new();
    }
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    extract_session_token(cookie_header)
        .and_then(|id| get_session_csrf(&state.sessions, &id, state.auth.session_ttl))
        .unwrap_or_default()
}

/// Extract the client IP from `X-Forwarded-For` / `X-Real-IP` reverse-proxy
/// headers, or return `"unknown"` if neither is present.
///
/// **Note for deployment:** this function trusts `X-Forwarded-For`.  Ensure
/// the reverse proxy is configured to set this header and that direct
/// (non-proxied) access to the panel is not possible from untrusted networks.
fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
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

/// Escape a string for safe use inside a JavaScript string literal in an HTML attribute.
///
/// Handles both JS-level escaping (backslash, quote) and HTML-level escaping
/// so the value is safe in `onclick="confirm('...')"` contexts.
///
/// **Important:** `&` must be replaced first to avoid double-escaping
/// entities produced by later replacements (e.g. `&lt;` → `&amp;lt;`).
fn esc_js(s: &str) -> String {
    // Build the escaped string in a single pass to avoid double-escaping.
    let mut out = String::with_capacity(s.len());

    for ch in s.chars() {
        match ch {
            // HTML escaping
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),

            // JS string escaping
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),

            // JS line terminators / control characters that would break the string
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),

            _ => out.push(ch),
        }
    }

    out
}

/// Render legacy combined status badge (used by tests).
#[allow(dead_code)]
fn status_badge(status: &PeerStatus) -> &'static str {
    match status {
        PeerStatus::Online => r#"<span style="color:green">&#x25CF; online</span>"#,
        PeerStatus::Inactive => r#"<span style="color:gray">&#x25CF; inactive</span>"#,
        PeerStatus::Disabled => r#"<span style="color:red">&#x25CF; disabled</span>"#,
        PeerStatus::Unlinked => r#"<span style="color:orange">&#x25CF; unlinked</span>"#,
    }
}

fn connection_badge(status: &ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Online => r#"<span style="color:green">&#x25CF; online</span>"#,
        ConnectionStatus::Inactive => r#"<span style="color:gray">&#x25CF; inactive</span>"#,
        ConnectionStatus::Never => r#"<span style="color:gray">&#x25CB; never connected</span>"#,
        ConnectionStatus::Disabled => r#"<span style="color:red">&#x25CF; disabled</span>"#,
    }
}

fn identity_badge(status: &IdentityStatus) -> &'static str {
    match status {
        IdentityStatus::Linked => {
            r#"<span style="color:#0a0" title="Peer matched to a config file">&#x1F517; linked</span>"#
        }
        IdentityStatus::Unlinked => {
            r#"<span style="color:orange" title="No matching config file found">&#x26A0; unlinked</span>"#
        }
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
///
/// `csrf_token` is embedded as a hidden field in the logout form.
fn nav_bar(csrf_token: &str) -> String {
    format!(
        r#"<nav class="nav">
  <span><a href="/">AmneziaWG Panel</a></span>
  <form class="nav-logout" method="POST" action="/logout">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button type="submit">Log out</button>
  </form>
</nav>
"#,
        csrf = esc(csrf_token)
    )
}

/// Render the login page.
///
/// `show_error`: when `true`, a generic "invalid credentials" message is shown.
/// `csrf_token`: the pre-login CSRF token to embed in the form.
fn render_login_page(show_error: bool, csrf_token: &str) -> String {
    let error_html = if show_error {
        "  <p class=\"error\">Invalid username or password.</p>\n"
    } else {
        ""
    };
    render_login_page_inner(error_html, csrf_token)
}

/// Render the login page with a custom message string.
fn render_login_page_with_msg(msg: &str, csrf_token: &str) -> String {
    let error_html = format!("  <p class=\"error\">{}</p>\n", esc(msg));
    render_login_page_inner(&error_html, csrf_token)
}

fn render_login_page_inner(error_html: &str, csrf_token: &str) -> String {
    let mut buf = html_head("AmneziaWG – Login");
    buf.push_str(&format!(
        r#"<div class="edit-form" style="max-width:340px;margin:4rem auto">
<h2>AmneziaWG Login</h2>
<form method="POST" action="/login">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" autocomplete="username" required>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" autocomplete="current-password" required>
{error}  <button type="submit">Log in</button>
</form>
</div>
</body></html>
"#,
        csrf = esc(csrf_token),
        error = error_html,
    ));
    buf
}

fn render_peer_list(peers: &[PeerSummaryDto], csrf_token: &str) -> String {
    render_peer_list_inner(peers, csrf_token, None)
}

fn render_peer_list_with_error(peers: &[PeerSummaryDto], csrf_token: &str, error: &str) -> String {
    render_peer_list_inner(peers, csrf_token, Some(error))
}

fn render_peer_list_inner(
    peers: &[PeerSummaryDto],
    csrf_token: &str,
    error: Option<&str>,
) -> String {
    let mut buf = html_head("AmneziaWG – Peers");
    buf.push_str(&nav_bar(csrf_token));
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
             <tr><th>Name</th><th>Connection</th><th>Identity</th><th>Endpoint</th>\
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
                "<tr><td>{name_link}</td><td>{conn}</td><td>{ident}</td><td>{endpoint}</td>\
                 <td>{handshake}</td><td>{rx}</td><td>{tx}</td></tr>\n",
                conn = connection_badge(&p.connection_status),
                ident = identity_badge(&p.identity_status),
                rx = fmt_bytes(p.rx_bytes),
                tx = fmt_bytes(p.tx_bytes),
            ));
        }
        buf.push_str("</table>\n");
    }

    // Add user form
    if let Some(err) = error {
        buf.push_str(&format!(
            "<p class=\"error\">Add user failed: {}</p>\n",
            esc(err)
        ));
    }
    buf.push_str(&format!(
        r#"<div class="edit-form">
<h2>Add user</h2>
<form method="POST" action="/admin/users/add">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <label for="add_user_name">Client name</label>
  <input type="text" id="add_user_name" name="name" required
         pattern="[a-zA-Z0-9_-]+" maxlength="15"
         placeholder="e.g. iphone" title="Alphanumeric, underscore, or hyphen (max 15 chars)">
  <p class="meta" style="margin-top:.25rem">Letters, digits, underscore, or hyphen. Max 15 characters.</p>
  <button type="submit">Add user</button>
</form>
</div>
"#,
        csrf = esc(csrf_token)
    ));

    buf.push_str("</body></html>");
    buf
}

fn render_peer_detail(
    dto: &PeerDetailDto,
    csrf_token: &str,
    events: &[crate::db::events::EventRow],
) -> String {
    let mut buf = html_head(&format!("Peer – {}", dto.name));
    buf.push_str(&nav_bar(csrf_token));
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
        "<tr><th>Connection</th><td>{}</td></tr>\n",
        connection_badge(&dto.connection_status)
    ));
    buf.push_str(&format!(
        "<tr><th>Identity</th><td>{}</td></tr>\n",
        identity_badge(&dto.identity_status)
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
    if dto.has_config {
        buf.push_str(&format!(
            "<tr><th>Config</th><td><a href=\"/api/peers/{}/config\">&#x2B73; Download</a></td></tr>\n",
            dto.id
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
  <input type="hidden" name="csrf_token" value="{csrf}">
  <label for="display_name">Display name</label>
  <input type="text" id="display_name" name="display_name"
         value="{dn}" maxlength="128" placeholder="e.g. Ivan iPhone">
  <label for="comment">Comment</label>
  <textarea id="comment" name="comment" maxlength="512"
            placeholder="Optional note about this peer">{cm}</textarea>
  <label style="margin-top:.75rem;display:flex;align-items:center;gap:.4rem;font-weight:bold">
    <input type="checkbox" name="disabled" value="1"{disabled_checked}> Disabled
  </label>
  <button type="submit">Save</button>
</form>
</div>
"#,
        id = dto.id,
        csrf = esc(csrf_token),
        dn = esc(current_display_name),
        cm = esc(current_comment),
        disabled_checked = if dto.disabled { " checked" } else { "" },
    ));

    // Remove user form (only shown when the peer has a linked config and the
    // friendly name passes installer-managed name validation, i.e. it matches
    // the `-client-<name>` pattern and `[a-zA-Z0-9_-]{1,15}`).
    if dto.has_config {
        if let Some(ref fn_name) = dto.friendly_name {
            if crate::admin::script_bridge::validate_client_name(fn_name).is_ok() {
                buf.push_str(&format!(
                    r#"<div class="edit-form" style="margin-top:1.5rem;border-color:#c00">
<h2 style="color:#c00">Remove user</h2>
<p>This will permanently revoke the client <strong>{name}</strong> and delete its config file.
Historical data (snapshots, events) will be preserved.</p>
<form method="POST" action="/admin/users/{id}/remove">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="confirm" value="yes">
  <button type="submit" style="background:#c00;margin-top:.5rem"
          onclick="return confirm('Are you sure you want to remove user {name_js}? This cannot be undone.')">
    Remove user
  </button>
</form>
</div>
"#,
                    id = dto.id,
                    csrf = esc(csrf_token),
                    name = esc(fn_name),
                    name_js = esc_js(fn_name),
                ));
            }
        }
    }

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

    // Recent audit events for this peer
    buf.push_str(&format!("<h2>Recent activity ({})</h2>\n", events.len()));
    if events.is_empty() {
        buf.push_str("<p>No recorded activity yet.</p>\n");
    } else {
        buf.push_str(
            "<table>\n\
             <tr><th>When</th><th>Event</th><th>Actor</th><th>Detail</th></tr>\n",
        );
        for ev in events {
            let detail_cell = ev
                .detail
                .as_deref()
                .map(|d| format!("<code>{}</code>", esc(d)))
                .unwrap_or_else(|| "–".to_string());
            buf.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&ev.created_at),
                esc(&ev.action),
                esc(&ev.actor),
                detail_cell,
            ));
        }
        buf.push_str("</table>\n");
    }

    buf.push_str("</body></html>");
    buf
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DEFAULT_SESSION_TTL_SECS;
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
        router(
            db,
            AuthConfig::disabled(),
            std::path::PathBuf::from("/tmp/test-configs"),
            std::path::PathBuf::from("/tmp/test-install.sh"),
        )
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
            session_ttl: std::time::Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
        };
        (
            router(
                db,
                auth,
                std::path::PathBuf::from("/tmp/test-configs"),
                std::path::PathBuf::from("/tmp/test-install.sh"),
            ),
            "testpassword".to_string(),
        )
    }

    // ── CSRF test helpers ───────────────────────────────────────────────────

    /// Extract the CSRF token from a hidden form field in an HTML page.
    ///
    /// Looks for `name="csrf_token" value="TOKEN"` pattern.
    fn extract_hidden_csrf(html: &str) -> String {
        let marker = "name=\"csrf_token\" value=\"";
        html.find(marker)
            .map(|pos| {
                let rest = &html[pos + marker.len()..];
                rest[..rest.find('"').unwrap_or(0)].to_string()
            })
            .unwrap_or_default()
    }

    /// Call `GET /login`, extract the pre-login CSRF token, then `POST /login`
    /// with the given credentials.  Returns the login `Response`.
    async fn do_login(app: Router, username: &str, password: &str) -> axum::response::Response {
        // Step 1: GET /login to obtain the CSRF token.
        let get_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let csrf = extract_hidden_csrf(html);

        // Step 2: POST /login with the CSRF token.
        let form_body = format!(
            "username={}&password={}&csrf_token={}",
            username, password, csrf,
        );
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    /// Extract the session cookie value from a `Set-Cookie` header.
    fn session_cookie_value(response: &axum::response::Response) -> String {
        response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .trim()
            .to_string()
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
        let html = render_login_page(false, "test_csrf_token");
        assert!(html.contains(r#"action="/login""#));
        assert!(html.contains(r#"name="username""#));
        assert!(html.contains(r#"name="password""#));
        assert!(html.contains(r#"name="csrf_token" value="test_csrf_token""#));
        assert!(!html.contains("Invalid username"));
    }

    #[test]
    fn login_page_shows_error() {
        let html = render_login_page(true, "tok");
        assert!(html.contains("Invalid username or password"));
    }

    #[test]
    fn login_page_embeds_csrf_token() {
        let html = render_login_page(false, "mytoken123");
        assert!(html.contains("name=\"csrf_token\" value=\"mytoken123\""));
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
    async fn login_page_contains_csrf_token() {
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        // The login form must have a non-empty CSRF hidden field.
        let token = extract_hidden_csrf(html);
        assert!(
            !token.is_empty(),
            "login form must contain a csrf_token field"
        );
        assert_eq!(token.len(), 32, "CSRF token must be 32 hex chars");
    }

    #[tokio::test]
    async fn login_wrong_password_shows_error_page() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = do_login(app, "admin", "wrongpassword").await;
        // Should stay on login page (200), not redirect.
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Invalid username or password"));
    }

    #[tokio::test]
    async fn login_missing_csrf_returns_403() {
        // Submitting the login form without a CSRF token must be rejected.
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
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn login_invalid_csrf_returns_403() {
        // Submitting the login form with a wrong CSRF token must be rejected.
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "username=admin&password=testpassword&csrf_token=bogus",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn login_correct_credentials_sets_cookie_and_redirects() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = do_login(app, "admin", "testpassword").await;
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
        let login_response = do_login(app.clone(), "admin", "testpassword").await;
        assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
        let session_value = session_cookie_value(&login_response);

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

        // 1. Login.
        let login_response = do_login(app.clone(), "admin", "testpassword").await;
        assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
        let session_value = session_cookie_value(&login_response);

        // 2. Fetch the main page to get the CSRF token for the logout form.
        let page_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", &session_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let page_body = axum::body::to_bytes(page_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let page_html = std::str::from_utf8(&page_body).unwrap();
        let csrf = extract_hidden_csrf(page_html);
        assert!(!csrf.is_empty(), "page must contain a csrf_token");

        // 3. Logout with session cookie + CSRF token.
        let logout_body = format!("csrf_token={csrf}");
        let logout_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header("cookie", &session_value)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(logout_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_response.status(), StatusCode::SEE_OTHER);
        let clear_cookie = logout_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(clear_cookie.contains("Max-Age=0"));

        // 4. Subsequent request with old cookie must be rejected.
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

    #[tokio::test]
    async fn logout_missing_csrf_returns_403() {
        let db = test_db().await;
        let (app, _) = test_router_with_auth(db);

        let login_response = do_login(app.clone(), "admin", "testpassword").await;
        let session_value = session_cookie_value(&login_response);

        // Logout without CSRF token → 403.
        let logout_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header("cookie", &session_value)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(""))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_response.status(), StatusCode::FORBIDDEN);
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

    // ── CSRF: peer edit form ───────────────────────────────────────────────

    #[tokio::test]
    async fn peer_edit_form_requires_csrf() {
        let db = test_db().await;
        let id = insert_peer(&db, "CSRF_PEER_TEST_KEY===", Some("Original")).await;
        let (app, _) = test_router_with_auth(db);

        // Login.
        let login_response = do_login(app.clone(), "admin", "testpassword").await;
        let session_value = session_cookie_value(&login_response);

        // POST the edit form without a CSRF token → 403.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/peers/{id}"))
                    .header("cookie", &session_value)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("display_name=Hacked"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn peer_edit_form_valid_csrf_succeeds() {
        let db = test_db().await;
        let id = insert_peer(&db, "CSRF_PEER_VALID_KEY==", Some("Original")).await;
        let (app, _) = test_router_with_auth(db);

        // Login.
        let login_response = do_login(app.clone(), "admin", "testpassword").await;
        let session_value = session_cookie_value(&login_response);

        // Fetch the edit page to get the CSRF token.
        let page_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/peers/{id}"))
                    .header("cookie", &session_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let page_body = axum::body::to_bytes(page_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let page_html = std::str::from_utf8(&page_body).unwrap();
        let csrf = extract_hidden_csrf(page_html);
        assert!(!csrf.is_empty());

        // POST with valid CSRF token → redirect (PRG).
        let form_body = format!("display_name=Updated&csrf_token={csrf}");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/peers/{id}"))
                    .header("cookie", &session_value)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn api_patch_unaffected_by_csrf() {
        // PATCH /api/peers/:id uses bearer token and should not be affected by
        // CSRF protection.
        let db = test_db().await;
        let id = insert_peer(&db, "CSRF_API_PATCH_KEY===", None).await;
        let (app, _) = test_router_with_auth(db);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("authorization", "Bearer super-secret-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"No CSRF needed"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Rate limiting ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_rate_limited_after_many_attempts() {
        let (app, _) = test_router_with_auth(test_db().await);

        // Get one CSRF token (re-used across attempts; each will consume it,
        // so we need a fresh one per request).  Simulate multiple failed logins
        // by doing the full GET /login → POST /login cycle each time.
        let mut last_status = StatusCode::OK;
        for i in 0..10 {
            let resp = do_login(app.clone(), "admin", &format!("wrong{i}")).await;
            last_status = resp.status();
            if last_status == StatusCode::TOO_MANY_REQUESTS {
                break;
            }
        }
        assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
    }

    // ── Session TTL ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expired_session_rejected() {
        // Build a router whose session TTL is 0 – sessions expire immediately.
        let db = test_db().await;
        let hash = AuthConfig::hash_password_fast("pass");
        let auth = AuthConfig {
            enabled: true,
            username: "admin".to_string(),
            password_hash: hash,
            api_token: None,
            secure_cookie: false,
            session_ttl: std::time::Duration::from_secs(0),
        };
        let app = router(
            db,
            auth,
            std::path::PathBuf::from("/tmp/test-configs"),
            std::path::PathBuf::from("/tmp/test-install.sh"),
        );

        // Login succeeds and we get a session cookie ...
        let login_resp = do_login(app.clone(), "admin", "pass").await;
        assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
        let session_value = session_cookie_value(&login_resp);

        // ... but the session TTL is 0, so it expires immediately.
        let api_resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .header("cookie", &session_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Audit events API ───────────────────────────────────────────────────

    #[tokio::test]
    async fn events_api_returns_empty_list_initially() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/events")
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
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn patch_peer_creates_audit_event() {
        let db = test_db().await;
        let id = insert_peer(&db, "AUDIT_PATCH_KEY===", Some("OldName")).await;
        let app = test_router(db);

        // PATCH the peer.
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"NewName"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Check events API.
        let events_resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/events?peer_id={id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(events_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(events_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = events.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["event_type"], "peer_updated");
        assert_eq!(arr[0]["peer_id"], id);
        // Payload must contain old and new names.
        let payload = &arr[0]["payload"];
        assert_eq!(payload["old_display_name"], "OldName");
        assert_eq!(payload["new_display_name"], "NewName");
    }

    #[tokio::test]
    async fn events_api_filter_by_event_type() {
        let db = test_db().await;
        let id = insert_peer(&db, "AUDIT_FILTER_KEY==", None).await;
        let app = test_router(db);

        // Cause a peer_updated event.
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"Filtered"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Filter to only peer_updated events.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/events?event_type=peer_updated")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!events.is_empty());
        assert!(events.iter().all(|e| e["event_type"] == "peer_updated"));

        // Filter to a non-existent event type – should return empty list.
        let resp2 = app
            .oneshot(
                Request::builder()
                    .uri("/api/events?event_type=no_such_event")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let events2: Vec<serde_json::Value> = serde_json::from_slice(&body2).unwrap();
        assert!(events2.is_empty());
    }

    #[tokio::test]
    async fn events_api_limit_parameter() {
        let db = test_db().await;
        let id = insert_peer(&db, "AUDIT_LIMIT_KEY===", None).await;
        let app = test_router(db);

        // Create 5 events.
        for i in 0..5 {
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("PATCH")
                        .uri(format!("/api/peers/{id}"))
                        .header("content-type", "application/json")
                        .body(Body::from(format!(r#"{{"display_name":"Name{i}"}}"#)))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        // Limit to 2.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/events?limit=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn patch_peer_logging_does_not_break_response() {
        // Even with audit logging, the PATCH response must remain valid.
        let db = test_db().await;
        let id = insert_peer(&db, "AUDIT_NOBREAK_KEY=", Some("Before")).await;
        let app = test_router(db);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"After"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["display_name"], "After");
    }

    #[tokio::test]
    async fn events_api_requires_auth_when_enabled() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_api_accessible_with_bearer_token() {
        let (app, _) = test_router_with_auth(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/events")
                    .header("authorization", "Bearer super-secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Epic 10: Admin Write Actions ─────────────────────────────────────────

    #[tokio::test]
    async fn patch_peer_disable_sets_disabled_flag() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_DISABLE=", Some("DisableMe")).await;
        let app = test_router(db);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"disabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["disabled"], true);
        assert_eq!(json["status"], "disabled");
    }

    #[tokio::test]
    async fn patch_peer_enable_clears_disabled_flag() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_ENABLE=", Some("EnableMe")).await;
        let app = test_router(db.clone());

        // Disable first.
        crate::db::peers::update_peer_disabled(&db.pool, id, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"disabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["disabled"], false);
    }

    #[tokio::test]
    async fn patch_peer_disable_creates_audit_event() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_DIS_AUDIT=", None).await;
        let app = test_router(db);

        app.clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"disabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Check audit log.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/events?event_type=peer_disabled")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0]["event_type"], "peer_disabled");
    }

    #[tokio::test]
    async fn patch_peer_disable_unchanged_no_audit_event() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_DIS_NOAUDIT=", None).await;
        let app = test_router(db);

        // Peer is already enabled (disabled=0). Setting disabled=false should not create event.
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"disabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/events?event_type=peer_disabled")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn patch_peer_metadata_only_no_disabled_event() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_META_ONLY=", None).await;
        let app = test_router(db);

        // Only update display_name, no disabled field.
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/peers/{id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"display_name":"MetaOnly"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/events?event_type=peer_disabled")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn get_peer_config_no_config_returns_404() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_NOCONF=", None).await;
        let app = test_router(db);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}/config"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_peer_config_peer_not_found_returns_404() {
        let app = test_router(test_db().await);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/peers/9999/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_peer_config_returns_file_content() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_DLCONF=", None).await;

        // Create a temp config file.
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("test-client.conf");
        std::fs::write(&conf_path, "[Interface]\nAddress = 10.0.0.2/32\n").unwrap();

        // Map the config to the peer.
        crate::db::peers::apply_config_mapping(
            &db.pool,
            "KEY_DLCONF=",
            "test-client",
            conf_path.to_str().unwrap(),
            "test-client",
        )
        .await
        .unwrap();

        let app = test_router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/peers/{id}/config"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/plain"));

        let disposition = response
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(disposition.contains("attachment"));
        assert!(disposition.contains("test-client.conf"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("[Interface]"));
        assert!(text.contains("10.0.0.2/32"));
    }

    #[tokio::test]
    async fn peer_detail_page_shows_disabled_checkbox() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_CKBOX=", Some("CheckboxPeer")).await;
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("name=\"disabled\""));
        assert!(html.contains("value=\"1\""));
    }

    #[tokio::test]
    async fn peer_detail_page_shows_download_link_when_config_exists() {
        let db = test_db().await;
        let id = insert_peer(&db, "KEY_DLINK=", None).await;
        crate::db::peers::apply_config_mapping(
            &db.pool,
            "KEY_DLINK=",
            "test-dl",
            "/etc/awg/test-dl.conf",
            "test-dl",
        )
        .await
        .unwrap();

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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains(&format!("/api/peers/{id}/config")));
        assert!(html.contains("Download"));
    }

    // ── User lifecycle UI tests ──────────────────────────────────────────

    #[tokio::test]
    async fn peer_list_page_contains_add_user_form() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Add user"),
            "peer list page should contain 'Add user' form"
        );
        assert!(
            html.contains("/admin/users/add"),
            "peer list page should contain add user form action"
        );
        assert!(
            html.contains("name=\"name\""),
            "peer list page should contain name input field"
        );
    }

    #[tokio::test]
    async fn peer_detail_page_shows_remove_button_when_config_linked() {
        let db = test_db().await;
        let id = insert_peer(&db, "REMOVE_TEST_KEY==", Some("myuser")).await;

        // Set config metadata so has_config=1 and friendly_name is set
        sqlx::query(
            "UPDATE peers SET has_config = 1, friendly_name = 'myuser', \
             config_name = 'awg0-client-myuser' WHERE id = ?",
        )
        .bind(id)
        .execute(&db.pool)
        .await
        .unwrap();

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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Remove user"),
            "detail page should contain 'Remove user' when config is linked"
        );
        assert!(
            html.contains(&format!("/admin/users/{id}/remove")),
            "detail page should contain remove form action"
        );
        assert!(
            html.contains("confirm"),
            "detail page should have confirmation mechanism"
        );
    }

    #[tokio::test]
    async fn peer_detail_page_no_remove_when_unlinked() {
        let db = test_db().await;
        let id = insert_peer(&db, "NOREMOVE_KEY==", Some("noconf")).await;

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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("Remove user"),
            "detail page should NOT show 'Remove user' when config is not linked"
        );
    }

    #[tokio::test]
    async fn peer_detail_page_no_remove_when_name_not_installer_managed() {
        let db = test_db().await;
        let id = insert_peer(&db, "DOTNAME_KEY==", Some("custom.name")).await;

        // Config is linked but the friendly_name contains a dot (not installer-managed).
        sqlx::query(
            "UPDATE peers SET has_config = 1, friendly_name = 'custom.name', \
             config_name = 'custom.name' WHERE id = ?",
        )
        .bind(id)
        .execute(&db.pool)
        .await
        .unwrap();

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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("Remove user"),
            "detail page should NOT show 'Remove user' when friendly_name fails installer validation"
        );
    }

    // ── API user lifecycle tests ─────────────────────────────────────────

    #[tokio::test]
    async fn api_create_user_rejects_empty_name() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/users")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_create_user_rejects_invalid_chars() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/users")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"../etc/passwd"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_create_user_rejects_too_long_name() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/users")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"1234567890123456"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_remove_user_not_found_returns_404() {
        let app = test_router(test_db().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/users/9999/remove")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_remove_user_no_config_returns_400() {
        let db = test_db().await;
        let id = insert_peer(&db, "NOCONF_REMOVE_KEY==", Some("noconf")).await;

        let app = test_router(db);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/users/{id}/remove"))
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn esc_js_escapes_html_and_js_specials() {
        assert_eq!(
            super::esc_js("a&b<c>d\"e'f\\g"),
            "a&amp;b&lt;c&gt;d&quot;e\\'f\\\\g"
        );
    }

    #[test]
    fn esc_js_escapes_line_terminators() {
        assert_eq!(super::esc_js("a\nb\rc"), "a\\nb\\rc");
        assert_eq!(super::esc_js("x\u{2028}y\u{2029}z"), "x\\u2028y\\u2029z");
    }
}
