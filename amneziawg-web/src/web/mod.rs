//! HTTP router and handler stubs.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;
use tower_http::trace::TraceLayer;

use crate::db::Database;

/// Build the application router.
pub fn router(db: Database) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/peers", get(list_peers))
        .route("/api/peers/:id", get(get_peer))
        .with_state(db)
        .layer(TraceLayer::new_for_http())
}

/// `GET /api/health` – liveness probe.
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/peers` – list all known peers.
///
/// TODO: Query `peers` table and return paginated results.
async fn list_peers(State(_db): State<Database>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "peers": [],
            "note": "placeholder – full implementation pending"
        })),
    )
}

/// `GET /api/peers/:id` – fetch a single peer by its base64 public key.
///
/// TODO: Look up peer from DB and return details including snapshots.
async fn get_peer(State(_db): State<Database>, Path(id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "peer": null,
            "id": id,
            "note": "placeholder – full implementation pending"
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::util::ServiceExt;

    async fn test_db() -> Database {
        let db = Database::connect("sqlite::memory:").await.expect("connect");
        db.migrate().await.expect("migrate");
        db
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
    async fn list_peers_returns_200() {
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
    }
}
