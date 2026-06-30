//! HTTP Admin API for SIPhon.
//!
//! Provides a lightweight REST API on a separate port for:
//! - Prometheus metrics scraping (`GET /metrics`)
//! - Runtime inspection (registrations, dialogs, transactions, connections)
//! - Health/readiness probes (`GET /admin/health`)
//! - Force-unregister (`DELETE /admin/registrations/:aor`)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get};
use axum::Router;
use serde::Serialize;
use tracing::{error, info};

use crate::dispatcher::DrainState;
use crate::registrar::Registrar;

/// Shared state available to all admin API handlers.
#[derive(Clone)]
pub struct AdminState {
    pub registrar: Arc<Registrar>,
    pub start_time: Instant,
    /// Drain signal, when wired by the server. `/admin/ready` returns 503 while
    /// draining so a load balancer / orchestrator stops sending new work. `None`
    /// (e.g. in tests) means "never draining".
    pub draining: Option<Arc<DrainState>>,
}

/// Start the HTTP admin API server.
pub async fn serve(listen_addr: SocketAddr, state: AdminState) {
    let app = router(state);

    info!("Admin API listening on {}", listen_addr);

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            error!("Failed to bind admin API on {}: {}", listen_addr, error);
            return;
        }
    };

    if let Err(error) = axum::serve(listener, app).await {
        error!("Admin API server error: {}", error);
    }
}

/// Build the router (also used by tests without binding a port).
fn router(state: AdminState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/admin/health", get(health_handler))
        .route("/admin/ready", get(ready_handler))
        .route("/admin/stats", get(stats_handler))
        .route("/admin/registrations", get(registrations_handler))
        .route("/admin/registrations/{aor}", get(registration_detail_handler))
        .route("/admin/registrations/{aor}", delete(registration_delete_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /metrics` — Prometheus text format scrape endpoint.
async fn metrics_handler() -> impl IntoResponse {
    let body = crate::metrics::encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// `GET /admin/health` — liveness probe. 200 for as long as the process is
/// alive and the admin server is servicing requests. It does NOT flip during
/// drain (use `/admin/ready` for that): a liveness probe failing during a
/// graceful drain would make an orchestrator kill the pod mid-drain.
async fn health_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_seconds: uptime,
    })
}

/// `GET /admin/ready` — readiness probe. 200 normally; **503 while draining**
/// (SIGTERM received) so a load balancer / orchestrator removes this node from
/// rotation before it stops accepting new INVITEs. When no drain signal is wired
/// it always reports ready.
async fn ready_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let draining = state
        .draining
        .as_ref()
        .map(|drain| drain.is_draining.load(std::sync::atomic::Ordering::SeqCst))
        .unwrap_or(false);
    if draining {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "draining" })),
        )
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready" })),
        )
    }
}

/// `GET /admin/stats` — aggregate counters.
async fn stats_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let registrations = state.registrar.aor_count();

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.uptime_seconds.set(uptime as f64);
    }

    Json(StatsResponse {
        uptime_seconds: uptime,
        registrations_active: registrations,
    })
}

/// `GET /admin/registrations` — list all active AoRs with their contacts.
async fn registrations_handler(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let all = state.registrar.all_contacts();
    let entries: Vec<serde_json::Value> = all
        .iter()
        .map(|(aor, contact)| {
            serde_json::json!({
                "aor": aor,
                "uri": contact.uri.to_string(),
                "q": contact.q,
                "expires_remaining": contact.remaining_seconds(),
            })
        })
        .collect();
    Json(entries)
}

/// `GET /admin/registrations/:aor` — detail for a single AoR.
async fn registration_detail_handler(
    State(state): State<AdminState>,
    Path(aor): Path<String>,
) -> impl IntoResponse {
    let contacts = state.registrar.lookup(&aor);
    if contacts.is_empty() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "not found",
            "aor": aor,
        }))).into_response();
    }

    let contact_list: Vec<serde_json::Value> = contacts
        .iter()
        .map(|contact| {
            serde_json::json!({
                "uri": contact.uri.to_string(),
                "q": contact.q,
                "expires_remaining": contact.remaining_seconds(),
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "aor": aor,
        "contacts": contact_list,
    }))).into_response()
}

/// `DELETE /admin/registrations/:aor` — force-unregister all contacts for an AoR.
async fn registration_delete_handler(
    State(state): State<AdminState>,
    Path(aor): Path<String>,
) -> impl IntoResponse {
    if !state.registrar.is_registered(&aor) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "not found",
            "aor": aor,
        })));
    }

    state.registrar.remove_all(&aor);

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.registrations_active.dec();
    }

    (StatusCode::OK, Json(serde_json::json!({
        "status": "removed",
        "aor": aor,
    })))
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct StatsResponse {
    uptime_seconds: u64,
    registrations_active: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    fn test_state() -> AdminState {
        AdminState {
            registrar: Arc::new(Registrar::new(crate::registrar::RegistrarConfig::default())),
            start_time: Instant::now(),
            draining: None,
        }
    }

    fn test_app() -> Router {
        router(test_state())
    }

    #[tokio::test]
    async fn health_endpoint() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(Request::get("/admin/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json["uptime_seconds"].as_u64().is_some());
    }

    #[tokio::test]
    async fn ready_when_not_draining() {
        // No drain signal wired -> always ready.
        let app = test_app();

        let response = app
            .oneshot(Request::get("/admin/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ready");
    }

    #[tokio::test]
    async fn ready_returns_503_while_draining() {
        let drain = Arc::new(DrainState::new());
        drain
            .is_draining
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let state = AdminState {
            registrar: Arc::new(Registrar::new(crate::registrar::RegistrarConfig::default())),
            start_time: Instant::now(),
            draining: Some(drain),
        };
        let app = router(state);

        let response = app
            .oneshot(Request::get("/admin/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "draining");
    }

    #[tokio::test]
    async fn metrics_endpoint() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("siphon_"));
    }

    #[tokio::test]
    async fn stats_endpoint() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(Request::get("/admin/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["uptime_seconds"].as_u64().is_some());
        assert_eq!(json["registrations_active"], 0);
    }

    #[tokio::test]
    async fn registrations_empty() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(
                Request::get("/admin/registrations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registration_not_found() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(
                Request::get("/admin/registrations/sip:nobody@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_nonexistent_registration() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(
                Request::delete("/admin/registrations/sip:nobody@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
