//! HTTP Admin API for SIPhon.
//!
//! Provides a lightweight REST API on a separate port for:
//! - Prometheus metrics scraping (`GET /metrics`)
//! - Runtime inspection (registrations, dialogs, transactions, connections)
//! - Health/readiness probes (`GET /admin/health`)
//! - Force-unregister (`DELETE /admin/registrations/:aor`)
//! - List / lift auto-bans (`GET /admin/bans`, `DELETE /admin/bans/:ip`)

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get};
use axum::Router;
use serde::Serialize;
use tracing::{error, info};

use crate::config::CorsConfig;
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
///
/// `cors` optionally attaches an `Access-Control-Allow-Origin` policy so a
/// browser dashboard served from another origin can `fetch()` the admin API
/// (and the `/metrics` it also serves). `None` = no CORS headers.
pub async fn serve(listen_addr: SocketAddr, state: AdminState, cors: Option<CorsConfig>) {
    let app = router(state, cors.as_ref());

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
fn router(state: AdminState, cors: Option<&CorsConfig>) -> Router {
    let mut app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/admin/health", get(health_handler))
        .route("/admin/ready", get(ready_handler))
        .route("/admin/stats", get(stats_handler))
        .route("/admin/registrations", get(registrations_handler))
        .route("/admin/registrations/{aor}", get(registration_detail_handler))
        .route("/admin/registrations/{aor}", delete(registration_delete_handler))
        .route("/admin/bans", get(bans_handler))
        .route("/admin/bans/{ip}", delete(ban_delete_handler))
        .with_state(state);
    if let Some(layer) = cors.and_then(crate::cors::build_cors_layer) {
        app = app.layer(layer);
    }
    app
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

/// `GET /admin/bans` — list the sources currently auto-banned by
/// `failed_auth_ban`, each with its remaining ban time in seconds. Empty when
/// the feature is not configured.
async fn bans_handler() -> impl IntoResponse {
    let entries: Vec<serde_json::Value> = crate::security::auto_ban()
        .map(|store| store.banned_sources())
        .unwrap_or_default()
        .into_iter()
        .map(|(address, remaining)| {
            serde_json::json!({
                "ip": address.to_string(),
                "expires_remaining": remaining,
            })
        })
        .collect();
    Json(entries)
}

/// `DELETE /admin/bans/:ip` — lift an auto-ban early (operator clearing a false
/// positive). Removes the userspace ban and, when the kernel firewall is wired,
/// the matching nf_tables element too, so the in-kernel drop is lifted in
/// lockstep. 404 when the source is not banned or `failed_auth_ban` is off,
/// 400 when `:ip` is not a valid address.
async fn ban_delete_handler(Path(ip): Path<String>) -> impl IntoResponse {
    let address: IpAddr = match ip.parse() {
        Ok(address) => address,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid IP address", "ip": ip })),
            );
        }
    };

    match crate::security::auto_ban() {
        Some(store) if store.unban(address) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "unbanned", "ip": address.to_string() })),
        ),
        Some(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not banned", "ip": address.to_string() })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "auto-ban not enabled", "ip": address.to_string() })),
        ),
    }
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
        router(test_state(), None)
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
        let app = router(state, None);

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

    // The auto-ban store is a process-global `OnceLock` that another test in the
    // lib binary installs, so these assert only what holds regardless of whether
    // a store is installed (list is always a JSON array; a bad IP is always 400).
    // The unban / list-contents logic is covered by store-level tests in
    // `crate::security` where a local store can be constructed deterministically.
    #[tokio::test]
    async fn bans_list_returns_json_array() {
        let app = test_app();

        let response = app
            .oneshot(Request::get("/admin/bans").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn ban_delete_invalid_ip_returns_400() {
        let app = test_app();

        let response = app
            .oneshot(
                Request::delete("/admin/bans/not-an-ip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid IP address");
    }

    #[tokio::test]
    async fn cors_echoes_configured_origin_on_metrics() {
        crate::metrics::init().unwrap();
        let cors = CorsConfig {
            allowed_origins: vec!["http://localhost:5173".to_owned()],
        };
        let app = router(test_state(), Some(&cors));

        // A simple cross-origin GET must come back with the allow-origin echo,
        // or the browser hides the body from the dashboard.
        let response = app
            .oneshot(
                Request::get("/metrics")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:5173"),
        );
    }

    #[tokio::test]
    async fn cors_preflight_is_answered_for_admin_delete() {
        let cors = CorsConfig {
            allowed_origins: vec!["http://localhost:5173".to_owned()],
        };
        let app = router(test_state(), Some(&cors));

        // The admin DELETE routes are non-simple requests, so the browser sends
        // an OPTIONS preflight first; the layer must answer it 2xx with the echo.
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/admin/registrations/sip:alice@example.com")
                    .header("origin", "http://localhost:5173")
                    .header("access-control-request-method", "DELETE")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status().is_success());
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:5173"),
        );
    }

    #[tokio::test]
    async fn no_cors_config_emits_no_header() {
        crate::metrics::init().unwrap();
        // Default (no cors block) stays byte-for-byte as before — no CORS header.
        let app = router(test_state(), None);

        let response = app
            .oneshot(
                Request::get("/metrics")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }
}
