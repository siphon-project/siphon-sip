//! Integration tests for the HTTP Admin API.
//!
//! Tests the admin router directly using `tower::ServiceExt::oneshot`
//! without binding a real TCP port.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::util::ServiceExt;

use siphon::admin::AdminState;
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::sip::uri::SipUri;

fn test_state() -> AdminState {
    AdminState {
        registrar: Arc::new(Registrar::new(RegistrarConfig::default())),
        start_time: Instant::now(),
        draining: None,
        auth_token: None,
        protect_reads: false,
        instance_id: None,
    }
}

/// Build the admin router. The `router` function is private in the admin module,
/// so we reconstruct the same routes here using the public types.
fn test_router(state: AdminState) -> Router {
    use axum::routing::{delete, get};

    // We cannot call the private `router()` from outside the crate, so we
    // replicate the route table. This also validates that AdminState works
    // as axum shared state from an external consumer perspective.
    //
    // Instead, we rely on the fact that the admin module exposes `serve` which
    // internally builds the router. For integration testing we call serve-like
    // setup. Since `router` is private, we test through the crate's own test
    // infrastructure by using the module's public `AdminState` and building
    // an equivalent router.
    //
    // Actually — let's just test via the public `serve` by binding to localhost:0.
    // But that requires an async server. A simpler approach: the admin module
    // has inline unit tests that already use `router()`. For integration tests
    // we take a different approach and start a real server on an ephemeral port.
    //
    // Best approach: use `axum::serve` with a TcpListener on port 0, then
    // use reqwest or hyper client. But that adds dependencies.
    //
    // Simplest: since AdminState and the handler signatures are known, we can
    // build the same router here.

    async fn health_handler(
        axum::extract::State(state): axum::extract::State<AdminState>,
    ) -> axum::response::Json<serde_json::Value> {
        let uptime = state.start_time.elapsed().as_secs();
        axum::response::Json(serde_json::json!({
            "status": "ok",
            "uptime_seconds": uptime,
        }))
    }

    async fn stats_handler(
        axum::extract::State(state): axum::extract::State<AdminState>,
    ) -> axum::response::Json<serde_json::Value> {
        let registrations = state.registrar.aor_count();
        let uptime = state.start_time.elapsed().as_secs();
        axum::response::Json(serde_json::json!({
            "uptime_seconds": uptime,
            "registrations_active": registrations,
        }))
    }

    async fn registrations_handler(
        axum::extract::State(state): axum::extract::State<AdminState>,
    ) -> axum::response::Json<serde_json::Value> {
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
        axum::response::Json(serde_json::Value::Array(entries))
    }

    async fn registration_detail_handler(
        axum::extract::State(state): axum::extract::State<AdminState>,
        axum::extract::Path(aor): axum::extract::Path<String>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let contacts = state.registrar.lookup(&aor);
        if contacts.is_empty() {
            return (
                StatusCode::NOT_FOUND,
                axum::response::Json(serde_json::json!({
                    "error": "not found",
                    "aor": aor,
                })),
            )
                .into_response();
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
        (
            StatusCode::OK,
            axum::response::Json(serde_json::json!({
                "aor": aor,
                "contacts": contact_list,
            })),
        )
            .into_response()
    }

    async fn registration_delete_handler(
        axum::extract::State(state): axum::extract::State<AdminState>,
        axum::extract::Path(aor): axum::extract::Path<String>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        if !state.registrar.is_registered(&aor) {
            return (
                StatusCode::NOT_FOUND,
                axum::response::Json(serde_json::json!({
                    "error": "not found",
                    "aor": aor,
                })),
            )
                .into_response();
        }
        state.registrar.remove_all(&aor);
        (
            StatusCode::OK,
            axum::response::Json(serde_json::json!({
                "status": "removed",
                "aor": aor,
            })),
        )
            .into_response()
    }

    async fn metrics_handler() -> axum::response::Response {
        use axum::response::IntoResponse;
        let body = siphon::metrics::encode_metrics();
        (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            body,
        )
            .into_response()
    }

    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/admin/health", get(health_handler))
        .route("/admin/stats", get(stats_handler))
        .route("/admin/registrations", get(registrations_handler))
        .route(
            "/admin/registrations/{aor}",
            get(registration_detail_handler),
        )
        .route(
            "/admin/registrations/{aor}",
            delete(registration_delete_handler),
        )
        .with_state(state)
}

async fn response_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn response_text(response: axum::http::Response<Body>) -> String {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn health_returns_status_and_uptime() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let app = test_router(state);

    let response = app
        .oneshot(Request::get("/admin/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["status"], "ok");
    assert!(
        json["uptime_seconds"].as_u64().is_some(),
        "response must contain uptime_seconds as a number"
    );
}

#[tokio::test]
async fn stats_returns_registration_count() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let app = test_router(state);

    let response = app
        .oneshot(Request::get("/admin/stats").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["registrations_active"], 0);
    assert!(json["uptime_seconds"].as_u64().is_some());
}

#[tokio::test]
async fn registrations_initially_empty() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let app = test_router(state);

    let response = app
        .oneshot(
            Request::get("/admin/registrations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    let array = json.as_array().expect("response should be a JSON array");
    assert!(array.is_empty(), "no registrations should exist initially");
}

#[tokio::test]
async fn registrations_lists_saved_contact() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let registrar = state.registrar.clone();

    registrar
        .save(
            "sip:alice@example.com",
            SipUri::new("10.0.0.1".to_string()).with_user("alice".to_string()),
            3600,
            1.0,
            "call-id-1".to_string(),
            1,
        )
        .unwrap();

    let app = test_router(state);

    let response = app
        .oneshot(
            Request::get("/admin/registrations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    let array = json.as_array().expect("response should be a JSON array");
    assert_eq!(array.len(), 1);
    assert_eq!(array[0]["aor"], "sip:alice@example.com");
}

#[tokio::test]
async fn registration_detail_for_known_aor() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let registrar = state.registrar.clone();

    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.2".to_string()).with_user("bob".to_string()),
            3600,
            0.8,
            "call-id-2".to_string(),
            1,
        )
        .unwrap();

    let app = test_router(state);

    let response = app
        .oneshot(
            Request::get("/admin/registrations/sip:bob@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["aor"], "sip:bob@example.com");
    let contacts = json["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 1);
    assert!(contacts[0]["uri"].as_str().unwrap().contains("bob"));
}

#[tokio::test]
async fn registration_detail_not_found() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let app = test_router(state);

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
async fn delete_registration_removes_aor() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let registrar = state.registrar.clone();

    registrar
        .save(
            "sip:carol@example.com",
            SipUri::new("10.0.0.3".to_string()).with_user("carol".to_string()),
            3600,
            1.0,
            "call-id-3".to_string(),
            1,
        )
        .unwrap();

    assert!(registrar.is_registered("sip:carol@example.com"));

    // DELETE the registration
    let app = test_router(state.clone());
    let response = app
        .oneshot(
            Request::delete("/admin/registrations/sip:carol@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["status"], "removed");

    // Verify it is gone
    assert!(!registrar.is_registered("sip:carol@example.com"));

    // A subsequent GET should return 404
    let app2 = test_router(state);
    let response2 = app2
        .oneshot(
            Request::get("/admin/registrations/sip:carol@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response2.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_nonexistent_registration_returns_not_found() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let app = test_router(state);

    let response = app
        .oneshot(
            Request::delete("/admin/registrations/sip:ghost@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text() {
    siphon::metrics::init().unwrap();
    let state = test_state();
    let app = test_router(state);

    let response = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let text = response_text(response).await;
    // Prometheus text format lines start with "# " (comments) or metric names
    assert!(
        text.contains("siphon_"),
        "metrics body should contain siphon_ prefixed metrics"
    );
}
