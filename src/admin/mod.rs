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

use axum::extract::{Path, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
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
    /// Bearer token gating the admin API. `None` = no auth (network-placement
    /// trust only). Stored as `Arc<str>` for a cheap per-request clone in the
    /// auth layer.
    pub auth_token: Option<Arc<str>>,
    /// When true, the token is required on the read routes too, not only the
    /// mutating `DELETE` routes.
    pub protect_reads: bool,
    /// This node's instance id, surfaced in `/admin/metrics.json`. `None` when
    /// `server.instance_id` is unset and `$HOSTNAME` is absent.
    pub instance_id: Option<String>,
}

/// Start the HTTP admin API server.
///
/// `cors` optionally attaches an `Access-Control-Allow-Origin` policy so a
/// browser dashboard served from another origin can `fetch()` the admin API
/// (and the `/metrics` it also serves). `None` = no CORS headers.
///
/// `ui_enabled` serves the embedded web dashboard at `/` (and its assets),
/// same-origin with the API. It only has an effect on a binary built with the
/// `ui` cargo feature; without that feature a `true` here is a loud warning and
/// nothing is served.
pub async fn serve(
    listen_addr: SocketAddr,
    state: AdminState,
    cors: Option<CorsConfig>,
    ui_enabled: bool,
) {
    #[cfg(not(feature = "ui"))]
    if ui_enabled {
        tracing::warn!(
            "admin.ui.enabled is set but this binary was built without the `ui` \
             feature; no dashboard will be served (rebuild with --features ui)"
        );
    }

    let app = router(state, cors.as_ref(), ui_enabled);

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
///
/// Layer order (outermost first): CORS → bearer auth → routes. CORS is
/// outermost so an unauthenticated `401` still carries the
/// `Access-Control-Allow-Origin` echo (else the browser hides the body from the
/// dashboard). The auth layer gates mutating routes (and reads when
/// `protect_reads`) on the configured bearer token.
fn router(state: AdminState, cors: Option<&CorsConfig>, ui_enabled: bool) -> Router {
    let base = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/admin/metrics.json", get(metrics_json_handler))
        .route("/admin/health", get(health_handler))
        .route("/admin/ready", get(ready_handler))
        .route("/admin/stats", get(stats_handler))
        .route("/admin/registrations", get(registrations_handler))
        .route("/admin/registrations/{aor}", get(registration_detail_handler))
        .route("/admin/registrations/{aor}", delete(registration_delete_handler))
        .route("/admin/bans", get(bans_handler))
        .route("/admin/bans/{ip}", delete(ban_delete_handler))
        .route("/admin/gateways", get(gateways_handler))
        .route(
            "/admin/gateways/{group}/{destination}/{action}",
            post(gateway_action_handler),
        );

    // Everything not matched by an API route falls through to the embedded
    // dashboard (single-page app), so `/` and any client route serve it.
    #[cfg(feature = "ui")]
    let base = if ui_enabled {
        base.fallback(get(ui_handler))
    } else {
        base
    };
    #[cfg(not(feature = "ui"))]
    let _ = ui_enabled;

    let app = base
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_auth,
        ))
        .with_state(state);

    match cors.and_then(crate::cors::build_cors_layer) {
        Some(layer) => app.layer(layer),
        None => app,
    }
}

/// Bearer-token gate for the admin API (RFC 6750). No-op when no token is
/// configured. Always lets CORS preflight (`OPTIONS`) through so the browser
/// can complete a preflight before it holds the token. Otherwise requires
/// `Authorization: Bearer <token>` on every mutating method (`POST`, `PUT`,
/// `PATCH`, `DELETE`) — and, when `protect_reads`, on the read methods too —
/// comparing in constant time.
async fn require_admin_auth(State(state): State<AdminState>, request: Request, next: Next) -> Response {
    let method = request.method();
    let is_read = method == Method::GET || method == Method::HEAD || method == Method::OPTIONS;
    let needs_auth = state.auth_token.is_some()
        && method != Method::OPTIONS
        && (state.protect_reads || !is_read);

    if needs_auth {
        let presented = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let authorized = match (presented, state.auth_token.as_deref()) {
            (Some(presented), Some(expected)) => {
                constant_time_eq(presented.as_bytes(), expected.as_bytes())
            }
            _ => false,
        };
        if !authorized {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                Json(serde_json::json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Length-checked constant-time byte comparison, so a wrong token can't be
/// recovered by timing the response. (Length is allowed to leak — a bearer
/// token's length is not the secret.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }
    difference == 0
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

/// `GET /admin/metrics.json` — a curated JSON snapshot of the live gauges and
/// counters for the embedded dashboard. Deliberately not the Prometheus text
/// format: the browser polls this and diffs the cumulative counters over time
/// to derive rates, so no server-side time series is needed. Returns a minimal
/// shape (version/uptime/registrations) when metrics are not initialised.
async fn metrics_json_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Refresh jemalloc gauges so `memory.*` isn't stale between dispatcher ticks.
    crate::metrics::update_memory_stats();

    let uptime = state.start_time.elapsed().as_secs();
    let registrations = state.registrar.aor_count();
    let version = env!("CARGO_PKG_VERSION");

    let Some(metrics) = crate::metrics::try_metrics() else {
        return Json(serde_json::json!({
            "version": version,
            "instance_id": state.instance_id,
            "uptime_seconds": uptime,
            "registrations_active": registrations,
            "metrics": "uninitialized",
        }));
    };

    let connections = crate::metrics::gauge_vec_by_label(&metrics.connections_active, "transport");

    Json(serde_json::json!({
        "version": version,
        "instance_id": state.instance_id,
        "uptime_seconds": uptime,
        "jemalloc_active": crate::metrics::jemalloc_is_active(),
        "registrations_active": registrations,
        "sip": {
            "dialogs_active": metrics.dialogs_active.get(),
            "transactions_active": metrics.transactions_active.get(),
            "uac_pending": metrics.uac_pending_requests.get(),
            "subscribe_dialogs": metrics.subscribe_dialogs.get(),
            "cdr_sessions": metrics.cdr_sessions.get(),
            "connections": connections,
        },
        "counters": {
            "requests_total": crate::metrics::sum_int_counter_vec(&metrics.requests_total),
            "responses_total": crate::metrics::sum_int_counter_vec(&metrics.responses_total),
            "auth_failures_total": metrics.auth_failures_total.get(),
            "credential_failures_total": metrics.credential_failures_total.get(),
            "scanner_blocked_total": metrics.scanner_blocked_total.get(),
            "rate_limited_total": metrics.rate_limited_total.get(),
            "malformed_messages_total": metrics.malformed_messages_total.get(),
            "script_errors_total": metrics.script_errors_total.get(),
        },
        "memory": {
            "allocated": metrics.memory_allocated_bytes.get(),
            "resident": metrics.memory_resident_bytes.get(),
            "active": metrics.memory_active_bytes.get(),
            "retained": metrics.memory_retained_bytes.get(),
            "mapped": metrics.memory_mapped_bytes.get(),
            "glibc_system": metrics.glibc_system_bytes.get(),
            "glibc_in_use": metrics.glibc_in_use_bytes.get(),
            "glibc_arenas": metrics.glibc_arena_count.get(),
            "python_allocated_blocks": metrics.python_allocated_blocks.get(),
        },
        "pyexec": {
            "pool_size": metrics.pyexec_pool_size.get(),
            "pool_max": metrics.pyexec_pool_max.get(),
            "inflight": metrics.pyexec_inflight.get(),
            "queue_depth": metrics.pyexec_queue_depth.get(),
            "jobs_completed": metrics.pyexec_jobs_completed_total.get(),
            "jobs_shed": metrics.pyexec_jobs_shed_total.get(),
        },
        "diameter": { "peers_connected": metrics.diameter_peers_connected.get() },
        "rtpengine": {
            "up": metrics.rtpengine_instances_up.get(),
            "total": metrics.rtpengine_instances_total.get(),
        },
        "sbi": { "npcf_sessions_active": metrics.sbi_npcf_app_sessions_active.get() },
        "ipsec": { "sa_pairs": metrics.ipsec_sa_pairs.get() },
        "security": { "banned_ips": metrics.banned_ips.get() },
    }))
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

/// `GET /admin/gateways` — per-group gateway dispatcher status: every configured
/// group with its algorithm and each destination's health, weight, priority,
/// address, transport, and attributes. Reads the shared dispatcher the routing
/// datapath and `from_gateway` predicates already use (no new state, no probe).
/// Empty array when no `gateway` block is configured.
async fn gateways_handler() -> impl IntoResponse {
    match crate::script::api::gateway_manager() {
        Some(manager) => Json(gateways_json(manager)),
        None => Json(serde_json::Value::Array(Vec::new())),
    }
}

/// Serialize the gateway dispatcher state. Split from the handler so it can be
/// unit-tested against a locally-built manager without the process-global.
fn gateways_json(manager: &crate::gateway::DispatcherManager) -> serde_json::Value {
    let mut groups: Vec<serde_json::Value> = Vec::new();
    for name in manager.group_names() {
        let Some(group) = manager.get_group(&name) else {
            continue;
        };
        let destinations: Vec<serde_json::Value> = group
            .list_destinations()
            .iter()
            .map(|destination| {
                serde_json::json!({
                    "uri": destination.uri,
                    "address": destination
                        .address_str
                        .clone()
                        .unwrap_or_else(|| destination.address().to_string()),
                    "transport": destination.transport.to_string(),
                    "healthy": destination.is_healthy(),
                    "weight": destination.weight,
                    "priority": destination.priority,
                    "attrs": destination.attrs,
                })
            })
            .collect();
        let up = destinations
            .iter()
            .filter(|value| value.get("healthy").and_then(|h| h.as_bool()).unwrap_or(false))
            .count();
        groups.push(serde_json::json!({
            "name": group.name,
            "algorithm": group.algorithm.as_str(),
            "up": up,
            "total": destinations.len(),
            "destinations": destinations,
        }));
    }
    // Stable order for the dashboard (DashMap iteration order is arbitrary).
    groups.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    serde_json::Value::Array(groups)
}

/// `POST /admin/gateways/{group}/{destination}/{action}` — mark a gateway
/// destination `up` or `down` by hand (drain a bad carrier, then restore it).
/// `destination` is the destination URI exactly as returned by
/// `GET /admin/gateways`. Mutating, so it sits behind the bearer gate.
async fn gateway_action_handler(
    Path((group, destination, action)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let Some(manager) = crate::script::api::gateway_manager() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no gateway groups configured" })),
        );
    };
    let Some(dispatcher_group) = manager.get_group(&group) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown group", "group": group })),
        );
    };
    let changed = match action.as_str() {
        "down" => dispatcher_group.mark_down(&destination),
        "up" => dispatcher_group.mark_up(&destination),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "action must be 'up' or 'down'", "action": action })),
            );
        }
    };
    if changed {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": action, "group": group, "destination": destination })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown destination", "group": group, "destination": destination })),
        )
    }
}

// ---------------------------------------------------------------------------
// Embedded web dashboard (feature = "ui")
// ---------------------------------------------------------------------------

#[cfg(feature = "ui")]
mod embedded {
    use rust_embed::RustEmbed;

    /// Dashboard assets baked into the binary at compile time from the `ui/`
    /// directory (a single self-contained `index.html` today — no build step).
    #[derive(RustEmbed)]
    #[folder = "ui"]
    pub struct Assets;
}

/// Serve an embedded dashboard asset by path, falling back to `index.html` for
/// any unmatched path (single-page-app routing). Content-type is guessed from
/// the served file's name.
#[cfg(feature = "ui")]
async fn ui_handler(uri: axum::http::Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    let requested = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };

    let (name, asset) = match embedded::Assets::get(requested) {
        Some(asset) => (requested, asset),
        None => match embedded::Assets::get("index.html") {
            Some(asset) => ("index.html", asset),
            None => return (StatusCode::NOT_FOUND, "not found").into_response(),
        },
    };

    let mime = mime_guess::from_path(name).first_or_octet_stream();
    (
        [(header::CONTENT_TYPE, mime.as_ref())],
        asset.data.into_owned(),
    )
        .into_response()
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
            auth_token: None,
            protect_reads: false,
            instance_id: None,
        }
    }

    fn authed_state(token: &str, protect_reads: bool) -> AdminState {
        AdminState {
            auth_token: Some(Arc::from(token)),
            protect_reads,
            ..test_state()
        }
    }

    fn test_app() -> Router {
        router(test_state(), None, false)
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
            auth_token: None,
            protect_reads: false,
            instance_id: None,
        };
        let app = router(state, None, false);

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
        let app = router(test_state(), Some(&cors), false);

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
        let app = router(test_state(), Some(&cors), false);

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
        let app = router(test_state(), None, false);

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

    #[tokio::test]
    async fn metrics_json_endpoint_shape() {
        crate::metrics::init().unwrap();
        let app = test_app();

        let response = app
            .oneshot(
                Request::get("/admin/metrics.json")
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
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert!(json["uptime_seconds"].as_u64().is_some());
        // Metrics are initialised in this test, so the rich shape is present.
        assert!(json["sip"]["dialogs_active"].as_i64().is_some());
        assert!(json["counters"]["requests_total"].as_u64().is_some());
        assert!(json["memory"]["allocated"].as_i64().is_some());
    }

    #[tokio::test]
    async fn auth_rejects_delete_without_bearer() {
        crate::metrics::init().unwrap();
        // A token is configured, so the mutating DELETE route must present it.
        let app = router(authed_state("s3cret", false), None, false);

        let response = app
            .oneshot(
                Request::delete("/admin/registrations/sip:alice@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_allows_delete_with_bearer() {
        crate::metrics::init().unwrap();
        let app = router(authed_state("s3cret", false), None, false);

        let response = app
            .oneshot(
                Request::delete("/admin/registrations/sip:nobody@example.com")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Passed the auth layer; the AoR isn't registered, so it's a 404, not 401.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn auth_wrong_bearer_is_rejected() {
        crate::metrics::init().unwrap();
        let app = router(authed_state("s3cret", false), None, false);

        let response = app
            .oneshot(
                Request::delete("/admin/registrations/sip:alice@example.com")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reads_open_by_default_even_with_token() {
        crate::metrics::init().unwrap();
        // Token set but protect_reads = false: GET routes stay open.
        let app = router(authed_state("s3cret", false), None, false);

        let response = app
            .oneshot(
                Request::get("/admin/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protect_reads_requires_bearer_on_get() {
        crate::metrics::init().unwrap();
        let app = router(authed_state("s3cret", true), None, false);

        let unauth = app
            .clone()
            .oneshot(Request::get("/admin/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let authed = app
            .oneshot(
                Request::get("/admin/stats")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::OK);
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"tokeX"));
        assert!(!constant_time_eq(b"token", b"tok"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn gateways_json_empty_manager_is_empty_array() {
        let manager = crate::gateway::DispatcherManager::new();
        assert_eq!(gateways_json(&manager), serde_json::json!([]));
    }

    #[test]
    fn gateways_json_serializes_groups_and_destinations() {
        use crate::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
        use crate::transport::Transport;

        let manager = DispatcherManager::new();
        let dest_one = Destination::new(
            "sip:gw1.carrier.com:5060".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            3,
            1,
        );
        let dest_two = Destination::new(
            "sip:gw2.carrier.com:5061".to_string(),
            "10.0.0.2:5061".parse().unwrap(),
            Transport::Udp,
            1,
            2,
        );
        manager.add_group(DispatcherGroup::new(
            "carriers".to_string(),
            Algorithm::Weighted,
            vec![dest_one, dest_two],
        ));

        let json = gateways_json(&manager);
        let groups = json.as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["name"], "carriers");
        assert_eq!(groups[0]["algorithm"], "weighted");
        assert_eq!(groups[0]["total"], 2);
        // Fresh destinations start healthy.
        assert_eq!(groups[0]["up"], 2);
        let destinations = groups[0]["destinations"].as_array().unwrap();
        assert_eq!(destinations.len(), 2);
        assert_eq!(destinations[0]["uri"], "sip:gw1.carrier.com:5060");
        assert_eq!(destinations[0]["weight"], 3);
        assert_eq!(destinations[0]["healthy"], true);
        assert_eq!(destinations[0]["address"], "10.0.0.1:5060");
    }

    #[tokio::test]
    async fn gateway_action_post_requires_bearer() {
        crate::metrics::init().unwrap();
        // The write action is a POST — the generalized gate must cover it, not
        // just DELETE.
        let app = router(authed_state("s3cret", false), None, false);
        let response = app
            .oneshot(
                Request::post("/admin/gateways/carriers/sip:gw1.example.com:5060/down")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn gateway_action_unknown_group_is_404_with_token() {
        crate::metrics::init().unwrap();
        let app = router(authed_state("s3cret", false), None, false);
        let response = app
            .oneshot(
                Request::post("/admin/gateways/nope/sip:gw1.example.com:5060/down")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // No gateway manager is wired in unit tests -> no groups configured.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(feature = "ui")]
    #[tokio::test]
    async fn ui_served_at_root_when_enabled() {
        let app = router(test_state(), None, true);

        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(content_type.starts_with("text/html"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.windows(6).any(|window| window == b"SIPhon"));
    }

    #[cfg(feature = "ui")]
    #[tokio::test]
    async fn ui_absent_when_disabled() {
        // Feature is on but the operator left admin.ui.enabled off.
        let app = router(test_state(), None, false);

        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
