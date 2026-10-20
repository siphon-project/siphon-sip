//! `POST /admin/config/reload`: read the `--config` file again and apply what
//! can change at runtime.
//!
//! The reloader itself lives in [`crate::server::config_reload`]; this is its
//! HTTP face. Gated on the admin bearer token like every mutating route.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use tracing::error;

use super::AdminState;
use crate::server::config_reload::ConfigReloadError;

/// `POST /admin/config/reload` — re-read, validate and apply the config file.
///
/// - `200` with the per-section report when the file validated. Sections that
///   changed only in fields needing a restart say so and name the fields.
/// - `422` when the file does not read, parse or validate, or a value could
///   not be built from it: `{"error", "detail": "nothing was changed"}`.
/// - `501` when the node was started from a config string, with no file.
pub(super) async fn config_reload_handler(State(state): State<AdminState>) -> Response {
    let Some(ref reloader) = state.config_reloader else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "this node was not started from a config file, so there is nothing to reload",
            })),
        )
            .into_response();
    };
    match reloader.reload().await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(reload_error) => {
            let detail = reload_error.to_string();
            error!(%detail, "admin: config reload refused; nothing was changed");
            let status = match reload_error {
                ConfigReloadError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ConfigReloadError::Invalid(_) | ConfigReloadError::Build { .. } => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
            };
            (
                status,
                Json(serde_json::json!({
                    "error": detail,
                    "detail": "nothing was changed",
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::util::ServiceExt;

    use super::super::{router, AdminFeatures};
    use super::*;
    use crate::config::{Config, IdentityHeaders, SharedIdentityHeaders};
    use crate::server::config_reload::{ConfigReloader, ReloadTargets};

    const TOKEN: &str = "reload-token";

    fn config_file(server_header: &str, extra: &str) -> String {
        format!(
            concat!(
                "listen:\n",
                "  udp: [\"0.0.0.0:5060\"]\n",
                "domain:\n",
                "  local: [\"example.com\"]\n",
                "server:\n",
                "  server_header: \"{server_header}\"\n",
                "{extra}",
            ),
            server_header = server_header,
            extra = extra,
        )
    }

    struct Node {
        _directory: tempfile::TempDir,
        path: std::path::PathBuf,
        identity: SharedIdentityHeaders,
        state: AdminState,
    }

    /// An admin API over a node started from a file, its token `auth_token`.
    fn node(auth_token: Option<&str>) -> Node {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("siphon.yaml");
        std::fs::write(&path, config_file("edge-a", "")).expect("write the config");
        let (config, baseline) = Config::load_with_document(&path).expect("loads");
        let identity = IdentityHeaders::resolve(config.server.as_ref(), "SIPhon", "9.9.9").shared();
        let reloader = ConfigReloader::new(
            path.clone(),
            baseline,
            ReloadTargets::new(Arc::clone(&identity), "SIPhon", "9.9.9"),
        );
        let state = AdminState {
            registrar: Arc::new(crate::registrar::Registrar::new(
                crate::registrar::RegistrarConfig::default(),
            )),
            start_time: std::time::Instant::now(),
            draining: None,
            auth_token: auth_token.map(Arc::from),
            protect_reads: false,
            instance_id: None,
            features: AdminFeatures::default(),
            script_engine: None,
            script_config: None,
            config_reloader: Some(Arc::new(reloader)),
            credential_cache: None,
            ui_enabled: false,
        };
        Node {
            _directory: directory,
            path,
            identity,
            state,
        }
    }

    /// `POST /admin/config/reload` through the router, auth layer included.
    async fn post_reload(
        state: AdminState,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::post("/admin/config/reload");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router(state, None, false)
            .oneshot(request.body(Body::empty()).expect("a request"))
            .await
            .expect("the router answers");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn a_valid_file_is_applied_and_reported() {
        let node = node(Some(TOKEN));
        std::fs::write(&node.path, config_file("edge-b", "")).expect("rewrite");
        let (status, body) = post_reload(node.state.clone(), Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["sections"]["server"],
            serde_json::json!({
                "status": "applied",
                "applied": ["server.server_header"],
                "restart_required": [],
            })
        );
        assert_eq!(body["sections"]["listen"]["status"], "unchanged");
        assert_eq!(body["applied"], serde_json::json!(["server.server_header"]));
        assert_eq!(body["restart_required"], serde_json::json!([]));
        assert_eq!(body["warnings"], serde_json::json!([]));
        assert_eq!(node.identity.load().server.as_deref(), Some("edge-b"));
    }

    #[tokio::test]
    async fn an_invalid_file_is_422_and_changes_nothing() {
        let node = node(None);
        std::fs::write(
            &node.path,
            config_file("edge-b", "advertised_address: \"198.51.100.7:5070\"\n"),
        )
        .expect("rewrite");
        let (status, body) = post_reload(node.state.clone(), None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["detail"], "nothing was changed");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("advertised_address")),
            "{body}"
        );
        assert_eq!(node.identity.load().server.as_deref(), Some("edge-a"));
    }

    /// Mutating, so gated on the token like every other `POST`.
    #[tokio::test]
    async fn without_the_token_it_is_401_and_changes_nothing() {
        let node = node(Some(TOKEN));
        std::fs::write(&node.path, config_file("edge-b", "")).expect("rewrite");
        let (status, _) = post_reload(node.state.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = post_reload(node.state.clone(), Some("not-the-token")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(node.identity.load().server.as_deref(), Some("edge-a"));
    }

    /// A node started from a config string has no file to read again.
    #[tokio::test]
    async fn without_a_config_file_it_is_501() {
        let state = AdminState {
            config_reloader: None,
            credential_cache: None,
            ..node(None).state
        };
        let (status, body) = post_reload(state, None).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(body["error"].as_str().is_some(), "{body}");
    }
}
