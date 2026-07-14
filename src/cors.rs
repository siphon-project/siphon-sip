//! CORS layer construction for SIPhon's browser-facing HTTP endpoints.
//!
//! Both the Prometheus `/metrics` listener and the admin API are plain axum
//! routers. A browser refuses to expose a cross-origin `fetch()` response to
//! page JavaScript unless the server sends an `Access-Control-Allow-Origin`
//! header matching the caller's origin. This module turns a [`CorsConfig`] into
//! a [`tower_http::cors::CorsLayer`] that both routers can `.layer(...)`.
//!
//! The layer also answers CORS preflight (`OPTIONS`) requests automatically, so
//! a dashboard that sends custom headers or hits the admin API's `DELETE`
//! routes works too — not just the simple `GET /metrics` case.

use axum::http::HeaderValue;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::warn;

use crate::config::CorsConfig;

/// Build a [`CorsLayer`] from a [`CorsConfig`], or `None` when CORS should stay
/// off (no origins configured, or every configured origin was unparseable).
///
/// - A single `"*"` origin (or any entry equal to `"*"`) allows any origin via
///   `Access-Control-Allow-Origin: *`.
/// - Otherwise each entry is parsed as an exact origin; invalid ones are
///   logged and skipped rather than failing the whole endpoint.
///
/// Methods and request headers are allowed wildcard: these endpoints carry no
/// cookies/credentials, so `Access-Control-Allow-Origin` never needs to be a
/// single credentialed origin, and a dashboard is free to send whatever headers
/// and methods (`GET`, the admin `DELETE`) it needs.
pub fn build_cors_layer(config: &CorsConfig) -> Option<CorsLayer> {
    if config.allowed_origins.is_empty() {
        return None;
    }

    let base = CorsLayer::new().allow_methods(Any).allow_headers(Any);

    if config.allowed_origins.iter().any(|origin| origin == "*") {
        return Some(base.allow_origin(Any));
    }

    let mut values: Vec<HeaderValue> = Vec::with_capacity(config.allowed_origins.len());
    for origin in &config.allowed_origins {
        match origin.parse::<HeaderValue>() {
            Ok(value) => values.push(value),
            Err(error) => {
                warn!(origin = %origin, "ignoring invalid CORS origin: {error}");
            }
        }
    }

    if values.is_empty() {
        return None;
    }
    Some(base.allow_origin(AllowOrigin::list(values)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_origins_disables_cors() {
        let config = CorsConfig {
            allowed_origins: vec![],
        };
        assert!(build_cors_layer(&config).is_none());
    }

    #[test]
    fn explicit_origins_build_a_layer() {
        let config = CorsConfig {
            allowed_origins: vec!["http://localhost:5173".to_owned()],
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn wildcard_origin_builds_a_layer() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_owned()],
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn all_invalid_origins_disable_cors() {
        // `HeaderValue` accepts visible ASCII (spaces included) but rejects
        // control characters, so an embedded newline is never parseable — the
        // only configured origin drops out and the layer collapses to None.
        let config = CorsConfig {
            allowed_origins: vec!["http://bad\norigin".to_owned()],
        };
        assert!(build_cors_layer(&config).is_none());
    }
}
