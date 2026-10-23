//! `GET /admin/rate-limit/bans`: the sources `security.rate_limit` has banned,
//! each with the seconds left on its ban.
//!
//! Apart from `GET /admin/bans`, which lists the `failed_auth_ban` store: the
//! two bans differ in what raised them, in whether they slide and in whether
//! the kernel enforces them, and an operator looking for the peer that went
//! quiet needs to know which of the two holds it.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

use crate::security::SecurityFilter;

pub(super) async fn rate_limit_bans_handler() -> Response {
    rate_limit_bans_response(crate::security::security_filter().map(|filter| filter.as_ref()))
}

/// 404 when `rate_limit` is not in force, so an empty list always means
/// "limiting, nothing banned" and never "not limiting at all".
fn rate_limit_bans_response(filter: Option<&SecurityFilter>) -> Response {
    let Some(filter) = filter.filter(|filter| filter.rate_limit_enabled()) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "rate limit not enabled",
                "detail": "set security.rate_limit in siphon.yaml",
            })),
        )
            .into_response();
    };
    let entries: Vec<serde_json::Value> = filter
        .rate_limit_banned_sources()
        .into_iter()
        .map(|(address, remaining)| {
            serde_json::json!({
                "ip": address.to_string(),
                "expires_remaining": remaining,
            })
        })
        .collect();
    Json(entries).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (status, serde_json::from_slice(&bytes).expect("a JSON body"))
    }

    fn filter(yaml: &str) -> std::sync::Arc<SecurityFilter> {
        let config: crate::config::SecurityConfig =
            crate::config::yaml::from_str(yaml).expect("a security section");
        SecurityFilter::from_config(&config).expect("a filter")
    }

    #[tokio::test]
    async fn lists_the_banned_source_with_its_remaining_time() {
        let filter =
            filter("rate_limit: { window_secs: 10, max_requests: 1, ban_duration_secs: 300 }\n");
        let source: std::net::IpAddr = "203.0.113.60".parse().expect("an address");
        filter.evaluate(source, None);
        filter.evaluate(source, None);

        let (status, json) = body(rate_limit_bans_response(Some(&filter))).await;
        assert_eq!(status, StatusCode::OK);
        let entries = json.as_array().expect("a list");
        assert_eq!(entries.len(), 1, "{json}");
        assert_eq!(entries[0]["ip"], "203.0.113.60");
        let remaining = entries[0]["expires_remaining"].as_u64().expect("seconds");
        assert!((298..=300).contains(&remaining), "{remaining}");
    }

    #[tokio::test]
    async fn not_found_unless_the_rate_limit_is_in_force() {
        let (status, _) = body(rate_limit_bans_response(None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A filter installed for scanner_block alone is not limiting rates.
        let scanner_only = filter("scanner_block: { user_agents: [friendly-scanner] }\n");
        let (status, _) = body(rate_limit_bans_response(Some(&scanner_only))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
