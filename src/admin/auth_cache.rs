//! `POST /admin/auth/cache/invalidate` — drop credential-cache entries.
//!
//! What lets a deployment keep a long `cache_ttl_secs` and still have a
//! password reset or a removed user take effect at once: the controller that
//! writes the credential calls this as it writes.

use axum::body::Bytes;
use serde::Deserialize;

use super::*;
use crate::auth::credential_cache::Invalidation;

/// The request body. Every field is optional; an unknown one is refused so a
/// misspelt `user` cannot quietly widen a one-user flush into a flush of all.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidateRequest {
    realm: Option<String>,
    username: Option<String>,
}

/// `{"realm","username"}` drops one user, `{"realm"}` one realm, `{}` (or no
/// body) everything. 204 on success, 404 when this node caches no credentials,
/// 400 for a body that names a username without its realm or does not parse.
pub(super) async fn auth_cache_invalidate_handler(
    State(state): State<AdminState>,
    body: Bytes,
) -> Response {
    let scope = match invalidation_scope(&body) {
        Ok(scope) => scope,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response();
        }
    };
    let Some(cache) = state.credential_cache.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no credential cache" })),
        )
            .into_response();
    };
    let removed = cache.invalidate(&scope);
    info!(?scope, removed, "admin: credential cache invalidated");
    StatusCode::NO_CONTENT.into_response()
}

/// Read the body into what to drop. An empty body is `{}`.
fn invalidation_scope(body: &[u8]) -> Result<Invalidation, String> {
    let request = if body.iter().all(u8::is_ascii_whitespace) {
        InvalidateRequest::default()
    } else {
        serde_json::from_slice::<InvalidateRequest>(body)
            .map_err(|error| format!("invalid body: {error}"))?
    };
    match (request.realm, request.username) {
        (Some(realm), Some(username)) => Ok(Invalidation::User { realm, username }),
        (Some(realm), None) => Ok(Invalidation::Realm(realm)),
        (None, None) => Ok(Invalidation::All),
        (None, Some(_)) => Err(
            "a username needs its realm: the same username in two realms is two users".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credential_cache::{CredentialCache, CredentialKey};
    use axum::body::Body;
    use tower::util::ServiceExt;

    fn populated() -> Arc<CredentialCache> {
        let cache = Arc::new(CredentialCache::new());
        for (realm, username) in [
            ("a.example.com", "1001"),
            ("a.example.com", "1002"),
            ("b.example.com", "1001"),
        ] {
            cache.store(&CredentialKey::new(realm, username, None), "hash");
        }
        cache
    }

    fn state(cache: Option<Arc<CredentialCache>>, token: Option<&str>) -> AdminState {
        AdminState {
            credential_cache: cache,
            auth_token: token.map(Arc::from),
            ..tests_state()
        }
    }

    fn tests_state() -> AdminState {
        AdminState {
            registrar: Arc::new(Registrar::new(crate::registrar::RegistrarConfig::default())),
            start_time: Instant::now(),
            draining: None,
            auth_token: None,
            protect_reads: false,
            instance_id: None,
            features: AdminFeatures::default(),
            script_engine: None,
            script_config: None,
            config_reloader: None,
            credential_cache: None,
            ui_enabled: false,
        }
    }

    async fn post(state: AdminState, body: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut request = axum::http::Request::post("/admin/auth/cache/invalidate")
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router(state, None, false)
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn invalidates_one_user() {
        let cache = populated();
        let (status, _) = post(
            state(Some(Arc::clone(&cache)), None),
            r#"{"realm":"a.example.com","username":"1001"}"#,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(cache.len(), 2);
        assert!(cache
            .get(&CredentialKey::new("a.example.com", "1001", None), 300)
            .is_none());
        assert!(cache
            .get(&CredentialKey::new("b.example.com", "1001", None), 300)
            .is_some());
    }

    #[tokio::test]
    async fn invalidates_one_realm() {
        let cache = populated();
        let (status, _) = post(
            state(Some(Arc::clone(&cache)), None),
            r#"{"realm":"a.example.com"}"#,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn invalidates_everything_with_an_empty_object_or_no_body() {
        for body in ["{}", ""] {
            let cache = populated();
            let (status, _) = post(state(Some(Arc::clone(&cache)), None), body, None).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "body {body:?}");
            assert!(cache.is_empty(), "body {body:?}");
        }
    }

    #[tokio::test]
    async fn not_found_when_caching_is_off() {
        let (status, body) = post(state(None, None), "{}", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "no credential cache");
    }

    #[tokio::test]
    async fn refuses_a_username_without_its_realm_and_flushes_nothing() {
        let cache = populated();
        let (status, _) = post(
            state(Some(Arc::clone(&cache)), None),
            r#"{"username":"1001"}"#,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(cache.len(), 3);
    }

    #[tokio::test]
    async fn refuses_an_unknown_field_rather_than_flushing_everything() {
        let cache = populated();
        let (status, _) = post(
            state(Some(Arc::clone(&cache)), None),
            r#"{"realm":"a.example.com","user":"1001"}"#,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(cache.len(), 3);
    }

    #[tokio::test]
    async fn requires_the_bearer_token_like_every_mutating_route() {
        let cache = populated();
        let (status, _) = post(state(Some(Arc::clone(&cache)), Some("secret")), "{}", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = post(
            state(Some(Arc::clone(&cache)), Some("secret")),
            "{}",
            Some("wrong"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(cache.len(), 3, "an unauthenticated call flushes nothing");

        let (status, _) = post(
            state(Some(Arc::clone(&cache)), Some("secret")),
            "{}",
            Some("secret"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(cache.is_empty());
    }
}
