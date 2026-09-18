//! Re-reading a `registrant.backend` / `gateway.backend` source on demand.
//!
//! What makes each source's `refresh_secs` a floor rather than the mechanism: a
//! controller that has just saved a trunk or a carrier calls these and the
//! change is live, instead of landing up to an interval later.

use super::*;

/// `POST /admin/registrants/refresh` — re-read the configured registrant source
/// and reconcile now, rather than waiting out `refresh_secs`.
///
/// What makes the poll interval a floor rather than the mechanism: a controller
/// that has just saved a trunk calls this and the change is live, instead of
/// landing up to an interval later.
pub(super) async fn registrants_refresh_handler() -> Response {
    let (Some(source), Some(manager)) = (
        crate::registrant::source::configured_source(),
        crate::registrant::manager(),
    ) else {
        return source_not_configured("registrant.backend");
    };

    match crate::registrant::source::reconcile_once(manager, source).await {
        Ok(report) => {
            info!(
                added = report.added,
                updated = report.updated,
                removed = report.removed,
                rejected = report.rejected,
                "admin: registrant source refreshed"
            );
            refresh_response(
                report.added,
                report.updated,
                report.removed,
                report.rejected,
            )
        }
        Err(error) => source_unreadable("registrant", &error),
    }
}

/// `POST /admin/gateways/refresh` — the same for the gateway source.
pub(super) async fn gateways_refresh_handler() -> Response {
    let (Some(source), Some(manager)) = (
        crate::gateway::source::configured_source(),
        crate::script::api::gateway_manager(),
    ) else {
        return source_not_configured("gateway.backend");
    };

    match crate::gateway::source::reconcile_once(manager, source).await {
        Ok(report) => {
            info!(
                added = report.added,
                updated = report.updated,
                removed = report.removed,
                rejected = report.rejected,
                "admin: gateway source refreshed"
            );
            refresh_response(
                report.added,
                report.updated,
                report.removed,
                report.rejected,
            )
        }
        Err(error) => source_unreadable("gateway", &error),
    }
}

/// What a reconcile pass did, for the caller that asked for it.
fn refresh_response(added: usize, updated: usize, removed: usize, rejected: usize) -> Response {
    Json(serde_json::json!({
        "refreshed": true,
        "added": added,
        "updated": updated,
        "removed": removed,
        "rejected": rejected,
    }))
    .into_response()
}

/// `501` when this node reads no source at all: nothing failed, there is simply
/// nothing to refresh, and reporting it as an error would have a controller
/// retrying forever.
fn source_not_configured(setting: &str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "refreshed": false,
            "error": format!("{setting} is static on this node — there is no source to re-read"),
        })),
    )
        .into_response()
}

/// `502` when the source itself could not be read. The live set is unchanged:
/// reconciling an unreadable source to "nothing" would tear the estate down.
fn source_unreadable(which: &str, error: &str) -> Response {
    warn!(%which, %error, "admin: source refresh failed; keeping the current set");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({
            "refreshed": false,
            "error": error,
            "detail": "the current set is unchanged",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refresh_body_reports_what_the_pass_did() {
        let response = refresh_response(2, 1, 3, 0);
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn an_unreadable_source_says_the_current_set_is_unchanged() {
        // The caller has to be able to tell "I could not read it" from "I read
        // it and everything is gone", because the second would be a teardown.
        let response = source_unreadable("registrant", "connection refused");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
