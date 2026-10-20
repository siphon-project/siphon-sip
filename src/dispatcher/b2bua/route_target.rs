//! One target of the `route` verb and the failover queue its targets become.
//!
//! Split from [`control`](super::control) to keep that file inside its size
//! budget; the `route` verb itself ([`b2bua_route_call`](super::control::b2bua_route_call)) stays there.

/// One routing target for [`b2bua_route_call`](super::control::b2bua_route_call). Built by the control adapter from
/// the `route` verb's `targets[]` — a bare URI (`ruri` only) or an object
/// carrying a per-target `next_hop` / `headers` / ring `timeout`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    /// The Request-URI for this carrier attempt.
    pub uri: String,
    /// Optional wire next-hop (steer egress without reshaping the R-URI).
    pub next_hop: Option<String>,
    /// Headers to inject on this attempt's B-leg INVITE.
    pub headers: Vec<(String, String)>,
    /// Per-attempt ring timeout (seconds); falls back to the call default.
    pub timeout_secs: Option<u32>,
    /// Fail this carrier over at its ring timeout even after it has shown
    /// progress. See [`crate::lcr::Route::reroute_after_progress`].
    pub reroute_after_progress: bool,
    /// Route set for this attempt's INVITE, topmost first. See
    /// [`crate::lcr::Route::route`].
    pub route: Vec<String>,
    /// Host siphon presents in its own `Contact` on this attempt's leg. See
    /// [`DialTarget::contact_host`](crate::dispatcher::DialTarget::contact_host).
    pub contact_host: Option<String>,
    /// User part of siphon's own `Contact` on this attempt ([`DialTarget::contact_user`](crate::dispatcher::DialTarget::contact_user)).
    pub contact_user: Option<String>,
    /// This attempt's server verification: see [`DialTarget::verify_server`](crate::dispatcher::DialTarget::verify_server).
    pub verify_server: Option<bool>,
}

/// The failover queue a `route` verb's targets become: R-URI carriers, as
/// `call.route()` gets them. The command's `extra_headers` apply to every
/// attempt, and a target's own header overrides one on a key collision.
///
/// These are carriers from an out-of-process routing decision, so the LCR rule
/// applies: a carrier that has shown progress keeps the call past its ring
/// timeout, unless its target sets `reroute_after_progress`.
pub(super) fn route_verb_routes(
    targets: Vec<RouteTarget>,
    extra_headers: &[(String, String)],
    default_timeout: u32,
) -> Vec<crate::lcr::Route> {
    targets
        .into_iter()
        .map(|target| {
            let mut headers: std::collections::HashMap<String, String> =
                extra_headers.iter().cloned().collect();
            headers.extend(target.headers);
            crate::lcr::Route {
                ruri: Some(target.uri),
                next_hop: target.next_hop,
                timeout_secs: Some(target.timeout_secs.unwrap_or(default_timeout)),
                headers,
                reroute_after_progress: target.reroute_after_progress,
                route: target.route,
                contact_host: target.contact_host,
                contact_user: target.contact_user,
                verify_server: target.verify_server,
                ..Default::default()
            }
        })
        .collect()
}
