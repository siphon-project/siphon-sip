//! The [`Call::route`](crate::sip::Call::route) target.
//!
//! Split from [`sip`](crate::sip) for the reason [`dial`](crate::dial) is: that
//! file is at its size budget.

use serde_json::json;

use crate::sip::headers_to_json;

/// One entry in a [`Call::route`](crate::sip::Call::route) target list: a B-leg
/// URI plus optional per-target overrides.
///
/// A bare URI (no overrides) serializes to a plain string on the wire; a target
/// carrying any override serializes to
/// `{uri, next_hop?, headers?, timeout?, reroute_after_progress?, route?, contact_host?,
/// verify_server?}` — both
/// shapes the server's `route` verb accepts. Build a bare-URI target with
/// [`RouteTarget::uri`], or from a `&str` / `String`, and set overrides with
/// struct-update syntax: `RouteTarget { timeout_secs: Some(6), ..RouteTarget::uri(uri) }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteTarget {
    /// The B-leg request URI to dial.
    pub uri: String,
    /// Route egress to this next hop instead of resolving `uri` (optional).
    pub next_hop: Option<String>,
    /// Headers injected on this attempt's B-leg INVITE (optional).
    pub headers: Vec<(String, String)>,
    /// Per-target ring timeout in seconds (optional). It bounds the wait for
    /// this carrier to show progress (a 101-199), not the wait for its answer.
    pub timeout_secs: Option<u32>,
    /// Fail this carrier over at its ring timeout even after it has shown
    /// progress.
    ///
    /// By default a carrier that has sent a 180/183 keeps the call past its
    /// timeout, and the call then fails with 408 rather than trying the next
    /// target. `true` is for a carrier that plays its own ringback before it has
    /// reached anyone. Default `false`, which is never sent.
    pub reroute_after_progress: bool,
    /// The route set this attempt's B-leg INVITE carries, topmost first, each
    /// entry one Route value in name-addr form (`"<sip:scscf.example;lr>"`,
    /// RFC 3261 §25.1).
    ///
    /// The INVITE goes to the topmost entry unless `next_hop` pins it. This is
    /// how a controller acting as an IMS application server continues a session
    /// through the S-CSCF with the Route the S-CSCF gave it (TS 24.229
    /// §5.7.5.2.1). `Route` is framework-managed on a B-leg, so it cannot ride
    /// `headers`. The server refuses an entry that is not exactly one Route
    /// value with `bad_request`. Empty (the default) sends no route set.
    pub route: Vec<String>,
    /// Host of siphon's own Contact on this attempt's leg, in place of the
    /// address siphon advertises, for a peer that identifies the tenant or
    /// account by that host. Only the host changes; see
    /// [`DialTarget::contact_host`](crate::DialTarget::contact_host). `None`
    /// (the default) presents the advertised host.
    pub contact_host: Option<String>,
    /// Verify (`Some(true)`) or not (`Some(false)`) the server certificate when
    /// this attempt opens a new outbound TLS connection, over the gateway it
    /// routes to and the server's `tls.verify_server`; see
    /// [`DialTarget::verify_server`](crate::DialTarget::verify_server). `None`
    /// (the default) leaves it to the server.
    pub verify_server: Option<bool>,
}

impl RouteTarget {
    /// A bare-URI target with no overrides.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            ..Self::default()
        }
    }

    /// True when this target carries no overrides (serializes as a bare string).
    fn is_bare(&self) -> bool {
        self.next_hop.is_none()
            && self.headers.is_empty()
            && self.timeout_secs.is_none()
            && !self.reroute_after_progress
            && self.route.is_empty()
            && self.contact_host.is_none()
            && self.verify_server.is_none()
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        if self.is_bare() {
            return json!(self.uri);
        }
        let mut object = serde_json::Map::new();
        object.insert("uri".to_string(), json!(self.uri));
        if let Some(next_hop) = &self.next_hop {
            object.insert("next_hop".to_string(), json!(next_hop));
        }
        if !self.headers.is_empty() {
            object.insert("headers".to_string(), headers_to_json(&self.headers));
        }
        if let Some(timeout) = self.timeout_secs {
            object.insert("timeout".to_string(), json!(timeout));
        }
        // Off is the server's default, so only `true` goes on the wire.
        if self.reroute_after_progress {
            object.insert("reroute_after_progress".to_string(), json!(true));
        }
        if !self.route.is_empty() {
            object.insert("route".to_string(), json!(self.route));
        }
        if let Some(contact_host) = &self.contact_host {
            object.insert("contact_host".to_string(), json!(contact_host));
        }
        if let Some(verify_server) = self.verify_server {
            object.insert("verify_server".to_string(), json!(verify_server));
        }
        serde_json::Value::Object(object)
    }
}

impl From<&str> for RouteTarget {
    fn from(uri: &str) -> Self {
        Self::uri(uri)
    }
}

impl From<String> for RouteTarget {
    fn from(uri: String) -> Self {
        Self::uri(uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_uri_is_a_plain_string() {
        assert_eq!(RouteTarget::uri("sip:gw").to_json(), json!("sip:gw"));
    }

    #[test]
    fn verify_server_goes_out_either_way_once_set() {
        for verify in [true, false] {
            let target = RouteTarget {
                verify_server: Some(verify),
                ..RouteTarget::uri("sip:+15550100@trunk.example.net;transport=tls")
            };
            assert_eq!(
                target.to_json(),
                json!({
                    "uri": "sip:+15550100@trunk.example.net;transport=tls",
                    "verify_server": verify
                })
            );
        }
    }

    #[test]
    fn a_route_set_goes_out_in_order_topmost_first() {
        let target = RouteTarget {
            route: vec![
                "<sip:term@scscf.example.test;lr;odi=4f1c>".to_string(),
                "<sip:edge.example.test;lr>".to_string(),
            ],
            ..RouteTarget::uri("sip:+15550100@ims.example.test")
        };
        assert_eq!(
            target.to_json(),
            json!({
                "uri": "sip:+15550100@ims.example.test",
                "route": [
                    "<sip:term@scscf.example.test;lr;odi=4f1c>",
                    "<sip:edge.example.test;lr>"
                ]
            })
        );
    }

    #[test]
    fn a_contact_host_goes_out_on_the_target() {
        let target = RouteTarget {
            contact_host: Some("tenant-a.example.com".to_string()),
            ..RouteTarget::uri("sip:+15550100@carrier.example")
        };
        assert_eq!(
            target.to_json(),
            json!({
                "uri": "sip:+15550100@carrier.example",
                "contact_host": "tenant-a.example.com"
            })
        );
    }

    #[test]
    fn a_route_set_rides_beside_a_pinned_next_hop() {
        let target = RouteTarget {
            next_hop: Some("sip:192.0.2.10:5060".to_string()),
            route: vec!["<sip:scscf.example.test;lr>".to_string()],
            ..RouteTarget::uri("sip:alice@ims.example.test")
        };
        assert_eq!(
            target.to_json(),
            json!({
                "uri": "sip:alice@ims.example.test",
                "next_hop": "sip:192.0.2.10:5060",
                "route": ["<sip:scscf.example.test;lr>"]
            })
        );
    }
}
