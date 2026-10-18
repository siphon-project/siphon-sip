//! The caller side of `contact_host`: `answer`, `ring` and `progress` naming
//! the host of siphon's own Contact toward the caller, and `route` naming it as
//! `caller_contact_host` (a [`crate::sip::DialOptions`] field for `dial`).
//!
//! Split from [`sip`](crate::sip) for the reason [`dial`](crate::dial) is: that
//! file is at its size budget.

use serde_json::json;

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::sip::{headers_to_json, Call, RouteTarget};

/// Shaping for [`Call::answer_with_options`] and [`Call::progress_with_options`];
/// every field left unset takes the server's own default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseOptions {
    /// Status code (`200` for an answer, `183` for progress server-side).
    pub code: Option<u16>,
    /// Reason phrase.
    pub reason: Option<String>,
    /// Body, e.g. an SDP answer or early-media offer.
    pub body: Option<String>,
    /// The body's `Content-Type`.
    pub content_type: Option<String>,
    /// Synthesize the SDP against the media engine and anchor the leg, as
    /// [`Call::answer_anchored`] does (implied by `profile` or `ws_uri`).
    pub anchor: bool,
    /// Media profile for an anchored response.
    pub profile: Option<String>,
    /// WebSocket bridge URI for an anchored response.
    pub ws_uri: Option<String>,
    /// Host of siphon's own Contact toward the caller, in place of the address
    /// siphon advertises, for a peer that identifies the tenant or account by
    /// that host. Only the host changes, and every later Contact siphon
    /// presents the caller carries it. It is fixed once the caller has been
    /// sent an 18x or 2xx: the same host again is accepted, another is
    /// `invalid_state`.
    pub contact_host: Option<String>,
}

impl ResponseOptions {
    /// Present this host in siphon's Contact toward the caller.
    pub fn contact_host(mut self, host: impl Into<String>) -> Self {
        self.contact_host = Some(host.into());
        self
    }

    fn to_json(&self) -> serde_json::Value {
        let mut args = serde_json::Map::new();
        if let Some(code) = self.code {
            args.insert("code".to_string(), json!(code));
        }
        if self.anchor {
            args.insert("anchor".to_string(), json!(true));
        }
        for (name, value) in [
            ("reason", &self.reason),
            ("body", &self.body),
            ("content_type", &self.content_type),
            ("profile", &self.profile),
            ("ws_uri", &self.ws_uri),
            ("contact_host", &self.contact_host),
        ] {
            if let Some(value) = value {
                args.insert(name.to_string(), json!(value));
            }
        }
        serde_json::Value::Object(args)
    }
}

impl Call {
    /// [`Call::answer_with`], with every option including the caller's
    /// `contact_host`.
    pub async fn answer_with_options(&self, options: &ResponseOptions) -> Result<(), ControlError> {
        self.sip(SipVerb::Answer, options.to_json()).await.map(drop)
    }

    /// [`Call::progress_with`], with every option including the caller's
    /// `contact_host`.
    pub async fn progress_with_options(
        &self,
        options: &ResponseOptions,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Progress, options.to_json())
            .await
            .map(drop)
    }

    /// [`Call::ring`] presenting `contact_host` in siphon's Contact toward the
    /// caller (see [`ResponseOptions::contact_host`]), with an optional reason
    /// phrase.
    pub async fn ring_with_contact_host(
        &self,
        reason: Option<&str>,
        contact_host: &str,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Ring, ring_args(reason, contact_host))
            .await
            .map(drop)
    }

    /// [`Call::route`] naming `caller_contact_host`, the host of siphon's
    /// Contact toward the caller on the answer the route relays it. Each
    /// target's own `contact_host` is the host its attempt presents the
    /// carrier.
    pub async fn route_with_caller_contact_host(
        &self,
        targets: Vec<RouteTarget>,
        strategy: Option<&str>,
        headers: Vec<(String, String)>,
        caller_contact_host: &str,
    ) -> Result<serde_json::Value, ControlError> {
        self.sip(
            SipVerb::Route,
            route_args(&targets, strategy, &headers, Some(caller_contact_host)),
        )
        .await
    }
}

/// The `ring` arguments carrying a caller `contact_host`.
fn ring_args(reason: Option<&str>, contact_host: &str) -> serde_json::Value {
    let mut args = json!({ "contact_host": contact_host });
    if let Some(reason) = reason {
        args["reason"] = json!(reason);
    }
    args
}

/// The `route` arguments, `caller_contact_host` only when named.
pub(crate) fn route_args(
    targets: &[RouteTarget],
    strategy: Option<&str>,
    headers: &[(String, String)],
    caller_contact_host: Option<&str>,
) -> serde_json::Value {
    let mut args = json!({
        "targets": targets.iter().map(RouteTarget::to_json).collect::<Vec<_>>(),
    });
    if let Some(strategy) = strategy {
        args["strategy"] = json!(strategy);
    }
    if !headers.is_empty() {
        args["headers"] = headers_to_json(headers);
    }
    if let Some(host) = caller_contact_host {
        args["caller_contact_host"] = json!(host);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_options_send_the_contact_host_only_when_named() {
        assert_eq!(ResponseOptions::default().to_json(), json!({}));
        assert_eq!(
            ResponseOptions {
                code: Some(183),
                body: Some("v=0\r\n".to_string()),
                content_type: Some("application/sdp".to_string()),
                ..ResponseOptions::default()
            }
            .contact_host("tenant-a.example.com")
            .to_json(),
            json!({
                "code": 183,
                "body": "v=0\r\n",
                "content_type": "application/sdp",
                "contact_host": "tenant-a.example.com",
            })
        );
    }

    #[test]
    fn an_anchored_answer_and_a_ring_carry_the_contact_host() {
        assert_eq!(
            ResponseOptions {
                anchor: true,
                profile: Some("voice_ai".to_string()),
                ..ResponseOptions::default()
            }
            .contact_host("2001:db8::5")
            .to_json(),
            json!({ "anchor": true, "profile": "voice_ai", "contact_host": "2001:db8::5" })
        );
        assert_eq!(
            ring_args(Some("Ringing"), "tenant-a.example.com"),
            json!({ "reason": "Ringing", "contact_host": "tenant-a.example.com" })
        );
    }

    #[test]
    fn route_names_the_caller_contact_host_beside_the_targets() {
        assert_eq!(
            route_args(
                &[RouteTarget::uri("sip:+15550100@carrier.example")],
                None,
                &[],
                Some("tenant-a.example.com"),
            ),
            json!({
                "targets": ["sip:+15550100@carrier.example"],
                "caller_contact_host": "tenant-a.example.com",
            })
        );
        assert!(route_args(&[], None, &[], None)
            .get("caller_contact_host")
            .is_none());
    }
}
