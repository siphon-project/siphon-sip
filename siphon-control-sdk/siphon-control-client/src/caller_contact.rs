//! The caller side of `contact_host`: `answer`, `ring` and `progress` naming
//! the host of siphon's own Contact toward the caller, and `route` naming it as
//! `caller_contact_host` (a [`crate::sip::DialOptions`] field for `dial`), and
//! the same for `contact_user`, the user part of that Contact.
//!
//! Split from [`sip`](crate::sip) for the reason [`dial`](crate::dial) is: that
//! file is at its size budget.

use serde_json::json;

use siphon_control_proto::media_flags::MediaFlags;
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
    /// User part of siphon's own Contact toward the caller, which is otherwise
    /// userless (`<sip:trunk-7@sbc.example.net:5061;transport=tls>`), for a
    /// peer that identifies the trunk or account by it. An RFC 3261 SIP URI
    /// user; the server refuses an empty or invalid one with `bad_request`.
    /// Fixed as [`ResponseOptions::contact_host`] is once the caller has been
    /// sent an 18x or 2xx: the same user again is accepted, another is
    /// `invalid_state`.
    pub contact_user: Option<String>,
    /// Per-call overrides of the anchored response's media profile (its
    /// answer half), for this call only. Implies `anchor` server-side; see
    /// [`MediaFlags`].
    pub media_flags: Option<MediaFlags>,
}

impl ResponseOptions {
    /// Present this user part in siphon's Contact toward the caller.
    pub fn contact_user(mut self, user: impl Into<String>) -> Self {
        self.contact_user = Some(user.into());
        self
    }

    /// Present this host in siphon's Contact toward the caller.
    pub fn contact_host(mut self, host: impl Into<String>) -> Self {
        self.contact_host = Some(host.into());
        self
    }

    /// Anchor with these overrides of the profile's processing settings.
    pub fn media_flags(mut self, flags: MediaFlags) -> Self {
        self.media_flags = Some(flags);
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
            ("contact_user", &self.contact_user),
        ] {
            if let Some(value) = value {
                args.insert(name.to_string(), json!(value));
            }
        }
        if let Some(flags) = &self.media_flags {
            args.insert("media_flags".to_string(), flags.to_json());
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
        self.ring_with_caller_contact(reason, &CallerContact::default().host(contact_host))
            .await
    }

    /// [`Call::ring`] presenting `contact` (a host, a user part, or both) in
    /// siphon's Contact toward the caller, with an optional reason phrase.
    /// Each part left unset is not sent.
    pub async fn ring_with_caller_contact(
        &self,
        reason: Option<&str>,
        contact: &CallerContact,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Ring, ring_args(reason, contact))
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
        self.route_with_caller_contact(
            targets,
            strategy,
            headers,
            &CallerContact::default().host(caller_contact_host),
        )
        .await
    }

    /// [`Call::route`] naming `caller_contact_host` and / or
    /// `caller_contact_user`, the host and user part of siphon's Contact
    /// toward the caller on the answer the route relays it. Each target's own
    /// `contact_host` / `contact_user` is what its attempt presents the
    /// carrier.
    pub async fn route_with_caller_contact(
        &self,
        targets: Vec<RouteTarget>,
        strategy: Option<&str>,
        headers: Vec<(String, String)>,
        caller_contact: &CallerContact,
    ) -> Result<serde_json::Value, ControlError> {
        self.sip(
            SipVerb::Route,
            route_args(&targets, strategy, &headers, caller_contact),
        )
        .await
    }
}

/// The parts of siphon's own Contact toward the caller a `ring` or `route`
/// names: its host, its user part (otherwise userless), or both. Each part
/// left `None` is not sent, so the server keeps its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerContact {
    /// Host of the Contact; see [`ResponseOptions::contact_host`].
    pub host: Option<String>,
    /// User part of the Contact; see [`ResponseOptions::contact_user`].
    pub user: Option<String>,
}

impl CallerContact {
    /// Present this host.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Present this user part.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
}

/// The `ring` arguments carrying the caller's Contact parts that were named.
fn ring_args(reason: Option<&str>, contact: &CallerContact) -> serde_json::Value {
    let mut args = json!({});
    if let Some(reason) = reason {
        args["reason"] = json!(reason);
    }
    if let Some(host) = &contact.host {
        args["contact_host"] = json!(host);
    }
    if let Some(user) = &contact.user {
        args["contact_user"] = json!(user);
    }
    args
}

/// The `route` arguments, `caller_contact_host` / `caller_contact_user` only
/// when named.
pub(crate) fn route_args(
    targets: &[RouteTarget],
    strategy: Option<&str>,
    headers: &[(String, String)],
    caller_contact: &CallerContact,
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
    if let Some(host) = &caller_contact.host {
        args["caller_contact_host"] = json!(host);
    }
    if let Some(user) = &caller_contact.user {
        args["caller_contact_user"] = json!(user);
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
    fn an_anchored_response_carries_its_media_flags() {
        let options = ResponseOptions {
            anchor: true,
            profile: Some("voice_ai".to_string()),
            ..ResponseOptions::default()
        }
        .media_flags(MediaFlags {
            echo_cancellation: Some(false),
            ..MediaFlags::default()
        });
        assert_eq!(
            options.to_json(),
            json!({
                "anchor": true,
                "profile": "voice_ai",
                "media_flags": { "echo_cancellation": false },
            })
        );
        assert!(ResponseOptions::default()
            .to_json()
            .get("media_flags")
            .is_none());
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
            ring_args(
                Some("Ringing"),
                &CallerContact::default().host("tenant-a.example.com")
            ),
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
                &CallerContact::default().host("tenant-a.example.com"),
            ),
            json!({
                "targets": ["sip:+15550100@carrier.example"],
                "caller_contact_host": "tenant-a.example.com",
            })
        );
        assert!(route_args(&[], None, &[], &CallerContact::default())
            .get("caller_contact_host")
            .is_none());
    }

    #[test]
    fn response_options_send_the_contact_user_alone_or_beside_the_host() {
        assert_eq!(
            ResponseOptions::default().contact_user("trunk-7").to_json(),
            json!({ "contact_user": "trunk-7" })
        );
        assert_eq!(
            ResponseOptions {
                code: Some(183),
                ..ResponseOptions::default()
            }
            .contact_host("sbc.example.net")
            .contact_user("trunk-7")
            .to_json(),
            json!({ "code": 183, "contact_host": "sbc.example.net", "contact_user": "trunk-7" })
        );
        assert!(ResponseOptions {
            anchor: true,
            ..ResponseOptions::default()
        }
        .to_json()
        .get("contact_user")
        .is_none());
    }

    #[test]
    fn a_ring_carries_the_contact_user_alone_or_beside_the_host() {
        assert_eq!(
            ring_args(None, &CallerContact::default().user("trunk-7")),
            json!({ "contact_user": "trunk-7" })
        );
        assert_eq!(
            ring_args(
                Some("Ringing"),
                &CallerContact::default()
                    .host("sbc.example.net")
                    .user("trunk-7")
            ),
            json!({ "reason": "Ringing", "contact_host": "sbc.example.net", "contact_user": "trunk-7" })
        );
        assert_eq!(ring_args(None, &CallerContact::default()), json!({}));
    }

    #[test]
    fn route_names_the_caller_contact_user_beside_the_targets() {
        assert_eq!(
            route_args(
                &[RouteTarget::uri("sip:+15550100@carrier.example")],
                None,
                &[],
                &CallerContact::default().user("trunk-7"),
            ),
            json!({
                "targets": ["sip:+15550100@carrier.example"],
                "caller_contact_user": "trunk-7",
            })
        );
        assert_eq!(
            route_args(
                &[RouteTarget::uri("sip:+15550100@carrier.example")],
                None,
                &[],
                &CallerContact::default()
                    .host("sbc.example.net")
                    .user("trunk-7"),
            ),
            json!({
                "targets": ["sip:+15550100@carrier.example"],
                "caller_contact_host": "sbc.example.net",
                "caller_contact_user": "trunk-7",
            })
        );
        assert!(route_args(&[], None, &[], &CallerContact::default())
            .get("caller_contact_user")
            .is_none());
    }
}
