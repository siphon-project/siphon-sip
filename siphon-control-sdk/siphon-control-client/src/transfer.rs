//! Transfers that name how their new leg is dialled.
//!
//! [`Call::accept_refer`] and [`Call::replace_peer`] dial a URI and present the
//! identity the call already carried. These are the same two verbs with the
//! rest of what the server takes: a target named by its registered AoR, reached
//! over the flow its phone registered on, and the identity arguments
//! [`Call::dial`] takes. Split from [`sip`](crate::sip), which is at its size
//! budget.
//!
//! Also the transfer the application carries out itself:
//! [`Call::accept_refer_controller`] has the server answer the REFER and dial
//! nothing, and [`Call::complete_refer`] reports how it went.

use serde_json::json;

use siphon_control_proto::sip::{SipEvent, SipVerb, TransferTimedOutPayload};

use crate::error::ControlError;
use crate::originate::OriginatePrivacy;
use crate::sip::{Call, CallEvent};

/// Who a transfer's new leg is dialled at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferTarget {
    /// A SIP URI, resolved as written.
    Uri(String),
    /// A registered address-of-record. The server dials its registered contact
    /// over the flow it registered on and through the Path of its binding —
    /// the only way to reach a phone on TCP, TLS or WebSocket behind NAT.
    ///
    /// Refused `not_found` when nobody is registered at it. One with several
    /// registered contacts rings them all: the first to answer is the party
    /// brought into the call, and the server CANCELs the rest.
    Aor(String),
}

impl TransferTarget {
    /// A target named by its URI.
    pub fn uri(uri: impl Into<String>) -> Self {
        TransferTarget::Uri(uri.into())
    }

    /// A target named by its registered AoR.
    pub fn aor(aor: impl Into<String>) -> Self {
        TransferTarget::Aor(aor.into())
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            TransferTarget::Uri(uri) => json!(uri),
            TransferTarget::Aor(aor) => json!({ "aor": aor }),
        }
    }
}

/// How a transfer's new leg is routed and what it presents.
///
/// Every field is optional; unset, the leg goes where its target resolves and
/// presents the identity the call's own INVITE carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferDial {
    /// Routing destination when it differs from the target (a trunk, an
    /// outbound proxy). Not for a [`TransferTarget::Aor`], which is reached
    /// over its own flow: the server refuses the two together.
    pub next_hop: Option<String>,
    /// The calling identity to present — the From URI (RFC 3261 §8.1.1.3).
    pub from: Option<String>,
    /// The From display name. An empty one removes the caller's.
    pub from_display: Option<String>,
    /// `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1).
    pub p_asserted_identity: Option<String>,
    /// Whether the calling identity may be presented (RFC 3323 §4.1).
    pub privacy: Option<OriginatePrivacy>,
    /// The name of a number policy configured on the server, which decides how
    /// the numbers in the new leg's identity headers are written. Unset, the
    /// server's default for the calls it dials applies. Not together with
    /// [`format`](Self::format): the server refuses the two.
    pub number_policy: Option<String>,
    /// One number format for the new leg's identity headers, in place of a
    /// named policy: `"e164"`, `"plain"`, `"international"` or `"national"`.
    pub format: Option<String>,
    /// Headers for the new leg's INVITE, injected after the header policy.
    pub headers: Vec<(String, String)>,
}

impl TransferDial {
    fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        for (name, value) in [
            ("next_hop", &self.next_hop),
            ("from", &self.from),
            ("from_display", &self.from_display),
            ("p_asserted_identity", &self.p_asserted_identity),
            ("number_policy", &self.number_policy),
            ("format", &self.format),
        ] {
            if let Some(value) = value {
                args.insert(name.to_string(), json!(value));
            }
        }
        if let Some(privacy) = self.privacy {
            args.insert("privacy".to_string(), json!(privacy.as_str()));
        }
        if !self.headers.is_empty() {
            let headers: serde_json::Map<String, serde_json::Value> = self
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), json!(value)))
                .collect();
            args.insert("headers".to_string(), serde_json::Value::Object(headers));
        }
    }
}

impl Call {
    /// [`Call::accept_refer`], naming who the transfer dials and how.
    ///
    /// `target` overrides the Refer-To; `None` dials what the referrer named.
    /// `dial`'s fields apply to a siphon-terminated transfer, which is the
    /// one that dials a leg: the server refuses them with `mode`
    /// `"transparent"`, which relays the REFER and dials nothing.
    pub async fn accept_refer_dialling(
        &self,
        target: Option<&TransferTarget>,
        mode: Option<&str>,
        profile: Option<&str>,
        dial: &TransferDial,
    ) -> Result<(), ControlError> {
        let mut args = serde_json::Map::new();
        if let Some(target) = target {
            args.insert("target".to_string(), target.to_json());
        }
        if let Some(mode) = mode {
            args.insert("mode".to_string(), json!(mode));
        }
        if let Some(profile) = profile {
            args.insert("profile".to_string(), json!(profile));
        }
        dial.insert_into(&mut args);
        self.sip(SipVerb::AcceptRefer, serde_json::Value::Object(args))
            .await
            .map(drop)
    }

    /// Accept a pending inbound REFER for this application to carry out.
    ///
    /// The server answers `202 Accepted`, sends the referrer the first sipfrag
    /// NOTIFY (`100 Trying`) and dials nothing. Move the parties with the other
    /// verbs — [`Call::bridge`], [`Call::unbridge`], [`Call::replace_peer`],
    /// [`Call::dial`] — and then report with [`Call::complete_refer`].
    ///
    /// `timeout` is how many seconds there are to report in (default 60, at
    /// most 180). Past it the server reports `503` to the referrer itself,
    /// tells this application with [`SipEvent::TransferTimedOut`]
    /// ([`CallEvent::transfer_timed_out`]), and refuses a later
    /// [`Call::complete_refer`]. Until the report, a further REFER on the call
    /// is answered `491 Request Pending`.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::Call;
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// call.accept_refer_controller(Some(30)).await?;
    /// // ... bridge the parties that remain ...
    /// call.complete_refer(200, None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept_refer_controller(&self, timeout: Option<u32>) -> Result<(), ControlError> {
        self.sip(SipVerb::AcceptRefer, accept_refer_controller_args(timeout))
            .await
            .map(drop)
    }

    /// Report how a transfer accepted with [`Call::accept_refer_controller`]
    /// went.
    ///
    /// The server sends the referrer the sipfrag NOTIFY that ends its
    /// subscription: `code` is the status in it (200-699), a 2xx for a transfer
    /// that succeeded, and `reason` its reason phrase, used as given. Nothing
    /// else happens to the call.
    ///
    /// **Report before releasing the referrer's leg.** The NOTIFY travels on
    /// its dialog, so once that leg is hung up or replaced there is nothing to
    /// send it in, and this resolves to `ControlErrorCode::NotFound`.
    ///
    /// Resolves to [`ControlError::Command`] with
    /// `ControlErrorCode::InvalidState` (`details.reason` is
    /// `no_transfer_pending`) when the call has no such transfer open: already
    /// reported, past its deadline, or its referrer hung up.
    pub async fn complete_refer(
        &self,
        code: u16,
        reason: Option<&str>,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::CompleteRefer, complete_refer_args(code, reason))
            .await
            .map(drop)
    }

    /// [`Call::replace_peer`], naming who the replacement dials and how.
    pub async fn replace_peer_dialling(
        &self,
        target: &TransferTarget,
        replace_a_leg: Option<bool>,
        profile: Option<&str>,
        timeout: Option<u32>,
        dial: &TransferDial,
    ) -> Result<serde_json::Value, ControlError> {
        let mut args = serde_json::Map::new();
        args.insert("target".to_string(), target.to_json());
        if let Some(replace_a_leg) = replace_a_leg {
            args.insert("replace_a_leg".to_string(), json!(replace_a_leg));
        }
        if let Some(profile) = profile {
            args.insert("profile".to_string(), json!(profile));
        }
        if let Some(timeout) = timeout {
            args.insert("timeout".to_string(), json!(timeout));
        }
        dial.insert_into(&mut args);
        self.sip(SipVerb::ReplacePeer, serde_json::Value::Object(args))
            .await
    }
}

impl CallEvent {
    /// The typed [`TransferTimedOutPayload`] when this is a
    /// [`SipEvent::TransferTimedOut`] event, else `None`.
    ///
    /// A transfer accepted with [`Call::accept_refer_controller`] passed its
    /// deadline with no [`Call::complete_refer`]: the server has told the
    /// referrer the transfer failed, and there is nothing left to report on.
    pub fn transfer_timed_out(&self) -> Option<TransferTimedOutPayload> {
        if self.kind != SipEvent::TransferTimedOut {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }
}

/// The `accept_refer` arguments of a transfer the application carries out:
/// the mode, and the timeout only when one is given, so the server's default
/// applies otherwise.
fn accept_refer_controller_args(timeout: Option<u32>) -> serde_json::Value {
    match timeout {
        Some(timeout) => json!({ "mode": "controller", "timeout": timeout }),
        None => json!({ "mode": "controller" }),
    }
}

/// The `complete_refer` arguments: the reason only when one is given, so the
/// server's phrase for the status applies otherwise.
fn complete_refer_args(code: u16, reason: Option<&str>) -> serde_json::Value {
    match reason {
        Some(reason) => json!({ "code": code, "reason": reason }),
        None => json!({ "code": code }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_controller_accept_names_its_mode_and_only_a_given_timeout() {
        assert_eq!(
            accept_refer_controller_args(None),
            json!({ "mode": "controller" })
        );
        assert_eq!(
            accept_refer_controller_args(Some(90)),
            json!({ "mode": "controller", "timeout": 90 })
        );
    }

    #[test]
    fn a_missed_report_deadline_parses_from_its_frame() {
        let frame = |event: &str, payload: serde_json::Value| {
            let frame = siphon_control_proto::EventFrame::new(
                event,
                "ch1",
                "ivr-app",
                "call-uuid",
                "sip@host",
                payload,
            );
            CallEvent {
                kind: frame.sip_kind(),
                payload: frame.payload.clone(),
                frame,
            }
        };
        let timed_out = frame(
            "TransferTimedOut",
            json!({ "reason": "timeout", "code": 503, "referrer_leg": "a" }),
        );
        assert_eq!(timed_out.kind, SipEvent::TransferTimedOut);
        let payload = timed_out.transfer_timed_out().expect("timeout payload");
        assert_eq!(payload.reason, "timeout");
        assert_eq!(payload.code, Some(503));
        assert_eq!(payload.referrer_leg.as_deref(), Some("a"));
        // An outbound REFER's verdict is another event altogether.
        assert!(timed_out.transfer_outcome().is_none());
        assert!(!timed_out.is_transfer_final());
        let other = frame(
            "TransferRequested",
            json!({ "refer_to": "sip:x@example.com" }),
        );
        assert!(other.transfer_timed_out().is_none());
    }

    #[test]
    fn a_report_names_its_status_and_only_a_given_reason() {
        assert_eq!(complete_refer_args(200, None), json!({ "code": 200 }));
        assert_eq!(
            complete_refer_args(486, Some("Busy Here")),
            json!({ "code": 486, "reason": "Busy Here" })
        );
    }

    fn args_of(dial: &TransferDial) -> serde_json::Value {
        let mut args = serde_json::Map::new();
        dial.insert_into(&mut args);
        serde_json::Value::Object(args)
    }

    #[test]
    fn a_target_is_a_uri_string_or_an_aor_object() {
        assert_eq!(
            TransferTarget::uri("sip:204@198.51.100.7").to_json(),
            json!("sip:204@198.51.100.7")
        );
        assert_eq!(
            TransferTarget::aor("sip:204@example.com").to_json(),
            json!({ "aor": "sip:204@example.com" })
        );
    }

    #[test]
    fn only_what_is_named_goes_on_the_wire() {
        assert_eq!(args_of(&TransferDial::default()), json!({}));
        let dial = TransferDial {
            next_hop: Some("sip:edge.example.com".to_string()),
            from: Some("sip:+15550100000@trunk.example.com".to_string()),
            from_display: Some(String::new()),
            p_asserted_identity: Some("sip:+15550100000@trunk.example.com".to_string()),
            privacy: Some(OriginatePrivacy::Restricted),
            number_policy: None,
            format: None,
            headers: vec![("X-Account".to_string(), "main".to_string())],
        };
        assert_eq!(
            args_of(&dial),
            json!({
                "next_hop": "sip:edge.example.com",
                "from": "sip:+15550100000@trunk.example.com",
                "from_display": "",
                "p_asserted_identity": "sip:+15550100000@trunk.example.com",
                "privacy": "restricted",
                "headers": { "X-Account": "main" }
            })
        );
    }

    /// How the new leg's numbers are written goes out under the names the
    /// server reads: a named policy, or one format.
    #[test]
    fn a_transfer_names_a_number_policy_or_a_format() {
        let named = TransferDial {
            number_policy: Some("carrier_e164".to_string()),
            ..Default::default()
        };
        assert_eq!(args_of(&named), json!({ "number_policy": "carrier_e164" }));
        let inline = TransferDial {
            format: Some("national".to_string()),
            ..Default::default()
        };
        assert_eq!(args_of(&inline), json!({ "format": "national" }));
    }
}
