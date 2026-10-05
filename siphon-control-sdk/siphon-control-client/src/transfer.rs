//! Transfers that name how their new leg is dialled.
//!
//! [`Call::accept_refer`] and [`Call::replace_peer`] dial a URI and present the
//! identity the call already carried. These are the same two verbs with the
//! rest of what the server takes: a target named by its registered AoR, reached
//! over the flow its phone registered on, and the identity arguments
//! [`Call::dial`] takes. Split from [`sip`](crate::sip), which is at its size
//! budget.

use serde_json::json;

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::originate::OriginatePrivacy;
use crate::sip::Call;

/// Who a transfer's new leg is dialled at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferTarget {
    /// A SIP URI, resolved as written.
    Uri(String),
    /// A registered address-of-record. The server dials its registered contact
    /// over the flow it registered on and through the Path of its binding —
    /// the only way to reach a phone on TCP, TLS or WebSocket behind NAT.
    ///
    /// Refused `not_found` when nobody is registered at it, and `invalid_state`
    /// (`details.reason == "several_contacts"`) when several contacts are: a
    /// transfer rings one target.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
