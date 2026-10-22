//! Typed views over the application-level event payloads: the events an app
//! opts into with `control.apps[].events` (`registration`,
//! `outbound_registration`, `dialog`), which concern the deployment rather
//! than a channel, and the replies of the `registrations` /
//! `outbound_registrations` verbs that say what is held now.
//!
//! Re-exported from [`crate::sip`], where the SIP adapter's other payloads live.

use serde::{Deserialize, Serialize};

/// An RFC 4235 §3.7.1 dialog state — the `state` of a
/// [`DialogStateChangedPayload`].
///
/// Unrecognised tokens map to [`DialogState::Other`] rather than failing, so a
/// newer server never breaks an older client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum DialogState {
    /// The INVITE was sent or received and nothing has answered it.
    Trying,
    /// A provisional without a To-tag answered it.
    Proceeding,
    /// A provisional with a To-tag answered it: the phone is ringing.
    Early,
    /// A 2xx answered it: the phone is in a call.
    Confirmed,
    /// The dialog, or the attempt to set it up, is over.
    Terminated,
    /// Any other state token (forward-compatible catch-all).
    Other(String),
}

impl DialogState {
    /// The exact wire token.
    pub fn as_str(&self) -> &str {
        match self {
            DialogState::Trying => "trying",
            DialogState::Proceeding => "proceeding",
            DialogState::Early => "early",
            DialogState::Confirmed => "confirmed",
            DialogState::Terminated => "terminated",
            DialogState::Other(token) => token.as_str(),
        }
    }
}

impl From<&str> for DialogState {
    fn from(token: &str) -> Self {
        match token {
            "trying" => DialogState::Trying,
            "proceeding" => DialogState::Proceeding,
            "early" => DialogState::Early,
            "confirmed" => DialogState::Confirmed,
            "terminated" => DialogState::Terminated,
            other => DialogState::Other(other.to_string()),
        }
    }
}

impl From<String> for DialogState {
    fn from(token: String) -> Self {
        DialogState::from(token.as_str())
    }
}

impl From<DialogState> for String {
    fn from(state: DialogState) -> Self {
        state.as_str().to_string()
    }
}

/// Which end of the dialog the AoR is (RFC 4235 §4.1.1) — the `direction` of a
/// [`DialogStateChangedPayload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum DialogDirection {
    /// The AoR sent the INVITE: a call the phone placed.
    Initiator,
    /// The AoR received the INVITE: a call ringing the phone.
    Recipient,
    /// Any other direction token (forward-compatible catch-all).
    Other(String),
}

impl DialogDirection {
    /// The exact wire token.
    pub fn as_str(&self) -> &str {
        match self {
            DialogDirection::Initiator => "initiator",
            DialogDirection::Recipient => "recipient",
            DialogDirection::Other(token) => token.as_str(),
        }
    }
}

impl From<&str> for DialogDirection {
    fn from(token: &str) -> Self {
        match token {
            "initiator" => DialogDirection::Initiator,
            "recipient" => DialogDirection::Recipient,
            other => DialogDirection::Other(other.to_string()),
        }
    }
}

impl From<String> for DialogDirection {
    fn from(token: String) -> Self {
        DialogDirection::from(token.as_str())
    }
}

impl From<DialogDirection> for String {
    fn from(direction: DialogDirection) -> Self {
        direction.as_str().to_string()
    }
}

/// The party a registered AoR's dialog is with, as dialog-info renders
/// `<remote><identity>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogIdentity {
    /// The other party's URI, as presented on the phone's leg.
    #[serde(default)]
    pub uri: String,
    /// Its display name, when the header carried one.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// The `payload` of a [`SipEvent::DialogStateChanged`](crate::sip::SipEvent::DialogStateChanged) event: one dialog of a
/// registered AoR moved to a new RFC 4235 state, as the server observed it on
/// the wire. Everything is from the AoR's point of view, which is how
/// dialog-info renders it (RFC 4235 §4).
///
/// Each dialog reports its states in order and `terminated` exactly once, so a
/// phone is idle when every dialog it had has reported `terminated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogStateChangedPayload {
    /// The registered AoR (its canonical key) the dialog belongs to.
    pub aor: String,
    /// The state the dialog is now in.
    pub state: DialogState,
    /// Whether the AoR placed the call or is being called.
    pub direction: DialogDirection,
    /// The server's id for the phone's leg: stable for the dialog's life and
    /// unique, so usable as the dialog-info `id`. For a branch of a `dial` it
    /// is the `leg_id` its [`DialBranchPayload`](crate::sip::DialBranchPayload) named.
    pub leg_id: String,
    /// The SIP Call-ID of the phone's own dialog.
    pub call_id: String,
    /// The phone's tag, once known.
    #[serde(default)]
    pub local_tag: Option<String>,
    /// The other end's tag, once known.
    #[serde(default)]
    pub remote_tag: Option<String>,
    /// The party the phone is talking to.
    #[serde(default)]
    pub remote_identity: DialogIdentity,
}

/// One binding of a registered AoR, as `RegistrationChanged` and the
/// `registrations` reply report it.
///
/// Every field past `q` is absent from a server older than the one that added
/// it, and defaults here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationContact {
    /// The Contact URI.
    pub uri: String,
    /// Seconds left on the binding.
    pub expires: u64,
    /// Its q-value.
    pub q: f32,
    /// Where the REGISTER came from, `sip:<ip>:<port>;transport=<proto>`, byte
    /// for byte the script's `Contact.received`. This, not [`Self::uri`], is
    /// what an INVITE from the same phone comes from: the Contact can name a
    /// private address behind NAT, and over TCP or TLS the port names the
    /// connection.
    #[serde(default)]
    pub received: Option<String>,
    /// The transport the REGISTER arrived on (`udp`, `tcp`, `tls`, `ws`,
    /// `wss`).
    #[serde(default)]
    pub transport: Option<String>,
    /// The transport the client used to reach a front that declared a
    /// different one (PROXY protocol). `None` when nothing contradicted
    /// [`Self::transport`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_transport: Option<String>,
    /// The `+sip.instance` (RFC 5626).
    #[serde(default)]
    pub instance: Option<String>,
    /// The `reg-id` (RFC 5626).
    #[serde(default)]
    pub reg_id: Option<u32>,
    /// The binding's Path (RFC 3327), topmost first.
    #[serde(default)]
    pub path: Vec<String>,
    /// The Call-ID of the REGISTER that last wrote the binding.
    #[serde(default)]
    pub call_id: Option<String>,
    /// The CSeq number of the REGISTER that last wrote the binding.
    #[serde(default)]
    pub cseq: Option<u32>,
}

/// The `payload` of a `RegistrationChanged` event (`events: [registration]`):
/// an AoR's bindings changed, or were re-reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationChangedPayload {
    /// Per-process number, one higher on every `RegistrationChanged` the server
    /// publishes. A gap means events were lost: ask for
    /// [`RegistrationsReply`] and apply only events numbered above its `seq`.
    /// `None` from a server that predates it.
    #[serde(default)]
    pub seq: Option<u64>,
    /// The server process's boot epoch, new at every start: `seq` restarts
    /// with it, so a changed epoch means the numbers began again (resync). An
    /// identifier, not an order. `None` from a server without a registrar
    /// identity, or one that predates it.
    #[serde(default)]
    pub instance_epoch: Option<String>,
    /// The registered AoR, by its registrar key.
    pub aor: String,
    /// `registered`, `refreshed`, `deregistered`, `expired` or `snapshot` (a
    /// re-report of held state after the server's event task fell behind, not
    /// a change).
    pub event: String,
    /// The AoR's bindings now; empty once it has none.
    #[serde(default)]
    pub contacts: Vec<RegistrationContact>,
}

/// One registered AoR in a [`RegistrationsReply`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Registration {
    /// The registered AoR.
    pub aor: String,
    /// Its bindings.
    #[serde(default)]
    pub contacts: Vec<RegistrationContact>,
}

/// The reply of the `registrations` verb: one page of what the registrar
/// holds, in AoR order, and the `seq` it is current to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationsReply {
    /// Every `RegistrationChanged` numbered at or below this is reflected
    /// here; apply only events numbered above it. Across pages, keep the
    /// first page's.
    pub seq: u64,
    /// The server process's boot epoch, new at every start: `seq` restarts
    /// with it, so a changed epoch means the numbers began again (resync). An
    /// identifier, not an order. `None` from a server without a registrar
    /// identity, or one that predates it.
    #[serde(default)]
    pub instance_epoch: Option<String>,
    /// The registered AoRs of this page. Over the whole set, an AoR not listed
    /// has no binding.
    #[serde(default)]
    pub registrations: Vec<Registration>,
    /// The `after` that asks for the next page; `None` on the last.
    #[serde(default)]
    pub next: Option<String>,
}

/// One outbound registration (a REGISTER the server sends upstream), as
/// `RegistrantChanged` and the `outbound_registrations` reply report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundRegistration {
    /// The registration's AoR.
    pub aor: String,
    /// The registrar it registers with; `None` once it was removed.
    #[serde(default)]
    pub registrar: Option<String>,
    /// `unregistered`, `registering`, `challenging`, `registered`, `failed` or
    /// `awaiting_address` (it needs an address of its own and has none); `None`
    /// once it was removed.
    #[serde(default)]
    pub state: Option<String>,
    /// Seconds left on the binding the registrar granted, `0` when none.
    #[serde(default)]
    pub expires_in: u64,
    /// Consecutive failed attempts.
    #[serde(default)]
    pub failure_count: u32,
    /// The status of the last failed attempt, `None` once one succeeded.
    #[serde(default)]
    pub status_code: Option<u16>,
}

/// The `payload` of a `RegistrantChanged` event
/// (`events: [outbound_registration]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrantChangedPayload {
    /// Per-process number, its own sequence, as for
    /// [`RegistrationChangedPayload::seq`].
    #[serde(default)]
    pub seq: Option<u64>,
    /// The server process's boot epoch, new at every start: `seq` restarts
    /// with it, so a changed epoch means the numbers began again (resync). An
    /// identifier, not an order. `None` from a server without a registrar
    /// identity, or one that predates it.
    #[serde(default)]
    pub instance_epoch: Option<String>,
    /// `registered`, `refreshed`, `failed`, `deregistered`, `awaiting_address`
    /// or `snapshot`.
    pub event: String,
    /// The registration's state now.
    #[serde(flatten)]
    pub registration: OutboundRegistration,
}

/// The reply of the `outbound_registrations` verb, paged like
/// [`RegistrationsReply`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundRegistrationsReply {
    /// Every `RegistrantChanged` numbered at or below this is reflected here.
    pub seq: u64,
    /// The server process's boot epoch, new at every start: `seq` restarts
    /// with it, so a changed epoch means the numbers began again (resync). An
    /// identifier, not an order. `None` from a server without a registrar
    /// identity, or one that predates it.
    #[serde(default)]
    pub instance_epoch: Option<String>,
    /// The outbound registrations of this page.
    #[serde(default)]
    pub registrations: Vec<OutboundRegistration>,
    /// The `after` that asks for the next page; `None` on the last.
    #[serde(default)]
    pub next: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_registration_changed_payload_reads_every_contact_field() {
        let payload: RegistrationChangedPayload = serde_json::from_value(json!({
            "seq": 12,
            "instance_epoch": "boot-1",
            "aor": "sip:201@example.com",
            "event": "registered",
            "contacts": [{
                "uri": "sip:201@203.0.113.40",
                "expires": 590,
                "q": 1.0,
                "received": "sip:192.0.2.50:41000;transport=tcp",
                "transport": "tcp",
                "client_transport": "tls",
                "instance": "<urn:uuid:00000000-0000-1000-8000-000000000001>",
                "reg_id": 1,
                "path": ["<sip:edge.example.com;lr>"],
                "call_id": "register-call",
                "cseq": 42
            }]
        }))
        .expect("parses");
        assert_eq!(payload.seq, Some(12));
        assert_eq!(payload.instance_epoch.as_deref(), Some("boot-1"));
        let contact = &payload.contacts[0];
        assert_eq!(
            contact.received.as_deref(),
            Some("sip:192.0.2.50:41000;transport=tcp")
        );
        assert_eq!(contact.transport.as_deref(), Some("tcp"));
        assert_eq!(contact.client_transport.as_deref(), Some("tls"));
        assert_eq!(contact.reg_id, Some(1));
        assert_eq!(contact.path, vec!["<sip:edge.example.com;lr>".to_string()]);
        assert_eq!(contact.call_id.as_deref(), Some("register-call"));
        assert_eq!(contact.cseq, Some(42));
    }

    #[test]
    fn an_older_server_s_payload_still_parses() {
        let payload: RegistrationChangedPayload = serde_json::from_value(json!({
            "aor": "sip:201@example.com",
            "event": "expired",
            "contacts": [{"uri": "sip:201@203.0.113.40", "expires": 0, "q": 1.0}]
        }))
        .expect("parses");
        assert_eq!(payload.seq, None);
        assert_eq!(payload.instance_epoch, None);
        assert_eq!(payload.contacts[0].received, None);
        assert!(payload.contacts[0].path.is_empty());
    }

    #[test]
    fn the_registration_events_are_named() {
        use crate::sip::SipEvent;
        for (name, event) in [
            ("RegistrationChanged", SipEvent::RegistrationChanged),
            ("RegistrantChanged", SipEvent::RegistrantChanged),
        ] {
            assert_eq!(SipEvent::from(name), event);
            assert_eq!(event.as_str(), name);
        }
    }

    #[test]
    fn the_registrations_reply_parses() {
        let reply: RegistrationsReply = serde_json::from_value(json!({
            "seq": 1042,
            "registrations": [{"aor": "sip:201@example.com", "contacts": []}]
        }))
        .expect("parses");
        assert_eq!(reply.seq, 1042);
        assert_eq!(reply.registrations[0].aor, "sip:201@example.com");
        assert_eq!(reply.next, None);
    }

    #[test]
    fn a_registrant_changed_payload_flattens_the_registration() {
        let payload: RegistrantChangedPayload = serde_json::from_value(json!({
            "seq": 3,
            "aor": "sip:trunk@example.net",
            "event": "failed",
            "registrar": "sip:registrar.example.net",
            "state": "failed",
            "expires_in": 0,
            "failure_count": 2,
            "status_code": 503
        }))
        .expect("parses");
        assert_eq!(payload.event, "failed");
        assert_eq!(payload.registration.aor, "sip:trunk@example.net");
        assert_eq!(payload.registration.status_code, Some(503));
        assert_eq!(payload.registration.failure_count, 2);

        let reply: OutboundRegistrationsReply = serde_json::from_value(json!({
            "seq": 3,
            "registrations": [{"aor": "sip:trunk@example.net", "registrar": null,
                               "state": null, "expires_in": 0, "failure_count": 0,
                               "status_code": null}]
        }))
        .expect("parses");
        assert_eq!(reply.registrations[0].state, None);
    }
}
