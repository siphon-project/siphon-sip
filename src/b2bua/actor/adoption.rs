//! A call one of whose legs was merged into a conference room
//! (`b2bua.adopt_replaced`), and the check that the party asking for the merge
//! is the party whose dialog it names.
//!
//! A client merging two calls into a conference (RFC 4579 §5.5, TS 24.147)
//! REFERs the focus with a `Replaces` (RFC 3891) naming its own dialog with
//! the other party. When this node holds that dialog as one leg of a call, the
//! call's *other* leg is seated in the room in place and the named leg is
//! ended. The call stays a call: one SIP leg (the far party) in the A-leg slot,
//! and a room seat where its other leg was.

use std::net::SocketAddr;

use crate::transport::{ConnectionId, Transport};

use super::*;

/// What the call remembers of having been merged into a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adoption {
    /// The room the far party's leg is seated in.
    pub conference_id: String,
    /// Internal id of the call whose dialog adopted this one: the conference
    /// dialog the REFER arrived in.
    pub owner_call_id: String,
    /// Whether this call ends with that dialog (`on_owner_leave="end"`).
    pub ends_with_owner: bool,
    /// The SIP Call-ID the call was known by before the merge when its A-leg
    /// was the dialog that ended: still the call's name to a script, an event
    /// from the engine and `b2bua.terminate`, though no dialog carries it.
    pub alias_call_id: Option<String>,
    /// `false` while the seat is being asked for, `true` once it is in.
    pub seated: bool,
}

/// One end of a dialog of a call, as `adopt_replaced` compares it: the party
/// on the leg, where it is, and who it authenticated as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogParty {
    /// Internal id of the call the leg belongs to.
    pub internal_call_id: String,
    /// The dialog's SIP Call-ID.
    pub sip_call_id: String,
    /// Whether the leg is the call's A-leg (the party placed the call).
    pub on_a_leg: bool,
    /// Where the party's signalling comes from.
    pub source: SocketAddr,
    /// Its transport, and the connection on a stream transport.
    pub transport: Transport,
    pub connection_id: ConnectionId,
    /// The party's own URI on the dialog: the `From` of the INVITE it sent,
    /// or the `To` of the one siphon sent it, which is the `From` of every
    /// request it sends in the dialog.
    pub uri: Option<String>,
    /// The digest identity the party authenticated as, when it placed the
    /// call and authenticated (`None` on a leg siphon dialled).
    pub auth_user: Option<String>,
}

impl DialogParty {
    /// The party on `leg` of `call`.
    pub fn on_leg(call: &CallActor, leg: &Leg, on_a_leg: bool) -> Self {
        Self {
            internal_call_id: call.id.clone(),
            sip_call_id: leg.dialog.call_id.clone(),
            on_a_leg,
            source: leg.transport.remote_addr,
            transport: leg.transport.transport,
            connection_id: leg.transport.connection_id,
            uri: leg.dialog.remote_to_uri.clone(),
            auth_user: if on_a_leg {
                call.auth_user.clone()
            } else {
                None
            },
        }
    }

    /// The user part of the party's URI.
    pub fn user(&self) -> Option<String> {
        let uri = extract_contact_uri(self.uri.as_deref()?);
        crate::sip::parser::parse_uri_standalone(&uri)
            .ok()
            .and_then(|parsed| parsed.user)
            .filter(|user| !user.is_empty())
    }
}

/// How the named dialog was found to be the referrer's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamePartyBy {
    /// Both legs carry the same digest identity.
    AuthUser,
    /// Both legs are on the same stream connection.
    Connection,
    /// Same source address and the same user on both dialogs.
    SourceAndUser,
}

/// Whether the dialog `named` faces the same party as the dialog `referrer`
/// the REFER arrived in (RFC 3891 §5: knowing a dialog's identifiers is no
/// authority to take it over).
///
/// - Both carry a digest identity: it has to be the same one.
/// - Otherwise, both on a stream transport: the same connection.
/// - Otherwise: the same source address (address and port) and the same user
///   on both dialogs. This is the rule a deployment that authorises INVITEs by
///   registration source rather than digest runs on, since neither leg has an
///   identity there.
///
/// `Err` names what differed.
pub fn same_party(
    referrer: &DialogParty,
    named: &DialogParty,
) -> Result<SamePartyBy, &'static str> {
    if let (Some(referrer_user), Some(named_user)) = (&referrer.auth_user, &named.auth_user) {
        return if referrer_user == named_user {
            Ok(SamePartyBy::AuthUser)
        } else {
            Err("the two dialogs authenticated as different users")
        };
    }
    if referrer.transport.is_stream() && named.transport.is_stream() {
        return if referrer.transport == named.transport
            && referrer.connection_id == named.connection_id
            && referrer.connection_id != ConnectionId::default()
        {
            Ok(SamePartyBy::Connection)
        } else {
            Err("the two dialogs are not on the same connection")
        };
    }
    if referrer.source != named.source {
        return Err("the two dialogs come from different source addresses");
    }
    match (referrer.user(), named.user()) {
        (Some(referrer_user), Some(named_user)) if referrer_user == named_user => {
            Ok(SamePartyBy::SourceAndUser)
        }
        _ => Err("the two dialogs name different users"),
    }
}

/// Why a call cannot be merged into a room, as the status the REFER's report
/// carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptRefusal {
    /// No confirmed dialog here matches (481).
    NoDialog,
    /// The call is busy with something a merge cannot run beside: a transfer,
    /// a bridge, a takeover, or another merge (488).
    Busy,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(source: &str, transport: Transport, connection: u64, uri: &str) -> DialogParty {
        DialogParty {
            internal_call_id: "call".into(),
            sip_call_id: "dialog@192.0.2.10".into(),
            on_a_leg: true,
            source: source.parse().expect("a literal address"),
            transport,
            connection_id: ConnectionId(connection),
            uri: Some(uri.into()),
            auth_user: None,
        }
    }

    #[test]
    fn the_same_digest_identity_is_the_same_party_wherever_it_calls_from() {
        let mut referrer = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        let mut named = party(
            "192.0.2.99:5070",
            Transport::Udp,
            0,
            "<sip:9999@example.com>",
        );
        referrer.auth_user = Some("1001".into());
        named.auth_user = Some("1001".into());
        assert_eq!(same_party(&referrer, &named), Ok(SamePartyBy::AuthUser));
    }

    #[test]
    fn two_digest_identities_that_differ_are_refused_without_a_fallback() {
        let mut referrer = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        let mut named = referrer.clone();
        referrer.auth_user = Some("1001".into());
        named.auth_user = Some("1002".into());
        assert!(same_party(&referrer, &named).is_err());
    }

    #[test]
    fn a_stream_transport_has_to_be_the_same_connection() {
        let referrer = party(
            "192.0.2.10:5061",
            Transport::Tls,
            7,
            "<sip:1001@example.com>",
        );
        let same = party(
            "192.0.2.10:5061",
            Transport::Tls,
            7,
            "<sip:1001@example.com>",
        );
        let other = party(
            "192.0.2.10:5061",
            Transport::Tls,
            8,
            "<sip:1001@example.com>",
        );
        assert_eq!(same_party(&referrer, &same), Ok(SamePartyBy::Connection));
        assert!(same_party(&referrer, &other).is_err());
    }

    #[test]
    fn without_identities_the_source_and_the_user_both_have_to_match() {
        let referrer = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "\"Sub\" <sip:1001@example.com>;tag=a",
        );
        let same = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        let elsewhere = party(
            "192.0.2.11:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        let other_user = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "<sip:1002@example.com>",
        );
        assert_eq!(same_party(&referrer, &same), Ok(SamePartyBy::SourceAndUser));
        assert!(same_party(&referrer, &elsewhere).is_err());
        assert!(same_party(&referrer, &other_user).is_err());
    }

    #[test]
    fn one_identity_alone_falls_back_to_the_source_and_the_user() {
        let mut referrer = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        referrer.auth_user = Some("1001".into());
        let named = party(
            "192.0.2.10:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        assert_eq!(
            same_party(&referrer, &named),
            Ok(SamePartyBy::SourceAndUser)
        );
        let stranger = party(
            "198.51.100.7:5060",
            Transport::Udp,
            0,
            "<sip:1001@example.com>",
        );
        assert!(same_party(&referrer, &stranger).is_err());
    }

    #[test]
    fn a_uri_without_a_user_matches_nobody() {
        let referrer = party("192.0.2.10:5060", Transport::Udp, 0, "<sip:example.com>");
        let named = referrer.clone();
        assert!(same_party(&referrer, &named).is_err());
    }
}
