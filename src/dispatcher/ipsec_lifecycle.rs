//! What a 2xx to a REGISTER means for the UE's security associations: the
//! pair it came over now carries a registration, or, when the REGISTER
//! removed the last binding the UE held over it, goes once the server
//! transaction is over (3GPP TS 24.229 clause 5.2.5.1). The rules are in
//! [`crate::ipsec::retire`]; this is where the dispatcher, which sees the
//! response leave, starts them. It runs whether the script relayed the
//! response or answered the REGISTER itself.

use std::net::SocketAddr;
use std::time::Duration;

use super::DispatcherState;
use crate::ipsec::retire::RetireCondition;
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::headers::SipHeaders;
use crate::sip::message::SipMessage;
use crate::transport::Transport;

/// A 2xx to `register`, which `ue` sent over `transport`, has been sent to it.
pub(super) fn after_register_2xx(
    state: &DispatcherState,
    register: &SipMessage,
    ue: SocketAddr,
    transport: Transport,
) {
    let Some(manager) = state.ipsec_manager.as_ref() else {
        return;
    };
    // A REGISTER over a pair comes from the UE's protected client port, so its
    // source names the pair.
    if !manager.has_sa(&ue.ip(), ue.port()) {
        return;
    }
    if removes_every_binding(&register.headers) {
        manager.retire_pair(
            ue.ip(),
            ue.port(),
            server_transaction_lifetime(state, transport),
            RetireCondition::Unregistered,
            "de-registered",
        );
    } else if crate::script::api::registrar_arc()
        .is_some_and(|registrar| registrar.has_live_binding_from(ue))
    {
        manager.note_registered(&ue.ip(), ue.port());
    }
}

/// How long the server transaction of a REGISTER answered over `transport`
/// lasts once its final response is sent: Timer J, 64*T1 over an unreliable
/// transport (RFC 3261 §17.2.2), when a retransmitted request is still
/// answered from the transaction and so over the association. Zero over a
/// reliable one, where T1 stands in so the response queued for the connection
/// is written before the association and the connection go.
fn server_transaction_lifetime(state: &DispatcherState, transport: Transport) -> Duration {
    let timers = state.transaction_manager.timers();
    match transport {
        Transport::Udp => timers.timer_j_udp(),
        _ => timers.t1,
    }
}

/// Whether a REGISTER removes every binding it names (RFC 3261 §10.2.2): a
/// `Contact: *` with `Expires: 0`, or Contacts that each end up with an
/// expiration of zero, from their own `expires` parameter or else from the
/// `Expires` header. A REGISTER without a Contact is a query, and one that
/// cannot be read removes nothing.
pub(super) fn removes_every_binding(headers: &SipHeaders) -> bool {
    let expires_header = headers
        .get("Expires")
        .and_then(|value| value.trim().parse::<u32>().ok());
    let Some(values) = headers.get_all("Contact") else {
        return false;
    };
    let mut contacts = Vec::new();
    for value in values {
        if value.trim() == "*" {
            return expires_header == Some(0);
        }
        match NameAddr::parse_multi(value) {
            Ok(parsed) => contacts.extend(parsed),
            Err(_) => return false,
        }
    }
    !contacts.is_empty()
        && contacts
            .iter()
            .all(|contact| contact.expires.or(expires_header) == Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(lines: &[(&str, &str)]) -> SipHeaders {
        let mut headers = SipHeaders::new();
        for (name, value) in lines {
            headers.add(name, value.to_string());
        }
        headers
    }

    #[test]
    fn expires_zero_on_every_contact_removes_every_binding() {
        assert!(removes_every_binding(&headers(&[
            ("Contact", "<sip:ue@198.51.100.7:6101>"),
            ("Expires", "0"),
        ])));
        assert!(removes_every_binding(&headers(&[(
            "Contact",
            "<sip:ue@198.51.100.7:6101>;expires=0, <sip:ue@198.51.100.7:6103>;expires=0"
        )])));
        assert!(removes_every_binding(&headers(&[
            ("Contact", "<sip:ue@198.51.100.7:6101>;expires=0"),
            ("Contact", "<sip:ue@198.51.100.7:6103>"),
            ("Expires", "0"),
        ])));
        assert!(removes_every_binding(&headers(&[
            ("Contact", "*"),
            ("Expires", "0"),
        ])));
    }

    #[test]
    fn a_contact_that_stays_registered_removes_nothing_here() {
        // One Contact kept: the UE is still registered over the pair.
        assert!(!removes_every_binding(&headers(&[(
            "Contact",
            "<sip:ue@198.51.100.7:6101>;expires=0, <sip:ue@198.51.100.7:6103>;expires=600"
        )])));
        // A Contact's own expires wins over the header.
        assert!(!removes_every_binding(&headers(&[
            ("Contact", "<sip:ue@198.51.100.7:6101>;expires=600"),
            ("Expires", "0"),
        ])));
        // A registration, a refresh without Expires, a query, a wildcard
        // without Expires: 0, and a Contact that does not parse.
        assert!(!removes_every_binding(&headers(&[
            ("Contact", "<sip:ue@198.51.100.7:6101>"),
            ("Expires", "600000"),
        ])));
        assert!(!removes_every_binding(&headers(&[(
            "Contact",
            "<sip:ue@198.51.100.7:6101>"
        )])));
        assert!(!removes_every_binding(&headers(&[("Expires", "0")])));
        assert!(!removes_every_binding(&headers(&[
            ("Contact", "*"),
            ("Expires", "60"),
        ])));
        assert!(!removes_every_binding(&headers(&[
            ("Contact", "<not a uri"),
            ("Expires", "0"),
        ])));
    }

    /// A parameter of the URI is not the Contact's expiration.
    #[test]
    fn an_expires_uri_parameter_is_not_the_contacts() {
        assert!(!removes_every_binding(&headers(&[
            ("Contact", "<sip:ue@198.51.100.7:6101;expires=0>"),
            ("Expires", "600"),
        ])));
    }
}
