//! What a 2xx to a REGISTER means for the UE's security associations: the
//! pair it came over now carries a registration, or, when the REGISTER
//! removed the last binding the UE held over it, goes once the server
//! transaction is over (3GPP TS 24.229 clause 5.2.5.1). The rules are in
//! [`crate::ipsec::retire`]; this is where the dispatcher, which sees the
//! response leave, starts them. It runs whether the script relayed the
//! response or answered the REGISTER itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::error;

use super::DispatcherState;
use crate::ipsec::retire::RetireCondition;
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::headers::SipHeaders;
use crate::sip::message::SipMessage;
use crate::transport::{OutboundRouter, Transport};

/// A 2xx to `register`, which `ue` sent over `transport`, has been sent to it.
pub(super) fn on_register_2xx(
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

/// A 401 with Security-Server to a REGISTER `ue` sent, arriving on `local`, is
/// being relayed to it: record the offer, and, when the REGISTER came over a
/// pair of the UE's (its source is that pair's client port, on the protected
/// server port), the pair a re-registration keeps for a while (TS 33.203
/// clause 7.4.2a).
fn record_challenge(
    state: &DispatcherState,
    challenge: &SipMessage,
    ue: SocketAddr,
    local: SocketAddr,
) {
    let Some(manager) = state.ipsec_manager.as_ref() else {
        return;
    };
    let protected_by_port_c = state
        .ipsec_config
        .as_ref()
        .is_some_and(|config| local.port() == config.pcscf_port_s)
        .then_some(ue.port())
        .filter(|port_c| manager.has_sa(&ue.ip(), *port_c));
    crate::ipsec::runtime::record_security_server_with(
        manager,
        &ue.ip(),
        challenge,
        protected_by_port_c,
    );
}

/// A final response to a REGISTER `ue` sent, arriving on `local` (`flow`), is
/// about to be relayed to it: a 401 with Security-Server records the challenge
/// ([`record_challenge`]), and a 2xx first takes the pair the REGISTER came
/// over into use ([`take_into_use_before_2xx`]).
pub(super) fn before_register_final(
    state: &DispatcherState,
    response: &SipMessage,
    status_code: u16,
    (ue, local): (SocketAddr, SocketAddr),
) {
    if status_code == 401 && response.headers.has("Security-Server") {
        record_challenge(state, response, ue, local);
    } else if (200..300).contains(&status_code) {
        take_into_use_before_2xx(state, ue);
    }
}

/// A 2xx to a REGISTER `ue` sent is about to leave. When the REGISTER came over
/// a pair still pending (the one a re-authentication's challenge set up), take
/// it into use first, so the 2xx goes over it: TS 24.229 clause 5.2.2.2
/// ("protect the 200 (OK) response to the REGISTER request within the same
/// security association to that in which the REGISTER request was
/// protected"), TS 33.203 clause 7.4.2a (SM12 "shall be protected using the new
/// outbound SA").
///
/// Never waits. The kernel policy update runs on a task of its own, and until
/// it is over every message to the UE, this 2xx first, is held at the egress
/// and then sent in order ([`crate::ipsec::switch`]). Waiting here instead
/// blocked the answering thread on a netlink round trip, which, on an executor
/// worker attached to Python, held up every stop-the-world of the
/// free-threaded interpreter and with it every thread that attaches.
pub(super) fn take_into_use_before_2xx(state: &DispatcherState, ue: SocketAddr) {
    let Some(manager) = state.ipsec_manager.as_ref() else {
        return;
    };
    if !manager.is_pending(&ue.ip(), ue.port()) {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        error!(ue = %ue, "IPsec: no runtime to take the new SA pair into use on");
        return;
    };
    crate::ipsec::switch::hold(ue.ip());
    let manager = Arc::clone(manager);
    let outbound = Arc::clone(&state.outbound);
    let switch = handle.spawn(async move { manager.take_into_use(&ue.ip(), ue.port()).await });
    handle.spawn(async move {
        match tokio::time::timeout(SWITCH_HOLD_BOUND, switch).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(error))) => error!(
                ue = %ue,
                %error,
                "IPsec: could not take the new SA pair into use; the 2xx to the REGISTER \
                 leaves over the old set"
            ),
            Ok(Err(join_error)) => error!(
                ue = %ue,
                %join_error,
                "IPsec: the task taking the new SA pair into use failed; the 2xx to the \
                 REGISTER leaves over the old set"
            ),
            Err(_elapsed) => error!(
                ue = %ue,
                bound = ?SWITCH_HOLD_BOUND,
                "IPsec: the kernel has not taken the new SA pair into use yet; the 2xx to \
                 the REGISTER is not held any longer and may leave over the old set"
            ),
        }
        send_held(&outbound, ue);
    });
}

/// A final response from `source` reached the dispatcher. One to a NOTIFY ends
/// the transaction a pair kept through a network de-registration waited for,
/// so the pair goes now rather than at the end of its grace (TS 24.229 clause
/// 5.2.5.2, NOTE 2).
pub(super) fn on_final_response(
    state: &DispatcherState,
    response: &SipMessage,
    status_code: u16,
    source: SocketAddr,
) {
    let Some(manager) = state.ipsec_manager.as_ref() else {
        return;
    };
    let answers_notify = || {
        response.headers.cseq().is_some_and(|cseq| {
            cseq.split_whitespace()
                .nth(1)
                .is_some_and(|method| method.eq_ignore_ascii_case("NOTIFY"))
        })
    };
    if status_code >= 200 && answers_notify() {
        manager.notify_answered(source);
    }
}

/// How long messages to a UE are held for its pair's policy update at most. An
/// update takes milliseconds; one the kernel never answers must not keep the
/// UE's messages, and their memory, for ever.
pub(super) const SWITCH_HOLD_BOUND: Duration = Duration::from_secs(2);

/// Send what was held for `ue` while its pair was taken into use, in order,
/// and stop holding.
fn send_held(outbound: &OutboundRouter, ue: SocketAddr) {
    crate::ipsec::switch::unhold(ue.ip());
    while let Some(batch) = crate::ipsec::switch::release(ue.ip()) {
        for message in batch {
            if let Err(flume::SendError(message)) = outbound.deliver(message) {
                error!(
                    ue = %ue,
                    destination = %message.destination,
                    "IPsec: a message held while the new SA pair was taken into use could \
                     not be sent"
                );
            }
        }
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
