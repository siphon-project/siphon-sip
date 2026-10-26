//! What a 2xx to a REGISTER means for the UE's security associations: the
//! pair it came over now carries a registration, or, when the REGISTER
//! removed the last binding the UE held over it, the binding goes at once and
//! the pair once the server transaction is over (3GPP TS 24.229 clause
//! 5.2.5.1). The rules are in
//! [`crate::ipsec::retire`]; this is where the dispatcher, which sees the
//! response leave, starts them. It runs whether the script relayed the
//! response or answered the REGISTER itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error};

use super::DispatcherState;
use crate::ipsec::retire::{Pending, RetireCondition};
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
    let deregistered = deregistered(&register.headers);
    if let Some(deregistered) = &deregistered {
        forget_deregistered_bindings(register, ue, deregistered);
    }
    if deregistered.is_some_and(|deregistered| deregistered.every_named) {
        // TS 24.229 clause 5.2.5.1 step 2: "When all of the public user
        // identities that were registered by this UE are deregistered, the
        // P-CSCF shall delete any security associations ... towards the UE,
        // after the server transaction (as defined in RFC 3261 [26])
        // pertaining to this deregistration terminates". TS 33.203 clause
        // 7.4.2a: "The P-CSCF shall delete all SAs it holds that are
        // associated with a particular IMPI once all the associated IMPUs are
        // de-registered." The 200 leaves over the pair; the retirement waits
        // out the server transaction, then deletes the pair by its own SPIs,
        // unless a binding of another identity is still registered over it.
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
/// With a single protected client port the pair shares the outbound policy of
/// SA #3 with the set in use, so the kernel policy update must be over before
/// the 2xx leaves. Never waits for it: the update runs on a task of its own,
/// and until it is over every message to the UE, this 2xx first, is held at
/// the egress and then sent in order ([`crate::ipsec::switch`]). Waiting here
/// instead blocked the answering thread on a netlink round trip, which, on an
/// executor worker attached to Python, held up every stop-the-world of the
/// free-threaded interpreter and with it every thread that attaches.
///
/// With a protected client port of its own (`ipsec.pcscf_port_c` lists
/// several) the 2xx goes over the pair anyway, a response to the request that
/// came over it, and nothing in the kernel moves or is held: the pair is
/// marked registered, and requests to the UE move to it once a further
/// message arrives over it (TS 33.203 clause 7.4.2a,
/// [`crate::ipsec::IpsecManager::note_protected_inbound`]).
pub(super) fn take_into_use_before_2xx(state: &DispatcherState, ue: SocketAddr) {
    let Some(manager) = state.ipsec_manager.as_ref() else {
        return;
    };
    match manager.pending_how(&ue.ip(), ue.port()) {
        None | Some(Pending::Registered) => return,
        Some(Pending::Challenged) => {
            manager.confirm_registration(&ue.ip(), ue.port());
            return;
        }
        Some(Pending::SharedPolicy) => {}
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

/// The 2xx to a REGISTER from `ue` that de-registered contact addresses has
/// left: the P-CSCF's own binding of each goes now. TS 24.229 clause 5.2.5.1
/// step 1: "remove the binding between the public user identity found in the
/// To header field (together with the implicitly registered public user
/// identities) and the contact address indicated in the Contact header field".
///
/// The script may have removed it already (`registrar.save_proxy` with the
/// 2xx), and then nothing is left to do here. When it did not (no call, or one
/// refused because the 2xx carries the expiration on the Contact rather than
/// in an `Expires` header), the binding outlived the de-registration as a live
/// binding over the pair, so the retirement scheduled with it found the UE
/// still registered and kept the pair until the binding expired.
fn forget_deregistered_bindings(
    register: &SipMessage,
    ue: SocketAddr,
    deregistered: &Deregistered,
) {
    let Some(registrar) = crate::script::api::registrar_arc() else {
        return;
    };
    let Some(aor) = register
        .headers
        .to()
        .and_then(|to| NameAddr::parse(to).ok())
        .map(|to| to.uri.to_string())
    else {
        return;
    };
    let removed = registrar.remove_contacts_from(&aor, ue, deregistered.contacts.as_deref());
    if removed > 0 {
        debug!(
            ue = %ue,
            removed,
            "IPsec: bindings de-registered over the pair removed (TS 24.229 clause 5.2.5.1)"
        );
    }
}

/// What a REGISTER de-registers (RFC 3261 §10.2.2).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Deregistered {
    /// The URIs of the Contacts given an expiration of zero; `None` for a
    /// `Contact: *` with `Expires: 0`, which takes every one.
    contacts: Option<Vec<String>>,
    /// Whether every Contact the REGISTER names is de-registered.
    every_named: bool,
}

/// What a REGISTER de-registers: a `Contact: *` with `Expires: 0`, or the
/// Contacts that end up with an expiration of zero, from their own `expires`
/// parameter or else from the `Expires` header. `None` when it de-registers
/// nothing: a registration, a query (no Contact), or one that cannot be read.
pub(super) fn deregistered(headers: &SipHeaders) -> Option<Deregistered> {
    let expires_header = headers
        .get("Expires")
        .and_then(|value| value.trim().parse::<u32>().ok());
    let values = headers.get_all("Contact")?;
    let mut contacts = Vec::new();
    for value in values {
        if value.trim() == "*" {
            return (expires_header == Some(0)).then_some(Deregistered {
                contacts: None,
                every_named: true,
            });
        }
        contacts.extend(NameAddr::parse_multi(value).ok()?);
    }
    let named = contacts.len();
    let zero: Vec<String> = contacts
        .into_iter()
        .filter(|contact| contact.expires.or(expires_header) == Some(0))
        .map(|contact| contact.uri.to_string())
        .collect();
    (!zero.is_empty()).then_some(Deregistered {
        every_named: zero.len() == named,
        contacts: Some(zero),
    })
}

/// Whether a REGISTER removes every binding it names ([`deregistered`]).
#[cfg(test)]
fn removes_every_binding(headers: &SipHeaders) -> bool {
    deregistered(headers).is_some_and(|deregistered| deregistered.every_named)
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

    /// The Contacts given an expiration of zero are the ones de-registered,
    /// whether or not every named Contact is; a wildcard names none.
    #[test]
    fn the_contacts_given_zero_are_the_ones_de_registered() {
        assert_eq!(
            deregistered(&headers(&[(
                "Contact",
                "<sip:ue@198.51.100.7:6101>;expires=0, <sip:ue@198.51.100.7:6103>;expires=600"
            )])),
            Some(Deregistered {
                contacts: Some(vec!["sip:ue@198.51.100.7:6101".to_string()]),
                every_named: false,
            })
        );
        assert_eq!(
            deregistered(&headers(&[("Contact", "*"), ("Expires", "0")])),
            Some(Deregistered {
                contacts: None,
                every_named: true,
            })
        );
        assert_eq!(
            deregistered(&headers(&[
                ("Contact", "<sip:ue@198.51.100.7:6101>"),
                ("Expires", "600"),
            ])),
            None
        );
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
