//! Where a proxied branch's CANCEL and ACK go, and from where.
//!
//! RFC 3261 §9.1: "The destination address, port, and transport for the CANCEL
//! MUST be identical to those used to send the original request." On a host
//! with more than one listener the socket it leaves from matters as much: a
//! branch pinned to one (a `send_socket`, a captured flow, a protected port)
//! names that socket in its Via, and a CANCEL from another one is another
//! sender to the peer. §17.1.1.3 says the same of the ACK of a failure.
//!
//! Relayed through the dispatcher's own relay path with an egress pin, and
//! read off the UDP egress with the socket each message left from.

use super::proxy_cancel_awaits_provisional_tests::{caller_cancels, caller_invite, CALLER, SILENT};
use super::proxy_dialog_state_tests::{header, inbound, response_to, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// The listener the branch is pinned to; not the dispatcher's default one.
const PINNED: &str = "192.0.2.1:5070";

/// What the proxy sent `destination` since the last call, as it left.
fn sent_to(proxy: &Proxy, destination: &str) -> Vec<(OutboundMessage, SipMessage)> {
    let mut sent = Vec::new();
    while let Ok(outbound) = proxy.udp.try_recv() {
        if outbound.destination.to_string() != destination {
            continue;
        }
        let message = parse_sip_message_bytes(&outbound.data).expect("a SIP message");
        sent.push((outbound, message));
    }
    sent
}

/// An INVITE relayed to [`SILENT`] from the pinned listener. Returns the
/// proxy, the caller's INVITE, and the branch's INVITE as it left.
fn relayed_from_the_pinned_listener(call_id: &str) -> (Proxy, String, OutboundMessage, SipMessage) {
    let dispatcher = test_dispatcher_with_script("");
    let proxy = Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    };
    let raw = caller_invite(call_id);
    let original = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let server_key = TransactionManager::key_from_message(&original).expect("a server key");
    let pin = crate::transport::SendSocket {
        transport: Transport::Udp,
        addr: PINNED.parse().expect("a literal address"),
        advertise: None,
    };
    relay_request(
        &original,
        Some(&format!("sip:callee@{SILENT}")),
        false,
        &inbound(CALLER, &raw),
        Some(&server_key),
        &proxy.state,
        None,
        None,
        None,
        None,
        None,
        Some(&pin),
    );
    let mut sent = sent_to(&proxy, SILENT);
    assert_eq!(sent.len(), 1, "the INVITE");
    let (left, invite) = sent.remove(0);
    assert_eq!(left.source_local_addr, Some(pin.addr));
    assert!(
        header(&invite, "Via").contains(PINNED),
        "its Via names the listener it left from: {}",
        header(&invite, "Via")
    );

    // The transaction records the hop the INVITE took.
    let client_key = TransactionManager::key_from_message(&invite).expect("a client key");
    assert_eq!(
        proxy.state.transaction_manager.client_hop(&client_key),
        Some(crate::transaction::state::BranchHop {
            destination: left.destination,
            transport: left.transport,
            connection_id: left.connection_id,
            source_local_addr: left.source_local_addr,
        })
    );
    (proxy, raw, left, invite)
}

fn answer(proxy: &Proxy, invite: &SipMessage, status_code: u16, reason: &str) {
    proxy.response(
        SILENT,
        response_to(
            invite,
            status_code,
            reason,
            "callee-tag",
            &format!("sip:callee@{SILENT}"),
            "",
        ),
    );
}

/// The one request with `method` among `sent`, checked to have left the way
/// the INVITE did.
fn the_one(
    sent: &[(OutboundMessage, SipMessage)],
    method: Method,
    invite_left: &OutboundMessage,
) -> SipMessage {
    let matching: Vec<_> = sent
        .iter()
        .filter(|(_, message)| message.method() == Some(&method))
        .collect();
    assert_eq!(matching.len(), 1, "one {method:?}");
    let (left, message) = matching[0];
    assert_eq!(
        left.source_local_addr, invite_left.source_local_addr,
        "{method:?}: from the socket the INVITE left from"
    );
    assert_eq!(left.destination, invite_left.destination);
    assert_eq!(left.transport, invite_left.transport);
    assert_eq!(left.connection_id, invite_left.connection_id);
    message.clone()
}

/// A branch that rang is CANCELled at once, and the `487` it answers is ACKed:
/// both from the listener the INVITE left from.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_sent_at_once_and_the_ack_leave_from_the_invites_socket() {
    let (proxy, raw, invite_left, invite) =
        relayed_from_the_pinned_listener("pinned-now@example.com");
    answer(&proxy, &invite, 180, "Ringing");
    caller_cancels(&proxy, &raw);
    let cancel = the_one(&sent_to(&proxy, SILENT), Method::Cancel, &invite_left);
    assert_eq!(header(&cancel, "Via"), header(&invite, "Via"));

    answer(&proxy, &invite, 487, "Request Terminated");
    let ack = the_one(&sent_to(&proxy, SILENT), Method::Ack, &invite_left);
    assert_eq!(header(&ack, "Via"), header(&invite, "Via"));
}

/// A branch that had sent nothing is CANCELled on its first provisional, from
/// the listener the INVITE left from, although that provisional may arrive on
/// any socket and the session is gone by then.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_that_waited_leaves_from_the_invites_socket() {
    let (proxy, raw, invite_left, invite) =
        relayed_from_the_pinned_listener("pinned-later@example.com");
    caller_cancels(&proxy, &raw);
    assert!(
        sent_to(&proxy, SILENT).is_empty(),
        "nothing yet (RFC 3261 §9.1)"
    );

    answer(&proxy, &invite, 100, "Trying");
    let cancel = the_one(&sent_to(&proxy, SILENT), Method::Cancel, &invite_left);
    assert_eq!(header(&cancel, "Via"), header(&invite, "Via"));
}

/// The ACK of a failure nobody cancelled leaves from the INVITE's socket too.
#[tokio::test(flavor = "multi_thread")]
async fn the_ack_of_a_failure_leaves_from_the_invites_socket() {
    let (proxy, _, invite_left, invite) =
        relayed_from_the_pinned_listener("pinned-ack@example.com");
    answer(&proxy, &invite, 486, "Busy Here");
    the_one(&sent_to(&proxy, SILENT), Method::Ack, &invite_left);
}
