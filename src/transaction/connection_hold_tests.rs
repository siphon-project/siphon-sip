//! A client transaction holds the connection its request left on.
//!
//! The response to a request is owed on the connection the request arrived on
//! (RFC 3261 §18.2.2), so the sender must not close that connection for
//! idleness while the transaction is pending: a callee that rings for longer
//! than the idle timeout is silent for exactly that long. The hold lives in
//! the transaction and ends with it, whatever ends it.
//!
//! Driven through [`TransactionManager`] against a bare
//! [`ConnectionHolds`], which is what the outbound pool consults when its idle
//! timer fires.

use super::*;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::uri::SipUri;
use crate::transport::hold::ConnectionHolds;
use crate::transport::ConnectionId;

const CONNECTION: ConnectionId = ConnectionId(22);

fn request(method: Method, branch: &str) -> SipMessage {
    SipMessageBuilder::new()
        .request(
            method.clone(),
            SipUri::new("198.51.100.20".to_string()).with_user("callee".to_string()),
        )
        .via(format!("SIP/2.0/TCP 192.0.2.1:5060;branch={branch}"))
        .to("<sip:callee@example.org>".to_string())
        .from("<sip:caller@example.org>;tag=caller-tag".to_string())
        .call_id("connection-hold@example.org".to_string())
        .cseq(format!("1 {}", method.as_str()))
        .content_length(0)
        .build()
        .expect("the request builds")
}

fn response(status_code: u16, reason: &str, method: &Method, branch: &str) -> SipMessage {
    SipMessageBuilder::new()
        .response(status_code, reason.to_string())
        .via(format!("SIP/2.0/TCP 192.0.2.1:5060;branch={branch}"))
        .to("<sip:callee@example.org>;tag=callee-tag".to_string())
        .from("<sip:caller@example.org>;tag=caller-tag".to_string())
        .call_id("connection-hold@example.org".to_string())
        .cseq(format!("1 {}", method.as_str()))
        .content_length(0)
        .build()
        .expect("the response builds")
}

/// A client transaction for `method` over a reliable transport, holding
/// [`CONNECTION`].
fn held_transaction(
    manager: &TransactionManager,
    holds: &ConnectionHolds,
    method: Method,
    branch: &str,
) -> TransactionKey {
    let request = request(method, branch);
    let wire = bytes::Bytes::from(request.to_bytes());
    let (key, _) = manager
        .new_client_transaction(&request, wire, Transport::Reliable)
        .expect("the client transaction is created");
    manager.hold_client_connection(&key, holds.hold(CONNECTION));
    key
}

#[test]
fn a_ringing_invite_holds_its_connection_until_it_is_answered() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let branch = "z9hG4bK-hold-answered";
    let key = held_transaction(&manager, &holds, Method::Invite, branch);
    assert!(holds.is_held(CONNECTION));

    manager
        .process_client_event(
            &key,
            ClientEvent::Ict(IctEvent::Provisional(response(
                180,
                "Ringing",
                &Method::Invite,
                branch,
            ))),
        )
        .expect("the 180 is taken");
    assert!(
        holds.is_held(CONNECTION),
        "a provisional released the connection of an INVITE still owed its final response"
    );

    manager
        .process_client_event(
            &key,
            ClientEvent::Ict(IctEvent::Response2xx(response(
                200,
                "OK",
                &Method::Invite,
                branch,
            ))),
        )
        .expect("the 200 is taken");
    assert_eq!(manager.count(), 0);
    assert!(
        !holds.is_held(CONNECTION),
        "an answered INVITE still holds its connection"
    );
}

#[test]
fn a_failed_invite_holds_its_connection_until_its_ack_is_out() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let branch = "z9hG4bK-hold-failed";
    let key = held_transaction(&manager, &holds, Method::Invite, branch);

    let actions = manager
        .process_client_event(
            &key,
            ClientEvent::Ict(IctEvent::ResponseNon2xx(response(
                486,
                "Busy Here",
                &Method::Invite,
                branch,
            ))),
        )
        .expect("the 486 is taken");
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::SendFrame(_) | Action::SendMessage(_))),
        "precondition: the transaction sends the ACK of its failure itself"
    );
    if manager.contains(&key) {
        // Completed, waiting for Timer D: the ACK goes on this connection.
        assert!(holds.is_held(CONNECTION));
        manager
            .process_client_event(&key, ClientEvent::Ict(IctEvent::TimerD))
            .expect("Timer D is taken");
    }
    assert_eq!(manager.count(), 0);
    assert!(!holds.is_held(CONNECTION));
}

#[test]
fn an_invite_that_times_out_releases_its_connection() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let key = held_transaction(&manager, &holds, Method::Invite, "z9hG4bK-hold-timer-b");

    manager
        .process_client_event(&key, ClientEvent::Ict(IctEvent::TimerB))
        .expect("Timer B is taken");
    assert_eq!(manager.count(), 0);
    assert!(!holds.is_held(CONNECTION));
}

#[test]
fn a_non_invite_holds_its_connection_until_its_final_response() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let branch = "z9hG4bK-hold-options";
    let key = held_transaction(&manager, &holds, Method::Options, branch);
    assert!(holds.is_held(CONNECTION));

    manager
        .process_client_event(
            &key,
            ClientEvent::Nict(NictEvent::FinalResponse(response(
                200,
                "OK",
                &Method::Options,
                branch,
            ))),
        )
        .expect("the 200 is taken");
    assert_eq!(manager.count(), 0);
    assert!(!holds.is_held(CONNECTION));
}

#[test]
fn a_non_invite_that_times_out_releases_its_connection() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let key = held_transaction(&manager, &holds, Method::Options, "z9hG4bK-hold-timer-f");

    manager
        .process_client_event(&key, ClientEvent::Nict(NictEvent::TimerF))
        .expect("Timer F is taken");
    assert_eq!(manager.count(), 0);
    assert!(!holds.is_held(CONNECTION));
}

#[test]
fn removing_a_transaction_releases_its_connection() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let key = held_transaction(&manager, &holds, Method::Invite, "z9hG4bK-hold-removed");

    drop(manager.remove(&key));
    assert!(!holds.is_held(CONNECTION));
}

/// The send can lose the race with the response on a fast link: by the time
/// the connection is known, the transaction has already ended. The hold must
/// not outlive a transaction that is no longer there to release it.
#[test]
fn a_hold_for_a_transaction_that_has_ended_is_released_at_once() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let key = held_transaction(&manager, &holds, Method::Options, "z9hG4bK-hold-late");
    drop(manager.remove(&key));

    manager.hold_client_connection(&key, holds.hold(CONNECTION));
    assert!(!holds.is_held(CONNECTION));
}

#[test]
fn two_transactions_on_one_connection_each_hold_it() {
    let manager = TransactionManager::default();
    let holds = ConnectionHolds::new();
    let first = held_transaction(&manager, &holds, Method::Invite, "z9hG4bK-hold-first");
    let second = held_transaction(&manager, &holds, Method::Invite, "z9hG4bK-hold-second");

    drop(manager.remove(&first));
    assert!(
        holds.is_held(CONNECTION),
        "one call ending released the connection another is still ringing on"
    );
    drop(manager.remove(&second));
    assert!(!holds.is_held(CONNECTION));
    assert_eq!(holds.len(), 0);
}
