//! RFC 3261 §9.1 on an INVITE client transaction: a CANCEL waits for the
//! INVITE's first provisional response, is sent at once when one has arrived,
//! and is not sent at all once the final response has.
//!
//! Driven through [`TransactionManager`], as the dispatcher drives it. Every
//! way a waiting CANCEL can end is checked to leave nothing behind
//! ([`TransactionManager::waiting_cancel_count`]).

use std::sync::{Arc, Barrier};

use bytes::Bytes;

use super::*;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::uri::SipUri;
use crate::transport::ConnectionId;

const BRANCH: &str = "z9hG4bK-cancel-waits";

fn invite() -> SipMessage {
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("example.com".to_string()).with_user("callee".to_string()),
        )
        .via(format!("SIP/2.0/UDP 192.0.2.1:5060;branch={BRANCH}"))
        .to("<sip:callee@example.com>".to_string())
        .from("<sip:caller@example.com>;tag=caller-tag".to_string())
        .call_id("cancel-waits@example.com".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .expect("the INVITE builds")
}

fn response(status_code: u16, reason: &str) -> SipMessage {
    SipMessageBuilder::new()
        .response(status_code, reason.to_string())
        .via(format!("SIP/2.0/UDP 192.0.2.1:5060;branch={BRANCH}"))
        .to("<sip:callee@example.com>;tag=callee-tag".to_string())
        .from("<sip:caller@example.com>;tag=caller-tag".to_string())
        .call_id("cancel-waits@example.com".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .expect("the response builds")
}

/// The CANCEL a TU would hand over for [`invite`], and where that went.
fn cancel() -> BranchCancel {
    BranchCancel {
        frame: Bytes::from_static(b"CANCEL sip:callee@example.com SIP/2.0\r\n\r\n"),
        destination: "198.51.100.20:5060".parse().expect("a literal address"),
        transport: crate::transport::Transport::Udp,
        connection_id: ConnectionId::default(),
    }
}

/// A manager with the INVITE's client transaction started over `transport`.
fn started(transport: Transport) -> (TransactionManager, TransactionKey, Vec<Action>) {
    let manager = TransactionManager::default();
    let request = invite();
    let (key, actions) = manager
        .new_client_transaction(&request, Bytes::from(request.to_bytes()), transport)
        .expect("the client transaction starts");
    (manager, key, actions)
}

fn feed(manager: &TransactionManager, key: &TransactionKey, event: IctEvent) -> Vec<Action> {
    manager
        .process_client_event(key, ClientEvent::Ict(event))
        .expect("the transaction is live")
}

fn cancels_in(actions: &[Action]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, Action::SendCancel(_)))
        .count()
}

fn retransmits_in(actions: &[Action]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, Action::SendFrame(_)))
        .count()
}

#[test]
fn a_cancel_for_an_invite_with_no_response_waits_for_its_first_provisional() {
    let (manager, key, _) = started(Transport::Udp);
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::Deferred
    ));
    assert_eq!(manager.waiting_cancel_count(), 1);

    // The INVITE is still an unanswered request: Timer A retransmits it.
    let actions = feed(&manager, &key, IctEvent::TimerA);
    assert_eq!(retransmits_in(&actions), 1);
    assert_eq!(cancels_in(&actions), 0);

    // A 100 Trying is a provisional response for §9.1.
    let actions = feed(
        &manager,
        &key,
        IctEvent::Provisional(response(100, "Trying")),
    );
    let sent: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            Action::SendCancel(cancel) => Some(cancel),
            _ => None,
        })
        .collect();
    assert_eq!(sent.len(), 1, "the CANCEL goes on the first provisional");
    assert_eq!(sent[0].frame, cancel().frame);
    assert_eq!(sent[0].destination, cancel().destination);
    assert_eq!(manager.waiting_cancel_count(), 0);

    // Once: neither a later provisional nor a later request sends another.
    let actions = feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    assert_eq!(cancels_in(&actions), 0);
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::NothingToSend
    ));

    // The 487 the CANCEL draws is ACKed by the transaction, which then ends.
    let actions = feed(
        &manager,
        &key,
        IctEvent::ResponseNon2xx(response(487, "Request Terminated")),
    );
    assert_eq!(retransmits_in(&actions), 1, "the ACK of the 487");
    feed(&manager, &key, IctEvent::TimerD);
    assert_eq!(manager.count(), 0);
}

#[test]
fn a_cancel_for_an_invite_with_a_provisional_is_sent_at_once_and_only_once() {
    let (manager, key, _) = started(Transport::Udp);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    match manager.cancel_invite_client(&key, cancel()) {
        CancelOutcome::SendNow(now) => assert_eq!(now.frame, cancel().frame),
        other => panic!("expected the CANCEL back to send, got {other:?}"),
    }
    assert_eq!(manager.waiting_cancel_count(), 0);
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::NothingToSend
    ));
}

#[test]
fn a_second_request_while_the_first_cancel_waits_does_not_send_two() {
    let (manager, key, _) = started(Transport::Udp);
    for _ in 0..2 {
        assert!(matches!(
            manager.cancel_invite_client(&key, cancel()),
            CancelOutcome::Deferred
        ));
    }
    assert_eq!(manager.waiting_cancel_count(), 1);
    let actions = feed(
        &manager,
        &key,
        IctEvent::Provisional(response(183, "Session Progress")),
    );
    assert_eq!(cancels_in(&actions), 1);
}

#[test]
fn an_invite_with_its_final_response_is_not_cancelled() {
    // A non-2xx final leaves the transaction in Completed until Timer D.
    let (manager, key, _) = started(Transport::Udp);
    feed(
        &manager,
        &key,
        IctEvent::ResponseNon2xx(response(486, "Busy Here")),
    );
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::NothingToSend
    ));
    assert_eq!(manager.waiting_cancel_count(), 0);

    // A 2xx ends the transaction outright.
    let (manager, key, _) = started(Transport::Udp);
    feed(&manager, &key, IctEvent::Response2xx(response(200, "OK")));
    assert_eq!(manager.count(), 0);
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::NothingToSend
    ));
}

#[test]
fn a_waiting_cancel_is_dropped_unsent_by_a_final_response() {
    for success in [true, false] {
        let (manager, key, _) = started(Transport::Udp);
        assert!(matches!(
            manager.cancel_invite_client(&key, cancel()),
            CancelOutcome::Deferred
        ));
        let actions = if success {
            feed(&manager, &key, IctEvent::Response2xx(response(200, "OK")))
        } else {
            feed(
                &manager,
                &key,
                IctEvent::ResponseNon2xx(response(486, "Busy Here")),
            )
        };
        assert_eq!(cancels_in(&actions), 0, "no CANCEL for a final response");
        assert_eq!(manager.waiting_cancel_count(), 0);
        if !success {
            assert_eq!(retransmits_in(&actions), 1, "the ACK of the 486, alone");
            // A retransmitted final is ACKed again and still draws no CANCEL.
            let actions = feed(
                &manager,
                &key,
                IctEvent::ResponseNon2xx(response(486, "Busy Here")),
            );
            assert_eq!(cancels_in(&actions), 0);
            assert!(matches!(
                manager.cancel_invite_client(&key, cancel()),
                CancelOutcome::NothingToSend
            ));
        }
    }
}

#[test]
fn timer_b_ends_a_waiting_cancel_without_sending_it() {
    let (manager, key, _) = started(Transport::Udp);
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::Deferred
    ));
    let actions = feed(&manager, &key, IctEvent::TimerB);
    assert_eq!(cancels_in(&actions), 0);
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Timeout)));
    assert_eq!(manager.waiting_cancel_count(), 0);
    assert_eq!(manager.count(), 0);
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::NothingToSend
    ));
}

/// Over a reliable transport nothing is retransmitted (RFC 3261 §17.1.1.2),
/// so the only timer the INVITE has is Timer B, and it is what ends a CANCEL
/// that never got its provisional.
#[test]
fn over_a_reliable_transport_a_waiting_cancel_ends_at_the_transaction_timeout() {
    let (manager, key, started_with) = started(Transport::Reliable);
    let timers: Vec<_> = started_with
        .iter()
        .filter_map(|action| match action {
            Action::StartTimer(name, _) => Some(*name),
            _ => None,
        })
        .collect();
    assert_eq!(timers, [TimerName::B], "no Timer A to retransmit on");
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::Deferred
    ));
    assert_eq!(manager.waiting_cancel_count(), 1);
    let actions = feed(&manager, &key, IctEvent::TimerB);
    assert_eq!(cancels_in(&actions), 0);
    assert_eq!(manager.waiting_cancel_count(), 0);
    assert_eq!(manager.count(), 0);
}

/// Every way a waiting CANCEL ends, over many transactions at once: the count
/// of them returns to zero, and so does the count of transactions.
#[test]
fn waiting_cancels_drain_to_baseline_over_every_exit() {
    let manager = TransactionManager::default();
    let mut keys = Vec::new();
    for index in 0..400usize {
        let mut request = invite();
        request.headers.set(
            "Via",
            format!("SIP/2.0/UDP 192.0.2.1:5060;branch={BRANCH}-{index}"),
        );
        let (key, _) = manager
            .new_client_transaction(&request, Bytes::from(request.to_bytes()), Transport::Udp)
            .expect("the client transaction starts");
        assert!(matches!(
            manager.cancel_invite_client(&key, cancel()),
            CancelOutcome::Deferred
        ));
        keys.push(key);
    }
    assert_eq!(manager.waiting_cancel_count(), 400);

    let mut cancels_sent = 0;
    for (index, key) in keys.iter().enumerate() {
        match index % 4 {
            // A provisional: the CANCEL goes, its 487 is ACKed, Timer D ends it.
            0 => {
                cancels_sent += cancels_in(&feed(
                    &manager,
                    key,
                    IctEvent::Provisional(response(180, "Ringing")),
                ));
                feed(
                    &manager,
                    key,
                    IctEvent::ResponseNon2xx(response(487, "Request Terminated")),
                );
                feed(&manager, key, IctEvent::TimerD);
            }
            // A late 2xx.
            1 => {
                cancels_sent += cancels_in(&feed(
                    &manager,
                    key,
                    IctEvent::Response2xx(response(200, "OK")),
                ));
            }
            // A late non-2xx final: ACKed, then Timer D.
            2 => {
                cancels_sent += cancels_in(&feed(
                    &manager,
                    key,
                    IctEvent::ResponseNon2xx(response(486, "Busy Here")),
                ));
                feed(&manager, key, IctEvent::TimerD);
            }
            // Nothing at all: Timer B.
            _ => {
                cancels_sent += cancels_in(&feed(&manager, key, IctEvent::TimerB));
            }
        }
    }
    assert_eq!(
        cancels_sent, 100,
        "one CANCEL per INVITE that got a provisional"
    );
    assert_eq!(manager.waiting_cancel_count(), 0);
    assert_eq!(manager.count(), 0);
}

#[test]
fn a_request_other_than_invite_is_never_cancelled() {
    let manager = TransactionManager::default();
    let options = SipMessageBuilder::new()
        .request(Method::Options, SipUri::new("example.com".to_string()))
        .via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-options".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:caller@example.com>;tag=caller-tag".to_string())
        .call_id("options@example.com".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .expect("the OPTIONS builds");
    let (key, _) = manager
        .new_client_transaction(&options, Bytes::from(options.to_bytes()), Transport::Udp)
        .expect("the client transaction starts");
    assert!(matches!(
        manager.cancel_invite_client(&key, cancel()),
        CancelOutcome::NothingToSend
    ));
}

/// A provisional response and a request to cancel race on two threads. Whatever
/// the order, the provisional has been seen by the time both are done, so
/// exactly one CANCEL is sent: by the request when it came second, by the
/// response when it did.
#[test]
fn a_provisional_and_a_cancel_racing_send_exactly_one_cancel() {
    for round in 0..2_000usize {
        let (manager, key, _) = started(Transport::Udp);
        let manager = Arc::new(manager);
        let barrier = Arc::new(Barrier::new(2));

        let responder = {
            let (manager, key, barrier) = (Arc::clone(&manager), key.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                cancels_in(&feed(
                    &manager,
                    &key,
                    IctEvent::Provisional(response(180, "Ringing")),
                ))
            })
        };
        let canceller = {
            let (manager, key, barrier) = (Arc::clone(&manager), key.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                match manager.cancel_invite_client(&key, cancel()) {
                    CancelOutcome::SendNow(_) => 1,
                    CancelOutcome::Deferred | CancelOutcome::NothingToSend => 0,
                }
            })
        };
        let from_response = responder.join().expect("the responder ran");
        let from_request = canceller.join().expect("the canceller ran");
        assert_eq!(
            from_response + from_request,
            1,
            "round {round}: {from_response} from the response, {from_request} from the request"
        );
        assert_eq!(manager.waiting_cancel_count(), 0);
    }
}

/// The same race against a final response: the CANCEL is sent at most once,
/// and never when the final response came first.
#[test]
fn a_final_response_and_a_cancel_racing_never_send_two_cancels() {
    for round in 0..2_000usize {
        let (manager, key, _) = started(Transport::Udp);
        feed(
            &manager,
            &key,
            IctEvent::Provisional(response(180, "Ringing")),
        );
        let manager = Arc::new(manager);
        let barrier = Arc::new(Barrier::new(3));

        let responder = {
            let (manager, key, barrier) = (Arc::clone(&manager), key.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                cancels_in(&feed(
                    &manager,
                    &key,
                    IctEvent::ResponseNon2xx(response(486, "Busy Here")),
                ))
            })
        };
        let cancellers: Vec<_> = (0..2)
            .map(|_| {
                let (manager, key, barrier) =
                    (Arc::clone(&manager), key.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    match manager.cancel_invite_client(&key, cancel()) {
                        CancelOutcome::SendNow(_) => 1,
                        CancelOutcome::Deferred | CancelOutcome::NothingToSend => 0,
                    }
                })
            })
            .collect();
        let mut sent = responder.join().expect("the responder ran");
        for canceller in cancellers {
            sent += canceller.join().expect("a canceller ran");
        }
        assert!(sent <= 1, "round {round}: {sent} CANCELs for one INVITE");
        assert_eq!(manager.waiting_cancel_count(), 0);
    }
}
