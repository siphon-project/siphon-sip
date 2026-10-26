//! The no-response timer of a client transaction ([`TimerName::NoResponse`]):
//! how long a proxied request may go without drawing any response at all.
//!
//! TS 24.229 §5.4.3.3 has an S-CSCF act when it "fails to receive any SIP
//! response" from the next hop within a configurable time, which NOTE 24 puts
//! below Timer B and Timer F. Any response stops it, a `100 Trying` included.
//! When it runs out the request is handled as RFC 3261 §16.8 handles a Timer C
//! that fires before a provisional: as if a `408` had been received. The INVITE
//! is not CANCELled then (§9.1 forbids it), but a provisional that comes later
//! draws its CANCEL.

use std::time::Duration;

use bytes::Bytes;

use super::*;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::uri::SipUri;
use crate::transport::ConnectionId;

const BRANCH: &str = "z9hG4bK-no-response";
const AFTER: Duration = Duration::from_millis(2000);

fn request(method: Method) -> SipMessage {
    SipMessageBuilder::new()
        .request(
            method.clone(),
            SipUri::new("198.51.100.20".to_string()).with_user("callee".to_string()),
        )
        .via(format!("SIP/2.0/UDP 192.0.2.1:5060;branch={BRANCH}"))
        .to("<sip:callee@example.com>".to_string())
        .from("<sip:caller@example.com>;tag=caller-tag".to_string())
        .call_id("no-response@example.com".to_string())
        .cseq(format!("1 {}", method.as_str()))
        .content_length(0)
        .build()
        .expect("the request builds")
}

fn response(method: Method, status_code: u16, reason: &str) -> SipMessage {
    SipMessageBuilder::new()
        .response(status_code, reason.to_string())
        .via(format!("SIP/2.0/UDP 192.0.2.1:5060;branch={BRANCH}"))
        .to("<sip:callee@example.com>;tag=callee-tag".to_string())
        .from("<sip:caller@example.com>;tag=caller-tag".to_string())
        .call_id("no-response@example.com".to_string())
        .cseq(format!("1 {}", method.as_str()))
        .content_length(0)
        .build()
        .expect("the response builds")
}

/// A manager with a client transaction for a `method` request started and its
/// no-response timer armed; returns the actions arming produced.
fn armed(method: Method) -> (TransactionManager, TransactionKey, Option<Action>) {
    let manager = TransactionManager::default();
    let sent = request(method);
    let (key, _) = manager
        .new_client_transaction(&sent, Bytes::from(sent.to_bytes()), Transport::Udp)
        .expect("the client transaction starts");
    manager.set_client_hop(
        &key,
        BranchHop {
            destination: "198.51.100.20:5060".parse().expect("a literal address"),
            transport: crate::transport::Transport::Udp,
            connection_id: ConnectionId::default(),
            source_local_addr: None,
        },
    );
    let started = manager.arm_no_response(&key, AFTER);
    (manager, key, started)
}

fn feed(manager: &TransactionManager, key: &TransactionKey, event: ClientEvent) -> Vec<Action> {
    manager
        .process_client_event(key, event)
        .expect("the transaction is live")
}

fn ict(event: IctEvent) -> ClientEvent {
    ClientEvent::Ict(event)
}

fn nict(event: NictEvent) -> ClientEvent {
    ClientEvent::Nict(event)
}

fn has(actions: &[Action], wanted: impl Fn(&Action) -> bool) -> bool {
    actions.iter().any(wanted)
}

fn stops_the_timer(actions: &[Action]) -> bool {
    has(actions, |action| {
        matches!(action, Action::CancelTimer(TimerName::NoResponse))
    })
}

fn times_out(actions: &[Action]) -> bool {
    has(actions, |action| matches!(action, Action::Timeout))
}

fn passes_up(actions: &[Action]) -> bool {
    has(actions, |action| matches!(action, Action::PassToTu(_)))
}

fn cancels(actions: &[Action]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, Action::SendCancel(_)))
        .count()
}

#[test]
fn arming_starts_the_timer_for_the_time_asked() {
    for method in [Method::Invite, Method::Message] {
        let (_, _, started) = armed(method);
        assert!(matches!(
            started,
            Some(Action::StartTimer(TimerName::NoResponse, after)) if after == AFTER
        ));
    }
}

#[test]
fn a_request_that_has_drawn_a_response_is_not_armed() {
    let (manager, key, _) = armed(Method::Invite);
    feed(
        &manager,
        &key,
        ict(IctEvent::Provisional(response(
            Method::Invite,
            100,
            "Trying",
        ))),
    );
    assert!(manager.arm_no_response(&key, AFTER).is_none());
}

/// Any provisional stops it, `100 Trying` included: TS 24.229 asks about "any
/// SIP response".
#[test]
fn any_provisional_stops_the_timer_of_an_invite() {
    for (status_code, reason) in [(100, "Trying"), (180, "Ringing"), (183, "Session Progress")] {
        let (manager, key, _) = armed(Method::Invite);
        let actions = feed(
            &manager,
            &key,
            ict(IctEvent::Provisional(response(
                Method::Invite,
                status_code,
                reason,
            ))),
        );
        assert!(stops_the_timer(&actions), "{status_code} stops the timer");
        assert!(passes_up(&actions));
        let late = feed(&manager, &key, ict(IctEvent::NoResponse));
        assert!(
            late.is_empty(),
            "a stale fire after a {status_code} does nothing"
        );
        assert!(manager.invite_client_is_pending(&key));
    }
}

#[test]
fn a_final_response_stops_the_timer_of_an_invite() {
    let (manager, key, _) = armed(Method::Invite);
    let actions = feed(
        &manager,
        &key,
        ict(IctEvent::Response2xx(response(Method::Invite, 200, "OK"))),
    );
    assert!(stops_the_timer(&actions));
    let (manager, key, _) = armed(Method::Invite);
    let actions = feed(
        &manager,
        &key,
        ict(IctEvent::ResponseNon2xx(response(
            Method::Invite,
            486,
            "Busy Here",
        ))),
    );
    assert!(stops_the_timer(&actions));
}

#[test]
fn any_response_stops_the_timer_of_a_non_invite() {
    let (manager, key, _) = armed(Method::Message);
    let actions = feed(
        &manager,
        &key,
        nict(NictEvent::Provisional(response(
            Method::Message,
            100,
            "Trying",
        ))),
    );
    assert!(stops_the_timer(&actions));
    assert!(feed(&manager, &key, nict(NictEvent::NoResponse)).is_empty());

    let (manager, key, _) = armed(Method::Message);
    let actions = feed(
        &manager,
        &key,
        nict(NictEvent::FinalResponse(response(
            Method::Message,
            202,
            "Accepted",
        ))),
    );
    assert!(stops_the_timer(&actions));
}

/// Timer B or F firing first (it cannot, under a validated bound, but the
/// transaction must not leave the timer behind if it does) stops it too.
#[test]
fn the_transaction_timing_out_first_stops_the_timer() {
    let (manager, key, _) = armed(Method::Invite);
    let actions = feed(&manager, &key, ict(IctEvent::TimerB));
    assert!(times_out(&actions));
    assert!(stops_the_timer(&actions));

    let (manager, key, _) = armed(Method::Message);
    let actions = feed(&manager, &key, nict(NictEvent::TimerF));
    assert!(times_out(&actions));
    assert!(stops_the_timer(&actions));
}

/// A silent non-INVITE ends as Timer F would end it, and no later.
#[test]
fn a_silent_non_invite_ends_as_timer_f_ends_it() {
    let (manager, key, _) = armed(Method::Message);
    let actions = feed(&manager, &key, nict(NictEvent::NoResponse));
    assert!(times_out(&actions));
    assert!(has(&actions, |action| matches!(action, Action::Terminated)));
    assert!(has(&actions, |action| matches!(
        action,
        Action::CancelTimer(TimerName::E)
    )));
    assert!(has(&actions, |action| matches!(
        action,
        Action::CancelTimer(TimerName::F)
    )));
    assert!(!manager.contains(&key), "the transaction is over");
}

/// A silent INVITE: no more retransmissions, a timeout for the TU, and no
/// CANCEL (RFC 3261 §9.1). The transaction stays for Timer B, holding the
/// CANCEL for a provisional that may still come.
#[test]
fn a_silent_invite_is_given_up_on_without_a_cancel() {
    let (manager, key, _) = armed(Method::Invite);
    let actions = feed(&manager, &key, ict(IctEvent::NoResponse));
    assert!(times_out(&actions));
    assert!(has(&actions, |action| matches!(
        action,
        Action::CancelTimer(TimerName::A)
    )));
    assert_eq!(
        cancels(&actions),
        0,
        "RFC 3261 §9.1: no CANCEL before a provisional"
    );
    assert!(!has(&actions, |action| matches!(
        action,
        Action::Terminated
    )));
    assert!(manager.invite_client_gave_up(&key));
    assert_eq!(manager.waiting_cancel_count(), 1);

    // Timer A no longer retransmits, even on a stale fire.
    assert!(feed(&manager, &key, ict(IctEvent::TimerA)).is_empty());
    // A second fire does not time it out twice.
    assert!(feed(&manager, &key, ict(IctEvent::NoResponse)).is_empty());

    // Timer B ends it quietly: the timeout has been reported already.
    let actions = feed(&manager, &key, ict(IctEvent::TimerB));
    assert!(!times_out(&actions));
    assert!(has(&actions, |action| matches!(action, Action::Terminated)));
    assert!(!manager.contains(&key));
    assert_eq!(manager.waiting_cancel_count(), 0);
}

/// A provisional after the give-up releases the CANCEL, once, and is not the
/// branch's response any more; the final response that follows is ACKed and
/// absorbed.
#[test]
fn a_late_provisional_draws_the_cancel_and_nothing_reaches_the_tu() {
    let (manager, key, _) = armed(Method::Invite);
    feed(&manager, &key, ict(IctEvent::NoResponse));

    let actions = feed(
        &manager,
        &key,
        ict(IctEvent::Provisional(response(
            Method::Invite,
            180,
            "Ringing",
        ))),
    );
    assert_eq!(cancels(&actions), 1);
    assert!(!passes_up(&actions));
    assert!(
        has(&actions, |action| matches!(
            action,
            Action::StartTimer(TimerName::B, after) if *after == TimerConfig::default().timer_b()
        )),
        "the final response gets 64*T1 from the CANCEL (RFC 3261 §9.1)"
    );
    let again = feed(
        &manager,
        &key,
        ict(IctEvent::Provisional(response(
            Method::Invite,
            180,
            "Ringing",
        ))),
    );
    assert_eq!(cancels(&again), 0, "one CANCEL");
    assert!(again.is_empty());

    let actions = feed(
        &manager,
        &key,
        ict(IctEvent::ResponseNon2xx(response(
            Method::Invite,
            487,
            "Request Terminated",
        ))),
    );
    assert!(!passes_up(&actions));
    assert!(
        has(&actions, |action| matches!(action, Action::SendFrame(_))),
        "the 487 is ACKed (RFC 3261 §17.1.1.3)"
    );
}

/// A 2xx after the give-up still goes to the TU: a proxy forwards every 2xx
/// (RFC 3261 §16.7 step 5).
#[test]
fn a_late_2xx_still_reaches_the_tu() {
    let (manager, key, _) = armed(Method::Invite);
    feed(&manager, &key, ict(IctEvent::NoResponse));
    let actions = feed(
        &manager,
        &key,
        ict(IctEvent::Response2xx(response(Method::Invite, 200, "OK"))),
    );
    assert!(passes_up(&actions));
    assert!(!manager.contains(&key));
    assert_eq!(manager.waiting_cancel_count(), 0);
}

/// The TU cancelling the INVITE stops the timer: the branch is being given up
/// on anyway.
#[test]
fn cancelling_the_invite_disarms_the_timer() {
    let (manager, key, _) = armed(Method::Invite);
    assert!(manager.disarm_no_response(&key));
    assert!(!manager.disarm_no_response(&key), "only once");
    assert!(feed(&manager, &key, ict(IctEvent::NoResponse)).is_empty());
    assert!(!manager.invite_client_gave_up(&key));
}

/// A transaction set aside while its branch is answered is put back only when
/// it was given up on, and never over another.
#[test]
fn a_set_aside_invite_is_restored_but_never_over_another() {
    let (manager, key, _) = armed(Method::Invite);
    feed(&manager, &key, ict(IctEvent::NoResponse));
    let transaction = manager.remove(&key).expect("it is there");
    manager.restore_given_up(&key, transaction);
    assert!(manager.invite_client_gave_up(&key));

    let (other, other_key, _) = armed(Method::Invite);
    feed(&other, &other_key, ict(IctEvent::NoResponse));
    let taken = other.remove(&other_key).expect("it is there");
    // The slot has been taken again meanwhile: it keeps what it has.
    manager.restore_given_up(&key, taken);
    assert_eq!(manager.count(), 1);
}
