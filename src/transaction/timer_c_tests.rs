//! Timer C on an INVITE client transaction (RFC 3261 §16.6 step 11, §16.7
//! step 2, §16.8).
//!
//! Set, in effect, when the INVITE is forwarded, and to more than 3 minutes;
//! reset by each 101-199 provisional; and on firing, a CANCEL for a
//! transaction that has had a provisional. A transaction that has had none is
//! Timer B's, which ends it long before.
//!
//! Driven through [`TransactionManager`] with the transaction's clock moved by
//! the test ([`TransactionManager::age_invite_client`]).

use std::time::Duration;

use bytes::Bytes;

use super::timer::{TimerConfig, DEFAULT_TIMER_C};
use super::*;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::uri::SipUri;
use crate::transport::ConnectionId;

const BRANCH: &str = "z9hG4bK-timer-c";

fn invite() -> SipMessage {
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("198.51.100.20".to_string()).with_user("callee".to_string()),
        )
        .via(format!("SIP/2.0/UDP 192.0.2.1:5060;branch={BRANCH}"))
        .to("<sip:callee@example.com>".to_string())
        .from("<sip:caller@example.com>;tag=caller-tag".to_string())
        .call_id("timer-c@example.com".to_string())
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
        .call_id("timer-c@example.com".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .expect("the response builds")
}

fn hop() -> BranchHop {
    BranchHop {
        destination: "198.51.100.20:5060".parse().expect("a literal address"),
        transport: crate::transport::Transport::Udp,
        connection_id: ConnectionId::default(),
        source_local_addr: None,
    }
}

/// A manager running `timers` with the INVITE's client transaction started.
fn started(timers: TimerConfig) -> (TransactionManager, TransactionKey, Vec<Action>) {
    let manager = TransactionManager::new(timers);
    let request = invite();
    let (key, actions) = manager
        .new_client_transaction(&request, Bytes::from(request.to_bytes()), Transport::Udp)
        .expect("the client transaction starts");
    manager.set_client_hop(&key, hop());
    (manager, key, actions)
}

fn feed(manager: &TransactionManager, key: &TransactionKey, event: IctEvent) -> Vec<Action> {
    manager
        .process_client_event(key, ClientEvent::Ict(event))
        .expect("the transaction is live")
}

/// The duration Timer C is (re)started for among `actions`, if it is.
fn timer_c_set(actions: &[Action]) -> Option<Duration> {
    actions.iter().find_map(|action| match action {
        Action::StartTimer(TimerName::C, duration) => Some(*duration),
        _ => None,
    })
}

fn cancels_in(actions: &[Action]) -> Vec<&BranchCancel> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::SendCancel(cancel) => Some(&**cancel),
            _ => None,
        })
        .collect()
}

fn within_a_second_of(duration: Duration, expected: Duration) -> bool {
    duration <= expected && expected - duration < Duration::from_secs(1)
}

/// The default is the RFC's: larger than 3 minutes.
#[test]
fn the_default_timer_c_is_larger_than_three_minutes() {
    assert!(DEFAULT_TIMER_C > Duration::from_secs(180));
    assert_eq!(TimerConfig::default().timer_c(), DEFAULT_TIMER_C);
    let unset: crate::config::TransactionConfig =
        serde_yaml_ng::from_str("{}").expect("an empty transaction block parses");
    assert_eq!(
        Duration::from_secs(u64::from(unset.timer_c_secs)),
        DEFAULT_TIMER_C
    );
}

/// `transaction.timer_c_secs` reaches the timer: the configured value is what
/// the transaction sets Timer C for.
#[test]
fn the_configured_timer_c_is_what_the_transaction_runs() {
    let configured: crate::config::TransactionConfig =
        serde_yaml_ng::from_str("timer_c_secs: 240").expect("the transaction block parses");
    let timers = TimerConfig {
        timer_c_secs: configured.timer_c_secs,
        ..TimerConfig::default()
    };
    assert_eq!(timers.timer_c(), Duration::from_secs(240));
    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    let set = timer_c_set(&feed(&manager, &key, IctEvent::TimerB)).expect("Timer C is set");
    assert!(
        within_a_second_of(set, Duration::from_secs(240)),
        "240 s from the 180: {set:?}"
    );

    // Never less than Timer B, which is the INVITE's own bound until then.
    let short = TimerConfig {
        timer_c_secs: 5,
        ..TimerConfig::default()
    };
    assert_eq!(short.timer_c(), short.timer_b());
}

/// A call answered, or failed, inside Timer B never sees Timer C: nothing is
/// started for it and nothing has to be stopped.
#[test]
fn a_transaction_that_ends_within_timer_b_never_starts_timer_c() {
    let (manager, key, started_with) = started(TimerConfig::default());
    assert!(timer_c_set(&started_with).is_none());
    let ringing = feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    assert!(timer_c_set(&ringing).is_none());
    let answered = feed(&manager, &key, IctEvent::Response2xx(response(200, "OK")));
    assert!(!answered
        .iter()
        .any(|action| matches!(action, Action::CancelTimer(TimerName::C))));
}

/// Timer B finds the INVITE with a provisional: Timer C takes over, counted
/// from when the INVITE was forwarded if all it has had is a `100`, and from
/// its last 101-199 otherwise.
#[test]
fn timer_b_hands_a_transaction_with_a_provisional_to_timer_c() {
    let timers = TimerConfig::default();
    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(100, "Trying")),
    );
    let set = timer_c_set(&feed(&manager, &key, IctEvent::TimerB)).expect("Timer C is set");
    assert!(
        within_a_second_of(set, timers.timer_c() - timers.timer_b()),
        "what is left of Timer C since the INVITE went: {set:?}"
    );
    assert_eq!(manager.count(), 1, "the transaction lives on");

    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(183, "Session Progress")),
    );
    let set = timer_c_set(&feed(&manager, &key, IctEvent::TimerB)).expect("Timer C is set");
    assert!(within_a_second_of(set, timers.timer_c()), "{set:?}");
}

/// RFC 3261 §16.7 step 2: a 101-199 resets Timer C; a `100` does not.
#[test]
fn a_101_to_199_provisional_resets_timer_c_and_a_100_does_not() {
    let timers = TimerConfig::default();
    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    feed(&manager, &key, IctEvent::TimerB);

    // Time passes, the callee reports progress again, and Timer C comes due.
    manager.age_invite_client(&key, timers.timer_c());
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(183, "Session Progress")),
    );
    let actions = feed(&manager, &key, IctEvent::TimerC);
    assert!(cancels_in(&actions).is_empty(), "reset, not fired");
    let set = timer_c_set(&actions).expect("set again");
    assert!(within_a_second_of(set, timers.timer_c()), "{set:?}");

    // The same with nothing but a 100 in between: it runs out.
    manager.age_invite_client(&key, timers.timer_c());
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(100, "Trying")),
    );
    let actions = feed(&manager, &key, IctEvent::TimerC);
    assert_eq!(cancels_in(&actions).len(), 1, "fired");
}

/// RFC 3261 §16.8: Timer C firing on a transaction with a provisional sends
/// its CANCEL, built from the INVITE and addressed where that went. The `487`
/// it draws ends the transaction like any final response.
#[test]
fn timer_c_running_out_cancels_the_invite() {
    let timers = TimerConfig::default();
    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    feed(&manager, &key, IctEvent::TimerB);
    manager.age_invite_client(&key, timers.timer_c());

    let actions = feed(&manager, &key, IctEvent::TimerC);
    let cancels = cancels_in(&actions);
    assert_eq!(cancels.len(), 1);
    assert_eq!(cancels[0].hop, hop());
    let cancel =
        crate::sip::parser::parse_sip_message_bytes(&cancels[0].frame).expect("the CANCEL parses");
    assert_eq!(cancel.method(), Some(&Method::Cancel));
    assert_eq!(
        cancel.headers.get_all("Via").cloned(),
        invite().headers.get_all("Via").cloned()
    );
    assert_eq!(
        timer_c_set(&actions),
        Some(timers.timer_b()),
        "64*T1 for the final response to arrive (RFC 3261 §9.1)"
    );
    // The TU asking again sends no second CANCEL.
    assert!(matches!(
        manager.cancel_invite_client(&key, &[]),
        CancelOutcome::NothingToSend
    ));

    let actions = feed(
        &manager,
        &key,
        IctEvent::ResponseNon2xx(response(487, "Request Terminated")),
    );
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::CancelTimer(TimerName::C))));
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::PassToTu(_))));
    feed(&manager, &key, IctEvent::TimerD);
    assert_eq!(manager.count(), 0);
}

/// The CANCELled INVITE never gets its final response: after 64*T1 the
/// transaction ends as a timeout, which the proxy answers the branch with as
/// a `408` (RFC 3261 §9.1, §16.7 step 2).
#[test]
fn a_cancelled_invite_that_stays_silent_ends_as_a_timeout() {
    let timers = TimerConfig::default();
    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    feed(&manager, &key, IctEvent::TimerB);
    manager.age_invite_client(&key, timers.timer_c());
    feed(&manager, &key, IctEvent::TimerC);

    let actions = feed(&manager, &key, IctEvent::TimerC);
    assert!(cancels_in(&actions).is_empty());
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Timeout)));
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Terminated)));
    assert_eq!(manager.count(), 0, "the transaction is gone");
}

/// A transaction the TU already CANCELled, whose far end then went silent, is
/// bounded the same way, and is not CANCELled twice.
#[test]
fn timer_c_does_not_cancel_an_invite_already_cancelled() {
    let timers = TimerConfig::default();
    let (manager, key, _) = started(timers);
    feed(
        &manager,
        &key,
        IctEvent::Provisional(response(180, "Ringing")),
    );
    assert!(matches!(
        manager.cancel_invite_client(&key, &[]),
        CancelOutcome::SendNow(_)
    ));
    feed(&manager, &key, IctEvent::TimerB);
    manager.age_invite_client(&key, timers.timer_c());
    let actions = feed(&manager, &key, IctEvent::TimerC);
    assert!(cancels_in(&actions).is_empty(), "one CANCEL per INVITE");
    assert_eq!(timer_c_set(&actions), Some(timers.timer_b()));
    let actions = feed(&manager, &key, IctEvent::TimerC);
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Timeout)));
    assert_eq!(manager.count(), 0);
}

/// A final response stops a running Timer C.
#[test]
fn a_final_response_stops_a_running_timer_c() {
    for success in [true, false] {
        let (manager, key, _) = started(TimerConfig::default());
        feed(
            &manager,
            &key,
            IctEvent::Provisional(response(180, "Ringing")),
        );
        feed(&manager, &key, IctEvent::TimerB);
        let actions = if success {
            feed(&manager, &key, IctEvent::Response2xx(response(200, "OK")))
        } else {
            feed(
                &manager,
                &key,
                IctEvent::ResponseNon2xx(response(486, "Busy Here")),
            )
        };
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::CancelTimer(TimerName::C))));
    }
}

/// An INVITE with no response at all is Timer B's: it ends there, as before,
/// and Timer C never comes into it.
#[test]
fn an_invite_with_no_response_is_still_ended_by_timer_b() {
    let (manager, key, _) = started(TimerConfig::default());
    let actions = feed(&manager, &key, IctEvent::TimerB);
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Timeout)));
    assert!(timer_c_set(&actions).is_none());
    assert_eq!(manager.count(), 0);
}
