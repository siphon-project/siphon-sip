//! The `200` to an offerless re-INVITE repeats the session in force, which is
//! an offer: it is retransmitted until the caller's ACK answers it, and a
//! caller that never ACKs has its call ended (RFC 3261 §13.3.1.4), by the same
//! machinery the initial 2xx uses.

use super::control_dial_delayed_offer_tests::{refreshed_dial, to_caller, CALLER_ANSWER};
use super::*;

/// Copies of the refresh's 200 reach the caller until its ACK stops them.
#[tokio::test(flavor = "multi_thread")]
async fn the_refresh_200_is_retransmitted_until_the_ack() {
    let (dial, _caller_200, refreshed) = refreshed_dial("2 INVITE").await;
    // T1 is 500 ms: the first copy follows by then.
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let copies: Vec<_> = dial
        .wire()
        .into_iter()
        .filter(|sent| sent.message.status_code() == Some(200))
        .collect();
    assert!(
        !copies.is_empty(),
        "the 200 is sent again while no ACK came"
    );
    assert_eq!(copies[0].message.body, refreshed.body);

    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &refreshed, Some(CALLER_ANSWER));
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);
    dial.wire();
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(
        to_caller(&dial.wire())
            .iter()
            .all(|sent| sent.message.status_code() != Some(200)),
        "the ACK stopped the retransmission"
    );
    assert!(
        dial.state.uas_2xx_retransmits.is_empty(),
        "nothing left registered for the 2xx"
    );
    assert!(dial
        .state
        .call_actors
        .get_call(&dial.call_id)
        .is_some_and(|call| call.pending_refresh_answer.is_none()));
}

/// At 64*T1 with no ACK the caller is sent a BYE, the marker is gone and the
/// engine call deleted.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_200_never_acked_ends_the_call_at_the_deadline() {
    let (dial, _caller_200, refreshed) = refreshed_dial("2 INVITE").await;
    // Push the registered 2xx past its deadline instead of waiting 32 s.
    let dialog = refreshed.headers.call_id().expect("a Call-ID").to_string();
    let expired = Arc::new(UnackedAnswer {
        cancel: tokio::sync::Notify::new(),
        deadline: tokio::time::Instant::now() - std::time::Duration::from_secs(1),
        internal_call_id: dial.call_id.clone(),
    });
    let replaced = dial
        .state
        .uas_2xx_retransmits
        .insert(dialog, expired)
        .expect("the refresh's 200 is registered for its ACK");
    replaced.cancel.notify_one();
    sweep_unacked_uas_2xx(&dial.state);
    assert!(
        to_caller(&dial.wire())
            .iter()
            .any(|sent| sent.is(Method::Bye)),
        "the caller is sent a BYE"
    );
    dial.deleted(1).await;
    assert!(!dial.call_is_up());
    assert!(dial.state.uas_2xx_retransmits.is_empty());
}
