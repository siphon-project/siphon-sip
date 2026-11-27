//! The `200` to an offerless re-INVITE repeats the session in force, which is
//! an offer: it is retransmitted until the caller's ACK answers it, and a
//! caller that never ACKs has its call ended (RFC 3261 §13.3.1.4), by the same
//! machinery the initial 2xx uses.

use super::control_dial_delayed_offer_tests::{
    refreshed_dial, relayed_200, to_caller, DelayedDial, CALLER_ANSWER, PHONE,
};
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
        cseq: None,
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

/// A late duplicate ACK of the first INVITE (CSeq 1) names the dialog of the
/// refresh outstanding (CSeq 3) but does not answer it: the refresh's 200 keeps
/// being retransmitted and 64*T1 still ends the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_ack_leaves_the_refresh_retransmission_and_deadline_running() {
    let (dial, _caller_200, refreshed) = refreshed_dial("3 INVITE").await;
    let (inbound, stale) = dial.caller_request("ACK", "1 ACK", &refreshed, Some(CALLER_ANSWER));
    handle_request(inbound, stale, "ACK".to_string(), &dial.state);
    assert!(
        !dial.state.uas_2xx_retransmits.is_empty(),
        "the refresh's 200 is still waiting for its own ACK"
    );
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    assert!(
        dial.wire()
            .iter()
            .any(|sent| sent.message.status_code() == Some(200)),
        "the 200 is still retransmitted"
    );

    let dialog = refreshed.headers.call_id().expect("a Call-ID").to_string();
    let expired = Arc::new(UnackedAnswer {
        cseq: None,
        cancel: tokio::sync::Notify::new(),
        deadline: tokio::time::Instant::now() - std::time::Duration::from_secs(1),
        internal_call_id: dial.call_id.clone(),
    });
    dial.state
        .uas_2xx_retransmits
        .insert(dialog, expired)
        .expect("still registered");
    sweep_unacked_uas_2xx(&dial.state);
    assert!(
        to_caller(&dial.wire())
            .iter()
            .any(|sent| sent.is(Method::Bye)),
        "64*T1 still ends the call"
    );
}

/// The ACK that answers the refresh can reach another worker the moment its
/// marker is visible (a retransmitted INVITE replays the 200 from it). The
/// 200's entry for that ACK is registered first, so the ACK removes it: no
/// acknowledged exchange is left registered for the sweep to tear a healthy
/// call down over.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_arriving_once_the_marker_is_visible_finds_the_registered_entry() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());
    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    dial.wire();
    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &caller_200, Some(CALLER_ANSWER));
    let state = Arc::clone(&dial.state);
    crate::dispatcher::on_marker_published(
        &dial.call_id,
        Box::new(move |_| {
            handle_request(inbound.clone(), ack.clone(), "ACK".to_string(), &state);
        }),
    );
    dial.refresh("2 INVITE", &caller_200);
    assert!(
        dial.state.uas_2xx_retransmits.is_empty(),
        "the ACK took the entry; nothing is left to be swept"
    );
    assert!(dial
        .state
        .call_actors
        .get_call(&dial.call_id)
        .is_some_and(|call| call.pending_refresh_answer.is_none()));
    sweep_unacked_uas_2xx(&dial.state);
    assert!(dial.call_is_up());
}
