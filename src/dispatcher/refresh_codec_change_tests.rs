//! The caller's ACK answers the offer an offerless re-INVITE's `200` repeated.
//! The engine takes it on the ports the caller was told. An answer it can take
//! only by replacing the session (a changed codec: new ports, attachments
//! dropped) would leave the caller signalled with the old ones, so the call
//! ends instead of carrying on mis-signalled.

use super::delayed_offer_answer_tests::OfferlessCall;
use super::originate_test_harness::socket;
use super::*;
use crate::b2bua::actor::PendingRefreshAnswer;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const CALLER_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.40\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.40\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
);

/// A call the engine answers itself, with an offerless refresh outstanding
/// whose ACK will carry CSeq 1.
async fn call_with_refresh_outstanding(sip_call_id: &str) -> (OfferlessCall, SipMessage) {
    let call = OfferlessCall::park(
        NativeTestEngine::start_with_offer_local().await,
        sip_call_id,
    );
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    call.acks(&two_xx, Some(CALLER_ANSWER));
    call.state.call_actors.expect_refresh_answer(
        &call.call_id,
        PendingRefreshAnswer::new(1, "z9hG4bK-refresh".to_string(), two_xx.clone()),
    );
    (call, two_xx)
}

/// An answer in the same codec reaches the engine as a re-offer on the live
/// session, and the call carries on.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_engine_takes_in_place_keeps_the_session() {
    let (call, two_xx) = call_with_refresh_outstanding("dly-codec-1").await;
    let moved = CALLER_ANSWER.replace("m=audio 40000", "m=audio 41000");
    call.acks(&two_xx, Some(&moved));
    assert_eq!(call.engine.commands("reoffer").len(), 1);
    assert!(call.engine.commands("offer").is_empty());
    assert!(call.call_is_up());
}

/// An answer the engine can take only by replacing the session ends the call:
/// BYE, the engine call deleted, and no replacement `offer` ever sent.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_would_replace_the_session_ends_the_call() {
    let (call, two_xx) = call_with_refresh_outstanding("dly-codec-2").await;
    call.wire();
    let changed = format!("{CALLER_ANSWER}a=x-test-codec-change\r\n");
    call.acks(&two_xx, Some(&changed));
    assert_eq!(call.engine.commands("reoffer").len(), 1, "asked in place");
    assert!(
        call.engine.commands("offer").is_empty(),
        "never a replacement offer behind the caller's back"
    );
    assert!(
        call.wire()
            .iter()
            .any(|sent| sent.message.method() == Some(&Method::Bye)
                && sent.destination == socket("192.0.2.40:5060")),
        "the caller is sent a BYE"
    );
    call.deleted(1).await;
    assert!(!call.call_is_up());
}
