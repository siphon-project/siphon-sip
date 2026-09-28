//! The ACK siphon re-sends when a callee retransmits the 2xx to an offerless
//! originate.
//!
//! An originate that anchors its media goes out with no offer, so the callee
//! offers in its 2xx and siphon's answer rides on the ACK (RFC 3261 §13.2.2.4,
//! RFC 3264 §5). A callee that did not get that ACK retransmits the 2xx, and the
//! ACK it is re-sent has to be the same one: re-ACKing without the answer leaves
//! the callee's offer unanswered, which is a connected call with no media.

use super::originate_test_harness::{
    anchored_dispatcher, anchored_params, drain, phone_offer, phone_response, phone_sends,
    requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::{NativeTestEngine, NATIVE_ENGINE_ANSWER};

const PHONE: &str = "198.51.100.31:5060";

fn body_text(message: &SipMessage) -> &str {
    std::str::from_utf8(&message.body).expect("a text body")
}

/// RFC 3261 §13.2.2.4: a retransmitted 2xx is re-ACKed with the answer the
/// first ACK carried.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_2xx_is_re_acked_with_the_same_answer() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let prepared = prepare_originate(
        &dispatcher.state,
        anchored_params(&format!("sip:2001@{PHONE}")),
    )
    .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Invite)
        .pop()
        .expect("siphon sent the phone an INVITE")
        .message;
    assert!(
        invite.body.is_empty(),
        "an anchored originate goes out offerless"
    );

    let answered = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:2001@{PHONE}"),
        Some(&phone_offer("198.51.100.31")),
    );
    phone_sends(&dispatcher.state, socket(PHONE), &answered);
    let first = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Ack);
    assert_eq!(first.len(), 1, "the 2xx is ACKed once");
    // Positive control: the first ACK carries the engine's answer.
    assert_eq!(body_text(&first[0].message), NATIVE_ENGINE_ANSWER);
    assert_eq!(
        first[0]
            .message
            .headers
            .get("Content-Type")
            .map(String::as_str),
        Some("application/sdp")
    );

    // The phone did not get it and retransmits the 2xx.
    phone_sends(&dispatcher.state, socket(PHONE), &answered);
    let again = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Ack);
    assert_eq!(again.len(), 1, "the retransmitted 2xx is ACKed again");
    assert_eq!(
        body_text(&again[0].message),
        NATIVE_ENGINE_ANSWER,
        "the re-sent ACK must carry the answer to the phone's offer"
    );
    assert_eq!(
        again[0]
            .message
            .headers
            .get("Content-Type")
            .map(String::as_str),
        Some("application/sdp")
    );
    // Nothing else was re-done: the engine answered once.
    assert_eq!(engine.commands("answer_local").len(), 1);
}

/// An originate that carried its own offer gets the answer in the 2xx, so its
/// ACK carries nothing, first time or again.
#[tokio::test(flavor = "multi_thread")]
async fn an_offered_originate_re_acks_with_no_body() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let mut params = anchored_params(&format!("sip:2002@{PHONE}"));
    params.media = OriginateMedia::Offer {
        body: phone_offer("192.0.2.1").into_bytes(),
        content_type: "application/sdp".to_string(),
    };
    let prepared = prepare_originate(&dispatcher.state, params).expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Invite)
        .pop()
        .expect("siphon sent the phone an INVITE")
        .message;

    let answered = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:2002@{PHONE}"),
        Some(&phone_offer("198.51.100.31")),
    );
    phone_sends(&dispatcher.state, socket(PHONE), &answered);
    phone_sends(&dispatcher.state, socket(PHONE), &answered);
    let acks = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Ack);
    assert_eq!(acks.len(), 2);
    assert!(acks.iter().all(|ack| ack.message.body.is_empty()));
    assert!(engine.commands("answer_local").is_empty());
}
