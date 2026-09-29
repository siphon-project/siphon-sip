//! The media ingress an anchored originate pins when the callee answers.
//!
//! An offerless originate is anchored on the callee's 2xx offer with the
//! engine's `answer_local`. A profile that asks for `received_from` pins the
//! leg's media to the address its signalling came from, as every other
//! anchoring path does: the SDP address alone is what a phone behind NAT gets
//! wrong.

use super::originate_test_harness::{
    anchored_dispatcher, anchored_params, drain, phone_offer, phone_response, phone_sends,
    pinned_ingress_profiles, requests_to, socket, PINNED_INGRESS,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Place an anchored originate to `phone` with `profile`, have the phone answer
/// from `source` with an offer naming `sdp_host`, and return the engine's
/// `received_from` on the `answer_local` that anchored it.
async fn anchor_answered_from(
    phone: &str,
    source: &str,
    sdp_host: &str,
    profile: &str,
) -> Option<std::net::IpAddr> {
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = anchored_dispatcher(&engine);
    dispatcher.state.rtpengine_profiles = Some(pinned_ingress_profiles());
    let mut params = anchored_params(&format!("sip:2101@{phone}"));
    params.media = OriginateMedia::Anchor {
        profile: profile.to_string(),
        ws_uri: None,
    };
    let prepared = prepare_originate(&dispatcher.state, params).expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(phone), Method::Invite)
        .pop()
        .expect("siphon sent the phone an INVITE")
        .message;
    let answered = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:2101@{phone}"),
        Some(&phone_offer(sdp_host)),
    );
    phone_sends(&dispatcher.state, socket(source), &answered);
    let anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 1, "the 2xx offer was anchored once");
    anchored[0].received_from
}

/// A profile carrying `received_from` pins the originated leg's media to the
/// address the callee's 2xx came from.
#[tokio::test(flavor = "multi_thread")]
async fn an_answered_originate_pins_ingress_to_the_callee_signalling_source() {
    const PHONE: &str = "198.51.100.41:5060";
    let received_from = anchor_answered_from(PHONE, PHONE, "198.51.100.41", PINNED_INGRESS).await;
    assert_eq!(received_from, Some(socket(PHONE).ip()));
}

/// Positive control: a profile that does not ask for it sends none.
#[tokio::test(flavor = "multi_thread")]
async fn an_answered_originate_sends_no_ingress_the_profile_does_not_ask_for() {
    const PHONE: &str = "198.51.100.42:5060";
    let received_from =
        anchor_answered_from(PHONE, PHONE, "198.51.100.42", "rtp_passthrough").await;
    assert_eq!(received_from, None);
}

/// A callee behind NAT offers the address it believes it has; the pin is the
/// address its answer actually arrived from, never the one in its SDP.
#[tokio::test(flavor = "multi_thread")]
async fn the_pin_is_the_signalling_source_not_the_sdp_address() {
    const PHONE: &str = "198.51.100.43:5060";
    const NAT_SOURCE: &str = "203.0.113.43:40123";
    let received_from =
        anchor_answered_from(PHONE, NAT_SOURCE, "192.0.2.243", PINNED_INGRESS).await;
    assert_eq!(received_from, Some(socket(NAT_SOURCE).ip()));
}
