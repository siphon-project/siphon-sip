//! Whose policy pins a party's media ingress on an anchored call with a
//! delayed offer (RFC 3264 §4), and how its media session names the two
//! parties once the caller has answered.
//!
//! The callee offers in its 2xx and the caller answers in its ACK, so each
//! party's SDP rides the command the other's rides on an ordinary call. That
//! changes nothing about whose policy is whose: a profile is chosen for the
//! dial before anyone knows which party will offer, its `offer` half written
//! for the party that sent the INVITE and its `answer` half for the party
//! dialled. The caller's answer is pinned where the `offer` half asks.
//!
//! Once answered the session names the caller first, as every session does,
//! so a later re-offer names the party that sent it and reads that party's
//! policy.

use super::delayed_offer_ack_tests::{
    relayed_answer, OfferlessCall, CALLEE, CALLEE_OFFER, CALLER, CALLER_ANSWER, CALLER_CALL_ID,
};
use super::dial_bridge_test_harness::in_dialog_response;
use super::lcr_ring_timeout_tests::top_via_branch;
use super::reoffer_ingress_tests::{last_on, reoffers, Party};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::transfer_ingress_tests::{
    ip, profiles, sdp_naming, OPEN, PINNED, PINS_ANSWERER, PINS_OFFERER, SIGNALLED,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// The caller's offerless call, dialled and answered by the callee with an
/// offer the engine holds under `profile` as `rtpengine.answer` leaves it: the
/// callee as the offerer, no answerer yet.
async fn offered_by_the_callee(engine: &NativeTestEngine, profile: &str) -> OfferlessCall {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script("");
    let registry = profiles();
    let backend = engine.backend();
    backend
        .offer(
            CALLER_CALL_ID,
            "callee-tag",
            CALLEE_OFFER.as_bytes(),
            &registry.get(profile).expect("a known profile").offer,
        )
        .await
        .expect("the engine takes the callee's offer");
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    sessions.insert(crate::rtpengine::MediaSession {
        call_id: CALLER_CALL_ID.to_string(),
        rtpengine_call_id: CALLER_CALL_ID.to_string(),
        from_tag: "callee-tag".to_string(),
        to_tag: None,
        profile: profile.to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    state.rtpengine_set = Some(backend);
    state.rtpengine_profiles = Some(registry);
    state.rtpengine_sessions = Some(sessions);
    let call = OfferlessCall::dial_on(TestDispatcher { state, udp });
    call.callee_answers_with_an_offer();
    call
}

/// (profile, the caller is pinned, the callee is pinned): the caller by the
/// `offer` half, the callee by the `answer` half.
const POLICIES: [(&str, bool, bool); 4] = [
    (PINS_OFFERER, true, false),
    (PINS_ANSWERER, false, true),
    (PINNED, true, true),
    (OPEN, false, false),
];

/// The caller's answer in its ACK completes the callee's offer on the engine.
/// It is the caller's SDP: pinned to where the caller signals from when the
/// caller's own half asks, not when the half that shapes the command does,
/// and not left without a hint. The command is shaped for the callee, which
/// the result is sent to in its ACK: by the `offer` half, as everything the
/// callee of a dial is sent.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_answer_to_a_delayed_offer_is_pinned_by_the_callers_own_policy() {
    for (profile, caller_pinned, _) in POLICIES {
        let engine = NativeTestEngine::start().await;
        let call = offered_by_the_callee(&engine, profile).await;
        let relayed = relayed_answer(&call.wire());

        call.caller_acks(&relayed, Some(CALLER_ANSWER));
        let answer = last_on(&engine, "answer", CALLER_CALL_ID);
        assert_eq!(
            answer.received_from,
            caller_pinned.then(|| ip(CALLER)),
            "{profile}: the answer carries the caller's SDP"
        );
        assert_eq!(
            answer.from_tag, "callee-tag",
            "answering the callee's offer"
        );
        assert_eq!(answer.sip_call_id.as_deref(), Some(CALLER_CALL_ID));
        assert_eq!(
            answer.transport_protocol.as_deref(),
            Some("RTP/SAVP"),
            "{profile}: the result goes to the callee, shaped by the half that describes it"
        );
        let session = call
            .state
            .rtpengine_sessions
            .as_ref()
            .and_then(|sessions| sessions.get(CALLER_CALL_ID))
            .expect("the media session");
        assert_eq!(
            session.from_tag, "caller-tag",
            "{profile}: the caller first"
        );
        assert_eq!(
            session.to_tag.as_deref(),
            Some("callee-tag"),
            "{profile}: then the callee"
        );
    }
}

/// After a delayed offer either party's re-INVITE reaches the engine as that
/// party's own re-offer, under its own tag, pinned by its own policy. Named
/// by the other's tag the engine would take the offer for the other party's
/// and re-point the wrong side of the relay.
#[tokio::test(flavor = "multi_thread")]
async fn a_reoffer_after_a_delayed_offer_names_and_pins_the_party_that_sent_it() {
    for (profile, caller_pinned, callee_pinned) in POLICIES {
        let engine = NativeTestEngine::start().await;
        let call = offered_by_the_callee(&engine, profile).await;
        let relayed = relayed_answer(&call.wire());
        call.caller_acks(&relayed, Some(CALLER_ANSWER));
        let _ = call.wire();

        // The caller holds.
        let hold = sdp_naming(SIGNALLED);
        let (arrived, reinvite) = call.caller_request("INVITE", "2 INVITE", &relayed, Some(&hold));
        handle_b2bua_reinvite(arrived, reinvite, &call.state);
        let reoffer = last_on(&engine, "reoffer", CALLER_CALL_ID);
        assert_eq!(
            reoffer.from_tag, "caller-tag",
            "{profile}: the caller's own"
        );
        assert_eq!(
            reoffer.received_from,
            caller_pinned.then(|| ip(CALLER)),
            "{profile}: the re-offer carries the caller's SDP"
        );
        let to_callee = call
            .wire()
            .into_iter()
            .find(|sent| sent.destination.to_string() == CALLEE && sent.is(Method::Invite))
            .expect("the hold is relayed to the callee")
            .message;
        let mut accepted = in_dialog_response(
            &to_callee,
            200,
            "OK",
            &format!("sip:callee@{CALLEE}"),
            Some(&sdp_naming(SIGNALLED)),
        );
        assert!(handle_b2bua_response(
            &call.call_id,
            &top_via_branch(&to_callee),
            &mut accepted,
            200,
            CALLEE.parse().expect("a literal address"),
            &call.state,
        ));
        let answer = last_on(&engine, "answer", CALLER_CALL_ID);
        assert_eq!(
            answer.received_from,
            callee_pinned.then(|| ip(CALLEE)),
            "{profile}: the answer carries the callee's SDP"
        );
        let _ = call.wire();

        // The callee re-offers in its own dialog.
        let header = |name: &str| {
            call.invite
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("siphon's INVITE has a {name}"))
        };
        let callee = Party {
            address: CALLEE.to_string(),
            from: format!("{};tag=callee-tag", header("To")),
            to: header("From"),
            call_id: header("Call-ID"),
        };
        reoffers(&call.state, &callee, "INVITE", 2);
        let reoffer = last_on(&engine, "reoffer", CALLER_CALL_ID);
        assert_eq!(
            reoffer.from_tag, "callee-tag",
            "{profile}: the callee's own"
        );
        assert_eq!(
            reoffer.received_from,
            callee_pinned.then(|| ip(CALLEE)),
            "{profile}: the re-offer carries the callee's SDP"
        );
        assert!(
            call.wire()
                .iter()
                .any(|sent| sent.destination.to_string() == CALLER && sent.is(Method::Invite)),
            "{profile}: and is relayed to the caller"
        );

        call.caller_hangs_up(&relayed);
        assert_eq!(call.state.call_actors.count(), 0, "{profile}");
    }
}
