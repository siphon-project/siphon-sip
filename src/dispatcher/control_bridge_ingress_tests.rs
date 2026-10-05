//! Whose profile decides that a bridged party's media ingress is pinned to its
//! signalling source.
//!
//! Every engine command of a bridge carries one party's SDP and is shaped by
//! the profile half of the party the result goes to, which is the *other* one.
//! The `received_from` hint is about the party whose SDP the command carries:
//! it names where that party's media really comes from, which behind NAT is
//! not the address its SDP names. So the hint follows that party's own profile
//! and the shaping the other's, and a pair profile, which describes both,
//! decides both.
//!
//! The parties here are bridged by a dial, the way an answered caller is joined
//! to a phone, and by the `bridge` verb. The proof is the command the
//! in-process engine records: a party that sends media from the address it
//! signals cannot show the difference on the wire.

use std::sync::Arc;

use super::control_bridge_media_tests::{
    accepts, bridge_offer_to, caller_accepts, host, last, stored,
};
use super::control_bridge_relay_tests::{
    accept_with, deliver, finals_to, request, sdp_from, wait_for, Pair,
};
use super::dial_bridge_test_harness::{
    answered_caller_from, bridging_dispatcher, command, controller_owning, dial, eventually,
    in_dialog_response, invite_to, reinvites_to, CALLER,
};
use super::originate_test_harness::{drain, phone_offer, phone_response, phone_sends, socket};
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Plain RTP, no source hint on either half.
pub(super) const OPEN_PLAIN: &str = "open_plain";
/// Plain RTP, the source hint on both halves.
pub(super) const PINNED_PLAIN: &str = "pinned_plain";
/// SRTP, no source hint on either half.
pub(super) const OPEN_SECURE: &str = "open_secure";
/// SRTP, the source hint on both halves.
pub(super) const PINNED_SECURE: &str = "pinned_secure";
/// A pair profile whose `offer` half alone asks for the hint: the party whose
/// SDP the offer carries (the anchor) is pinned, the answering one is not.
const PAIR_PINS_OFFERER: &str = "pair_pins_offerer";
/// A pair profile whose `answer` half alone asks for it.
const PAIR_PINS_ANSWERER: &str = "pair_pins_answerer";

/// The address the phone's SDP names. It stands for the private address a
/// party behind NAT signals: not where its signalling, or its media, comes
/// from.
const SIGNALLED: &str = "203.0.113.77";

/// The built-in profiles plus the six above.
pub(super) fn profiles() -> Arc<crate::rtpengine::ProfileRegistry> {
    let half = |transport: &str, received_from: bool| crate::config::NgFlagsConfig {
        transport_protocol: Some(transport.to_string()),
        received_from,
        ..Default::default()
    };
    let both = |transport: &str, received_from: bool| crate::config::MediaProfileConfig {
        offer: half(transport, received_from),
        answer: half(transport, received_from),
    };
    let pair = |offer: bool, answer: bool| crate::config::MediaProfileConfig {
        offer: half("RTP/AVP", offer),
        answer: half("RTP/AVP", answer),
    };
    let mut custom = std::collections::HashMap::new();
    custom.insert(OPEN_PLAIN.to_string(), both("RTP/AVP", false));
    custom.insert(PINNED_PLAIN.to_string(), both("RTP/AVP", true));
    custom.insert(OPEN_SECURE.to_string(), both("RTP/SAVP", false));
    custom.insert(PINNED_SECURE.to_string(), both("RTP/SAVP", true));
    custom.insert(PAIR_PINS_OFFERER.to_string(), pair(true, false));
    custom.insert(PAIR_PINS_ANSWERER.to_string(), pair(false, true));
    Arc::new(crate::rtpengine::ProfileRegistry::from_config(&custom))
}

/// A caller answered with `caller_profile`, bridged by a dial to a phone rung
/// with `phone_profile`. The phone signals from `phone` and names
/// [`SIGNALLED`] in every SDP it sends.
async fn bridged(
    app: &str,
    phone: &'static str,
    caller_profile: &str,
    phone_profile: &str,
) -> Pair {
    let contact = format!("sip:ingress@{phone}");
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = bridging_dispatcher(&engine);
    dispatcher.state.rtpengine_profiles = Some(profiles());
    let caller = answered_caller_from(
        &dispatcher,
        &format!("{app}@192.0.2.10"),
        CALLER,
        caller_profile,
    );
    let controller = controller_owning(app, dispatcher, &caller, app, "hangup");
    let (reply, _) = dial(
        &controller,
        app,
        serde_json::json!({ "targets": [contact], "on_answer": "bridge", "profile": phone_profile }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let invite = invite_to(&drain(udp), phone);
    phone_sends(
        state,
        socket(phone),
        &phone_response(
            &invite,
            200,
            "OK",
            &format!("tag-{}", host(phone)),
            &contact,
            Some(&phone_offer(SIGNALLED)),
        ),
    );
    let offer = bridge_offer_to(udp, phone).await;
    let pair_call_id = last(&engine, "offer").call_id;
    phone_sends(
        state,
        socket(phone),
        &in_dialog_response(&offer, 200, "OK", &contact, Some(&phone_offer(SIGNALLED))),
    );
    caller_accepts(state, udp, &caller).await;
    assert!(eventually(|| state.dial_bridges.ringing_count() == 0).await);
    assert!(
        eventually(|| engine.held_count() == 1).await,
        "the bridge formed"
    );
    drain(udp);
    Pair {
        controller,
        engine,
        caller,
        phone,
        contact,
        phone_dialog: offer,
        pair_call_id,
        carrier_cseq: std::cell::Cell::new(10),
        phone_cseq: std::cell::Cell::new(10),
    }
}

/// The reported failure. The caller was answered with a profile that does not
/// ask for the hint, the phone rung with one that does, and the phone's SDP
/// names an address its media does not come from. The engine is given the
/// phone's answer pinned to the phone's signalling source, by the phone's own
/// profile; without it the engine expects the phone's media from the address
/// in its SDP and both directions are silent.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridged_peer_is_pinned_to_its_signalling_source_by_its_own_profile() {
    const PHONE: &str = "198.51.100.191:5060";
    let pair = bridged("ingress-peer", PHONE, OPEN_PLAIN, PINNED_SECURE).await;

    let pickup = last(&pair.engine, "answer_local");
    assert_eq!(
        pickup.received_from,
        Some(socket(PHONE).ip()),
        "positive control: the phone's own anchor is pinned"
    );
    let answer = last(&pair.engine, "answer");
    assert_eq!(answer.call_id, pair.pair_call_id);
    assert_eq!(
        answer.received_from,
        Some(socket(PHONE).ip()),
        "the phone's answer is pinned to where the phone signals from"
    );
    assert_ne!(
        answer.received_from,
        SIGNALLED.parse().ok(),
        "never to the address its SDP names"
    );
    assert_eq!(
        answer.transport_protocol.as_deref(),
        Some("RTP/AVP"),
        "the caller's own profile still shapes what the caller is re-INVITEd with"
    );
}

/// The same bridge from the caller's side: the offer carries the caller's
/// SDP, and the caller's profile does not ask for the hint. The phone's
/// profile, which shapes that offer, does not get to pin the caller: a caller
/// whose media comes from another address than its signalling would be gated
/// out.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridged_anchor_is_not_pinned_by_the_peers_profile() {
    const PHONE: &str = "198.51.100.192:5060";
    let pair = bridged("ingress-anchor-open", PHONE, OPEN_PLAIN, PINNED_SECURE).await;
    let offer = last(&pair.engine, "offer");
    assert_eq!(offer.call_id, pair.pair_call_id);
    assert_eq!(
        offer.received_from, None,
        "the caller's profile asks for no hint"
    );
    assert_eq!(
        offer.transport_protocol.as_deref(),
        Some("RTP/SAVP"),
        "the phone's own profile still shapes what the phone is offered"
    );
}

/// The mirror image: the caller's profile asks for the hint and the phone's
/// does not. The caller is pinned on the offer that carries its SDP, and the
/// phone is not pinned on its answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridged_anchor_is_pinned_by_its_own_profile_and_the_peer_by_its_own() {
    const PHONE: &str = "198.51.100.193:5060";
    let pair = bridged("ingress-anchor-pinned", PHONE, PINNED_PLAIN, OPEN_SECURE).await;
    let offer = last(&pair.engine, "offer");
    assert_eq!(
        offer.received_from,
        Some(socket(CALLER).ip()),
        "the caller's own profile pins the caller"
    );
    assert_eq!(offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
    let answer = last(&pair.engine, "answer");
    assert_eq!(
        answer.received_from, None,
        "the phone's profile asks for no hint, so the caller's does not pin the phone"
    );
    assert_eq!(answer.transport_protocol.as_deref(), Some("RTP/AVP"));
    assert_eq!(
        last(&pair.engine, "answer_local").received_from,
        None,
        "positive control: the phone's own anchor is not pinned either"
    );
}

/// The positive control for the three above: two parties whose profiles ask
/// for no hint are sent none, on any command.
#[tokio::test(flavor = "multi_thread")]
async fn parties_whose_profiles_ask_for_no_hint_are_sent_none() {
    const PHONE: &str = "198.51.100.194:5060";
    let pair = bridged("ingress-none", PHONE, OPEN_PLAIN, OPEN_SECURE).await;
    for name in ["answer_local", "offer", "answer"] {
        for sent in pair.engine.commands(name) {
            assert_eq!(sent.received_from, None, "{name}");
        }
    }
    assert_eq!(
        last(&pair.engine, "offer").transport_protocol.as_deref(),
        Some("RTP/SAVP")
    );
    assert_eq!(
        last(&pair.engine, "answer").transport_protocol.as_deref(),
        Some("RTP/AVP")
    );
}

/// `bridge {profile}` names one profile for the pair, and it describes both
/// parties: its `offer` half decides for the anchor, whose SDP the offer
/// carries, and its `answer` half for the answering leg, whatever each was
/// anchored with.
#[tokio::test(flavor = "multi_thread")]
async fn a_pair_profile_decides_for_both_parties_whatever_each_was_anchored_with() {
    for (index, (pair_profile, anchor_profile, peer_profile, anchor_pinned, peer_pinned)) in [
        (PAIR_PINS_OFFERER, OPEN_PLAIN, PINNED_PLAIN, true, false),
        (PAIR_PINS_ANSWERER, PINNED_PLAIN, OPEN_PLAIN, false, true),
    ]
    .into_iter()
    .enumerate()
    {
        let peer_address = format!("198.51.100.{}:5060", 195 + index);
        let engine = NativeTestEngine::start().await;
        let mut dispatcher = bridging_dispatcher(&engine);
        dispatcher.state.rtpengine_profiles = Some(profiles());
        let caller = answered_caller_from(
            &dispatcher,
            &format!("ingress-pair-{index}@192.0.2.10"),
            CALLER,
            anchor_profile,
        );
        let controller = controller_owning(
            &format!("ingress-pair-{index}"),
            dispatcher,
            &caller,
            "anchor",
            "hangup",
        );
        let peer = answered_caller_from(
            &controller.dispatcher,
            &format!("ingress-pair-peer-{index}@198.51.100.195"),
            &peer_address,
            peer_profile,
        );
        controller.bus.register_channel(
            "peer",
            &controller.connection,
            &peer.internal_call_id,
            &peer.call_id,
            "hangup",
            std::collections::HashMap::new(),
        );
        let state = &controller.dispatcher.state;
        let udp = &controller.dispatcher.udp;
        drain(udp);
        let (reply, _) = command(
            &controller,
            "bridge",
            "anchor",
            serde_json::json!({ "with": "peer", "profile": pair_profile }),
        )
        .await;
        assert_eq!(reply["status"], "ok", "{pair_profile}: {reply}");
        let offer = bridge_offer_to(udp, &peer_address).await;
        accepts(
            state,
            &peer_address,
            &offer,
            &format!("sip:15550100001@{peer_address}"),
        );
        caller_accepts(state, udp, &caller).await;
        assert!(
            eventually(|| stored(state, &peer.call_id).is_none()).await,
            "{pair_profile}: the bridge formed"
        );
        assert_eq!(
            last(&engine, "offer").received_from,
            anchor_pinned.then(|| socket(CALLER).ip()),
            "{pair_profile}: the offer half decides for the anchor"
        );
        assert_eq!(
            last(&engine, "answer").received_from,
            peer_pinned.then(|| socket(&peer_address).ip()),
            "{pair_profile}: the answer half decides for the answering leg"
        );
    }
}

/// A re-offer relayed across the formed pair follows the same rule in both
/// directions: the party whose SDP a command carries is pinned by its own
/// profile, and the command is still shaped by the other party's side.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_offer_pins_each_party_by_its_own_profile() {
    const PHONE: &str = "198.51.100.197:5060";
    let pair = bridged("ingress-relay", PHONE, OPEN_PLAIN, PINNED_SECURE).await;

    // The phone holds: its SDP on the re-offer, the caller's on the answer.
    deliver(
        &pair,
        PHONE,
        request(
            &pair,
            false,
            "INVITE",
            Some(&sdp_from(SIGNALLED, "sendonly")),
        ),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, CALLER).is_empty()).await;
    let to_caller = reinvites_to(&sent, CALLER).remove(0);
    let reoffer = last(&pair.engine, "reoffer");
    assert_eq!(reoffer.from_tag, format!("tag-{}", host(PHONE)));
    assert_eq!(
        reoffer.received_from,
        Some(socket(PHONE).ip()),
        "the phone's re-offer is pinned by the phone's own profile"
    );
    assert_eq!(
        reoffer.transport_protocol.as_deref(),
        Some("RTP/AVP"),
        "and shaped by the caller's side"
    );
    let answers = pair.engine.commands("answer").len();
    accept_with(&pair, CALLER, &to_caller, "recvonly");
    let sent = wait_for(&pair, |sent| !finals_to(sent, PHONE).is_empty()).await;
    assert_eq!(finals_to(&sent, PHONE)[0].status_code(), Some(200));
    assert_eq!(pair.engine.commands("answer").len(), answers + 1);
    let answer = last(&pair.engine, "answer");
    assert_eq!(
        answer.received_from, None,
        "the caller's answer is not pinned: its profile asks for no hint"
    );
    assert_eq!(answer.transport_protocol.as_deref(), Some("RTP/SAVP"));

    // The caller resumes: its SDP on the re-offer, the phone's on the answer.
    let reoffers = pair.engine.commands("reoffer").len();
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendrecv"))),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    let to_phone = reinvites_to(&sent, PHONE).remove(0);
    assert_eq!(pair.engine.commands("reoffer").len(), reoffers + 1);
    let reoffer = last(&pair.engine, "reoffer");
    assert_eq!(reoffer.from_tag, "caller-tag");
    assert_eq!(
        reoffer.received_from, None,
        "the caller's re-offer is not pinned by the phone's profile"
    );
    assert_eq!(reoffer.transport_protocol.as_deref(), Some("RTP/SAVP"));
    let answers = pair.engine.commands("answer").len();
    phone_sends(
        pair.state(),
        socket(PHONE),
        &in_dialog_response(
            &to_phone,
            200,
            "OK",
            &pair.contact,
            Some(&sdp_from(SIGNALLED, "sendrecv")),
        ),
    );
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    assert_eq!(finals_to(&sent, CALLER)[0].status_code(), Some(200));
    assert_eq!(pair.engine.commands("answer").len(), answers + 1);
    let answer = last(&pair.engine, "answer");
    assert_eq!(
        answer.received_from,
        Some(socket(PHONE).ip()),
        "the phone's answer is pinned by the phone's own profile"
    );
    assert_eq!(answer.transport_protocol.as_deref(), Some("RTP/AVP"));
}
