//! Which media a bridge gives each leg, and what a bridge that fails leaves
//! behind.
//!
//! A bridge's engine `offer` produces what the peer is offered and its
//! `answer` what the anchor is re-INVITEd with. Each is shaped by the profile
//! of the party it is for — or by one pair profile the `bridge` verb names —
//! and each carries the signalling source of the party whose SDP it holds.
//! Nothing is deleted until the peer has accepted, so a peer that refuses
//! leaves both legs' media usable: the caller's ringback resumes on the very
//! session it was playing on, and the next phone bridges as the first would
//! have.
//!
//! Driven the way the other bridge dial tests are: frames through the control
//! consumer, the wire read off the egress channel, and the engine's own log
//! and the calls it holds read off the in-process native engine, which refuses
//! a command on a call it no longer holds as a deployment's would.

use std::sync::Arc;

use super::dial_bridge_test_harness::{
    answered_caller, answered_caller_from, assert_drained, bridging_dispatcher, caller_sends,
    command, controller_owning, dial, events, eventually, in_dialog_response, invite_to, names,
    register, reinvites_to, sent_until, Caller, CALLER,
};
use super::originate_test_harness::{
    drain, phone_offer, phone_response, phone_sends, requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::{NativeCommand, NativeTestEngine};

/// A plain-RTP profile a carrier caller is answered with, pinning media
/// ingress to the signalling source.
pub(super) const CARRIER: &str = "carrier_plain";
/// An SRTP-only profile a phone is rung with, pinning ingress likewise.
pub(super) const SRTP_PHONE: &str = "srtp_phone";

/// The built-in profiles plus [`CARRIER`] and [`SRTP_PHONE`], each with the
/// same transport on both halves.
pub(super) fn profiles() -> Arc<crate::rtpengine::ProfileRegistry> {
    let profile = |transport: &str| crate::config::MediaProfileConfig {
        offer: crate::config::NgFlagsConfig {
            transport_protocol: Some(transport.to_string()),
            received_from: true,
            ..Default::default()
        },
        answer: crate::config::NgFlagsConfig {
            transport_protocol: Some(transport.to_string()),
            received_from: true,
            ..Default::default()
        },
    };
    let mut custom = std::collections::HashMap::new();
    custom.insert(CARRIER.to_string(), profile("RTP/AVP"));
    custom.insert(SRTP_PHONE.to_string(), profile("RTP/SAVP"));
    Arc::new(crate::rtpengine::ProfileRegistry::from_config(&custom))
}

/// The last command of kind `name` the engine was sent.
pub(super) fn last(engine: &NativeTestEngine, name: &str) -> NativeCommand {
    engine
        .commands(name)
        .pop()
        .unwrap_or_else(|| panic!("the engine was sent an {name}"))
}

/// The engine session the store addresses the leg `sip_call_id` by.
pub(super) fn stored(
    state: &DispatcherState,
    sip_call_id: &str,
) -> Option<crate::rtpengine::MediaSession> {
    state
        .rtpengine_sessions
        .as_ref()
        .and_then(|store| store.get(sip_call_id))
}

pub(super) fn host(address: &str) -> &str {
    address.split(':').next().unwrap_or(address)
}

/// `phone` answers its INVITE `invite` with an offer of its own.
pub(super) fn phone_answers(
    state: &DispatcherState,
    phone: &str,
    invite: &SipMessage,
    contact: &str,
) {
    phone_sends(
        state,
        socket(phone),
        &phone_response(
            invite,
            200,
            "OK",
            &format!("tag-{}", host(phone)),
            contact,
            Some(&phone_offer(host(phone))),
        ),
    );
}

/// The bridge's re-INVITE to `address`, waited for.
pub(super) async fn bridge_offer_to(
    udp: &flume::Receiver<OutboundMessage>,
    address: &str,
) -> SipMessage {
    let sent = sent_until(udp, |sent| !reinvites_to(sent, address).is_empty()).await;
    reinvites_to(&sent, address)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("a bridge re-INVITE to {address}"))
}

/// The party at `address` answers the bridge's re-INVITE `offer`.
pub(super) fn accepts(state: &DispatcherState, address: &str, offer: &SipMessage, contact: &str) {
    phone_sends(
        state,
        socket(address),
        &in_dialog_response(offer, 200, "OK", contact, Some(&phone_offer(host(address)))),
    );
}

/// The party at `address` refuses the bridge's re-INVITE `offer`.
pub(super) fn refuses(state: &DispatcherState, address: &str, offer: &SipMessage, contact: &str) {
    phone_sends(
        state,
        socket(address),
        &in_dialog_response(offer, 488, "Not Acceptable Here", contact, None),
    );
}

/// The caller at `caller` accepts the bridge's re-INVITE to it.
pub(super) async fn caller_accepts(
    state: &DispatcherState,
    udp: &flume::Receiver<OutboundMessage>,
    caller: &Caller,
) {
    let to_caller = bridge_offer_to(udp, &caller.address).await;
    accepts(
        state,
        &caller.address,
        &to_caller,
        &format!("sip:15550100001@{}", caller.address),
    );
}

/// A plain-RTP carrier caller bridged to an SRTP phone: the phone is offered
/// SRTP by its own profile, the caller re-INVITEd with plain RTP by its own,
/// and each engine command pins the ingress of the party whose SDP it carries.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridged_phone_is_offered_what_its_own_profile_describes() {
    const PHONE: &str = "198.51.100.161:5060";
    let contact = format!("sip:bm3601@{PHONE}");
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = bridging_dispatcher(&engine);
    dispatcher.state.rtpengine_profiles = Some(profiles());
    let caller = answered_caller_from(&dispatcher, "media-srtp@192.0.2.10", CALLER, CARRIER);
    let controller = controller_owning("media-srtp", dispatcher, &caller, "srtp", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "srtp",
        serde_json::json!({ "targets": [contact], "on_answer": "bridge", "profile": SRTP_PHONE }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = invite_to(&drain(udp), PHONE);
    phone_answers(state, PHONE, &invite, &contact);
    let phone_call_id = invite.headers.call_id().cloned().expect("a Call-ID");
    let anchored = last(&engine, "answer_local");
    assert_eq!(
        anchored.transport_protocol.as_deref(),
        Some("RTP/SAVP"),
        "the phone was anchored with its own profile"
    );
    assert_eq!(
        anchored.received_from,
        Some(socket(PHONE).ip()),
        "the phone's pickup pins its ingress to where its answer came from"
    );

    // The bridge offers the phone: shaped by the phone's profile, carrying the
    // caller's source, since the SDP in the offer is the caller's.
    let offer = bridge_offer_to(udp, PHONE).await;
    let engine_offer = last(&engine, "offer");
    assert_eq!(engine_offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
    assert_eq!(engine_offer.received_from, Some(socket(CALLER).ip()));
    assert_ne!(
        engine_offer.call_id, caller.call_id,
        "a fresh call, beside the caller's own"
    );
    let offered = std::str::from_utf8(&offer.body).expect("a text body");
    assert!(
        offered.contains("m=audio 52000 RTP/SAVP 0 101") && offered.contains("a=crypto:1 "),
        "the phone is offered SRTP on the wire: {offered}"
    );

    // The phone accepts: the caller's re-INVITE is built from the caller's
    // own profile's answer half, pinned to the phone's source.
    accepts(state, PHONE, &offer, &contact);
    caller_accepts(state, udp, &caller).await;
    let engine_answer = last(&engine, "answer");
    assert_eq!(engine_answer.call_id, engine_offer.call_id);
    assert_eq!(engine_answer.transport_protocol.as_deref(), Some("RTP/AVP"));
    assert_eq!(engine_answer.received_from, Some(socket(PHONE).ip()));

    // Formed: the caller's entry moves to the pair's session and the two
    // single-party sessions go.
    let adopted = stored(state, &caller.call_id).expect("the caller keeps an entry");
    assert_eq!(adopted.rtpengine_id(), engine_offer.call_id);
    assert_eq!(
        adopted.to_tag.as_deref(),
        Some(format!("tag-{}", host(PHONE)).as_str())
    );
    assert!(stored(state, &phone_call_id).is_none());
    assert!(eventually(|| !engine.holds(&caller.call_id) && !engine.holds(&phone_call_id)).await);
    assert!(
        engine.holds(&engine_offer.call_id),
        "positive control: the pair's session is kept"
    );
    assert!(eventually(|| state.dial_bridges.ringing_count() == 0).await);
    assert_drained(state);
}

/// A profile that does not ask for `received_from` sends none, on either
/// command — the positive control for the test above.
#[tokio::test(flavor = "multi_thread")]
async fn received_from_is_carried_only_where_the_profile_asks_for_it() {
    const PHONE: &str = "198.51.100.162:5060";
    let contact = format!("sip:bm3602@{PHONE}");
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "media-plain@192.0.2.10");
    let controller = controller_owning("media-plain", dispatcher, &caller, "plain", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "plain",
        serde_json::json!({ "targets": [contact], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = invite_to(&drain(udp), PHONE);
    phone_answers(state, PHONE, &invite, &contact);
    let offer = bridge_offer_to(udp, PHONE).await;
    accepts(state, PHONE, &offer, &contact);
    caller_accepts(state, udp, &caller).await;
    for name in ["answer_local", "offer", "answer"] {
        let sent = last(&engine, name);
        assert_eq!(sent.received_from, None, "{name}");
        assert_eq!(
            sent.transport_protocol, None,
            "{name}: rtp_passthrough names none"
        );
    }
    // The dial concludes on its own task once the bridge has formed.
    assert!(eventually(|| state.dial_bridges.ringing_count() == 0).await);
    assert_drained(state);
}

/// The live failure: a phone that refuses the bridge offer must not take the
/// caller's media with it. The caller's own session is not deleted and its
/// entry not moved, the fresh one is deleted, the ringback resumes on the
/// caller's session and is accepted there, and the next phone bridges.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_bridge_leaves_the_callers_media_and_the_dial_rings_back_on_it() {
    const DESK: &str = "198.51.100.163:5060";
    const MOBILE: &str = "198.51.100.164:5060";
    let aor = "sip:bm3603@siphon.example.com";
    let (desk_contact, mobile_contact) =
        (format!("sip:bm3603@{DESK}"), format!("sip:bm3603@{MOBILE}"));
    register(aor, &desk_contact, 1.0);
    register(aor, &mobile_contact, 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "media-refused@192.0.2.10");
    let controller = controller_owning("media-refused", dispatcher, &caller, "refused", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let before = stored(state, &caller.call_id).expect("the caller is anchored");
    let (reply, _) = dial(
        &controller,
        "refused",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(udp);
    let (desk, mobile) = (invite_to(&sent, DESK), invite_to(&sent, MOBILE));

    // The mobile alerts: ringback on the caller's own session.
    phone_sends(
        state,
        socket(MOBILE),
        &phone_response(&mobile, 180, "Ringing", "tag-mobile", &mobile_contact, None),
    );
    assert!(eventually(|| engine.commands("play_media").len() == 1).await);

    // The mobile answers and refuses the bridge.
    phone_answers(state, MOBILE, &mobile, &mobile_contact);
    let offer = bridge_offer_to(udp, MOBILE).await;
    let fresh = last(&engine, "offer").call_id;
    assert_ne!(fresh, caller.call_id);
    refuses(state, MOBILE, &offer, &mobile_contact);

    // The fresh session goes; the caller's own does not.
    assert!(
        eventually(|| !engine.holds(&fresh)).await,
        "the fresh session is deleted"
    );
    assert!(
        engine
            .commands("delete")
            .iter()
            .all(|delete| delete.call_id != caller.call_id),
        "the caller's own session is never deleted"
    );
    assert!(engine.holds(&caller.call_id));
    let after = stored(state, &caller.call_id).expect("the caller keeps its entry");
    assert_eq!(after.rtpengine_id(), before.rtpengine_id());
    assert_eq!(after.from_tag, before.from_tag);
    assert_eq!(after.to_tag, before.to_tag);
    assert_eq!(after.profile, before.profile);

    // The ringback resumes on it, and the engine takes it.
    assert!(
        eventually(|| engine.commands("play_media").len() == 2).await,
        "the ringback resumes"
    );
    let plays = engine.commands("play_media");
    assert_eq!(plays[1].call_id, caller.call_id);
    assert!(
        !plays[1].refused,
        "the engine still holds the caller's session"
    );
    assert!(
        !plays[0].refused,
        "positive control: the first ringback was accepted"
    );
    let heard = events(&controller).await;
    assert!(
        names(&heard).contains(&"PlayStarted"),
        "the ringback is reported again: {:?}",
        names(&heard)
    );

    // The desk answers and bridges on a session of its own.
    phone_answers(state, DESK, &desk, &desk_contact);
    let offer = bridge_offer_to(udp, DESK).await;
    let second = last(&engine, "offer").call_id;
    assert_ne!(second, fresh);
    accepts(state, DESK, &offer, &desk_contact);
    caller_accepts(state, udp, &caller).await;
    assert_eq!(
        stored(state, &caller.call_id).map(|session| session.rtpengine_id().to_string()),
        Some(second.clone())
    );
    assert!(
        eventually(|| engine.held_count() == 1).await,
        "only the pair's session is left"
    );
    assert!(engine.holds(&second));

    // Both hang up: nothing is left in the store or on the engine.
    caller_sends(state, &caller, "BYE", "2 BYE");
    assert!(
        eventually(|| state
            .rtpengine_sessions
            .as_ref()
            .is_some_and(|store| store.is_empty()))
        .await
    );
    assert!(eventually(|| engine.held_count() == 0).await);
    assert_drained(state);
}

/// How many `BridgeFailed` were published for `sip_call_id` since the last
/// look, and the stages they name.
fn bridge_failures(sip_call_id: &str) -> Vec<serde_json::Value> {
    crate::control::channel_event_capture::take(sip_call_id)
        .into_iter()
        .filter(|(event, _)| event == "BridgeFailed")
        .map(|(_, payload)| payload["stage"].clone())
        .collect()
}

/// Two legs a controller owns, the second calling from `peer_address`.
pub(super) fn second_leg(
    controller: &super::control_originate_tests::Controller,
    call_id: &str,
    peer_address: &str,
    channel: &str,
) -> Caller {
    let peer = answered_caller_from(
        &controller.dispatcher,
        call_id,
        peer_address,
        "rtp_passthrough",
    );
    controller.bus.register_channel(
        channel,
        &controller.connection,
        &peer.internal_call_id,
        &peer.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    peer
}

/// The same failure through the plain `bridge` verb, where the peer is kept
/// up: neither leg's session is deleted or moved, both stay usable, a refused
/// bridge can be tried again, and hanging both up leaves nothing behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_the_peer_refuses_leaves_both_legs_media_as_it_was() {
    const PEER: &str = "198.51.100.165:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "verb-refused@192.0.2.10");
    let controller = controller_owning("verb-refused", dispatcher, &caller, "anchor", "hangup");
    let peer = second_leg(
        &controller,
        "verb-refused-peer@198.51.100.165",
        PEER,
        "peer",
    );
    crate::control::channel_event_capture::watch(&caller.call_id);
    crate::control::channel_event_capture::watch(&peer.call_id);
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    drain(udp);
    let anchor_before = stored(state, &caller.call_id).expect("the anchor is anchored");
    let peer_before = stored(state, &peer.call_id).expect("the peer is anchored");
    let peer_contact = format!("sip:15550100001@{PEER}");

    for attempt in 0..2 {
        let (reply, _) = command(
            &controller,
            "bridge",
            "anchor",
            serde_json::json!({ "with": "peer" }),
        )
        .await;
        assert_eq!(reply["status"], "ok", "attempt {attempt}: {reply}");
        let offer = bridge_offer_to(udp, PEER).await;
        let fresh = last(&engine, "offer").call_id;
        refuses(state, PEER, &offer, &peer_contact);
        assert!(
            eventually(|| !engine.holds(&fresh)).await,
            "attempt {attempt}"
        );
        for (leg, before) in [(&caller, &anchor_before), (&peer, &peer_before)] {
            let after = stored(state, &leg.call_id).expect("each leg keeps its entry");
            assert_eq!(after.rtpengine_id(), before.rtpengine_id());
            assert_eq!(after.to_tag, before.to_tag);
            assert!(
                engine.holds(after.rtpengine_id()),
                "attempt {attempt}: {}",
                leg.call_id
            );
        }
        assert!(
            state.call_actors.bridge(&caller.internal_call_id).is_none()
                && state.call_actors.bridge(&peer.internal_call_id).is_none(),
            "no half of the failed bridge is left"
        );
        for leg in [&caller, &peer] {
            assert_eq!(
                bridge_failures(&leg.call_id),
                vec![serde_json::json!("offering_peer")],
                "attempt {attempt}: {} hears it",
                leg.call_id
            );
        }
    }
    assert!(
        engine
            .commands("delete")
            .iter()
            .all(|delete| delete.call_id != caller.call_id && delete.call_id != peer.call_id),
        "neither leg's own session was deleted"
    );
    // The peer is still up: positive control that the refusal was not a
    // teardown in disguise.
    assert!(requests_to(&drain(udp), socket(PEER), Method::Bye).is_empty());

    // A third attempt forms, and hanging up leaves nothing behind.
    let (reply, _) = command(
        &controller,
        "bridge",
        "anchor",
        serde_json::json!({ "with": "peer" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let offer = bridge_offer_to(udp, PEER).await;
    let pair = last(&engine, "offer").call_id;
    accepts(state, PEER, &offer, &peer_contact);
    caller_accepts(state, udp, &caller).await;
    assert!(eventually(|| engine.held_count() == 1 && engine.holds(&pair)).await);
    caller_sends(state, &caller, "BYE", "2 BYE");
    assert!(eventually(|| engine.held_count() == 0).await);
    assert!(state
        .rtpengine_sessions
        .as_ref()
        .is_some_and(|store| store.is_empty()));
}

/// The peer accepted but the anchor refused its half: the anchor keeps its own
/// session untouched and the fresh one is deleted. The peer's own session is
/// kept too (it is still up); its endpoint was already re-pointed at the
/// fresh session, so it needs a new bridge or a hangup — what the
/// `BridgeFailed` with stage `offering_anchor` tells the controller.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchor_that_refuses_its_half_keeps_its_own_media() {
    const PEER: &str = "198.51.100.166:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "anchor-refused@192.0.2.10");
    let controller = controller_owning("anchor-refused", dispatcher, &caller, "anchor", "hangup");
    let peer = second_leg(
        &controller,
        "anchor-refused-peer@198.51.100.166",
        PEER,
        "peer",
    );
    crate::control::channel_event_capture::watch(&caller.call_id);
    crate::control::channel_event_capture::watch(&peer.call_id);
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    drain(udp);
    let (reply, _) = command(
        &controller,
        "bridge",
        "anchor",
        serde_json::json!({ "with": "peer" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let offer = bridge_offer_to(udp, PEER).await;
    let fresh = last(&engine, "offer").call_id;
    accepts(state, PEER, &offer, &format!("sip:15550100001@{PEER}"));
    let to_anchor = bridge_offer_to(udp, CALLER).await;
    refuses(state, CALLER, &to_anchor, "sip:15550100001@192.0.2.10:5060");
    assert!(eventually(|| !engine.holds(&fresh)).await);
    assert_eq!(
        stored(state, &caller.call_id).map(|session| session.rtpengine_id().to_string()),
        Some(caller.call_id.clone())
    );
    assert!(engine.holds(&caller.call_id) && engine.holds(&peer.call_id));
    for leg in [&caller, &peer] {
        assert_eq!(
            bridge_failures(&leg.call_id),
            vec![serde_json::json!("offering_anchor")],
            "{}",
            leg.call_id
        );
    }
}

/// `bridge {profile}` names one profile for the pair: its offer half for the
/// peer, its answer half for the anchor. An unknown or malformed one is refused
/// before either leg is touched.
#[tokio::test(flavor = "multi_thread")]
async fn the_bridge_verbs_profile_shapes_the_pair_and_an_unknown_one_is_refused() {
    const PEER: &str = "198.51.100.167:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "verb-profile@192.0.2.10");
    let controller = controller_owning("verb-profile", dispatcher, &caller, "anchor", "hangup");
    let peer = second_leg(
        &controller,
        "verb-profile-peer@198.51.100.167",
        PEER,
        "peer",
    );
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    drain(udp);

    for (profile, reason) in [
        (serde_json::json!("no_such_profile"), "unknown_profile"),
        (serde_json::json!(7), "invalid_value"),
        (serde_json::json!(" "), "invalid_value"),
    ] {
        let (reply, _) = command(
            &controller,
            "bridge",
            "anchor",
            serde_json::json!({ "with": "peer", "profile": profile }),
        )
        .await;
        assert_eq!(reply["status"], "error", "{reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
        assert_eq!(reply["error"]["details"]["verb"], "bridge");
        assert_eq!(reply["error"]["details"]["argument"], "profile");
        assert_eq!(reply["error"]["details"]["reason"], reason, "{reply}");
    }
    assert!(
        engine.commands("offer").is_empty(),
        "nothing reached the engine"
    );
    assert!(reinvites_to(&drain(udp), PEER).is_empty(), "nor the wire");

    let (reply, _) = command(
        &controller,
        "bridge",
        "anchor",
        serde_json::json!({ "with": "peer", "profile": "rtp_to_srtp" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["profile"], "rtp_to_srtp");
    let offer = bridge_offer_to(udp, PEER).await;
    assert_eq!(
        last(&engine, "offer").transport_protocol.as_deref(),
        Some("RTP/SAVP"),
        "the pair profile's offer half shapes the peer"
    );
    accepts(state, PEER, &offer, &format!("sip:15550100001@{PEER}"));
    caller_accepts(state, udp, &caller).await;
    assert_eq!(
        last(&engine, "answer").transport_protocol.as_deref(),
        Some("RTP/AVP"),
        "and its answer half the anchor"
    );
    assert_eq!(
        stored(state, &caller.call_id).map(|session| session.profile),
        Some("rtp_to_srtp".to_string()),
        "the pair's session carries the pair profile"
    );
    assert!(stored(state, &peer.call_id).is_none());
}

/// A leg that hangs up while its bridge is still forming leaves no session on
/// the engine: the fresh one is in no store entry, so the teardown deletes it
/// through the bridge's own half, and the two legs' sessions go with their
/// calls.
#[tokio::test(flavor = "multi_thread")]
async fn a_hangup_mid_bridge_leaves_no_session_behind() {
    const PEER: &str = "198.51.100.168:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "mid-bridge@192.0.2.10");
    let controller = controller_owning("mid-bridge", dispatcher, &caller, "anchor", "hangup");
    let peer = second_leg(&controller, "mid-bridge-peer@198.51.100.168", PEER, "peer");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    drain(udp);
    let (reply, _) = command(
        &controller,
        "bridge",
        "anchor",
        serde_json::json!({ "with": "peer" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    bridge_offer_to(udp, PEER).await;
    let fresh = last(&engine, "offer").call_id;
    assert_eq!(
        engine.held_count(),
        3,
        "both legs' own sessions and the fresh one"
    );

    caller_sends(state, &caller, "BYE", "2 BYE");
    assert!(
        eventually(|| engine.held_count() == 0).await,
        "left on the engine: fresh {} {}, caller {}, peer {}",
        fresh,
        engine.holds(&fresh),
        engine.holds(&caller.call_id),
        engine.holds(&peer.call_id)
    );
    assert!(state
        .rtpengine_sessions
        .as_ref()
        .is_some_and(|store| store.is_empty()));
}
