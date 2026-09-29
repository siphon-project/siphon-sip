//! A bridged pair's `MediaSummary`: the pair relays through one engine call on
//! an id of its own, so the summary the engine sends for it names neither
//! leg's SIP Call-ID. It still reaches both legs' owners, once each, after
//! their `StasisEnd`.
//!
//! Driven through the real bridge and teardown paths. The process-wide control
//! plane is not installed in the library tests, so its two effects are read
//! the way the other bridge tests read them: what the teardown published is
//! captured per SIP Call-ID, and the owner's side is the test controller's bus
//! fed the `StasisEnd` the process bus would have emitted.

use super::control_bridge_media_tests::{
    accepts, bridge_offer_to, caller_accepts, last, phone_answers, second_leg, stored,
};
use super::control_originate_tests::Controller;
use super::dial_bridge_test_harness::{
    answered_caller, bridging_dispatcher, caller_sends, command, controller_owning, dial, events,
    eventually, invite_to, reinvites_to, sent_until, Caller,
};
use super::originate_test_harness::drain;
use super::*;
use crate::rtpengine::events::CallSummary;
use crate::rtpengine::test_native_engine::NativeTestEngine;

fn summary(engine_call_id: &str) -> CallSummary {
    CallSummary {
        call_id: engine_call_id.to_string(),
        reason: "delete".to_string(),
        duration_ms: 42_000,
        legs: Vec::new(),
    }
}

/// The engine's summary for `engine_call_id`, published the way the event
/// loop publishes it, and also handed to the controller's bus the way the
/// process bus would hand it.
fn engine_reports(controller: &Controller, engine_call_id: &str) {
    deliver_media_summary(
        &controller.dispatcher.state,
        &summary(engine_call_id),
        |sip_call_id, payload| {
            crate::control::notify_media_summary(sip_call_id, payload.clone());
            controller.bus.forward_media_summary(sip_call_id, payload);
        },
    );
}

/// The teardown's `StasisEnd` and `MediaSummary` published for `sip_call_id`
/// since the last look, in order.
fn published(sip_call_id: &str) -> Vec<String> {
    crate::control::channel_event_capture::take(sip_call_id)
        .into_iter()
        .map(|(event, _)| event)
        .filter(|event| event == "StasisEnd" || event == "MediaSummary")
        .collect()
}

/// What the controller heard on `channel`, `StasisEnd` and `MediaSummary`
/// only, in order.
fn heard_on(heard: &[crate::control::protocol::EventFrame], channel: &str) -> Vec<String> {
    heard
        .iter()
        .filter(|event| event.channel.as_deref() == Some(channel))
        .map(|event| event.event.clone())
        .filter(|event| event == "StasisEnd" || event == "MediaSummary")
        .collect()
}

/// The `StasisEnd` the process bus emits for each torn-down leg, on the
/// controller's bus.
fn stasis_end(controller: &Controller, legs: &[&str]) {
    for sip_call_id in legs {
        controller.bus.on_call_terminated(sip_call_id, "bye");
    }
}

fn engine_parties(controller: &Controller) -> usize {
    controller
        .dispatcher
        .state
        .rtpengine_sessions
        .as_ref()
        .map_or(0, |store| store.engine_parties_count())
}

/// A caller rings a phone with `dial {on_answer: "bridge"}` and hangs up once
/// they talked. The pair's summary names the pair's own engine call, and still
/// reaches the caller's owner and the phone channel's owner after each
/// `StasisEnd`, once. The two single-party sessions the bridge replaced report
/// to their own legs while those are up.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_bridge_hang_up_reports_the_pair_to_both_owners() {
    const PHONE: &str = "198.51.100.181:5060";
    let contact = format!("sip:ms3701@{PHONE}");
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "summary-dial@192.0.2.10");
    let controller = controller_owning("summary-dial", dispatcher, &caller, "caller", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "caller",
        serde_json::json!({ "targets": [contact], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = invite_to(&drain(udp), PHONE);
    let phone_call_id = invite.headers.call_id().cloned().expect("a Call-ID");
    phone_answers(state, PHONE, &invite, &contact);
    let offer = bridge_offer_to(udp, PHONE).await;
    let pair = last(&engine, "offer").call_id;
    accepts(state, PHONE, &offer, &contact);
    caller_accepts(state, udp, &caller).await;
    assert!(
        eventually(
            || stored(state, &caller.call_id).is_some_and(|session| session.rtpengine_id() == pair)
        )
        .await,
        "the bridge formed on its own engine call"
    );
    assert_ne!(pair, caller.call_id);
    assert_ne!(pair, phone_call_id);
    let phone_channel = controller
        .bus
        .channel_id_for_sip_call_id(&phone_call_id)
        .expect("the phone was given a channel of its own");
    let _ = events(&controller).await;
    crate::control::channel_event_capture::watch(&caller.call_id);
    crate::control::channel_event_capture::watch(&phone_call_id);

    // The sessions the bridge replaced report to their own, live, legs.
    engine_reports(&controller, &caller.call_id);
    engine_reports(&controller, &phone_call_id);

    caller_sends(state, &caller, "BYE", "2 BYE");
    assert!(
        eventually(|| !engine.holds(&pair)).await,
        "the pair is deleted"
    );
    assert!(
        eventually(|| state
            .call_actors
            .find_by_sip_call_id(&phone_call_id)
            .is_none())
        .await,
        "the phone goes with the caller"
    );
    stasis_end(&controller, &[&caller.call_id, &phone_call_id]);

    // The pair's summary, after the delete, reaches both.
    engine_reports(&controller, &pair);
    for leg in [&caller.call_id, &phone_call_id] {
        assert_eq!(
            published(leg),
            ["MediaSummary", "StasisEnd", "MediaSummary"],
            "{leg}"
        );
    }
    let heard = events(&controller).await;
    for channel in ["caller", phone_channel.as_str()] {
        assert_eq!(
            heard_on(&heard, channel),
            ["MediaSummary", "StasisEnd", "MediaSummary"],
            "{channel}"
        );
    }
    let after_stasis_end = heard
        .iter()
        .rev()
        .find(|event| event.event == "MediaSummary")
        .expect("the pair's summary");
    assert_eq!(after_stasis_end.payload["duration_ms"], 42_000);

    // Spent: a repeat reaches nobody, and nothing is kept.
    engine_reports(&controller, &pair);
    assert!(published(&caller.call_id).is_empty());
    assert!(published(&phone_call_id).is_empty());
    assert_eq!(engine_parties(&controller), 0);
    assert_eq!(controller.bus.channel_tombstone_count(), 0);
}

/// Two legs bridged with `bridge`, parted with an unbridge, then hung up one
/// after the other: the pair's engine call is still the anchor's, both parties
/// are still on it, and its summary reaches both owners once.
#[tokio::test(flavor = "multi_thread")]
async fn an_unbridged_pair_hung_up_reports_to_both_owners() {
    const PEER: &str = "198.51.100.182:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "summary-unbridge@192.0.2.10");
    let controller = controller_owning("summary-unbridge", dispatcher, &caller, "anchor", "hangup");
    let peer: Caller = second_leg(
        &controller,
        "summary-unbridge-peer@198.51.100.182",
        PEER,
        "peer",
    );
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let peer_contact = format!("sip:15550100001@{PEER}");
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
    let pair = last(&engine, "offer").call_id;
    accepts(state, PEER, &offer, &peer_contact);
    caller_accepts(state, udp, &caller).await;
    assert!(
        eventually(
            || stored(state, &caller.call_id).is_some_and(|session| session.rtpengine_id() == pair)
        )
        .await
    );

    // Parted: each leg is held, and neither half of the bridge is left.
    b2bua_bridge_release(
        &caller.internal_call_id,
        &peer.internal_call_id,
        "unbridged",
        state,
    );
    let holds = sent_until(udp, |sent| {
        !reinvites_to(sent, PEER).is_empty() && !reinvites_to(sent, &caller.address).is_empty()
    })
    .await;
    let hold_to_peer = reinvites_to(&holds, PEER).remove(0);
    let hold_to_caller = reinvites_to(&holds, &caller.address).remove(0);
    accepts(state, PEER, &hold_to_peer, &peer_contact);
    accepts(
        state,
        &caller.address,
        &hold_to_caller,
        &format!("sip:15550100001@{}", caller.address),
    );
    assert!(
        eventually(
            || state.call_actors.bridge(&caller.internal_call_id).is_none()
                && state.call_actors.bridge(&peer.internal_call_id).is_none()
        )
        .await,
        "unbridged"
    );
    let _ = events(&controller).await;
    crate::control::channel_event_capture::watch(&caller.call_id);
    crate::control::channel_event_capture::watch(&peer.call_id);

    caller_sends(state, &caller, "BYE", "2 BYE");
    assert!(
        eventually(|| !engine.holds(&pair)).await,
        "the pair is deleted"
    );
    assert!(
        state
            .call_actors
            .find_by_sip_call_id(&peer.call_id)
            .is_some(),
        "positive control: the unbridged peer stays up"
    );
    caller_sends(state, &peer, "BYE", "2 BYE");
    assert!(
        eventually(|| state
            .call_actors
            .find_by_sip_call_id(&peer.call_id)
            .is_none())
        .await
    );
    stasis_end(&controller, &[&caller.call_id, &peer.call_id]);

    engine_reports(&controller, &pair);
    for leg in [&caller.call_id, &peer.call_id] {
        assert_eq!(published(leg), ["StasisEnd", "MediaSummary"], "{leg}");
    }
    let heard = events(&controller).await;
    for channel in ["anchor", "peer"] {
        assert_eq!(
            heard_on(&heard, channel),
            ["StasisEnd", "MediaSummary"],
            "{channel}"
        );
    }
    assert_eq!(engine_parties(&controller), 0);
    assert_eq!(controller.bus.channel_tombstone_count(), 0);
}
