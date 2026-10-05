//! A pair that is bridged, parted and bridged again is shaped and pinned the
//! way its first bridge shaped and pinned it.
//!
//! When a bridge forms the peer's own media session is retired: its party
//! relays through the pair's session, which is stored under the anchor. After
//! an `unbridge` the peer therefore has no session of its own to say which
//! profile it was anchored with. The pair's session still records it, and a
//! second `bridge` of the same two legs reads it there: the peer is offered
//! what its own profile describes and pinned by its own policy, not the
//! anchor's.
//!
//! The two legs are on different profiles (plain RTP against SRTP, one asking
//! for the source hint and one not), so each engine command says whose flags
//! shaped it and whose policy pinned it.

use super::control_bridge_ingress_tests::{
    profiles, OPEN_PLAIN, OPEN_SECURE, PINNED_PLAIN, PINNED_SECURE,
};
use super::control_bridge_media_tests::{accepts, bridge_offer_to, caller_accepts, last, stored};
use super::control_originate_tests::Controller;
use super::dial_bridge_test_harness::{
    answered_caller_from, assert_drained, bridging_dispatcher, caller_sends, command,
    controller_owning, eventually, reinvites_to, sent_until, Caller, CALLER,
};
use super::originate_test_harness::{drain, socket};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Two answered legs one controller owns, on profiles of their own.
struct Legs {
    controller: Controller,
    engine: NativeTestEngine,
    anchor: Caller,
    peer: Caller,
    peer_address: String,
}

impl Legs {
    fn state(&self) -> &DispatcherState {
        &self.controller.dispatcher.state
    }

    fn udp(&self) -> &flume::Receiver<OutboundMessage> {
        &self.controller.dispatcher.udp
    }

    fn peer_contact(&self) -> String {
        format!("sip:15550100001@{}", self.peer_address)
    }

    /// `bridge` addressed to `target` naming `with`, accepted by both legs.
    /// Returns once the bridge has formed.
    async fn bridge(&self, target: &str, with: &str) {
        let (reply, _) = command(
            &self.controller,
            "bridge",
            target,
            serde_json::json!({ "with": with }),
        )
        .await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let offer = bridge_offer_to(self.udp(), &self.peer_address).await;
        accepts(
            self.state(),
            &self.peer_address,
            &offer,
            &self.peer_contact(),
        );
        caller_accepts(self.state(), self.udp(), &self.anchor).await;
        assert!(
            eventually(|| {
                [&self.anchor, &self.peer].into_iter().all(|leg| {
                    self.state()
                        .call_actors
                        .bridge(&leg.internal_call_id)
                        .is_some_and(|half| !half.stage.is_pending())
                })
            })
            .await,
            "the bridge formed"
        );
        drain(self.udp());
    }

    /// Part the pair and answer both hold re-INVITEs, so each leg is parted
    /// and held before anything else is asked of it.
    async fn unbridge(&self) {
        tokio::task::block_in_place(|| {
            b2bua_bridge_release(
                &self.anchor.internal_call_id,
                &self.peer.internal_call_id,
                "unbridged",
                self.state(),
            )
        });
        let sent = sent_until(self.udp(), |sent| {
            !reinvites_to(sent, &self.peer_address).is_empty()
                && !reinvites_to(sent, CALLER).is_empty()
        })
        .await;
        accepts(
            self.state(),
            &self.peer_address,
            &reinvites_to(&sent, &self.peer_address).remove(0),
            &self.peer_contact(),
        );
        accepts(
            self.state(),
            CALLER,
            &reinvites_to(&sent, CALLER).remove(0),
            &format!("sip:15550100001@{CALLER}"),
        );
        assert!(
            eventually(|| {
                [&self.anchor, &self.peer].into_iter().all(|leg| {
                    self.state()
                        .call_actors
                        .bridge(&leg.internal_call_id)
                        .is_none()
                })
            })
            .await,
            "both legs are parted"
        );
        drain(self.udp());
    }
}

/// An anchor answered with `anchor_profile` and a peer calling from
/// `peer_address` answered with `peer_profile`, on channels `anchor` and
/// `peer`.
async fn legs(app: &str, peer_address: &str, anchor_profile: &str, peer_profile: &str) -> Legs {
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = bridging_dispatcher(&engine);
    dispatcher.state.rtpengine_profiles = Some(profiles());
    let anchor = answered_caller_from(
        &dispatcher,
        &format!("{app}@192.0.2.10"),
        CALLER,
        anchor_profile,
    );
    let controller = controller_owning(app, dispatcher, &anchor, "anchor", "hangup");
    let peer = answered_caller_from(
        &controller.dispatcher,
        &format!("{app}-peer@198.51.100.10"),
        peer_address,
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
    drain(&controller.dispatcher.udp);
    Legs {
        controller,
        engine,
        anchor,
        peer,
        peer_address: peer_address.to_string(),
    }
}

/// What a pair's session recorded for its peer describes that party and no
/// other. After the unbridge the anchor is bridged to a third leg with no
/// media session of its own: that leg is offered what the anchor's profile
/// describes and pinned by the anchor's `answer` half, as any such leg is,
/// not by what the first peer was anchored with.
#[tokio::test(flavor = "multi_thread")]
async fn what_was_recorded_for_one_peer_is_not_applied_to_another() {
    const FIRST: &str = "198.51.100.211:5060";
    const THIRD: &str = "198.51.100.212:5060";
    let legs = legs("rebridge-other", FIRST, OPEN_PLAIN, PINNED_SECURE).await;
    legs.bridge("anchor", "peer").await;
    legs.unbridge().await;

    let third = answered_caller_from(
        &legs.controller.dispatcher,
        "rebridge-other-third@198.51.100.212",
        THIRD,
        PINNED_SECURE,
    );
    legs.controller.bus.register_channel(
        "third",
        &legs.controller.connection,
        &third.internal_call_id,
        &third.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    // The third leg carries the same tag the first peer does, and no session
    // of its own.
    legs.state()
        .rtpengine_sessions
        .as_ref()
        .expect("a session store")
        .remove(&third.call_id);
    drain(legs.udp());

    let (reply, _) = command(
        &legs.controller,
        "bridge",
        "anchor",
        serde_json::json!({ "with": "third" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let offer = bridge_offer_to(legs.udp(), THIRD).await;
    accepts(
        legs.state(),
        THIRD,
        &offer,
        &format!("sip:15550100001@{THIRD}"),
    );
    caller_accepts(legs.state(), legs.udp(), &legs.anchor).await;
    let reoffer = last(&legs.engine, "reoffer");
    assert_eq!(
        reoffer.transport_protocol.as_deref(),
        Some("RTP/AVP"),
        "the anchor's profile, not the first peer's"
    );
    assert_eq!(
        last(&legs.engine, "answer").received_from,
        None,
        "nor the first peer's policy"
    );
}

/// The reported gap, in both orders the second `bridge` can be asked in and
/// with the source hint on either party. The second bridge renegotiates the
/// pair's live engine call: the `reoffer` carries the anchor's SDP and yields
/// what the peer is offered, the `answer` carries the peer's.
#[tokio::test(flavor = "multi_thread")]
async fn a_pair_bridged_again_is_shaped_and_pinned_as_its_first_bridge_was() {
    // (the anchor's profile, the peer's, anchor pinned, peer pinned)
    let cases = [
        (OPEN_PLAIN, PINNED_SECURE, false, true),
        (PINNED_PLAIN, OPEN_SECURE, true, false),
    ];
    let orders = [("anchor", "peer"), ("peer", "anchor")];
    for (index, ((anchor_profile, peer_profile, anchor_pinned, peer_pinned), (target, with))) in
        cases
            .into_iter()
            .flat_map(|case| orders.into_iter().map(move |order| (case, order)))
            .enumerate()
    {
        let what = format!("{anchor_profile} + {peer_profile}, bridge {target} with {with}");
        let peer_address = format!("198.51.100.{}:5060", 201 + index);
        let legs = legs(
            &format!("rebridge-{index}"),
            &peer_address,
            anchor_profile,
            peer_profile,
        )
        .await;
        let anchor_source = anchor_pinned.then(|| socket(CALLER).ip());
        let peer_source = peer_pinned.then(|| socket(&peer_address).ip());

        // The first bridge: the pair is offered onto a fresh engine call.
        legs.bridge("anchor", "peer").await;
        let offer = last(&legs.engine, "offer");
        assert_eq!(offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(offer.received_from, anchor_source, "{what}");
        let answer = last(&legs.engine, "answer");
        assert_eq!(answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(answer.received_from, peer_source, "{what}");
        let pair = stored(legs.state(), &legs.anchor.call_id).expect("the pair's session");
        assert!(
            stored(legs.state(), &legs.peer.call_id).is_none(),
            "the peer's own session is retired"
        );

        legs.unbridge().await;
        assert!(
            legs.engine.holds(pair.rtpengine_id()),
            "the pair's engine call outlives the unbridge"
        );
        assert!(legs.engine.commands("reoffer").is_empty());
        let answers = legs.engine.commands("answer").len();

        // The second, on the engine call the pair already holds.
        legs.bridge(target, with).await;
        let reoffers = legs.engine.commands("reoffer");
        assert_eq!(reoffers.len(), 1, "{what}: {reoffers:?}");
        assert_eq!(reoffers[0].call_id, pair.rtpengine_id(), "{what}");
        assert_eq!(
            reoffers[0].transport_protocol.as_deref(),
            Some("RTP/SAVP"),
            "{what}: the peer is offered what its own profile describes"
        );
        assert_eq!(
            reoffers[0].received_from, anchor_source,
            "{what}: the anchor is pinned by its own policy"
        );
        assert_eq!(legs.engine.commands("answer").len(), answers + 1, "{what}");
        let answer = last(&legs.engine, "answer");
        assert_eq!(answer.call_id, pair.rtpengine_id(), "{what}");
        assert_eq!(
            answer.transport_protocol.as_deref(),
            Some("RTP/AVP"),
            "{what}: the anchor is re-INVITEd with what its own describes"
        );
        assert_eq!(
            answer.received_from, peer_source,
            "{what}: the peer is pinned by its own policy, not the anchor's"
        );
        assert!(
            legs.engine
                .commands("offer")
                .iter()
                .all(|offer| offer.call_id != legs.peer.call_id),
            "{what}: nothing is offered on the session the peer no longer has"
        );

        // Nothing is kept for the pair beyond the calls: both hang up and the
        // store and the engine are empty.
        caller_sends(legs.state(), &legs.anchor, "BYE", "9 BYE");
        assert!(
            eventually(|| legs.state().call_actors.count() == 0).await,
            "{what}: both calls are gone"
        );
        assert!(eventually(|| legs.engine.held_count() == 0).await, "{what}");
        assert!(
            eventually(|| legs
                .state()
                .rtpengine_sessions
                .as_ref()
                .is_some_and(|store| store.is_empty()))
            .await,
            "{what}: no session is left"
        );
        assert_drained(legs.state());
    }
}
