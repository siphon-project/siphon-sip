//! A leg that was the `with` side of a bridge, parted, and then bridged to a
//! different anchor is still shaped and pinned as its own profile describes.
//!
//! Its own media session was retired when its first bridge formed, and the
//! pair's session that recorded what it was bridged with is stored under the
//! first anchor. A second anchor's session says nothing about it. What the
//! bridge shaped and pinned the leg with is therefore kept for the leg's own
//! call, for as long as that call lasts, and read wherever it is bridged next:
//! without it the second anchor's profile shapes the leg (a party that needs
//! SRTP is offered plain RTP) and the second anchor's policy pins it.
//!
//! The record is per call, so it has to go with the call on every way a call
//! ends. The last test drives whole calls through each and counts.

use super::control_bridge_ingress_tests::{OPEN_PLAIN, OPEN_SECURE, PINNED_PLAIN, PINNED_SECURE};
use super::control_bridge_media_tests::{accepts, bridge_offer_to, last, stored};
use super::control_rebridge_tests::{legs, retired_sessions_deleted, Legs};
use super::dial_bridge_test_harness::{
    answered_caller_from, assert_drained, caller_sends, command, eventually, reinvites_to,
    sent_until, Caller,
};
use super::originate_test_harness::{drain, socket};
use super::*;

/// Another answered leg the controller owns, calling from `address` and
/// answered with `profile`, on channel `channel`.
fn another_leg(legs: &Legs, channel: &str, address: &str, profile: &str) -> Caller {
    let leg = answered_caller_from(
        &legs.controller.dispatcher,
        &format!("{channel}@{}", socket(address).ip()),
        address,
        profile,
    );
    legs.controller.bus.register_channel(
        channel,
        &legs.controller.connection,
        &leg.internal_call_id,
        &leg.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    drain(legs.udp());
    leg
}

fn contact_of(leg: &Caller) -> String {
    format!("sip:15550100001@{}", leg.address)
}

fn bridged(legs: &Legs, leg: &Caller) -> Option<bool> {
    legs.state()
        .call_actors
        .bridge(&leg.internal_call_id)
        .map(|half| !half.stage.is_pending())
}

/// `bridge` addressed to channel `target` naming `with`, where `anchor` ends
/// up the anchor and `peer` the other leg. Returns once it has formed.
async fn bridge(legs: &Legs, target: &str, with: &str, anchor: &Caller, peer: &Caller) {
    let (reply, _) = command(
        &legs.controller,
        "bridge",
        target,
        serde_json::json!({ "with": with }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let offer = bridge_offer_to(legs.udp(), &peer.address).await;
    accepts(legs.state(), &peer.address, &offer, &contact_of(peer));
    let to_anchor = bridge_offer_to(legs.udp(), &anchor.address).await;
    accepts(
        legs.state(),
        &anchor.address,
        &to_anchor,
        &contact_of(anchor),
    );
    assert!(
        eventually(|| bridged(legs, anchor) == Some(true) && bridged(legs, peer) == Some(true))
            .await,
        "the bridge formed"
    );
    retired_sessions_deleted(legs).await;
    drain(legs.udp());
}

/// Part `anchor` and `peer` and answer both holds.
async fn unbridge(legs: &Legs, anchor: &Caller, peer: &Caller) {
    tokio::task::block_in_place(|| {
        b2bua_bridge_release(
            &anchor.internal_call_id,
            &peer.internal_call_id,
            "unbridged",
            legs.state(),
        )
    });
    let sent = sent_until(legs.udp(), |sent| {
        !reinvites_to(sent, &peer.address).is_empty()
            && !reinvites_to(sent, &anchor.address).is_empty()
    })
    .await;
    for leg in [peer, anchor] {
        accepts(
            legs.state(),
            &leg.address,
            &reinvites_to(&sent, &leg.address).remove(0),
            &contact_of(leg),
        );
    }
    assert!(
        eventually(|| bridged(legs, anchor).is_none() && bridged(legs, peer).is_none()).await,
        "both legs are parted"
    );
    drain(legs.udp());
}

/// How many calls have a record of what a bridge shaped and pinned them with.
fn records(legs: &Legs) -> usize {
    legs.state()
        .rtpengine_sessions
        .as_ref()
        .expect("a session store")
        .own_media_len()
}

/// Everything is gone: the calls, their sessions, the engine's calls and the
/// per-call records.
async fn assert_all_gone(legs: &Legs, what: &str) {
    assert!(
        eventually(|| legs.state().call_actors.count() == 0).await,
        "{what}: every call is gone"
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
    assert_eq!(records(legs), 0, "{what}: no per-call record is left");
    assert_drained(legs.state());
}

/// The reported gap, in both orders the second `bridge` can be asked in and
/// with the source hint on either side. The second anchor was answered by the
/// engine itself, so the pair is offered onto a fresh engine call: the `offer`
/// carries the second anchor's SDP and yields what the leg is offered, the
/// `answer` carries the leg's own.
#[tokio::test(flavor = "multi_thread")]
async fn a_leg_bridged_to_another_anchor_is_shaped_and_pinned_as_its_own_profile_describes() {
    const SECOND: &str = "192.0.2.30:5060";
    // (both anchors' profile, the leg's, anchors pinned, the leg pinned)
    let cases = [
        (OPEN_PLAIN, PINNED_SECURE, false, true),
        (PINNED_PLAIN, OPEN_SECURE, true, false),
    ];
    let orders = [("second", "peer"), ("peer", "second")];
    for (index, ((anchor_profile, leg_profile, anchor_pinned, leg_pinned), (target, with))) in cases
        .into_iter()
        .flat_map(|case| orders.into_iter().map(move |order| (case, order)))
        .enumerate()
    {
        let what = format!("{anchor_profile} + {leg_profile}, bridge {target} with {with}");
        let leg_address = format!("198.51.100.{}:5060", 231 + index);
        let legs = legs(
            &format!("elsewhere-{index}"),
            &leg_address,
            anchor_profile,
            leg_profile,
        )
        .await;
        legs.bridge("anchor", "peer").await;
        assert!(
            stored(legs.state(), &legs.peer.call_id).is_none(),
            "the leg's own session is retired"
        );
        legs.unbridge().await;

        let second = another_leg(&legs, "second", SECOND, anchor_profile);
        let offers = legs.engine.commands("offer").len();
        bridge(&legs, target, with, &second, &legs.peer).await;

        assert_eq!(
            legs.engine.commands("offer").len(),
            offers + 1,
            "{what}: the new pair is offered onto an engine call of its own"
        );
        let offer = last(&legs.engine, "offer");
        assert_eq!(
            offer.transport_protocol.as_deref(),
            Some("RTP/SAVP"),
            "{what}: the leg is offered what its own profile describes"
        );
        assert_eq!(
            offer.received_from,
            anchor_pinned.then(|| socket(SECOND).ip()),
            "{what}: the second anchor is pinned by its own policy"
        );
        let answer = last(&legs.engine, "answer");
        assert_eq!(answer.call_id, offer.call_id, "{what}");
        assert_eq!(
            answer.transport_protocol.as_deref(),
            Some("RTP/AVP"),
            "{what}: the second anchor is re-INVITEd with what its own describes"
        );
        assert_eq!(
            answer.received_from,
            leg_pinned.then(|| socket(&leg_address).ip()),
            "{what}: the leg is pinned by its own policy, not the second anchor's"
        );

        // The leg hangs up: the anchor it is bridged to goes with it, and the
        // first anchor, parted long since, ends on its own.
        caller_sends(legs.state(), &legs.peer, "BYE", "9 BYE");
        assert!(eventually(|| legs.state().call_actors.count() == 1).await);
        caller_sends(legs.state(), &legs.anchor, "BYE", "9 BYE");
        assert_all_gone(&legs, &what).await;
    }
}

/// The leak gate for the per-call record. Whole calls, each through the
/// bridge, unbridge, bridge-elsewhere cycle and then out by a different door:
/// a BYE from the leg, a BYE from the anchor it is bridged to (which ends it
/// by the bridge's hang-up policy), a teardown of siphon's own, and a BYE
/// while it is parted and bridged to nobody. After each the count is back at
/// zero, and it never exceeds the calls a bridge has retired a session of.
#[tokio::test(flavor = "multi_thread")]
async fn the_per_call_media_record_drains_on_every_way_a_call_ends() {
    const SECOND: &str = "192.0.2.31:5060";
    let exits = [
        "the leg hangs up",
        "its anchor hangs up",
        "siphon ends it",
        "parted",
    ];
    for round in 0..3 {
        for (index, exit) in exits.into_iter().enumerate() {
            let what = format!("round {round}: {exit}");
            let leg_address = format!("198.51.100.{}:5060", 241 + index);
            let legs = legs(
                &format!("record-drain-{round}-{index}"),
                &leg_address,
                OPEN_PLAIN,
                PINNED_SECURE,
            )
            .await;
            assert_eq!(records(&legs), 0, "{what}: nothing before a bridge");
            legs.bridge("anchor", "peer").await;
            assert_eq!(
                records(&legs),
                1,
                "{what}: the leg's own session was retired"
            );
            legs.unbridge().await;
            assert_eq!(records(&legs), 1, "{what}: kept while the call lasts");
            let second = another_leg(&legs, "second", SECOND, OPEN_PLAIN);
            bridge(&legs, "second", "peer", &second, &legs.peer).await;
            assert_eq!(records(&legs), 1, "{what}: one per call, not per bridge");

            match exit {
                "the leg hangs up" => caller_sends(legs.state(), &legs.peer, "BYE", "9 BYE"),
                "its anchor hangs up" => caller_sends(legs.state(), &second, "BYE", "9 BYE"),
                "siphon ends it" => {
                    assert!(tokio::task::block_in_place(|| b2bua_terminate_call_inner(
                        &legs.peer.internal_call_id,
                        None,
                        "b2bua",
                        legs.state(),
                    )));
                }
                _ => {
                    unbridge(&legs, &second, &legs.peer).await;
                    assert_eq!(records(&legs), 1, "{what}: still its call's");
                    caller_sends(legs.state(), &legs.peer, "BYE", "9 BYE");
                    assert!(eventually(|| legs.state().call_actors.count() == 2).await);
                    caller_sends(legs.state(), &second, "BYE", "9 BYE");
                }
            }
            // The leg and the anchor it was bridged to are gone; the first
            // anchor is left, and takes nothing of the leg's with it.
            assert!(
                eventually(|| legs.state().call_actors.count() == 1).await,
                "{what}"
            );
            assert_eq!(records(&legs), 0, "{what}: the record went with the call");
            caller_sends(legs.state(), &legs.anchor, "BYE", "9 BYE");
            assert_all_gone(&legs, &what).await;
        }
    }
}
