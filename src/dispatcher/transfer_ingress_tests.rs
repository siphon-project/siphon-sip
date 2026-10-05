//! Whose profile decides that a party's media ingress is pinned to its
//! signalling source when a transfer re-pairs an anchored call.
//!
//! A leg replacement and a `Replaces` takeover each put the surviving party
//! and a new one on a fresh engine call: one party's SDP goes there as the
//! `offer`, the other's as the `answer`. A fresh engine call has no hint from
//! before, so each command has to carry the `received_from` hint of the party
//! whose SDP it holds, or a party behind NAT is gated on the address in its
//! SDP and the call is silent.
//!
//! Whether a party is pinned is its own policy's decision:
//!
//! * a profile named for the transfer describes the pair it creates the way a
//!   dial's profile does, `offer` half for the party whose SDP is offered and
//!   `answer` half for the one that answers;
//! * with none named, the call's own profile is inherited: the surviving party
//!   keeps the half it was set up under, and the new party takes the half of
//!   the party it replaces.
//!
//! The parties here signal from one address and, where it matters, name
//! another in their SDP. The proof is the command the in-process engine
//! records: a party that sends media from the address it signals cannot show
//! the difference on the wire.

use std::net::IpAddr;

use super::dialog_state_events_tests::{header, inbound, register, tag_of, wire};
use super::dialog_state_transfer_tests::{
    establish, hang_up, host_of, in_dialog, invite, place, respond, response_to_phone,
    sent_invite_to, Established,
};
use super::replacement_fork_tests::ring_two_on;
use super::*;
use crate::b2bua::transfer::ReplacementOrigin;
use crate::rtpengine::test_native_engine::{NativeCommand, NativeTestEngine};

/// No source hint on either half.
const OPEN: &str = "open_pair";
/// The source hint on both halves.
const PINNED: &str = "pinned_pair";
/// The hint on the `offer` half alone: the party whose SDP is offered.
const PINS_OFFERER: &str = "pins_offerer";
/// The hint on the `answer` half alone: the party that answers.
const PINS_ANSWERER: &str = "pins_answerer";

/// The address a new party's SDP names. It stands for the private address a
/// party behind NAT signals: not where its signalling, or its media, comes
/// from.
const SIGNALLED: &str = "203.0.113.77";

/// The built-in profiles plus the four above. Each half names a transport of
/// its own, so a recorded command says which half shaped it.
fn profiles() -> Arc<crate::rtpengine::ProfileRegistry> {
    let pair = |offer: bool, answer: bool| crate::config::MediaProfileConfig {
        offer: crate::config::NgFlagsConfig {
            transport_protocol: Some("RTP/SAVP".to_string()),
            received_from: offer,
            ..Default::default()
        },
        answer: crate::config::NgFlagsConfig {
            transport_protocol: Some("RTP/AVP".to_string()),
            received_from: answer,
            ..Default::default()
        },
    };
    let mut custom = std::collections::HashMap::new();
    custom.insert(OPEN.to_string(), pair(false, false));
    custom.insert(PINNED.to_string(), pair(true, true));
    custom.insert(PINS_OFFERER.to_string(), pair(true, false));
    custom.insert(PINS_ANSWERER.to_string(), pair(false, true));
    Arc::new(crate::rtpengine::ProfileRegistry::from_config(&custom))
}

fn ip(address: &str) -> IpAddr {
    host_of(address).parse().expect("a literal address")
}

fn sdp_naming(address: &str) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 {address}\r\n",
            "s=-\r\n",
            "c=IN IP4 {address}\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        ),
        address = address,
    )
}

/// An answered call between A and B anchored on `engine` under `profile`: the
/// caller offered and the callee answered on an engine call keyed by the
/// caller's Call-ID, as a script's `rtpengine.offer` / `answer` leave it.
async fn anchored(prefix: u32, engine: &NativeTestEngine, profile: &str) -> Established {
    let mut call = establish(prefix, "terminate");
    let registry = profiles();
    let backend = engine.backend();
    let entry = registry.get(profile).expect("a known profile");
    backend
        .offer(
            &call.a_call_id,
            "a-tag",
            sdp_naming(host_of(call.a.1)).as_bytes(),
            &entry.offer,
        )
        .await
        .expect("the engine takes the caller's offer");
    backend
        .answer(
            &call.a_call_id,
            "a-tag",
            "b-tag",
            sdp_naming(host_of(call.b.1)).as_bytes(),
            &entry.answer,
        )
        .await
        .expect("the engine takes the callee's answer");
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    sessions.insert(crate::rtpengine::session::MediaSession {
        call_id: call.a_call_id.clone(),
        rtpengine_call_id: call.a_call_id.clone(),
        from_tag: "a-tag".to_string(),
        to_tag: Some("b-tag".to_string()),
        profile: profile.to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    call.dispatcher.state.rtpengine_set = Some(backend);
    call.dispatcher.state.rtpengine_profiles = Some(registry);
    call.dispatcher.state.rtpengine_sessions = Some(sessions);
    let _ = wire(&call.dispatcher);
    call
}

/// The one command of kind `name` the engine was sent on `engine_call_id`.
fn sent_on(engine: &NativeTestEngine, name: &str, engine_call_id: &str) -> NativeCommand {
    let mut sent: Vec<NativeCommand> = engine
        .commands(name)
        .into_iter()
        .filter(|command| command.call_id == engine_call_id)
        .collect();
    assert_eq!(sent.len(), 1, "one {name} on {engine_call_id}: {sent:?}");
    sent.remove(0)
}

/// The phone at `address` answers `invite` 200, tagged `to_tag`, with an SDP
/// that names [`SIGNALLED`].
fn answer_naming_another_address(invite: &SipMessage, address: &str, to_tag: &str) -> SipMessage {
    let body = sdp_naming(SIGNALLED);
    let mut raw = String::from("SIP/2.0 200 OK\r\n");
    for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag={to_tag}\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str(&format!("Contact: <sip:phone@{address}>\r\n"));
    raw.push_str("Content-Type: application/sdp\r\n");
    raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    parse_sip_message_bytes(raw.as_bytes()).expect("the answer parses")
}

/// One party of `call` sends a REFER naming `target` in its own dialog.
fn refers(call: &Established, from_a_leg: bool, target: &str) {
    let refer_to = format!("Refer-To: <sip:target@{target}>\r\n");
    let (source, (raw, message)) = if from_a_leg {
        (
            call.a.1,
            in_dialog(
                "REFER",
                call.a.1,
                &format!("<{}>;tag=a-tag", call.a.0),
                &header(&call.answer_to_a, "To"),
                &call.a_call_id,
                2,
                &refer_to,
            ),
        )
    } else {
        (
            call.b.1,
            in_dialog(
                "REFER",
                call.b.1,
                &format!("{};tag=b-tag", header(&call.to_b, "To")),
                &header(&call.to_b, "From"),
                &header(&call.to_b, "Call-ID"),
                2,
                &refer_to,
            ),
        )
    };
    tokio::task::block_in_place(|| {
        handle_b2bua_refer(inbound(source, &raw), message, &call.dispatcher.state)
    });
}

/// Replace one party of `call` with `target` the way `replace_peer` does,
/// naming `profile` for the pair when one is given.
fn replaces_peer(call: &Established, replace_a_leg: bool, target: &str, profile: Option<&str>) {
    let call_id = call.call_id();
    let dialled = tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &call_id,
            replace_a_leg,
            &format!("sip:target@{target}"),
            None,
            None,
            None,
            profile,
            None,
            0,
            ReplacementOrigin::SiphonInitiated,
            30,
            &ReplacementDial::default(),
            &call.dispatcher.state,
        )
    });
    assert!(dialled, "an INVITE reached the transport");
}

/// The target at `target` answers the INVITE the replacement sent it, from
/// `target` and naming [`SIGNALLED`]. Returns the fresh engine call-id the
/// pair was put on.
fn target_answers(call: &Established, target: &str) -> String {
    let to_target = sent_invite_to(&wire(&call.dispatcher), target);
    let fresh = header(&to_target, "Call-ID");
    assert_ne!(fresh, call.a_call_id, "a fresh engine call");
    respond(
        &call.dispatcher,
        &call.call_id(),
        target,
        &to_target,
        answer_naming_another_address(&to_target, target, "target-tag"),
    );
    fresh
}

/// Assert the hint on the `offer` and the `answer` of the fresh engine call
/// `fresh`: `offered` is where the party whose SDP was offered signals from
/// when it is to be pinned, `answering` likewise for the one that answered.
fn assert_hints(
    engine: &NativeTestEngine,
    fresh: &str,
    offered: Option<IpAddr>,
    answering: Option<IpAddr>,
    what: &str,
) {
    let offer = sent_on(engine, "offer", fresh);
    assert_eq!(offer.received_from, offered, "{what}: the offer");
    let answer = sent_on(engine, "answer", fresh);
    assert_eq!(answer.received_from, answering, "{what}: the answer");
    assert_ne!(
        answer.received_from,
        SIGNALLED.parse().ok(),
        "{what}: never the address an SDP names"
    );
}

/// A REFER-terminated transfer with no profile named inherits the call's own.
/// The surviving party keeps the half it was set up under (the caller the
/// `offer` half, the callee the `answer` half) whichever command its SDP now
/// rides, and the target takes the half of the party it replaces.
#[tokio::test(flavor = "multi_thread")]
async fn a_referred_transfer_pins_the_survivor_by_its_own_half_and_the_target_by_the_replaced_partys(
) {
    // (profile, the referrer is the caller, survivor pinned, target pinned)
    for (index, (profile, caller_refers, survivor_pinned, target_pinned)) in [
        (PINS_OFFERER, false, true, false),
        (PINS_OFFERER, true, false, true),
        (PINS_ANSWERER, false, false, true),
        (PINS_ANSWERER, true, true, false),
        (PINNED, false, true, true),
        (PINNED, true, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let what = format!("{profile}, caller refers: {caller_refers}");
        let target = format!("203.0.113.{}:5060", 201 + index);
        let engine = NativeTestEngine::start().await;
        let call = anchored(41000 + 10 * index as u32, &engine, profile).await;
        let survivor = if caller_refers { call.b.1 } else { call.a.1 };

        refers(&call, caller_refers, &target);
        let fresh = target_answers(&call, &target);
        assert_hints(
            &engine,
            &fresh,
            survivor_pinned.then(|| ip(survivor)),
            target_pinned.then(|| ip(&target)),
            &what,
        );
        // The commands keep their shape: the offer half toward the target, the
        // answer half toward the survivor.
        assert_eq!(
            sent_on(&engine, "offer", &fresh)
                .transport_protocol
                .as_deref(),
            Some("RTP/SAVP"),
            "{what}"
        );
        assert_eq!(
            sent_on(&engine, "answer", &fresh)
                .transport_protocol
                .as_deref(),
            Some("RTP/AVP"),
            "{what}"
        );
    }
}

/// `replace_peer` naming a profile for the pair it creates: that profile
/// describes both parties, its `offer` half the survivor (whose SDP is
/// offered) and its `answer` half the target, whatever the call was anchored
/// with. With none named the call's own profile decides, as for a REFER.
#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_peer_is_pinned_by_the_profile_named_for_the_pair() {
    // (the call's profile, the profile named, survivor pinned, target pinned)
    for (index, (anchored_with, named, survivor_pinned, target_pinned)) in [
        (OPEN, Some(PINNED), true, true),
        (OPEN, Some(PINS_OFFERER), true, false),
        (OPEN, Some(PINS_ANSWERER), false, true),
        (PINNED, Some(OPEN), false, false),
        (PINNED, None, true, true),
        (PINS_OFFERER, None, true, false),
    ]
    .into_iter()
    .enumerate()
    {
        let what = format!("{anchored_with}, named {named:?}");
        let target = format!("203.0.113.{}:5060", 211 + index);
        let engine = NativeTestEngine::start().await;
        let call = anchored(42000 + 10 * index as u32, &engine, anchored_with).await;

        replaces_peer(&call, false, &target, named);
        let fresh = target_answers(&call, &target);
        assert_hints(
            &engine,
            &fresh,
            survivor_pinned.then(|| ip(call.a.1)),
            target_pinned.then(|| ip(&target)),
            &what,
        );
    }
}

/// A replacement that rings two targets offers the survivor to each on an
/// engine call of its own, pinned alike, and the answer of the one that picks
/// up is pinned to where that one signals from. The other's engine call is
/// deleted without ever being answered.
#[tokio::test(flavor = "multi_thread")]
async fn each_ringing_target_is_offered_the_pinned_survivor_and_the_winner_pinned_by_its_own_source(
) {
    for (index, mobile_wins) in [false, true].into_iter().enumerate() {
        let prefix = 43000 + 10 * index as u32;
        let engine = NativeTestEngine::start().await;
        let call = anchored(prefix, &engine, PINNED).await;
        let survivor = ip(call.a.1);
        let ringing = ring_two_on(call, prefix, ReplacementOrigin::SiphonInitiated, false);
        let (desk_call, mobile_call) = (
            header(&ringing.to_desk, "Call-ID"),
            header(&ringing.to_mobile, "Call-ID"),
        );
        for fresh in [&desk_call, &mobile_call] {
            assert_eq!(
                sent_on(&engine, "offer", fresh).received_from,
                Some(survivor),
                "each target's offer carries the survivor's SDP"
            );
        }

        let (winner, invite, won, lost) = if mobile_wins {
            (ringing.mobile, &ringing.to_mobile, &mobile_call, &desk_call)
        } else {
            (ringing.desk(), &ringing.to_desk, &desk_call, &mobile_call)
        };
        respond(
            &ringing.call.dispatcher,
            &ringing.call_id,
            winner,
            invite,
            answer_naming_another_address(invite, winner, "winner-tag"),
        );
        assert_eq!(
            sent_on(&engine, "answer", won).received_from,
            Some(ip(winner)),
            "the winner's answer is pinned to where the winner signals from"
        );
        assert!(
            engine
                .commands("answer")
                .iter()
                .all(|answer| &answer.call_id != lost),
            "the other target's engine call is never answered"
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while engine.holds(lost) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!engine.holds(lost), "and is deleted");
        assert!(engine.holds(won), "positive control: the winner's is kept");
    }
}

/// An INVITE with `Replaces` takes the callee's place. The newcomer's SDP is
/// the `offer` on the fresh engine call and the survivor's the `answer`. The
/// survivor (the caller) keeps its own `offer` half, though its SDP now rides
/// the answer, and the newcomer takes the half of the callee it replaces.
#[tokio::test(flavor = "multi_thread")]
async fn a_replaces_takeover_pins_the_newcomer_and_the_survivor_by_their_own_policies() {
    // (profile, newcomer pinned, survivor pinned)
    for (index, (profile, newcomer_pinned, survivor_pinned)) in [
        (PINS_OFFERER, false, true),
        (PINS_ANSWERER, true, false),
        (PINNED, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let prefix = 44000 + 10 * index as u32;
        let engine = NativeTestEngine::start().await;
        let call = anchored(prefix, &engine, profile).await;
        let newcomer = format!("192.0.2.{}:5060", 221 + index);
        let fresh = takeover(&call, prefix, &newcomer);
        assert_hints(
            &engine,
            &fresh,
            newcomer_pinned.then(|| ip(&newcomer)),
            survivor_pinned.then(|| ip(call.a.1)),
            profile,
        );
    }
}

/// A newcomer at `newcomer` takes the callee's place in `call` with an INVITE
/// carrying `Replaces`. Returns the fresh engine call-id, the newcomer's own
/// Call-ID.
fn takeover(call: &Established, prefix: u32, newcomer: &str) -> String {
    let aor = format!("sip:{}@example.com", prefix + 4);
    register(&aor, newcomer);
    let siphon_tag = tag_of(&header(&call.to_b, "From"));
    let newcomer_call_id = format!("takeover-{prefix}@{}", host_of(newcomer));
    place(
        &call.dispatcher,
        newcomer,
        &invite(
            newcomer,
            &newcomer_call_id,
            &format!("<{aor}>;tag=newcomer-tag"),
            "sip:takeover@siphon.example.com",
            &format!(
                "Replaces: {};to-tag={siphon_tag};from-tag=b-tag\r\n",
                header(&call.to_b, "Call-ID")
            ),
        ),
    );
    let _ = response_to_phone(&wire(&call.dispatcher), newcomer, 200);
    newcomer_call_id
}

/// The positive control for all of the above: parties whose profile asks for
/// no hint are sent none, by a REFER, a `replace_peer` or a takeover.
#[tokio::test(flavor = "multi_thread")]
async fn parties_whose_profile_asks_for_no_hint_are_sent_none_by_any_transfer() {
    let engine = NativeTestEngine::start().await;
    let referred = anchored(45000, &engine, OPEN).await;
    refers(&referred, false, "203.0.113.231:5060");
    let fresh = target_answers(&referred, "203.0.113.231:5060");
    assert_hints(&engine, &fresh, None, None, "a REFER");

    let engine = NativeTestEngine::start().await;
    let replaced = anchored(45010, &engine, OPEN).await;
    replaces_peer(&replaced, true, "203.0.113.232:5060", None);
    let fresh = target_answers(&replaced, "203.0.113.232:5060");
    assert_hints(&engine, &fresh, None, None, "replace_peer");

    let engine = NativeTestEngine::start().await;
    let taken = anchored(45020, &engine, OPEN).await;
    let fresh = takeover(&taken, 45020, "192.0.2.233:5060");
    assert_hints(&engine, &fresh, None, None, "a takeover");
}

/// A call transferred once and then again: the pair the first transfer built
/// remembers whose policy pins each party, so the second reads the survivor's
/// own and not the half its engine tag happens to sit on. The session and the
/// engine calls go with the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_transfer_still_pins_each_party_by_its_own_policy() {
    const FIRST: &str = "203.0.113.241:5060";
    const SECOND: &str = "203.0.113.242:5060";
    let engine = NativeTestEngine::start().await;
    let call = anchored(46000, &engine, PINS_OFFERER).await;
    let caller = ip(call.a.1);

    // The callee is replaced: the caller survives on its `offer` half, the
    // first target takes the callee's `answer` half.
    refers(&call, false, FIRST);
    let first = target_answers(&call, FIRST);
    assert_hints(&engine, &first, Some(caller), None, "the first transfer");
    assert!(
        !engine.holds(&call.a_call_id),
        "the original anchor is gone"
    );
    // The caller's dialog is the one the call is keyed on before and after, so
    // the pair's session is found where the original anchor was.
    let sessions = call
        .dispatcher
        .state
        .rtpengine_sessions
        .clone()
        .expect("a session store");
    let pair = sessions
        .get(&call.a_call_id)
        .expect("the re-anchored pair keeps the call's media session");
    assert_eq!(pair.rtpengine_id(), first);
    let _ = wire(&call.dispatcher);

    // The first target is replaced in turn: the caller is still the one its
    // own half pins, and the second target takes the first's.
    replaces_peer(&call, false, SECOND, None);
    let second = target_answers(&call, SECOND);
    assert_hints(&engine, &second, Some(caller), None, "the second transfer");

    hang_up(
        &call.dispatcher,
        call.a.1,
        "<sip:x@example.com>;tag=a-tag",
        &header(&call.answer_to_a, "To"),
        &call.a_call_id,
    );
    assert_eq!(call.dispatcher.state.call_actors.count(), 0);
}
