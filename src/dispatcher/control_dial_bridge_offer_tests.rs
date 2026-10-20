//! `dial {on_answer: "bridge", offer: "early"}`: each phone's INVITE carries
//! an offer the media engine allocated for it from the caller's media, for
//! peers that refuse a delayed-offer INVITE.
//!
//! Driven as a controller drives it, against a native engine in the test
//! process whose own log says what it allocated, answered and deleted, and
//! which calls it still holds: the drain gate.

use super::dial_bridge_test_harness::{
    answered_caller, assert_drained, bridging_dispatcher, caller_sends, command, controller_owning,
    dial, events, events_through, eventually, in_dialog_response, invite_to, names, reinvites_to,
    sent_until, Caller, CALLER,
};
use super::originate_test_harness::{
    drain, phone_offer, phone_response, phone_sends, phone_tries, requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

fn body_text(message: &SipMessage) -> &str {
    std::str::from_utf8(&message.body).expect("a text body")
}

fn sessions(state: &DispatcherState) -> &Arc<crate::rtpengine::MediaSessionStore> {
    state.rtpengine_sessions.as_ref().expect("a media store")
}

fn call_id_of(invite: &SipMessage) -> String {
    invite.headers.call_id().cloned().expect("a Call-ID")
}

/// The engine call a leg's offer was allocated on, read off the leg's own
/// media session.
fn allocation_of(state: &DispatcherState, invite: &SipMessage) -> String {
    sessions(state)
        .get(&call_id_of(invite))
        .expect("the leg holds its allocation")
        .rtpengine_id()
        .to_string()
}

struct Rig {
    engine: NativeTestEngine,
    controller: super::control_originate_tests::Controller,
    caller: Caller,
    channel: String,
}

async fn rig(name: &str) -> Rig {
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, &format!("{name}@192.0.2.10"));
    let channel = format!("caller-{name}");
    let controller = controller_owning(name, dispatcher, &caller, &channel, "hangup");
    Rig {
        engine,
        controller,
        caller,
        channel,
    }
}

const DESK: &str = "198.51.100.171:5060";
const TRUNK: &str = "198.51.100.172:5060";

/// The case the option exists for: every leg's INVITE carries its own
/// allocation's offer, shaped by its own profile; the winner's 2xx answer is
/// given to its allocation, which becomes the caller's pair session; the
/// phone is never re-INVITEd, only the caller; the loser's allocation and the
/// caller's own session are deleted.
#[tokio::test(flavor = "multi_thread")]
async fn each_leg_is_offered_its_own_allocation_and_the_winners_answer_joins_the_caller() {
    let rig = rig("offer-win").await;
    let state = &rig.controller.dispatcher.state;
    let engine = &rig.engine;
    crate::control::channel_event_capture::watch(&rig.caller.call_id);

    let (reply, _) = dial(
        &rig.controller,
        &rig.channel,
        serde_json::json!({
            "on_answer": "bridge",
            "offer": "early",
            "targets": [
                format!("sip:300@{DESK}"),
                { "uri": format!("sip:+15550100@{TRUNK}"), "profile": "rtp_to_srtp" },
            ],
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["offer"], "early");

    let sent = drain(&rig.controller.dispatcher.udp);
    let desk = invite_to(&sent, DESK);
    let trunk = invite_to(&sent, TRUNK);
    let offers = engine.commands("offer");
    assert_eq!(offers.len(), 2, "one allocation per leg");
    assert_ne!(offers[0].call_id, offers[1].call_id);
    for offer in &offers {
        assert_ne!(offer.call_id, rig.caller.call_id, "beside the caller's own");
        assert_eq!(offer.from_tag, "caller-tag", "keyed on the caller's tag");
        assert_eq!(
            offer.sip_call_id.as_deref(),
            Some(rig.caller.call_id.as_str()),
            "the SDP offered is the caller's"
        );
    }
    let desk_allocation = allocation_of(state, &desk);
    let trunk_allocation = allocation_of(state, &trunk);
    assert_ne!(desk_allocation, trunk_allocation);
    for (invite, transport) in [(&desk, "RTP/AVP"), (&trunk, "RTP/SAVP")] {
        assert_eq!(
            invite.headers.get("Content-Type").map(String::as_str),
            Some("application/sdp")
        );
        assert_eq!(
            invite.headers.get("Content-Length").map(String::as_str),
            Some(invite.body.len().to_string().as_str())
        );
        assert!(
            body_text(invite).contains(&format!("m=audio 52000 {transport} 0 101")),
            "each leg offered under its own profile: {}",
            body_text(invite)
        );
    }
    assert!(
        sent.iter().all(|frame| frame.destination != socket(CALLER)),
        "nothing reaches the caller while the phones ring"
    );
    phone_tries(state, DESK, &desk);

    // The trunk answers in its 2xx (RFC 3264 §5).
    phone_sends(
        state,
        socket(TRUNK),
        &phone_response(
            &trunk,
            200,
            "OK",
            "trunk-tag",
            &format!("sip:+15550100@{TRUNK}"),
            Some(&phone_offer("198.51.100.172")),
        ),
    );
    let sent = sent_until(&rig.controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, CALLER).is_empty()
    })
    .await;
    let acks = requests_to(&sent, socket(TRUNK), Method::Ack);
    assert_eq!(acks.len(), 1);
    assert!(
        acks[0].message.body.is_empty(),
        "the offer was in the INVITE, so the ACK carries no SDP"
    );
    assert!(
        reinvites_to(&sent, TRUNK).is_empty(),
        "the trunk's offer/answer stands: it is not re-INVITEd"
    );
    let answers = engine.commands("answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(
        answers[0].call_id, trunk_allocation,
        "on the trunk's allocation"
    );
    assert_eq!(
        answers[0].sip_call_id.as_deref(),
        Some(call_id_of(&trunk).as_str()),
        "the trunk's answer, from the trunk's dialog"
    );
    assert_eq!(
        reinvites_to(&sent, CALLER).len(),
        1,
        "the caller is re-INVITEd"
    );
    assert!(requests_to(&sent, socket(DESK), Method::Cancel).is_empty());

    let to_caller = reinvites_to(&sent, CALLER).remove(0);
    phone_sends(
        state,
        socket(CALLER),
        &in_dialog_response(
            &to_caller,
            200,
            "OK",
            "sip:15550100001@192.0.2.10:5060",
            Some(&phone_offer("192.0.2.10")),
        ),
    );
    let heard = events_through(&rig.controller, "DialAnswered").await;
    assert_eq!(names(&heard), ["DialBranchFailed", "DialAnswered"]);
    let sent = drain(&rig.controller.dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(DESK), Method::Cancel).len(), 1);

    // The trunk's allocation is the caller's pair session now; the caller's
    // own session and the desk's allocation are gone.
    let pair = sessions(state).get(&rig.caller.call_id).expect("the pair");
    assert_eq!(pair.rtpengine_id(), trunk_allocation);
    assert_eq!(pair.to_tag.as_deref(), Some("trunk-tag"));
    assert!(sessions(state).get(&call_id_of(&desk)).is_none());
    assert!(sessions(state).get(&call_id_of(&trunk)).is_none());
    assert!(
        eventually(|| !engine.holds(&desk_allocation) && !engine.holds(&rig.caller.call_id)).await
    );
    assert!(engine.holds(&trunk_allocation), "the pair's media stays up");
    assert_eq!(engine.held_count(), 1);
    assert!(
        crate::control::channel_event_capture::take(&rig.caller.call_id)
            .iter()
            .any(|(event, _)| event == "ChannelBridged"),
        "the caller is bridged to the trunk"
    );
    assert_drained(state);
}

/// How a dial with early offers can end without a bridge.
#[derive(Debug, Clone, Copy)]
enum Ending {
    Rejected,
    RingTimeout,
    ControllerCancel,
    CallerHangup,
}

/// Per-module leak gate: a dial whose phones were all offered early, ended
/// every way it can end before a bridge, leaves the engine holding the
/// caller's own session alone (none, once the caller hung up), the media
/// store holding the caller alone, and nothing of the dial behind. Run in
/// iterations, so a per-dial leak shows up as growth.
#[tokio::test(flavor = "multi_thread")]
async fn early_offers_drain_to_baseline_however_the_dial_ends() {
    for round in 0..3 {
        for ending in [
            Ending::Rejected,
            Ending::RingTimeout,
            Ending::ControllerCancel,
            Ending::CallerHangup,
        ] {
            let rig = rig(&format!("offer-drain-{round}-{ending:?}")).await;
            let state = &rig.controller.dispatcher.state;
            let (reply, _) = dial(
                &rig.controller,
                &rig.channel,
                serde_json::json!({
                    "on_answer": "bridge",
                    "offer": "early",
                    "timeout": 5,
                    "targets": [format!("sip:300@{DESK}"), format!("sip:301@{TRUNK}")],
                }),
            )
            .await;
            assert_eq!(reply["status"], "ok", "{reply}");
            let sent = drain(&rig.controller.dispatcher.udp);
            let invites = [invite_to(&sent, DESK), invite_to(&sent, TRUNK)];
            assert_eq!(rig.engine.held_count(), 3, "the caller and two allocations");
            assert_eq!(sessions(state).len(), 3);
            for (phone, invite) in [DESK, TRUNK].iter().zip(&invites) {
                phone_tries(state, phone, invite);
            }

            match ending {
                Ending::Rejected => {
                    for (phone, invite) in [DESK, TRUNK].iter().zip(&invites) {
                        phone_sends(
                            state,
                            socket(phone),
                            &phone_response(invite, 486, "Busy Here", "busy", "sip:p@x", None),
                        );
                    }
                }
                Ending::RingTimeout => check_b2bua_answer_timeouts_at(
                    state,
                    std::time::Instant::now() + std::time::Duration::from_secs(6),
                ),
                Ending::ControllerCancel => {
                    // The reply waits for the dial to let go, so its
                    // `DialFailed` is queued ahead of it.
                    let (reply, queued) = command(
                        &rig.controller,
                        "cancel_dial",
                        &rig.channel,
                        serde_json::json!({}),
                    )
                    .await;
                    assert_eq!(reply["status"], "ok", "{reply}");
                    assert!(
                        names(&queued).contains(&"DialFailed"),
                        "{:?}",
                        names(&queued)
                    );
                }
                Ending::CallerHangup => caller_sends(state, &rig.caller, "BYE", "2 BYE"),
            }

            let caller_left = matches!(ending, Ending::CallerHangup);
            let baseline = usize::from(!caller_left);
            assert!(
                eventually(|| rig.engine.held_count() == baseline).await,
                "{ending:?}: the engine still holds {} calls",
                rig.engine.held_count()
            );
            assert_eq!(sessions(state).len(), baseline, "{ending:?}: the store");
            assert_eq!(
                rig.engine.commands("answer").len(),
                0,
                "nothing was answered"
            );
            if !caller_left {
                assert!(
                    rig.engine.holds(&rig.caller.call_id),
                    "the caller's own stays"
                );
            }
            if matches!(ending, Ending::Rejected | Ending::RingTimeout) {
                let _ = events_through(&rig.controller, "DialFailed").await;
            }
            assert!(
                eventually(|| state.dial_bridges.ringing_count() == 0).await,
                "{ending:?}: the dial let go"
            );
            assert_drained(state);
        }
    }
}

/// A 2xx with no SDP to an INVITE that carried an offer leaves it unanswered
/// (RFC 3261 §13.2.1): the phone is ACKed then BYEd, its allocation deleted,
/// the branch reported failed with 488, and with nobody else ringing the dial
/// fails. The caller is left as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_without_an_answer_to_the_offer_is_acked_byed_and_reported() {
    let rig = rig("offer-noanswer").await;
    let state = &rig.controller.dispatcher.state;
    let (reply, _) = dial(
        &rig.controller,
        &rig.channel,
        serde_json::json!({
            "on_answer": "bridge",
            "targets": [{ "uri": format!("sip:300@{DESK}"), "offer": "early" }],
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["result"]["offer"], "delayed",
        "the dial's own default"
    );
    let sent = drain(&rig.controller.dispatcher.udp);
    let desk = invite_to(&sent, DESK);
    assert!(!desk.body.is_empty(), "the target's own offer mode wins");
    let allocation = allocation_of(state, &desk);

    phone_sends(
        state,
        socket(DESK),
        &phone_response(&desk, 200, "OK", "desk-tag", "sip:300@198.51.100.171", None),
    );
    let sent = sent_until(&rig.controller.dispatcher.udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Bye).is_empty()
    })
    .await;
    assert_eq!(requests_to(&sent, socket(DESK), Method::Ack).len(), 1);
    assert_eq!(requests_to(&sent, socket(DESK), Method::Bye).len(), 1);
    assert!(sent.iter().all(|frame| frame.destination != socket(CALLER)));
    let heard = events_through(&rig.controller, "DialFailed").await;
    let failed = heard
        .iter()
        .find(|event| event.event == "DialBranchFailed")
        .expect("the branch is reported");
    assert_eq!(failed.payload["code"], 488);
    assert!(
        failed.payload["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("13.2.1")),
        "{}",
        failed.payload
    );
    assert!(eventually(|| !rig.engine.holds(&allocation)).await);
    assert!(rig.engine.commands("answer").is_empty());
    assert_eq!(rig.engine.held_count(), 1, "the caller's own alone");
    assert_eq!(sessions(state).len(), 1);
    assert!(state
        .call_actors
        .get_call(&rig.caller.internal_call_id)
        .is_some());
    assert_drained(state);
}

/// The default is unchanged: a bridging dial naming no offer sends its phones
/// offerless, and a target can ask for delayed under a dial asking early.
#[tokio::test(flavor = "multi_thread")]
async fn delayed_stays_the_default_and_a_target_can_keep_it() {
    let rig = rig("offer-default").await;
    let state = &rig.controller.dispatcher.state;
    let (reply, _) = dial(
        &rig.controller,
        &rig.channel,
        serde_json::json!({
            "on_answer": "bridge",
            "offer": "early",
            "targets": [
                { "uri": format!("sip:300@{DESK}"), "offer": "delayed" },
                format!("sip:301@{TRUNK}"),
            ],
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&rig.controller.dispatcher.udp);
    assert!(invite_to(&sent, DESK).body.is_empty(), "delayed: offerless");
    assert!(!invite_to(&sent, TRUNK).body.is_empty());
    assert_eq!(rig.engine.commands("offer").len(), 1);
    let (reply, queued) = command(
        &rig.controller,
        "cancel_dial",
        &rig.channel,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(names(&queued).contains(&"DialFailed"));
    assert!(
        eventually(|| rig.engine.held_count() == 1).await,
        "the allocation went"
    );

    let (reply, _) = dial(
        &rig.controller,
        &rig.channel,
        serde_json::json!({ "on_answer": "bridge", "targets": [format!("sip:302@{DESK}")] }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["offer"], "delayed");
    assert!(invite_to(&drain(&rig.controller.dispatcher.udp), DESK)
        .body
        .is_empty());
    assert_eq!(rig.engine.commands("offer").len(), 1, "no new allocation");
    let _ = command(
        &rig.controller,
        "cancel_dial",
        &rig.channel,
        serde_json::json!({}),
    )
    .await;
    let _ = events(&rig.controller).await;
    assert!(eventually(|| state.dial_bridges.ringing_count() == 0).await);
}

/// `offer` is validated: an unknown mode, a connecting dial (whose branches
/// carry the caller's own offer) and an originate (which has no caller to
/// offer from) are each refused rather than ignored, and nothing is rung.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_siphon_cannot_honour_is_refused() {
    let rig = rig("offer-refused").await;
    for (args, reason) in [
        (
            serde_json::json!({ "on_answer": "bridge", "offer": "late",
                                "targets": [format!("sip:300@{DESK}")] }),
            Some("unknown_value"),
        ),
        (
            serde_json::json!({ "on_answer": "bridge",
                                "targets": [{ "uri": format!("sip:300@{DESK}"), "offer": 1 }] }),
            None,
        ),
        (
            serde_json::json!({ "offer": "early", "targets": [format!("sip:300@{DESK}")] }),
            Some("requires_bridge"),
        ),
        (
            serde_json::json!({ "targets": [{ "uri": format!("sip:300@{DESK}"), "offer": "delayed" }] }),
            Some("requires_bridge"),
        ),
    ] {
        let (reply, _) = dial(&rig.controller, &rig.channel, args.clone()).await;
        assert_eq!(reply["status"], "error", "{args}: {reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
        if let Some(reason) = reason {
            assert_eq!(reply["error"]["details"]["reason"], reason, "{reply}");
        }
    }
    assert!(drain(&rig.controller.dispatcher.udp).is_empty());

    let reply = super::control_originate_tests::originate(
        &rig.controller,
        serde_json::json!({
            "channel": "offer-originate",
            "to": format!("sip:300@{DESK}"),
            "media": true,
            "offer": "early",
        }),
    )
    .await;
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["details"]["reason"], "no_caller", "{reply}");
    assert!(rig.engine.commands("offer").is_empty());
}

/// The caller refusing its bridge re-INVITE fails the bridge: the phone that
/// answered is released, its allocation deleted, and the caller keeps its own
/// session, from which the dial could ring again.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_the_caller_refuses_releases_the_phone_and_its_allocation() {
    let rig = rig("offer-refused-bridge").await;
    let state = &rig.controller.dispatcher.state;
    let (reply, _) = dial(
        &rig.controller,
        &rig.channel,
        serde_json::json!({
            "on_answer": "bridge",
            "offer": "early",
            "targets": [format!("sip:300@{DESK}")],
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let desk = invite_to(&drain(&rig.controller.dispatcher.udp), DESK);
    let allocation = allocation_of(state, &desk);
    phone_sends(
        state,
        socket(DESK),
        &phone_response(
            &desk,
            200,
            "OK",
            "desk-tag",
            "sip:300@198.51.100.171",
            Some(&phone_offer("198.51.100.171")),
        ),
    );
    let sent = sent_until(&rig.controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, CALLER).is_empty()
    })
    .await;
    let to_caller = reinvites_to(&sent, CALLER).remove(0);
    phone_sends(
        state,
        socket(CALLER),
        &in_dialog_response(
            &to_caller,
            488,
            "Not Acceptable Here",
            "sip:15550100001@192.0.2.10:5060",
            None,
        ),
    );
    let heard = events_through(&rig.controller, "DialFailed").await;
    assert!(
        names(&heard).contains(&"DialBranchFailed"),
        "{:?}",
        names(&heard)
    );
    let sent = sent_until(&rig.controller.dispatcher.udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Bye).is_empty()
    })
    .await;
    assert_eq!(requests_to(&sent, socket(DESK), Method::Bye).len(), 1);
    assert!(eventually(|| !rig.engine.holds(&allocation)).await);
    assert!(
        rig.engine.holds(&rig.caller.call_id),
        "the caller's own session stays"
    );
    assert_eq!(rig.engine.held_count(), 1);
    assert!(eventually(|| sessions(state).len() == 1).await);
    assert_eq!(
        sessions(state)
            .get(&rig.caller.call_id)
            .map(|own| own.rtpengine_id().to_string()),
        Some(rig.caller.call_id.clone())
    );
    assert!(eventually(|| state.dial_bridges.ringing_count() == 0).await);
    assert_drained(state);
}
