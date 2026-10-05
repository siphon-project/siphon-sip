//! Whose policy pins a party's media ingress when a re-INVITE or an UPDATE
//! renegotiates an anchored call between its two legs.
//!
//! The relay sends the engine two commands: a `reoffer` carrying the SDP of
//! the party that re-offers, and an `answer` carrying the other party's. Each
//! takes its shape from the profile half of the command, and its
//! `received_from` hint from the party whose SDP it carries: that party's own
//! policy, and where that party signals from. The caller of a dial is the
//! party its profile's `offer` half was written for and the callee the
//! `answer` half's, whichever of them re-offers.
//!
//! The parties here signal from one address and name another in their SDP,
//! as a party behind NAT does. The proof is the command the in-process engine
//! records.

use std::net::IpAddr;

use super::dial_bridge_test_harness::in_dialog_response;
use super::dialog_state_events_tests::{header, inbound, register, tag_of, wire, Sent};
use super::dialog_state_transfer_tests::{
    hang_up, host_of, invite, place, respond, response_to_phone, Established,
};
use super::transfer_ingress_tests::{
    anchored, ip, sdp_naming, OPEN, PINNED, PINS_ANSWERER, PINS_OFFERER, SIGNALLED,
};
use super::*;
use crate::rtpengine::test_native_engine::{NativeCommand, NativeTestEngine};

/// One party of a call as it sends in-dialog requests: where it signals from
/// and its own dialog with siphon.
pub(super) struct Party {
    pub(super) address: String,
    pub(super) from: String,
    pub(super) to: String,
    pub(super) call_id: String,
}

/// The caller of `call`, in the dialog its INVITE opened.
pub(super) fn caller_of(call: &Established) -> Party {
    Party {
        address: call.a.1.to_string(),
        from: format!("<{}>;tag=a-tag", call.a.0),
        to: header(&call.answer_to_a, "To"),
        call_id: call.a_call_id.clone(),
    }
}

/// The callee of `call`, in the dialog siphon's INVITE opened.
pub(super) fn callee_of(call: &Established) -> Party {
    Party {
        address: call.b.1.to_string(),
        from: format!("{};tag=b-tag", header(&call.to_b, "To")),
        to: header(&call.to_b, "From"),
        call_id: header(&call.to_b, "Call-ID"),
    }
}

/// `party` sends `method` in its dialog, with `body` when it carries one.
pub(super) fn request_from(
    party: &Party,
    method: &str,
    cseq: u32,
    body: Option<&str>,
) -> (String, SipMessage) {
    let content = match body {
        Some(body) => format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
        None => "Content-Length: 0\r\n\r\n".to_string(),
    };
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-{method}-{cseq}-{tag}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Contact: <sip:phone@{source}>\r\n",
            "{content}",
        ),
        method = method,
        source = party.address,
        from = party.from,
        to = party.to,
        call_id = party.call_id,
        cseq = cseq,
        tag = party.call_id.replace(['@', '.'], "-"),
        content = content,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    (raw, message)
}

/// `party` ACKs the 2xx that set its dialog up, which frees the dialog for a
/// re-INVITE relayed to it (RFC 3261 §14.1).
pub(super) fn acks(dispatcher: &super::test_dispatcher::TestDispatcher, party: &Party) {
    let (_, ack) = request_from(party, "ACK", 1, None);
    assert!(
        tokio::task::block_in_place(|| absorb_b2bua_ack(&party.call_id, &ack, &dispatcher.state)),
        "the ACK belongs to a call"
    );
}

/// `party` re-offers with `method` and an SDP naming [`SIGNALLED`], through
/// the handler the request path hands it to.
pub(super) fn reoffers(
    dispatcher: &super::test_dispatcher::TestDispatcher,
    party: &Party,
    method: &str,
    cseq: u32,
) {
    let body = sdp_naming(SIGNALLED);
    let (raw, message) = request_from(party, method, cseq, Some(&body));
    let arrived = inbound(&party.address, &raw);
    tokio::task::block_in_place(|| match method {
        "INVITE" => handle_b2bua_reinvite(arrived, message, &dispatcher.state),
        "UPDATE" => handle_b2bua_update(arrived, message, &dispatcher.state),
        other => panic!("no {other} re-offer in these tests"),
    });
}

/// The `method` request siphon sent to `address`.
pub(super) fn relayed_to(sent: &[Sent], address: &str, method: &str) -> SipMessage {
    let method = match method {
        "INVITE" => Method::Invite,
        _ => Method::Update,
    };
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.method() == Some(&method))
        .map(|sent| sent.message.clone())
        .unwrap_or_else(|| {
            panic!(
                "no {method:?} to {address}: {:?}",
                sent.iter()
                    .map(|sent| format!(
                        "{} {:?} {:?}",
                        sent.destination,
                        sent.message.method(),
                        sent.message.status_code()
                    ))
                    .collect::<Vec<_>>()
            )
        })
}

/// The party at `address` accepts the `relayed` request, from where it
/// signals and with an SDP naming [`SIGNALLED`].
pub(super) fn accepts(call: &Established, call_id: &str, address: &str, relayed: &SipMessage) {
    respond(
        &call.dispatcher,
        call_id,
        address,
        relayed,
        in_dialog_response(
            relayed,
            200,
            "OK",
            &format!("sip:phone@{address}"),
            Some(&sdp_naming(SIGNALLED)),
        ),
    );
}

/// The last command of kind `name` the engine was sent on `engine_call_id`.
pub(super) fn last_on(
    engine: &NativeTestEngine,
    name: &str,
    engine_call_id: &str,
) -> NativeCommand {
    engine
        .commands(name)
        .into_iter()
        .filter(|command| command.call_id == engine_call_id)
        .next_back()
        .unwrap_or_else(|| panic!("no {name} on {engine_call_id}"))
}

/// `offerer` re-offers with `method`, the relayed request reaches `answerer`
/// and is accepted. Returns the `reoffer` and the `answer` the engine was sent
/// for it on `engine_call_id`.
pub(super) fn renegotiates(
    call: &Established,
    engine: &NativeTestEngine,
    engine_call_id: &str,
    offerer: &Party,
    answerer: &Party,
    method: &str,
    cseq: u32,
) -> (NativeCommand, NativeCommand) {
    let reoffers_before = engine.commands("reoffer").len();
    let answers_before = engine.commands("answer").len();
    let _ = wire(&call.dispatcher);
    reoffers(&call.dispatcher, offerer, method, cseq);
    let relayed = relayed_to(&wire(&call.dispatcher), &answerer.address, method);
    accepts(call, &call.call_id(), &answerer.address, &relayed);
    assert_eq!(
        engine.commands("reoffer").len(),
        reoffers_before + 1,
        "one re-offer reaches the engine"
    );
    assert_eq!(
        engine.commands("answer").len(),
        answers_before + 1,
        "and one answer"
    );
    let _ = response_to_phone(&wire(&call.dispatcher), &offerer.address, 200);
    (
        last_on(engine, "reoffer", engine_call_id),
        last_on(engine, "answer", engine_call_id),
    )
}

fn pinned_at(pinned: bool, party: &Party) -> Option<IpAddr> {
    pinned.then(|| ip(&party.address))
}

/// A re-INVITE and an UPDATE from either party of an ordinary call: the
/// caller is pinned where the profile's `offer` half asks and the callee where
/// its `answer` half does, whichever of them re-offers and whichever command
/// carries its SDP. The commands keep their shape, the `offer` half on the
/// re-offer and the `answer` half on the answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_reoffer_pins_each_party_by_its_own_half_whoever_reoffers() {
    // (profile, the caller is pinned, the callee is pinned)
    let cases = [
        (PINS_OFFERER, true, false),
        (PINS_ANSWERER, false, true),
        (PINNED, true, true),
        (OPEN, false, false),
    ];
    let mut prefix = 51000;
    for (profile, caller_pinned, callee_pinned) in cases {
        for method in ["INVITE", "UPDATE"] {
            for caller_reoffers in [true, false] {
                prefix += 10;
                let what = format!("{profile}, {method}, caller re-offers: {caller_reoffers}");
                let engine = NativeTestEngine::start().await;
                let call = anchored(prefix, &engine, profile).await;
                let (caller, callee) = (caller_of(&call), callee_of(&call));
                acks(&call.dispatcher, &caller);
                let (offerer, answerer, offerer_pinned, answerer_pinned) = if caller_reoffers {
                    (&caller, &callee, caller_pinned, callee_pinned)
                } else {
                    (&callee, &caller, callee_pinned, caller_pinned)
                };

                let (reoffer, answer) = renegotiates(
                    &call,
                    &engine,
                    &call.a_call_id,
                    offerer,
                    answerer,
                    method,
                    2,
                );
                assert_eq!(
                    reoffer.received_from,
                    pinned_at(offerer_pinned, offerer),
                    "{what}: the re-offer carries the re-offering party's SDP"
                );
                assert_eq!(
                    answer.received_from,
                    pinned_at(answerer_pinned, answerer),
                    "{what}: the answer carries the answering party's SDP"
                );
                for command in [&reoffer, &answer] {
                    assert_ne!(
                        command.received_from,
                        SIGNALLED.parse().ok(),
                        "{what}: never the address an SDP names"
                    );
                }
                assert_eq!(reoffer.sip_call_id.as_deref(), Some(&*offerer.call_id));
                assert_eq!(answer.sip_call_id.as_deref(), Some(&*answerer.call_id));
                assert_eq!(
                    reoffer.transport_protocol.as_deref(),
                    Some("RTP/SAVP"),
                    "{what}: shaped by the `offer` half"
                );
                assert_eq!(
                    answer.transport_protocol.as_deref(),
                    Some("RTP/AVP"),
                    "{what}: shaped by the `answer` half"
                );

                hang_up(
                    &call.dispatcher,
                    &caller.address,
                    &caller.from,
                    &caller.to,
                    &caller.call_id,
                );
                assert_eq!(call.dispatcher.state.call_actors.count(), 0, "{what}");
            }
        }
    }
}

/// A newcomer at `newcomer` takes the callee's place in `call` with an INVITE
/// carrying `Replaces`, and is ACKed. Returns the newcomer as a party: its
/// Call-ID is the fresh engine call the pair is on.
fn taken_over_by(call: &Established, prefix: u32, newcomer: &str) -> Party {
    let aor = format!("sip:{}@example.com", prefix + 4);
    register(&aor, newcomer);
    let siphon_tag = tag_of(&header(&call.to_b, "From"));
    let call_id = format!("takeover-{prefix}@{}", host_of(newcomer));
    let from = format!("<{aor}>;tag=newcomer-tag");
    place(
        &call.dispatcher,
        newcomer,
        &invite(
            newcomer,
            &call_id,
            &from,
            "sip:takeover@siphon.example.com",
            &format!(
                "Replaces: {};to-tag={siphon_tag};from-tag=b-tag\r\n",
                header(&call.to_b, "Call-ID")
            ),
        ),
    );
    let sent = wire(&call.dispatcher);
    let answered = response_to_phone(&sent, newcomer, 200);
    let party = Party {
        address: newcomer.to_string(),
        from,
        to: header(&answered, "To"),
        call_id,
    };
    acks(&call.dispatcher, &party);
    // The surviving caller answers the re-INVITE that pointed it at the
    // newcomer, which frees its dialog for an offer relayed to it.
    let to_survivor = relayed_to(&sent, call.a.1, "INVITE");
    let internal = call
        .dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(&party.call_id)
        .expect("the call follows the newcomer's dialog");
    accepts(call, &internal, call.a.1, &to_survivor);
    party
}

/// After a `Replaces` takeover the newcomer sits in the caller's slot of the
/// call and the surviving caller in the callee's, so the slot no longer says
/// whose half is whose. The pair's session recorded it: the surviving caller
/// keeps the `offer` half it was set up under and the newcomer has the half of
/// the callee it replaced, on a re-offer from either of them.
#[tokio::test(flavor = "multi_thread")]
async fn a_reoffer_after_a_takeover_pins_each_party_by_what_the_pair_recorded() {
    // (profile, the surviving caller is pinned, the newcomer is pinned)
    let cases = [
        (PINS_OFFERER, true, false),
        (PINS_ANSWERER, false, true),
        (PINNED, true, true),
        (OPEN, false, false),
    ];
    let mut prefix = 52000;
    for (index, (profile, survivor_pinned, newcomer_pinned)) in cases.into_iter().enumerate() {
        for method in ["INVITE", "UPDATE"] {
            for newcomer_reoffers in [true, false] {
                prefix += 10;
                let what = format!("{profile}, {method}, newcomer re-offers: {newcomer_reoffers}");
                let engine = NativeTestEngine::start().await;
                let call = anchored(prefix, &engine, profile).await;
                let survivor = caller_of(&call);
                acks(&call.dispatcher, &survivor);
                let newcomer =
                    taken_over_by(&call, prefix, &format!("192.0.2.{}:5062", 231 + index));
                let fresh = newcomer.call_id.clone();
                let (offerer, answerer, offerer_pinned, answerer_pinned) = if newcomer_reoffers {
                    (&newcomer, &survivor, newcomer_pinned, survivor_pinned)
                } else {
                    (&survivor, &newcomer, survivor_pinned, newcomer_pinned)
                };

                let internal = call
                    .dispatcher
                    .state
                    .call_actors
                    .find_by_sip_call_id(&fresh)
                    .expect("the call");
                let _ = wire(&call.dispatcher);
                reoffers(&call.dispatcher, offerer, method, 7);
                let relayed = relayed_to(&wire(&call.dispatcher), &answerer.address, method);
                accepts(&call, &internal, &answerer.address, &relayed);
                let reoffer = last_on(&engine, "reoffer", &fresh);
                let answer = last_on(&engine, "answer", &fresh);
                assert_eq!(
                    reoffer.received_from,
                    pinned_at(offerer_pinned, offerer),
                    "{what}: the re-offer carries the re-offering party's SDP"
                );
                assert_eq!(
                    answer.received_from,
                    pinned_at(answerer_pinned, answerer),
                    "{what}: the answer carries the answering party's SDP"
                );
                assert_eq!(
                    reoffer.transport_protocol.as_deref(),
                    Some("RTP/SAVP"),
                    "{what}: shaped by the `offer` half"
                );
                assert_eq!(
                    answer.transport_protocol.as_deref(),
                    Some("RTP/AVP"),
                    "{what}: shaped by the `answer` half"
                );
            }
        }
    }
}
