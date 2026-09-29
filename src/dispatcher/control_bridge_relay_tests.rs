//! An in-dialog offer on either leg of a formed controller bridge is relayed
//! to the other leg.
//!
//! Each leg of a controller bridge is the A-leg of its own call actor, so
//! without a relay a re-INVITE on one looked like a call with nobody on the
//! other side: the carrier's hold was answered by the engine itself with an
//! `answer_local` on the pair's call-id (which a live engine takes as a new
//! single-party call, dropping the relay the phone was on), and the phone's
//! hold was refused `488`. The relay re-offers on the pair's session toward
//! the other party, shaped by that party's side of the bridge, and answers the
//! sender with the engine's answer, shaped by the sender's side.
//!
//! The pair here is a plain-RTP carrier caller bridged by a dial to an
//! SRTP-only phone, so every SDP says which side's flags shaped it.

use super::control_bridge_media_tests::{
    accepts, bridge_offer_to, caller_accepts, host, last, phone_answers, profiles, CARRIER,
    SRTP_PHONE,
};
use super::control_originate_tests::Controller;
use super::dial_bridge_test_harness::{
    answered_caller_from, bridging_dispatcher, controller_owning, dial, eventually,
    in_dialog_response, invite_to, reinvites_to, sent_until, Caller, CALLER,
};
use super::originate_test_harness::{drain, phone_offer, requests_to, socket, Sent};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// A formed bridge between a plain-RTP carrier caller and an SRTP phone.
pub(super) struct Pair {
    pub(super) controller: Controller,
    pub(super) engine: NativeTestEngine,
    pub(super) caller: Caller,
    /// The phone's address.
    pub(super) phone: &'static str,
    /// The phone's Contact.
    pub(super) contact: String,
    /// The bridge's re-INVITE to the phone: the phone's dialog, from siphon's
    /// side (its From is siphon's, its To the phone's).
    pub(super) phone_dialog: SipMessage,
    /// The engine call-id the pair relays on.
    pub(super) pair_call_id: String,
    /// The carrier's next CSeq.
    pub(super) carrier_cseq: std::cell::Cell<u32>,
    /// The phone's next CSeq.
    pub(super) phone_cseq: std::cell::Cell<u32>,
}

impl Pair {
    pub(super) fn state(&self) -> &DispatcherState {
        &self.controller.dispatcher.state
    }

    pub(super) fn udp(&self) -> &flume::Receiver<OutboundMessage> {
        &self.controller.dispatcher.udp
    }
}

/// Bridge a carrier caller to an SRTP phone at `phone` through a bridge dial,
/// and wait until the bridge has formed.
pub(super) async fn srtp_pair(app: &str, phone: &'static str) -> Pair {
    let contact = format!("sip:relay@{phone}");
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = bridging_dispatcher(&engine);
    dispatcher.state.rtpengine_profiles = Some(profiles());
    let caller = answered_caller_from(&dispatcher, &format!("{app}@192.0.2.10"), CALLER, CARRIER);
    let controller = controller_owning(app, dispatcher, &caller, app, "hangup");
    let (reply, _) = dial(
        &controller,
        app,
        serde_json::json!({ "targets": [contact], "on_answer": "bridge", "profile": SRTP_PHONE }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let invite = invite_to(&drain(udp), phone);
    phone_answers(state, phone, &invite, &contact);
    let offer = bridge_offer_to(udp, phone).await;
    let pair_call_id = last(&engine, "offer").call_id;
    accepts(state, phone, &offer, &contact);
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

/// An SDP from `address` stating `direction`.
pub(super) fn sdp_from(address: &str, direction: &str) -> String {
    phone_offer(host(address)).replace("a=sendrecv", &format!("a={direction}"))
}

/// An in-dialog `method` from one party of the pair, with `body` as its SDP.
pub(super) fn request(
    pair: &Pair,
    from_carrier: bool,
    method: &str,
    body: Option<&str>,
) -> SipMessage {
    let (address, from, to, call_id, contact, cseq) = if from_carrier {
        (
            pair.caller.address.clone(),
            pair.caller.answer.headers.from().cloned().expect("a From"),
            pair.caller.answer.headers.to().cloned().expect("a To"),
            pair.caller.call_id.clone(),
            format!("sip:15550100001@{}", pair.caller.address),
            &pair.carrier_cseq,
        )
    } else {
        (
            pair.phone.to_string(),
            pair.phone_dialog.headers.to().cloned().expect("a To"),
            pair.phone_dialog.headers.from().cloned().expect("a From"),
            pair.phone_dialog
                .headers
                .call_id()
                .cloned()
                .expect("a Call-ID"),
            pair.contact.clone(),
            &pair.phone_cseq,
        )
    };
    let number = cseq.get();
    cseq.set(number + 1);
    let (content_type, length, body) = match body {
        Some(sdp) => (
            "Content-Type: application/sdp\r\n".to_string(),
            sdp.len(),
            sdp.to_string(),
        ),
        None => (String::new(), 0, String::new()),
    };
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-relay-{method}-{number}-{side}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {number} {method}\r\n",
            "Contact: <{contact}>\r\n",
            "{content_type}",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        method = method,
        address = address,
        number = number,
        side = if from_carrier { "carrier" } else { "phone" },
        from = from,
        to = to,
        call_id = call_id,
        contact = contact,
        content_type = content_type,
        length = length,
        body = body,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the request parses")
}

/// Hand `message` from `address` to the dispatcher the way the request path does.
pub(super) fn deliver(pair: &Pair, address: &str, message: SipMessage) {
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket("192.0.2.1:5060"),
        remote_addr: socket(address),
        data: Bytes::from(message.to_bytes()),
    };
    let state = pair.state();
    tokio::task::block_in_place(|| match message.method() {
        Some(Method::Invite) => handle_b2bua_reinvite(inbound, message, state),
        Some(Method::Update) => handle_b2bua_update(inbound, message, state),
        Some(Method::Bye) => handle_b2bua_bye(inbound, message, state),
        other => panic!("the tests send no {other:?}"),
    });
}

/// The final responses among `sent` to `address`.
pub(super) fn finals_to(sent: &[Sent], address: &str) -> Vec<SipMessage> {
    sent.iter()
        .filter(|frame| frame.destination == socket(address))
        .filter(|frame| frame.message.status_code().is_some_and(|code| code >= 200))
        .map(|frame| frame.message.clone())
        .collect()
}

/// The in-dialog UPDATEs among `sent` to `address`.
pub(super) fn updates_to(sent: &[Sent], address: &str) -> Vec<SipMessage> {
    requests_to(sent, socket(address), Method::Update)
        .into_iter()
        .map(|frame| frame.message)
        .collect()
}

pub(super) fn text(message: &SipMessage) -> &str {
    std::str::from_utf8(&message.body).expect("a text body")
}

/// The engine never answers a formed pair's own call-id itself: on a live
/// engine an `answer_local` there is a new single-party call that drops the
/// relay and leaks its ports.
pub(super) fn assert_no_local_answer_on_the_pair(pair: &Pair) {
    assert!(
        pair.engine
            .commands("answer_local")
            .iter()
            .all(|command| command.call_id != pair.pair_call_id),
        "answer_local on the pair's call-id: {:?}",
        pair.engine.commands("answer_local")
    );
}

/// What siphon sent until `done` holds.
pub(super) async fn wait_for(pair: &Pair, done: impl Fn(&[Sent]) -> bool) -> Vec<Sent> {
    sent_until(pair.udp(), done).await
}

/// (a) The carrier holds: the phone is re-INVITEd with SRTP `sendonly`, shaped
/// by the phone's side and pinned to the carrier's source; its `recvonly`
/// answer goes back to the carrier as plain RTP `recvonly`, shaped by the
/// carrier's side and pinned to the phone's source.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_hold_is_relayed_to_the_phone_on_each_sides_media() {
    const PHONE: &str = "198.51.100.171:5060";
    let pair = srtp_pair("relay-hold", PHONE).await;
    let reoffers = pair.engine.commands("reoffer").len();
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    let to_phone = reinvites_to(&sent, PHONE)
        .into_iter()
        .next()
        .expect("the hold reaches the phone");
    assert!(
        text(&to_phone).contains("RTP/SAVP") && text(&to_phone).contains("a=sendonly"),
        "the phone is offered SRTP sendonly: {}",
        text(&to_phone)
    );
    assert!(
        finals_to(&sent, CALLER).is_empty(),
        "the carrier waits for the phone"
    );
    let reoffer = &pair.engine.commands("reoffer")[reoffers..];
    assert_eq!(reoffer.len(), 1, "one re-offer on the pair's session");
    assert_eq!(reoffer[0].call_id, pair.pair_call_id);
    assert_eq!(
        reoffer[0].from_tag, "caller-tag",
        "named by the sender's tag"
    );
    assert_eq!(reoffer[0].transport_protocol.as_deref(), Some("RTP/SAVP"));
    assert_eq!(reoffer[0].received_from, Some(socket(CALLER).ip()));
    assert_eq!(
        reoffer[0].sip_call_id.as_deref(),
        Some(pair.caller.call_id.as_str()),
        "the carrier's SDP, filed under the carrier's dialog"
    );

    accept_with(&pair, PHONE, &to_phone, "recvonly");
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    let answered = finals_to(&sent, CALLER);
    assert_eq!(answered[0].status_code(), Some(200));
    assert!(
        text(&answered[0]).contains("RTP/AVP") && text(&answered[0]).contains("a=recvonly"),
        "the carrier is answered plain RTP recvonly: {}",
        text(&answered[0])
    );
    assert_eq!(
        requests_to(&sent, socket(PHONE), Method::Ack).len(),
        1,
        "the phone's 200 is ACKed"
    );
    let answer = last(&pair.engine, "answer");
    assert_eq!(answer.call_id, pair.pair_call_id);
    assert_eq!(answer.from_tag, "caller-tag");
    assert_eq!(answer.transport_protocol.as_deref(), Some("RTP/AVP"));
    assert_eq!(answer.received_from, Some(socket(PHONE).ip()));
    assert_eq!(
        answer.sip_call_id.as_ref(),
        pair.phone_dialog.headers.call_id(),
        "the phone's SDP, filed under the phone's dialog"
    );
    assert_no_local_answer_on_the_pair(&pair);
}

/// The party at `address` accepts the relayed `offer` stating `direction`.
pub(super) fn accept_with(pair: &Pair, address: &str, offer: &SipMessage, direction: &str) {
    let contact = if address == pair.phone {
        pair.contact.clone()
    } else {
        format!("sip:15550100001@{address}")
    };
    phone_sends_response(
        pair,
        address,
        &in_dialog_response(
            offer,
            200,
            "OK",
            &contact,
            Some(&sdp_from(address, direction)),
        ),
    );
}

pub(super) fn phone_sends_response(pair: &Pair, address: &str, response: &SipMessage) {
    super::originate_test_harness::phone_sends(pair.state(), socket(address), response);
}

/// (b) The phone re-INVITEs: the carrier is offered plain RTP, and the phone's
/// 200 is SRTP.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_reinvite_is_relayed_to_the_carrier_on_each_sides_media() {
    const PHONE: &str = "198.51.100.172:5060";
    let pair = srtp_pair("relay-phone", PHONE).await;
    deliver(
        &pair,
        PHONE,
        request(&pair, false, "INVITE", Some(&sdp_from(PHONE, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| {
        !reinvites_to(sent, CALLER).is_empty() || !finals_to(sent, PHONE).is_empty()
    })
    .await;
    assert!(
        finals_to(&sent, PHONE).is_empty(),
        "not refused: {:?}",
        finals_to(&sent, PHONE)
            .iter()
            .map(|response| response.status_code())
            .collect::<Vec<_>>()
    );
    let to_carrier = reinvites_to(&sent, CALLER)
        .into_iter()
        .next()
        .expect("the phone's re-INVITE reaches the carrier");
    assert!(
        text(&to_carrier).contains("RTP/AVP") && text(&to_carrier).contains("a=sendonly"),
        "the carrier is offered plain RTP: {}",
        text(&to_carrier)
    );
    let reoffer = last(&pair.engine, "reoffer");
    assert_eq!(
        reoffer.from_tag,
        format!("tag-{}", host(PHONE)),
        "the phone's tag"
    );
    assert_eq!(reoffer.transport_protocol.as_deref(), Some("RTP/AVP"));
    assert_eq!(reoffer.received_from, Some(socket(PHONE).ip()));
    assert_eq!(
        reoffer.sip_call_id.as_ref(),
        pair.phone_dialog.headers.call_id()
    );

    accept_with(&pair, CALLER, &to_carrier, "recvonly");
    let sent = wait_for(&pair, |sent| !finals_to(sent, PHONE).is_empty()).await;
    let answered = finals_to(&sent, PHONE);
    assert_eq!(answered[0].status_code(), Some(200));
    assert!(
        text(&answered[0]).contains("RTP/SAVP") && text(&answered[0]).contains("a=recvonly"),
        "the phone is answered SRTP: {}",
        text(&answered[0])
    );
    let answer = last(&pair.engine, "answer");
    assert_eq!(answer.transport_protocol.as_deref(), Some("RTP/SAVP"));
    assert_eq!(answer.received_from, Some(socket(CALLER).ip()));
    assert_eq!(
        answer.sip_call_id.as_deref(),
        Some(pair.caller.call_id.as_str())
    );
    assert_no_local_answer_on_the_pair(&pair);
}

/// The UPDATE equivalents, in both directions: relayed as an UPDATE, answered
/// in its 200, never ACKed (RFC 3311 §5.4).
#[tokio::test(flavor = "multi_thread")]
async fn an_update_is_relayed_in_both_directions_on_each_sides_media() {
    const PHONE: &str = "198.51.100.173:5060";
    let pair = srtp_pair("relay-update", PHONE).await;

    deliver(
        &pair,
        CALLER,
        request(&pair, true, "UPDATE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| !updates_to(sent, PHONE).is_empty()).await;
    let to_phone = updates_to(&sent, PHONE)
        .into_iter()
        .next()
        .expect("an UPDATE to the phone");
    assert!(text(&to_phone).contains("RTP/SAVP") && text(&to_phone).contains("a=sendonly"));
    accept_with(&pair, PHONE, &to_phone, "recvonly");
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    let answered = finals_to(&sent, CALLER);
    assert_eq!(answered[0].status_code(), Some(200));
    assert!(text(&answered[0]).contains("RTP/AVP") && text(&answered[0]).contains("a=recvonly"));
    assert!(requests_to(&sent, socket(PHONE), Method::Ack).is_empty());

    deliver(
        &pair,
        PHONE,
        request(&pair, false, "UPDATE", Some(&sdp_from(PHONE, "sendrecv"))),
    );
    let sent = wait_for(&pair, |sent| {
        !updates_to(sent, CALLER).is_empty() || !finals_to(sent, PHONE).is_empty()
    })
    .await;
    let to_carrier = updates_to(&sent, CALLER)
        .into_iter()
        .next()
        .expect("an UPDATE to the carrier");
    assert!(text(&to_carrier).contains("RTP/AVP"));
    accept_with(&pair, CALLER, &to_carrier, "sendrecv");
    let sent = wait_for(&pair, |sent| !finals_to(sent, PHONE).is_empty()).await;
    let answered = finals_to(&sent, PHONE);
    assert_eq!(answered[0].status_code(), Some(200));
    assert!(text(&answered[0]).contains("RTP/SAVP"));
    assert_no_local_answer_on_the_pair(&pair);
}

/// The phone refuses the relayed hold: the carrier gets the phone's own
/// status, the engine is put back on the media both parties had, and the next
/// hold relays as the first would have.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_is_relayed_back_and_the_engine_restored() {
    const PHONE: &str = "198.51.100.174:5060";
    let pair = srtp_pair("relay-refused", PHONE).await;
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    let to_phone = reinvites_to(&sent, PHONE)
        .into_iter()
        .next()
        .expect("relayed");
    let reoffers = pair.engine.commands("reoffer").len();
    let answers = pair.engine.commands("answer").len();
    phone_sends_response(
        &pair,
        PHONE,
        &in_dialog_response(&to_phone, 488, "Not Acceptable Here", &pair.contact, None),
    );
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    assert_eq!(finals_to(&sent, CALLER)[0].status_code(), Some(488));
    assert_eq!(
        requests_to(&sent, socket(PHONE), Method::Ack).len(),
        1,
        "the phone's 488 is ACKed"
    );
    // Restored: the carrier's previous media re-offered, closed with the
    // phone's own current answer.
    let restore = &pair.engine.commands("reoffer")[reoffers..];
    assert_eq!(
        restore.len(),
        1,
        "the engine is re-offered the previous media"
    );
    assert_eq!(restore[0].call_id, pair.pair_call_id);
    assert_eq!(pair.engine.commands("answer").len(), answers + 1);

    // A later hold relays normally: nothing was left claimed.
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    assert!(finals_to(&sent, CALLER).is_empty(), "not refused as glare");
    assert_no_local_answer_on_the_pair(&pair);
}

/// While one relay is outstanding a second offer on either leg is refused
/// `491` (RFC 3261 §14.1), and it relays once the first has settled.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_crossing_an_outstanding_relay_is_refused_491() {
    const PHONE: &str = "198.51.100.175:5060";
    let pair = srtp_pair("relay-glare", PHONE).await;
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    let to_phone = reinvites_to(&sent, PHONE)
        .into_iter()
        .next()
        .expect("relayed");

    deliver(
        &pair,
        PHONE,
        request(&pair, false, "INVITE", Some(&sdp_from(PHONE, "sendonly"))),
    );
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "inactive"))),
    );
    let sent = wait_for(&pair, |sent| {
        !finals_to(sent, PHONE).is_empty() && !finals_to(sent, CALLER).is_empty()
    })
    .await;
    assert_eq!(finals_to(&sent, PHONE)[0].status_code(), Some(491));
    assert_eq!(finals_to(&sent, CALLER)[0].status_code(), Some(491));
    assert!(
        reinvites_to(&sent, CALLER).is_empty(),
        "the crossing offer goes nowhere"
    );

    accept_with(&pair, PHONE, &to_phone, "recvonly");
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    assert_eq!(finals_to(&sent, CALLER)[0].status_code(), Some(200));
    // Positive control: settled, the phone's retry relays.
    deliver(
        &pair,
        PHONE,
        request(&pair, false, "INVITE", Some(&sdp_from(PHONE, "sendonly"))),
    );
    let sent = wait_for(&pair, |sent| !reinvites_to(sent, CALLER).is_empty()).await;
    assert!(!reinvites_to(&sent, CALLER).is_empty());
}

/// A bodyless re-INVITE or UPDATE is a session refresh (RFC 4028): answered
/// at once from the session in force on that leg, with nothing sent to the
/// engine or to the other party.
#[tokio::test(flavor = "multi_thread")]
async fn a_bodyless_refresh_is_answered_from_the_session_in_force() {
    const PHONE: &str = "198.51.100.176:5060";
    let pair = srtp_pair("relay-refresh", PHONE).await;
    let in_force = pair
        .state()
        .call_actors
        .get_call(&pair.caller.internal_call_id)
        .and_then(|call| call.a_leg.dialog.last_sent_sdp.clone())
        .expect("the carrier has a session in force");
    let commands = |pair: &Pair| {
        ["reoffer", "answer", "answer_local", "offer"]
            .iter()
            .map(|name| pair.engine.commands(name).len())
            .sum::<usize>()
    };
    let before = commands(&pair);

    deliver(&pair, CALLER, request(&pair, true, "INVITE", None));
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    let answered = finals_to(&sent, CALLER);
    assert_eq!(answered[0].status_code(), Some(200));
    assert_eq!(answered[0].body, in_force, "the offer in force, unchanged");
    assert!(
        reinvites_to(&sent, PHONE).is_empty(),
        "nothing to the phone"
    );

    deliver(&pair, PHONE, request(&pair, false, "UPDATE", None));
    let sent = wait_for(&pair, |sent| !finals_to(sent, PHONE).is_empty()).await;
    let answered = finals_to(&sent, PHONE);
    assert_eq!(answered[0].status_code(), Some(200));
    assert!(
        answered[0].body.is_empty(),
        "an UPDATE refresh carries no offer"
    );
    assert!(
        updates_to(&sent, CALLER).is_empty(),
        "nothing to the carrier"
    );
    assert_eq!(commands(&pair), before, "the engine is not touched");
}

/// The carrier hangs up while its hold is being relayed: its re-INVITE is
/// answered `487` (RFC 3261 §15.1.2), the phone is released by the bridge's
/// hangup policy, and nothing is left on the engine.
#[tokio::test(flavor = "multi_thread")]
async fn a_hangup_mid_relay_answers_the_pending_offer_and_leaves_nothing() {
    const PHONE: &str = "198.51.100.177:5060";
    let pair = srtp_pair("relay-hangup", PHONE).await;
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    deliver(&pair, CALLER, request(&pair, true, "BYE", None));
    let sent = wait_for(&pair, |sent| {
        finals_to(sent, CALLER)
            .iter()
            .any(|response| response.status_code() == Some(487))
    })
    .await;
    assert!(
        finals_to(&sent, CALLER)
            .iter()
            .any(|response| response.status_code() == Some(487)),
        "the pending re-INVITE is answered"
    );
    assert!(eventually(|| pair.engine.held_count() == 0).await);
    assert_no_local_answer_on_the_pair(&pair);
}

/// The phone hangs up mid-relay: the carrier's pending re-INVITE is answered
/// too.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_hangup_mid_relay_answers_the_originator() {
    const PHONE: &str = "198.51.100.178:5060";
    let pair = srtp_pair("relay-peer-gone", PHONE).await;
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    deliver(&pair, PHONE, request(&pair, false, "BYE", None));
    let sent = wait_for(&pair, |sent| {
        finals_to(sent, CALLER)
            .iter()
            .any(|response| response.status_code() == Some(487))
    })
    .await;
    assert!(finals_to(&sent, CALLER)
        .iter()
        .any(|response| response.status_code() == Some(487)));
    assert!(eventually(|| pair.engine.held_count() == 0).await);
}

/// After a relayed hold and resume, unbridging still holds both legs, each on
/// its own side's media.
#[tokio::test(flavor = "multi_thread")]
async fn unbridge_after_relayed_offers_holds_each_leg_on_its_own_media() {
    const PHONE: &str = "198.51.100.179:5060";
    let pair = srtp_pair("relay-unbridge", PHONE).await;
    for direction in ["sendonly", "sendrecv"] {
        deliver(
            &pair,
            CALLER,
            request(&pair, true, "INVITE", Some(&sdp_from(CALLER, direction))),
        );
        let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
        let to_phone = reinvites_to(&sent, PHONE)
            .into_iter()
            .next()
            .expect("relayed");
        let answer = if direction == "sendonly" {
            "recvonly"
        } else {
            "sendrecv"
        };
        accept_with(&pair, PHONE, &to_phone, answer);
        wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    }
    let phone_internal = pair
        .state()
        .call_actors
        .find_by_sip_call_id(pair.phone_dialog.headers.call_id().expect("a Call-ID"))
        .expect("the phone's call");
    b2bua_bridge_release(
        &pair.caller.internal_call_id,
        &phone_internal,
        "unbridged",
        pair.state(),
    );
    let sent = wait_for(&pair, |sent| {
        !reinvites_to(sent, PHONE).is_empty() && !reinvites_to(sent, CALLER).is_empty()
    })
    .await;
    let to_phone = reinvites_to(&sent, PHONE).remove(0);
    let to_carrier = reinvites_to(&sent, CALLER).remove(0);
    assert!(text(&to_phone).contains("RTP/SAVP") && text(&to_phone).contains("a=sendonly"));
    assert!(text(&to_carrier).contains("RTP/AVP") && text(&to_carrier).contains("a=sendonly"));
}

/// The other leg never answers: after a whole transaction timeout the sender
/// is answered `408` and the pair's session put back.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_nobody_answers_times_out_408() {
    const PHONE: &str = "198.51.100.180:5060";
    let pair = srtp_pair("relay-timeout", PHONE).await;
    deliver(
        &pair,
        CALLER,
        request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
    );
    wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
    let reoffers = pair.engine.commands("reoffer").len();
    let state = pair.state();
    // Not yet: a relay inside its transaction is left alone.
    bridge_relay_sweep(state, std::time::Instant::now());
    assert!(finals_to(&drain(pair.udp()), CALLER).is_empty());
    tokio::task::block_in_place(|| {
        bridge_relay_sweep(
            state,
            std::time::Instant::now()
                + state.transaction_timeout
                + std::time::Duration::from_secs(1),
        )
    });
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    assert_eq!(finals_to(&sent, CALLER)[0].status_code(), Some(408));
    assert_eq!(
        pair.engine.commands("reoffer").len(),
        reoffers + 1,
        "the pair's session is put back"
    );
    assert_eq!(state.bridge_relays.len(), 0);
}
