//! A re-INVITE or an UPDATE from a party the script answered itself with SDP
//! that is no media session of the call: a conference participant, seated by
//! `rtpengine.conference_join` and answered with `call.answer()`.
//!
//! siphon has no second party to relay the offer to and no session the engine
//! answers for the leg, so on its own it answers a refresh from the session in
//! force and refuses a change `488` (RFC 3261 §14.2). A hold (`a=sendonly`) is
//! such a change. `@b2bua.on_reoffer` is shown the offer first, so the script
//! that seated the leg can answer it (RFC 3264 §8.4): `offer.answer()` from
//! the session in force with the direction the offer leaves, or its own SDP.

use std::sync::Arc;

use super::dial_bridge_test_harness::caller_invite;
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const CALLER: &str = "192.0.2.10:5060";

/// The answer the script gave the participant: the room's seat.
const SEAT_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 5 5 IN IP4 203.0.113.7\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.7\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// The participant holds: its first offer (`caller_invite`'s), new version,
/// `a=sendonly`.
const HOLD: &str = concat!(
    "v=0\r\n",
    "o=- 1 2 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendonly\r\n",
);

fn script(handler: &str) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    pass\n",
            "{}",
        ),
        handler
    )
}

struct Seat {
    dispatcher: TestDispatcher,
    internal_call_id: String,
    answer: SipMessage,
    call_id: String,
    _engine: NativeTestEngine,
}

/// A participant the script answered with the seat's SDP, ACKed, on a
/// dispatcher with a media engine that holds no session for it.
async fn seated(call_id: &str, source: &str) -> Seat {
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = test_dispatcher_with_script(source);
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.rtpengine_sessions =
        Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
    let state = &dispatcher.state;
    let invite = caller_invite(call_id, CALLER);
    let mut leg = Leg::new_a_leg(
        call_id.to_string(),
        "caller-tag".to_string(),
        format!("z9hG4bK-{call_id}"),
        LegTransport {
            remote_addr: socket(CALLER),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.dialog.remote_contact = invite
        .headers
        .get("Contact")
        .map(|contact| crate::b2bua::actor::extract_contact_uri(contact));
    leg.dialog.local_from_uri = invite
        .headers
        .to()
        .map(|to| format!("{to};tag={}", leg.dialog.local_tag));
    leg.dialog.remote_to_uri = invite.headers.from().cloned();
    leg.last_sdp = Some(invite.body.clone());
    let internal_call_id = state.call_actors.create_call(leg);
    state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite.clone())));
    assert!(send_uas_response(
        state,
        &internal_call_id,
        &invite,
        200,
        "OK",
        Some(SEAT_ANSWER.as_bytes().to_vec()),
        Some("application/sdp"),
        true,
        &[],
    ));
    let answer = drain(&dispatcher.udp)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("the participant is answered")
        .message;
    let seat = Seat {
        dispatcher,
        internal_call_id,
        answer,
        call_id: call_id.to_string(),
        _engine: engine,
    };
    seat.sends("ACK", 1, None);
    seat
}

impl Seat {
    fn sends(&self, method: &str, cseq: u32, body: Option<&str>) -> Vec<Sent> {
        let content = match body {
            Some(body) => format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            None => "Content-Length: 0\r\n\r\n".to_string(),
        };
        let cseq_method = if method == "ACK" { "ACK" } else { method };
        let raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP {address};branch=z9hG4bK-seat-{method}-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} {cseq_method}\r\n",
                "Contact: <sip:15550100001@{address}>\r\n",
                "{content}",
            ),
            method = method,
            address = CALLER,
            cseq = cseq,
            cseq_method = cseq_method,
            from = self.answer.headers.from().expect("a From"),
            to = self.answer.headers.to().expect("a To"),
            call_id = self.call_id,
            content = content,
        );
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: socket("192.0.2.1:5060"),
            remote_addr: socket(CALLER),
            data: Bytes::from(raw),
        };
        let state = &self.dispatcher.state;
        tokio::task::block_in_place(|| match method {
            "ACK" => {
                assert!(absorb_b2bua_ack(&self.call_id, &message, state));
            }
            "INVITE" => handle_b2bua_reinvite(inbound, message, state),
            "UPDATE" => handle_b2bua_update(inbound, message, state),
            other => panic!("no {other} in these tests"),
        });
        drain(&self.dispatcher.udp)
    }
}

/// The one final response among `sent`.
fn final_response(sent: &[Sent]) -> SipMessage {
    let finals: Vec<_> = sent
        .iter()
        .filter(|frame| frame.message.status_code().is_some_and(|code| code >= 200))
        .collect();
    assert_eq!(finals.len(), 1, "one final response");
    finals[0].message.clone()
}

fn body(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

/// Without a handler, a hold is still the change siphon cannot answer: 488,
/// and the session stays as it was.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_handler_a_hold_is_refused_as_before() {
    let seat = seated("seat-hold-none@192.0.2.10", &script("")).await;
    let refused = final_response(&seat.sends("INVITE", 2, Some(HOLD)));
    assert_eq!(refused.status_code(), Some(488));
}

/// `offer.answer()` answers the hold from the seat's answer, `recvonly` for
/// the `sendonly` it was offered (RFC 3264 §6.1), with siphon's `o=` at a new
/// version (§8), and the handler saw the offer read as a hold.
#[tokio::test(flavor = "multi_thread")]
async fn the_handler_answers_a_hold_from_the_seat() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    assert offer.kind == \"hold\", offer.kind\n",
        "    offer.answer()\n",
    );
    let seat = seated("seat-hold-answer@192.0.2.10", &script(handler)).await;
    let answered = final_response(&seat.sends("INVITE", 2, Some(HOLD)));
    assert_eq!(answered.status_code(), Some(200));
    let sdp = body(&answered);
    assert!(sdp.contains("a=recvonly"), "{sdp}");
    assert!(sdp.contains("m=audio 40000 RTP/AVP 0"), "{sdp}");
    assert!(sdp.contains("c=IN IP4 203.0.113.7"), "{sdp}");
    assert!(
        answered.headers.get("Contact").is_some(),
        "a 2xx to a target refresh carries the Contact"
    );
    assert!(seat
        .dispatcher
        .state
        .call_actors
        .get_call(&seat.internal_call_id)
        .is_some_and(|call| call.state == CallState::Answered));
}

/// The script's own SDP is the answer, and an UPDATE (RFC 3311) is shown to
/// the handler the same way.
#[tokio::test(flavor = "multi_thread")]
async fn the_handler_answers_an_update_with_its_own_sdp() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    offer.answer(sdp=offer.sdp.replace(\"sendonly\", \"recvonly\").replace(\"192.0.2.10\", \"203.0.113.9\"))\n",
    );
    let seat = seated("seat-update@192.0.2.10", &script(handler)).await;
    let answered = final_response(&seat.sends("UPDATE", 2, Some(HOLD)));
    assert_eq!(answered.status_code(), Some(200));
    let sdp = body(&answered);
    assert!(
        sdp.contains("c=IN IP4 203.0.113.9") && sdp.contains("a=recvonly"),
        "{sdp}"
    );
}

/// `offer.reject()` is the answer the offerer gets.
#[tokio::test(flavor = "multi_thread")]
async fn the_handler_refuses_an_offer() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    offer.reject(403, \"Forbidden\")\n",
    );
    let seat = seated("seat-reject@192.0.2.10", &script(handler)).await;
    let refused = final_response(&seat.sends("INVITE", 2, Some(HOLD)));
    assert_eq!(refused.status_code(), Some(403));
}

/// A handler that leaves the offer alone leaves siphon's own answer: an
/// offerless refresh (RFC 4028) is answered with the session in force.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_leaves_a_refresh_alone_gets_the_session_in_force() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    pass\n",
    );
    let seat = seated("seat-refresh@192.0.2.10", &script(handler)).await;
    let answered = final_response(&seat.sends("INVITE", 2, None));
    assert_eq!(answered.status_code(), Some(200));
    assert!(
        body(&answered).contains("m=audio 40000"),
        "{}",
        body(&answered)
    );
}
