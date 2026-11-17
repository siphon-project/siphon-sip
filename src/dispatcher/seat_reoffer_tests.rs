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
//!
//! The offer may ride in a `multipart/*` body beside a part of the service's
//! own (RFC 5621 §3), and the handler may send one back the same way, with
//! headers of its own on the 200. A seat the engine keyed, ran ICE for and
//! bundled is answered from the engine's description of it when the offer asks
//! for none of that again. The last tests are a call the engine answered
//! itself (`answer_local`), where the handler is shown the offer too and the
//! engine still answers it.

use std::sync::Arc;

use super::adopt_replaced_tests::focus_running;
use super::dial_bridge_test_harness::{answered_caller, caller_invite};
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_native_engine::{
    NativeTestEngine, NATIVE_ENGINE_ANSWER, NATIVE_ENGINE_REFUSED_OFFER,
};
use crate::siprec::multipart::parse_multipart;

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

/// The participant's first offer again at a new `o=` version: a refresh.
fn refresh() -> String {
    HOLD.replace("a=sendonly\r\n", "")
}

/// The part a mission-critical push-to-talk client sends beside its offer
/// (TS 24.379 annex F.1).
const INFO_TYPE: &str = "application/vnd.3gpp.mcptt-info+xml";
const INFO: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
    "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\">",
    "<mcptt-Params><emergency-ind type=\"Normal\">",
    "<mcpttBoolean>true</mcpttBoolean></emergency-ind></mcptt-Params>",
    "</mcpttinfo>",
);

/// `sdp` and [`INFO`] as the participant sends them together: the
/// `Content-Type` and the body.
fn with_info(sdp: &str) -> (String, String) {
    (
        "multipart/mixed;boundary=participant-1".to_string(),
        format!(
            "--participant-1\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n\
             --participant-1\r\nContent-Type: {INFO_TYPE}\r\n\r\n{INFO}\r\n\
             --participant-1--\r\n"
        ),
    )
}

/// A participant's offer toward a media engine that keys with DTLS, runs ICE
/// and bundles (RFC 8842, RFC 8839, RFC 9143).
const KEYED_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 4 4 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "t=0 0\r\n",
    "a=group:BUNDLE 0\r\n",
    "m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "a=mid:0\r\n",
    "a=ice-ufrag:ofrg\r\n",
    "a=ice-pwd:offererpassword0000000000\r\n",
    "a=fingerprint:sha-256 AA:BB\r\n",
    "a=setup:actpass\r\n",
    "a=rtcp-mux\r\n",
    "a=rtpmap:111 opus/48000/2\r\n",
);

/// The engine's answer to it, which the script answered the participant with.
const KEYED_SESSION: &str = concat!(
    "v=0\r\n",
    "o=- 9 9 IN IP4 203.0.113.7\r\n",
    "s=-\r\n",
    "t=0 0\r\n",
    "a=group:BUNDLE 0\r\n",
    "m=audio 40000 UDP/TLS/RTP/SAVPF 111\r\n",
    "c=IN IP4 203.0.113.7\r\n",
    "a=mid:0\r\n",
    "a=ice-ufrag:efrg\r\n",
    "a=ice-pwd:enginepassword00000000000\r\n",
    "a=fingerprint:sha-256 CC:DD\r\n",
    "a=setup:passive\r\n",
    "a=rtcp-mux\r\n",
    "a=rtpmap:111 opus/48000/2\r\n",
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
    engine: NativeTestEngine,
}

/// A participant the script answered with the seat's SDP, ACKed, on a
/// dispatcher with a media engine that holds no session for it.
async fn seated(call_id: &str, source: &str) -> Seat {
    seated_with(call_id, source, None, SEAT_ANSWER).await
}

/// [`seated`], the participant having offered `offer` (its INVITE's own SDP
/// when `None`) and been answered `answer`.
async fn seated_with(call_id: &str, source: &str, offer: Option<&str>, answer: &str) -> Seat {
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = test_dispatcher_with_script(source);
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.rtpengine_sessions =
        Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
    let state = &dispatcher.state;
    let mut invite = caller_invite(call_id, CALLER);
    if let Some(offer) = offer {
        invite.body = offer.as_bytes().to_vec();
        invite
            .headers
            .set("Content-Length", offer.len().to_string());
    }
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
        Some(answer.as_bytes().to_vec()),
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
        engine,
    };
    seat.sends("ACK", 1, None);
    seat
}

/// A caller the media engine answered itself (`answer_local`), ACKed: the
/// engine is the far side of its session, and answers its re-offers.
async fn engine_answered(call_id: &str, source: &str) -> Seat {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus_running(&engine, source);
    let caller = answered_caller(&dispatcher, call_id);
    Seat {
        dispatcher,
        internal_call_id: caller.internal_call_id,
        answer: caller.answer,
        call_id: call_id.to_string(),
        engine,
    }
}

impl Seat {
    fn sends(&self, method: &str, cseq: u32, body: Option<&str>) -> Vec<Sent> {
        self.sends_with(method, cseq, body.map(|body| ("application/sdp", body)), "")
    }

    /// [`Self::sends`] with a body of any `Content-Type` and `headers`, whole
    /// header lines, on the request.
    fn sends_with(
        &self,
        method: &str,
        cseq: u32,
        body: Option<(&str, &str)>,
        headers: &str,
    ) -> Vec<Sent> {
        let content = match body {
            Some((content_type, body)) => format!(
                "{headers}Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            None => format!("{headers}Content-Length: 0\r\n\r\n"),
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

    /// What the participant's dialog holds: the description it last gave, and
    /// the session in force toward it.
    fn descriptions(&self) -> (Option<String>, Option<String>) {
        let text = |sdp: &Option<Vec<u8>>| {
            sdp.as_ref()
                .map(|sdp| String::from_utf8_lossy(sdp).into_owned())
        };
        self.dispatcher
            .state
            .call_actors
            .get_call(&self.internal_call_id)
            .map(|call| {
                (
                    text(&call.a_leg.last_sdp),
                    text(&call.a_leg.dialog.last_sent_sdp),
                )
            })
            .expect("the call")
    }
}

/// The parts of a multipart response: each one's `Content-Type` and content.
fn parts(message: &SipMessage) -> Vec<(String, String)> {
    let content_type = message.headers.get("Content-Type").expect("a Content-Type");
    assert_eq!(
        message.headers.get("Content-Length").map(String::as_str),
        Some(message.body.len().to_string().as_str())
    );
    parse_multipart(content_type, &message.body)
        .expect("the body parses as multipart")
        .into_iter()
        .map(|part| {
            (
                part.content_type,
                String::from_utf8_lossy(&part.body).into_owned(),
            )
        })
        .collect()
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

/// The handler `offer.answer()`s with a part of its own and two headers, once
/// it has checked what it was shown of a multipart offer.
const ANSWERS_WITH_INFO: &str = concat!(
    "\n",
    "ANSWER_INFO = '<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>'\n",
    "\n",
    "@b2bua.on_reoffer\n",
    "def on_reoffer(call, offer):\n",
    "    assert offer.request.content_type.startswith(\"multipart/mixed\"), offer.request.content_type\n",
    "    assert b\"<emergency-ind\" in offer.request.body, offer.request.body\n",
    "    assert offer.sdp.startswith(\"v=0\"), offer.sdp\n",
    "    assert \"mcpttinfo\" not in offer.sdp and \"participant-1\" not in offer.sdp, offer.sdp\n",
    "    assert offer.request.get_header(\"Resource-Priority\") == \"mcpttp.5\"\n",
    "    offer.answer(body=ANSWER_INFO,\n",
    "                 content_type=\"application/vnd.3gpp.mcptt-info+xml\",\n",
    "                 headers={\"Resource-Priority\": \"mcpttp.5\", \"X-Second\": \"2\"})\n",
);

const ANSWER_INFO: &str = "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>";

/// A re-INVITE whose offer rides beside a part of the service's own (TS 24.379
/// §10.1.1.4.2 upgrades a group call this way, with `Resource-Priority`): the
/// handler is shown the whole body and the SDP part as the offer, read as the
/// refresh it is, and its `offer.answer(body=…, headers=…)` is a multipart 200
/// of the session in force as it was sent before and the handler's part, with
/// the handler's headers. The dialog keeps the descriptions, not the MIME
/// framing.
#[tokio::test(flavor = "multi_thread")]
async fn a_multipart_offer_is_shown_whole_and_answered_with_a_part_beside_the_session() {
    let handler = format!(
        "{ANSWERS_WITH_INFO}    assert offer.kind == \"refresh\", offer.kind\n    assert offer.method == \"INVITE\"\n"
    );
    let seat = seated("seat-multipart@192.0.2.10", &script(&handler)).await;
    let (content_type, offer) = with_info(&refresh());
    let answered = final_response(&seat.sends_with(
        "INVITE",
        2,
        Some((&content_type, &offer)),
        "Resource-Priority: mcpttp.5\r\n",
    ));
    assert_eq!(answered.status_code(), Some(200));
    let content_type = answered
        .headers
        .get("Content-Type")
        .expect("a Content-Type");
    assert!(
        content_type.starts_with("multipart/mixed;boundary=siphon-"),
        "{content_type}"
    );
    assert_eq!(
        parts(&answered),
        vec![
            (
                "application/sdp".to_string(),
                SEAT_ANSWER.trim_end().to_string()
            ),
            (INFO_TYPE.to_string(), ANSWER_INFO.to_string()),
        ]
    );
    // The SDP part keeps its own last line break ahead of the delimiter's
    // (RFC 2046 §5.1.1).
    assert!(
        body(&answered).contains(&format!("{SEAT_ANSWER}\r\n--siphon-")),
        "{}",
        body(&answered)
    );
    assert_eq!(
        answered
            .headers
            .get("Resource-Priority")
            .map(String::as_str),
        Some("mcpttp.5")
    );
    assert_eq!(
        answered.headers.get("X-Second").map(String::as_str),
        Some("2")
    );
    assert!(answered.headers.get("Contact").is_some());
    let (given, in_force) = seat.descriptions();
    assert_eq!(given.as_deref(), Some(refresh().trim_end()));
    assert_eq!(in_force.as_deref(), Some(SEAT_ANSWER));
}

/// A multipart body the script built itself, to give its part a header of its
/// own, takes the SDP part first under the script's boundary. Here the offer
/// is a hold, so the SDP is the session in force answering it (RFC 3264 §6.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_multipart_body_of_the_scripts_own_takes_the_sdp_part_first() {
    let handler = concat!(
        "\n",
        "BODY = (\"--own\\r\\nContent-Type: application/vnd.3gpp.mcptt-info+xml\\r\\n\"\n",
        "        \"Content-Disposition: render\\r\\n\\r\\n<mcpttinfo/>\\r\\n--own--\\r\\n\")\n",
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    offer.answer(body=BODY, content_type=\"multipart/mixed;boundary=own\")\n",
    );
    let seat = seated("seat-own-multipart@192.0.2.10", &script(handler)).await;
    let answered = final_response(&seat.sends("INVITE", 2, Some(HOLD)));
    assert_eq!(answered.status_code(), Some(200));
    assert_eq!(
        answered.headers.get("Content-Type").map(String::as_str),
        Some("multipart/mixed;boundary=own")
    );
    let text = body(&answered);
    assert!(
        text.starts_with("--own\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n"),
        "{text}"
    );
    assert!(
        text.ends_with(concat!(
            "\r\n\r\n--own\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n",
            "Content-Disposition: render\r\n\r\n<mcpttinfo/>\r\n--own--\r\n",
        )),
        "{text}"
    );
    let answer = parts(&answered);
    assert_eq!(answer.len(), 2);
    assert!(answer[0].1.contains("a=recvonly"), "{}", answer[0].1);
    let (_, in_force) = seat.descriptions();
    assert_eq!(
        in_force.as_deref().map(str::trim_end),
        Some(answer[0].1.as_str()),
        "the SDP part is the session in force"
    );
}

/// An UPDATE that carries the service's part and no SDP offers nothing: the
/// handler's part goes back as it was given, with no SDP beside it.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_without_an_offer_is_answered_with_the_scripts_body_alone() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    assert offer.sdp is None, offer.sdp\n",
        "    offer.answer(body=\"<mcpttinfo/>\", content_type=\"application/vnd.3gpp.mcptt-info+xml\")\n",
    );
    let seat = seated("seat-update-info@192.0.2.10", &script(handler)).await;
    let answered = final_response(&seat.sends_with("UPDATE", 2, Some((INFO_TYPE, INFO)), ""));
    assert_eq!(answered.status_code(), Some(200));
    assert_eq!(
        answered.headers.get("Content-Type").map(String::as_str),
        Some(INFO_TYPE)
    );
    assert_eq!(body(&answered), "<mcpttinfo/>");
    let (given, in_force) = seat.descriptions();
    assert_eq!(in_force.as_deref(), Some(SEAT_ANSWER));
    assert!(
        given.is_some_and(|given| given.starts_with("v=0")),
        "the part is not taken for the participant's media"
    );
}

/// A seat the engine keyed, ran ICE for and bundled. An offer that asks for
/// none of that again is answered from the engine's description of the seat:
/// a refresh with it as it was sent, a hold with it receiving only at a new
/// `o=` version (RFC 3264 §6.1, §8). An ICE restart takes the engine, and is
/// still refused 488 with the session left as it was (RFC 3261 §14.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_keyed_seat_answers_an_offer_that_renegotiates_nothing_from_its_session() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    offer.answer()\n",
    );
    let seat = seated_with(
        "seat-keyed@192.0.2.10",
        &script(handler),
        Some(KEYED_OFFER),
        KEYED_SESSION,
    )
    .await;

    let refreshed = KEYED_OFFER.replace("o=- 4 4", "o=- 4 5");
    let answered = final_response(&seat.sends("INVITE", 2, Some(&refreshed)));
    assert_eq!(answered.status_code(), Some(200));
    assert_eq!(body(&answered), KEYED_SESSION);
    seat.sends("ACK", 2, None);

    let held = format!(
        "{}a=sendonly\r\n",
        KEYED_OFFER.replace("o=- 4 4", "o=- 4 6")
    );
    let answered = final_response(&seat.sends("INVITE", 3, Some(&held)));
    assert_eq!(answered.status_code(), Some(200));
    let sdp = body(&answered);
    assert!(sdp.contains("a=recvonly\r\n"), "{sdp}");
    for kept in [
        "m=audio 40000 UDP/TLS/RTP/SAVPF 111\r\n",
        "a=group:BUNDLE 0\r\n",
        "a=ice-ufrag:efrg\r\n",
        "a=fingerprint:sha-256 CC:DD\r\n",
        "a=setup:passive\r\n",
    ] {
        assert!(sdp.contains(kept), "{kept}: {sdp}");
    }
    assert!(!sdp.contains("o=- 9 9 "), "a new version: {sdp}");
    seat.sends("ACK", 3, None);

    let restarted = held
        .replace("o=- 4 6", "o=- 4 7")
        .replace("ice-ufrag:ofrg", "ice-ufrag:new1");
    let refused = final_response(&seat.sends("INVITE", 4, Some(&restarted)));
    assert_eq!(refused.status_code(), Some(488));
    let (given, in_force) = seat.descriptions();
    assert_eq!(given.as_deref(), Some(held.as_str()));
    assert_eq!(in_force.as_deref(), Some(sdp.as_str()));
}

/// On a call the engine answered itself the handler is shown the offer too.
/// Its `offer.answer()` without an SDP leaves the answer to the engine, which
/// is handed the session description and not the MIME framing around it, and
/// the 200 carries the engine's answer with the handler's part and headers.
#[tokio::test(flavor = "multi_thread")]
async fn an_engine_answered_call_shows_the_offer_and_answers_it_from_the_engine() {
    let handler = format!("{ANSWERS_WITH_INFO}    assert offer.kind == \"hold\", offer.kind\n");
    let call = engine_answered("engine-multipart@192.0.2.10", &script(&handler)).await;
    let before = call.engine.commands("answer_local").len();
    let (content_type, offer) = with_info(HOLD);
    let answered = final_response(&call.sends_with(
        "INVITE",
        2,
        Some((&content_type, &offer)),
        "Resource-Priority: mcpttp.5\r\n",
    ));
    assert_eq!(answered.status_code(), Some(200));
    let commands = call.engine.commands("answer_local");
    assert_eq!(commands.len(), before + 1, "the engine answered the offer");
    assert_eq!(
        commands
            .last()
            .and_then(|command| command.detail.as_deref()),
        Some(HOLD.trim_end()),
        "the engine is handed the SDP part"
    );
    assert_eq!(
        parts(&answered),
        vec![
            (
                "application/sdp".to_string(),
                NATIVE_ENGINE_ANSWER.trim_end().to_string()
            ),
            (INFO_TYPE.to_string(), ANSWER_INFO.to_string()),
        ]
    );
    assert_eq!(
        answered
            .headers
            .get("Resource-Priority")
            .map(String::as_str),
        Some("mcpttp.5")
    );
    let (given, in_force) = call.descriptions();
    assert_eq!(given.as_deref(), Some(HOLD.trim_end()));
    assert_eq!(in_force.as_deref(), Some(NATIVE_ENGINE_ANSWER));
}

/// Without a handler a multipart offer on such a call is answered by the
/// engine as a plain one is, from its SDP part.
#[tokio::test(flavor = "multi_thread")]
async fn an_engine_answered_call_answers_a_multipart_offer_from_its_sdp_part() {
    let call = engine_answered("engine-plain@192.0.2.10", &script("")).await;
    let (content_type, offer) = with_info(HOLD);
    let answered = final_response(&call.sends_with("INVITE", 2, Some((&content_type, &offer)), ""));
    assert_eq!(answered.status_code(), Some(200));
    assert_eq!(
        answered.headers.get("Content-Type").map(String::as_str),
        Some("application/sdp")
    );
    assert_eq!(body(&answered), NATIVE_ENGINE_ANSWER);
    assert_eq!(
        call.engine
            .commands("answer_local")
            .last()
            .and_then(|command| command.detail.clone())
            .as_deref(),
        Some(HOLD.trim_end())
    );
}

/// A handler's refusal on such a call is the answer, the engine is asked
/// nothing, and the participant's description stays the one it had.
#[tokio::test(flavor = "multi_thread")]
async fn an_engine_answered_call_lets_the_handler_refuse_the_offer() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    offer.reject(403, \"Forbidden\")\n",
    );
    let call = engine_answered("engine-refuse@192.0.2.10", &script(handler)).await;
    let before = call.engine.commands("answer_local").len();
    let (had, _) = call.descriptions();
    let refused = final_response(&call.sends("INVITE", 2, Some(HOLD)));
    assert_eq!(refused.status_code(), Some(403));
    assert_eq!(call.engine.commands("answer_local").len(), before);
    assert_eq!(call.descriptions().0, had);
}

/// An offer the engine refuses is answered 488 and is not kept as the
/// participant's description: the one it had stays in force (RFC 3261 §14.1).
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_the_engine_refuses_leaves_the_description_the_party_had() {
    let call = engine_answered("engine-refused@192.0.2.10", &script("")).await;
    let (had, in_force) = call.descriptions();
    let refused_offer = format!("{HOLD}{NATIVE_ENGINE_REFUSED_OFFER}\r\n");
    let refused = final_response(&call.sends("INVITE", 2, Some(&refused_offer)));
    assert_eq!(refused.status_code(), Some(488));
    assert_eq!(call.descriptions(), (had, in_force));
}

/// A part header spelled in another case still names the SDP part: the
/// script's multipart answer is sent with its one SDP part, not a second one
/// put in front of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_multipart_answer_with_an_sdp_part_is_sent_with_that_one_part() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    body = (\"--own\\r\\nCONTENT-TYPE: application/sdp\\r\\n\\r\\n\" + offer.session_sdp\n",
        "            + \"\\r\\n--own\\r\\ncontent-type: text/plain\\r\\n\\r\\nx\\r\\n--own--\\r\\n\")\n",
        "    offer.answer(body=body, content_type=\"multipart/mixed;boundary=own\")\n",
    );
    let seat = seated("seat-own-sdp-part@192.0.2.10", &script(handler)).await;
    let answered = final_response(&seat.sends("INVITE", 2, Some(&refresh())));
    assert_eq!(answered.status_code(), Some(200));
    let answer = parts(&answered);
    assert_eq!(answer.len(), 2, "{}", body(&answered));
    assert_eq!(answer[0].0, "application/sdp");
    assert!(answer[0].1.contains("m=audio 40000 RTP/AVP 0 101"));
    assert_eq!(answer[1], ("text/plain".to_string(), "x".to_string()));
}

/// Without a handler, an UPDATE whose body is the service's own document and
/// no SDP offers nothing: it is answered 200 as a request without an offer
/// is, and the document is not taken for the participant's media.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_is_no_sdp_offers_nothing() {
    let seat = seated("seat-info-only@192.0.2.10", &script("")).await;
    let had = seat.descriptions();
    let answered = final_response(&seat.sends_with("UPDATE", 2, Some((INFO_TYPE, INFO)), ""));
    assert_eq!(answered.status_code(), Some(200));
    assert!(answered.body.is_empty());
    assert_eq!(seat.descriptions(), had);
}
