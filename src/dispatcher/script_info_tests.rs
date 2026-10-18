//! `@b2bua.on_info` and `b2bua.send_info()` on a call the script answered
//! itself (one leg): an application package carried in INFO (RFC 6086), its
//! requests answered with a status and a body, its events sent in the dialog.

use std::sync::Arc;

use super::dial_bridge_test_harness::caller_invite;
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::sip::headers::cseq::CSeq;

const CALLER: &str = "192.0.2.10:5060";

const ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 5 5 IN IP4 203.0.113.7\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.7\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
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

struct Answered {
    dispatcher: TestDispatcher,
    internal_call_id: String,
    answer: SipMessage,
    call_id: String,
}

/// A caller the script answered with its own SDP, ACKed: no far leg.
fn answered(call_id: &str, source: &str) -> Answered {
    let dispatcher = test_dispatcher_with_script(source);
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
        Some(ANSWER.as_bytes().to_vec()),
        Some("application/sdp"),
        true,
        &[],
    ));
    let answer = drain(&dispatcher.udp)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("the caller is answered")
        .message;
    let call = Answered {
        dispatcher,
        internal_call_id,
        answer,
        call_id: call_id.to_string(),
    };
    call.sends("ACK", 1, None);
    call
}

impl Answered {
    /// The caller sends `method` with CSeq `cseq` and an optional
    /// (content type, body); what siphon put on the wire in return.
    fn sends(&self, method: &str, cseq: u32, body: Option<(&str, &str)>) -> Vec<Sent> {
        let content = match body {
            Some((content_type, body)) => format!(
                "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            None => "Content-Length: 0\r\n\r\n".to_string(),
        };
        let raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP {address};branch=z9hG4bK-info-{method}-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} {method}\r\n",
                "{content}",
            ),
            method = method,
            address = CALLER,
            cseq = cseq,
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
            "INFO" => handle_b2bua_info(inbound, message, state),
            other => panic!("no {other} in these tests"),
        });
        drain(&self.dispatcher.udp)
    }
}

fn only_response(sent: &[Sent]) -> SipMessage {
    assert_eq!(sent.len(), 1, "one response");
    sent[0].message.clone()
}

const PACKAGE: &str = "application/example+xml";

/// Without a handler an INFO is answered a bare 200, as before.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_handler_an_info_gets_a_bare_200() {
    let call = answered("info-none@192.0.2.10", &script(""));
    let response = only_response(&call.sends("INFO", 2, Some((PACKAGE, "<do/>"))));
    assert_eq!(response.status_code(), Some(200));
    assert!(response.body.is_empty());
}

/// `b2bua.send_info` is reachable from a script, and refuses a call it does
/// not know with `not_found`.
#[tokio::test(flavor = "multi_thread")]
async fn send_info_is_on_the_script_namespace() {
    let handler = concat!(
        "\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    try:\n",
        "        b2bua.send_info(\"no-such-call@192.0.2.99\", b\"<x/>\", \"application/example+xml\")\n",
        "        outcome = b\"sent\"\n",
        "    except ValueError as error:\n",
        "        outcome = b\"not_found\" if \"not_found\" in str(error) else str(error).encode()\n",
        "    request.set_reply_body(outcome, \"text/plain\")\n",
        "    request.reply(200, \"OK\")\n",
    );
    let call = answered("info-namespace@192.0.2.10", &script(handler));
    let response = only_response(&call.sends("INFO", 2, Some((PACKAGE, "<do/>"))));
    assert_eq!(response.body.as_slice(), b"not_found");
}

/// The handler reads the body and its type and answers with a status and a
/// body of its own.
#[tokio::test(flavor = "multi_thread")]
async fn the_handler_answers_with_a_status_and_a_body() {
    let handler = concat!(
        "\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    assert request.content_type == \"application/example+xml\", request.content_type\n",
        "    assert request.body == b\"<do/>\", request.body\n",
        "    request.set_reply_body(b\"<done/>\", \"application/example+xml\")\n",
        "    request.reply(200, \"OK\")\n",
    );
    let call = answered("info-answer@192.0.2.10", &script(handler));
    let response = only_response(&call.sends("INFO", 2, Some((PACKAGE, "<do/>"))));
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(response.body.as_slice(), b"<done/>");
    assert_eq!(
        response.headers.get("Content-Type").map(String::as_str),
        Some(PACKAGE)
    );
}

/// An async handler, and a refusal.
#[tokio::test(flavor = "multi_thread")]
async fn an_async_handler_may_refuse() {
    let handler = concat!(
        "\n",
        "@b2bua.on_info\n",
        "async def on_info(call, request):\n",
        "    request.reply(415, \"Unsupported Media Type\")\n",
    );
    let call = answered("info-refuse@192.0.2.10", &script(handler));
    let response = only_response(&call.sends("INFO", 2, Some(("text/plain", "x"))));
    assert_eq!(response.status_code(), Some(415));
}

/// A retransmission gets the same answer and does not run the handler again
/// (RFC 3261 §17.2.2): the handler counts its runs into the body.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmission_is_answered_again_without_the_handler() {
    let handler = concat!(
        "\n",
        "runs = []\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    runs.append(1)\n",
        "    request.set_reply_body(str(len(runs)), \"text/plain\")\n",
        "    request.reply(200, \"OK\")\n",
    );
    let call = answered("info-retransmit@192.0.2.10", &script(handler));
    let first = only_response(&call.sends("INFO", 2, Some((PACKAGE, "<do/>"))));
    let again = only_response(&call.sends("INFO", 2, Some((PACKAGE, "<do/>"))));
    assert_eq!(first.body.as_slice(), b"1");
    assert_eq!(again.body.as_slice(), b"1");
    let next = only_response(&call.sends("INFO", 3, Some((PACKAGE, "<do/>"))));
    assert_eq!(next.body.as_slice(), b"2");
}

/// A handler that raises leaves the default 200: the INFO is still answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_raises_leaves_the_default_answer() {
    let handler = concat!(
        "\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    raise RuntimeError(\"boom\")\n",
    );
    let call = answered("info-raise@192.0.2.10", &script(handler));
    let response = only_response(&call.sends("INFO", 2, Some((PACKAGE, "<do/>"))));
    assert_eq!(response.status_code(), Some(200));
    assert!(response.body.is_empty());
}

/// An INFO siphon sends for the script is a request in the dialog: the next
/// CSeq of siphon's side, the remote target as the Request-URI, the dialog's
/// tags, the script's body; its final response reaches the script, and the
/// BYE siphon sends later follows it in CSeq order (RFC 3261 §12.2.1.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_sent_info_is_in_the_dialog_and_its_answer_comes_back() {
    let call = answered("info-send@192.0.2.10", &script(""));
    let state = &call.dispatcher.state;
    let mut sent = send_info_on_leg(
        state,
        &call.internal_call_id,
        true,
        Some(PACKAGE),
        b"<event/>".to_vec(),
        &[("X-Note".to_string(), "1".to_string())],
    )
    .expect("sent");
    let wire = drain(&call.dispatcher.udp);
    assert_eq!(wire.len(), 1);
    let info = &wire[0].message;
    assert_eq!(info.method(), Some(&Method::Info));
    assert_eq!(info.body.as_slice(), b"<event/>");
    assert_eq!(
        info.headers.get("Content-Type").map(String::as_str),
        Some(PACKAGE)
    );
    assert_eq!(info.headers.get("X-Note").map(String::as_str), Some("1"));
    assert_eq!(
        info.headers.call_id().map(String::as_str),
        Some(call.call_id.as_str())
    );
    let from = info.headers.from().expect("From");
    assert!(
        from.contains(&format!(
            "tag={}",
            call.dispatcher
                .state
                .call_actors
                .get_call(&call.internal_call_id)
                .expect("call")
                .a_leg
                .dialog
                .local_tag
        )),
        "{from}"
    );
    let info_cseq = CSeq::parse(info.headers.get("CSeq").expect("CSeq")).expect("parses");
    assert_eq!(info_cseq.method, Method::Info);
    assert!(
        info.request_uri()
            .map(|uri| uri.to_string())
            .is_some_and(|uri| uri.contains("15550100001")),
        "the remote target"
    );

    let raw = format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} INFO\r\n",
            "Content-Length: 0\r\n\r\n",
        ),
        via = info.headers.get("Via").expect("Via"),
        from = from,
        to = info.headers.to().expect("To"),
        call_id = call.call_id,
        cseq = info_cseq.sequence,
    );
    let response = parse_sip_message_bytes(raw.as_bytes()).expect("parses");
    assert!(take_sent_info_response(&response, 200));
    let answered = sent.response.try_recv().expect("answered");
    assert_eq!((answered.status, answered.reason.as_str()), (200, "OK"));
    assert!(answered.body.is_empty());
    // Taken once.
    assert!(!take_sent_info_response(&response, 200));

    let bye = build_b2bua_bye(
        &state
            .call_actors
            .clone_leg(&call.internal_call_id, true)
            .expect("leg"),
        state,
    )
    .expect("a BYE");
    let bye_cseq = CSeq::parse(bye.headers.get("CSeq").expect("CSeq")).expect("parses");
    assert!(
        bye_cseq.sequence > info_cseq.sequence,
        "{bye_cseq:?} after {info_cseq:?}"
    );
}

#[test]
fn the_dialog_headers_are_siphons() {
    for name in ["Call-ID", "cseq", "Via", "Route", "Content-Length", "i"] {
        assert!(
            check_info_headers(&[(name.to_string(), "x".to_string())]).is_err(),
            "{name}"
        );
    }
    assert!(check_info_headers(&[("X-A".to_string(), "a\r\nB: c".to_string())]).is_err());
    assert!(check_info_headers(&[("X-A".to_string(), "fine".to_string())]).is_ok());
}
