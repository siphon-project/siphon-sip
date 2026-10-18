//! `@b2bua.on_info` and `b2bua.send_info(leg="callee")` on a bridged call: an
//! application package the script speaks with the callee (a media server it
//! dialled, say), kept off the caller's dialog.

use super::b_leg_2xx_ack_tests::{callee, caller, Call};
use super::*;

const PACKAGE: &str = "application/example+xml";

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

fn answered(handler: &str) -> Call {
    let call = Call::bridged_with_script(&script(handler));
    call.callee_answers("");
    call.wire();
    call
}

/// The callee sends an INFO in the dialog its 2xx created. Each test uses its
/// own CSeq: answered INFOs are remembered process-wide by Call-ID, CSeq and
/// branch, and every test's callee has the fixture's Call-ID.
fn callee_sends_info(call: &Call, cseq: u32, body: &str) -> Vec<super::b_leg_2xx_ack_tests::Sent> {
    let raw = format!(
        concat!(
            "INFO sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.77:5060;branch=z9hG4bK-callee-info-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100042@198.51.100.77>;tag=callee-tag\r\n",
            "To: <sip:15550100001@192.0.2.1>;tag=sb-callee-leg\r\n",
            "Call-ID: b2b-callee@192.0.2.1\r\n",
            "CSeq: {cseq} INFO\r\n",
            "Content-Type: {package}\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        cseq = cseq,
        package = PACKAGE,
        length = body.len(),
        body = body,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the callee's INFO parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: callee(),
        data: Bytes::from(raw),
    };
    tokio::task::block_in_place(|| handle_b2bua_info(inbound, message, &call.state));
    call.wire()
}

/// The handler answers an INFO from the callee: the callee gets that answer,
/// and the caller sees nothing of it.
#[tokio::test(flavor = "multi_thread")]
async fn an_info_the_handler_answers_stays_off_the_other_leg() {
    let call = answered(concat!(
        "\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    if request.get_header(\"Call-ID\") != call.call_id:\n",
        "        request.set_reply_body(b\"<taken/>\", \"application/example+xml\")\n",
        "        request.reply(200, \"OK\")\n",
    ));
    let sent = callee_sends_info(&call, 11, "<event/>");
    assert_eq!(sent.len(), 1, "one message: the answer");
    assert_eq!(sent[0].destination, callee());
    assert_eq!(sent[0].message.status_code(), Some(200));
    assert_eq!(sent[0].message.body.as_slice(), b"<taken/>");
    assert!(sent.iter().all(|each| each.destination != caller()));
}

/// An INFO the handler leaves is relayed to the other party as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_info_the_handler_leaves_is_relayed() {
    let call = answered(concat!(
        "\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    pass\n",
    ));
    let sent = callee_sends_info(&call, 12, "<event/>");
    let relayed = sent
        .iter()
        .find(|each| each.message.method() == Some(&Method::Info))
        .expect("the INFO is relayed");
    assert_eq!(relayed.destination, caller());
    assert_eq!(relayed.message.body.as_slice(), b"<event/>");
}

/// Without a handler a bridged call relays INFO untouched.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_handler_an_info_is_relayed() {
    let call = answered("");
    let sent = callee_sends_info(&call, 13, "<event/>");
    assert!(sent
        .iter()
        .any(|each| each.message.method() == Some(&Method::Info) && each.destination == caller()));
}

/// A script's INFO on the callee leg goes in the callee's dialog: its
/// Call-ID, the callee's tag in To, siphon's in From, to the callee.
#[tokio::test(flavor = "multi_thread")]
async fn a_sent_info_on_the_callee_leg_is_in_the_callees_dialog() {
    let call = answered("");
    let sent = send_info_on_leg(
        &call.state,
        &call.call_id,
        false,
        Some(PACKAGE),
        b"<do/>".to_vec(),
        &[],
    )
    .expect("sent");
    let wire = call.wire();
    let info = wire
        .iter()
        .find(|each| each.message.method() == Some(&Method::Info))
        .expect("an INFO on the wire");
    assert_eq!(info.destination, callee());
    assert_eq!(
        info.message
            .headers
            .call_id()
            .map(|value| value.to_string()),
        Some("b2b-callee@192.0.2.1".to_string())
    );
    assert!(info
        .message
        .headers
        .get("To")
        .is_some_and(|to| to.contains("tag=callee-tag")));
    assert!(info
        .message
        .headers
        .get("From")
        .is_some_and(|from| from.contains("tag=sb-callee-leg")));
    assert_eq!(info.message.body.as_slice(), b"<do/>");

    // The callee answers with a body of its package: it comes back whole.
    let header = |name: &str| {
        info.message
            .headers
            .get(name)
            .map(|value| value.to_string())
            .expect("a header of the INFO")
    };
    let raw = format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Type: {package}\r\n",
            "Content-Length: 7\r\n\r\n",
            "<done/>",
        ),
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
        package = PACKAGE,
    );
    let response = parse_sip_message_bytes(raw.as_bytes()).expect("the 200 parses");
    assert!(take_sent_info_response(&response, 200));
    let mut receiver = sent.response;
    let answered = receiver.try_recv().expect("answered");
    assert_eq!(answered.status, 200);
    assert_eq!(answered.body.as_slice(), b"<done/>");
    assert_eq!(answered.content_type.as_deref(), Some(PACKAGE));
}

/// A call whose callee has not answered has no callee dialog to send in.
#[tokio::test(flavor = "multi_thread")]
async fn no_callee_dialog_before_the_answer() {
    let (state, _udp, call_id) = Call::caller_alone();
    let refused = send_info_on_leg(&state, &call_id, false, Some(PACKAGE), Vec::new(), &[]);
    assert!(matches!(refused, Err(SendInfoRefusal::NoDialog)));
}
