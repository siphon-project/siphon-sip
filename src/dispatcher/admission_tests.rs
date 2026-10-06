//! `b2bua.inbound_limit`: an inbound INVITE past the ceiling is refused before
//! a call or a script exists, and a call's slot comes back however it ends.
//!
//! Driven through [`handle_b2bua_invite`], with what siphon sent read back off
//! the UDP egress. "The script never ran" is proven by the wire: every script
//! here dials, so a script that ran leaves a `100` and an INVITE behind it.

use super::lcr_ring_timeout_tests::{carrier_response, summaries, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::admission::{AdmissionController, InboundLimits};
use std::time::{Duration, Instant};

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";
const RURI: &str = "sip:15550100042@siphon.example.com";

const DIAL: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
);

const REJECT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.reject(403, \"Forbidden\")\n",
);

const SILENT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    pass\n",
);

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

fn limits(max_concurrent_calls: u32, max_calls_per_second: u32) -> InboundLimits {
    InboundLimits {
        max_concurrent_calls,
        max_calls_per_second,
        ..InboundLimits::UNLIMITED
    }
}

/// A dispatcher running `script` that enforces `limits`.
fn limited(script: &str, limits: InboundLimits) -> TestDispatcher {
    let mut dispatcher = test_dispatcher_with_script(script);
    dispatcher.state.admission = Arc::new(AdmissionController::new(limits));
    dispatcher
}

fn sip_call_id(index: usize) -> String {
    format!("admission-{index}@192.0.2.10")
}

fn branch(index: usize) -> String {
    format!("z9hG4bK-admission-{index}")
}

/// The caller's `index`th INVITE, to `ruri`, with `extra` header lines and an
/// SDP offer.
fn caller_invite(index: usize, ruri: &str, extra: &str) -> String {
    format!(
        concat!(
            "INVITE {ruri} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag-{index}\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "{extra}",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{offer}",
        ),
        ruri = ruri,
        branch = branch(index),
        index = index,
        call_id = sip_call_id(index),
        extra = extra,
        length = OFFER.len(),
        offer = OFFER,
    )
}

fn from_caller(dispatcher: &TestDispatcher, raw: &str) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string().into_bytes()),
    }
}

fn wire(dispatcher: &TestDispatcher) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data)
                .expect("siphon sent a message that parses"),
        });
    }
    sent
}

/// The caller sends `raw`; everything siphon sent in return.
fn send_invite(dispatcher: &TestDispatcher, raw: &str) -> Vec<Sent> {
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses");
    handle_b2bua_invite(from_caller(dispatcher, raw), invite, &dispatcher.state);
    wire(dispatcher)
}

/// The caller's `index`th call, to the ordinary request URI.
fn place(dispatcher: &TestDispatcher, index: usize) -> Vec<Sent> {
    send_invite(dispatcher, &caller_invite(index, RURI, ""))
}

fn admitted() -> [String; 2] {
    [format!("100 to {CALLER}"), format!("INVITE to {CALLEE}")]
}

fn refused(code: u16) -> [String; 1] {
    [format!("{code} to {CALLER}")]
}

/// The INVITE siphon sent the callee, out of what `place` returned.
fn callee_invite(sent: Vec<Sent>) -> SipMessage {
    super::lcr_ring_timeout_tests::invite_to(sent, CALLEE)
}

fn internal_call_id(dispatcher: &TestDispatcher, index: usize) -> String {
    dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(&sip_call_id(index))
        .expect("the call exists")
}

/// The callee answers the INVITE siphon sent it with `status_code`.
fn callee_responds(
    dispatcher: &TestDispatcher,
    index: usize,
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
    body: &str,
) {
    let mut response = carrier_response(invite, status_code, reason);
    if !body.is_empty() {
        response
            .headers
            .set("Contact", format!("<sip:15550100042@{CALLEE}>"));
        response
            .headers
            .set("Content-Type", "application/sdp".to_string());
        response
            .headers
            .set("Content-Length", body.len().to_string());
        response.body = body.as_bytes().to_vec();
    }
    // A call that came in through the INVITE handler has its B-leg actor's
    // event channel, and the response path waits on it. The dispatcher runs
    // that on a blocking worker, never on a runtime thread.
    let handled = tokio::task::block_in_place(|| {
        handle_b2bua_response(
            &internal_call_id(dispatcher, index),
            &top_via_branch(invite),
            &mut response,
            status_code,
            CALLEE.parse().expect("a literal address"),
            &dispatcher.state,
        )
    });
    assert!(handled, "the call was gone when the {status_code} arrived");
}

fn caller_cancels(dispatcher: &TestDispatcher, index: usize) {
    let raw = format!(
        concat!(
            "CANCEL {ruri} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag-{index}\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 CANCEL\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ruri = RURI,
        branch = branch(index),
        index = index,
        call_id = sip_call_id(index),
    );
    let cancel = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's CANCEL parses");
    handle_b2bua_cancel(from_caller(dispatcher, &raw), cancel, &dispatcher.state);
}

/// The caller ACKs the 200 siphon relayed to it (RFC 3261 §13.2.2.4). Without
/// it siphon goes on retransmitting that 200, as it must, into whatever the
/// test does next.
fn caller_acks(dispatcher: &TestDispatcher, index: usize, relayed_200: &SipMessage) {
    let raw = format!(
        concat!(
            "ACK sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}-ack\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        branch = branch(index),
        from = relayed_200.headers.from().expect("the 200 has a From"),
        to = relayed_200.headers.to().expect("the 200 has a To"),
        call_id = sip_call_id(index),
    );
    let ack = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's ACK parses");
    assert!(
        absorb_b2bua_ack(&sip_call_id(index), &ack, &dispatcher.state),
        "the ACK matched the answered call"
    );
}

/// The caller hangs up in the dialog the relayed 200 created.
fn caller_hangs_up(dispatcher: &TestDispatcher, index: usize, relayed_200: &SipMessage) {
    let raw = format!(
        concat!(
            "BYE sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}-bye\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 2 BYE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        branch = branch(index),
        from = relayed_200.headers.from().expect("the 200 has a From"),
        to = relayed_200.headers.to().expect("the 200 has a To"),
        call_id = sip_call_id(index),
    );
    let bye = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's BYE parses");
    handle_b2bua_bye(from_caller(dispatcher, &raw), bye, &dispatcher.state);
}

/// One way for an admitted call to end.
#[derive(Debug, Clone, Copy)]
enum Ending {
    CalleeRefuses,
    CallerCancels,
    RingsOut,
    AnsweredThenCallerHangsUp,
}

const ENDINGS: [Ending; 4] = [
    Ending::CalleeRefuses,
    Ending::CallerCancels,
    Ending::RingsOut,
    Ending::AnsweredThenCallerHangsUp,
];

/// End the `index`th call, which `sent` shows being dialled.
fn end_call(dispatcher: &TestDispatcher, index: usize, sent: Vec<Sent>, ending: Ending) {
    let invite = callee_invite(sent);
    match ending {
        Ending::CalleeRefuses => {
            callee_responds(dispatcher, index, &invite, 486, "Busy Here", "");
        }
        Ending::CallerCancels => caller_cancels(dispatcher, index),
        Ending::RingsOut => check_b2bua_answer_timeouts_at(
            &dispatcher.state,
            Instant::now() + Duration::from_secs(3600),
        ),
        Ending::AnsweredThenCallerHangsUp => {
            callee_responds(dispatcher, index, &invite, 200, "OK", ANSWER);
            let relayed_200 = wire(dispatcher)
                .into_iter()
                .find(|sent| sent.message.status_code() == Some(200))
                .expect("siphon relayed the 200 to the caller")
                .message;
            caller_acks(dispatcher, index, &relayed_200);
            caller_hangs_up(dispatcher, index, &relayed_200);
        }
    }
    let _ = wire(dispatcher);
}

fn retry_after(sent: &Sent) -> Option<&str> {
    sent.message.headers.get("Retry-After").map(String::as_str)
}

fn reason_phrase(sent: &Sent) -> &str {
    match &sent.message.start_line {
        StartLine::Response(status_line) => &status_line.reason_phrase,
        StartLine::Request(_) => "",
    }
}

/// RFC 3261 §21.5.4: 503 is for a server "temporarily unable to process the
/// request due to a temporary overloading", and it "MAY indicate when the
/// client should retry the request in a Retry-After header field".
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_past_the_concurrent_ceiling_is_refused_before_the_script_runs() {
    let dispatcher = limited(DIAL, limits(1, 0));
    assert_eq!(summaries(&place(&dispatcher, 1)), admitted());

    let sent = place(&dispatcher, 2);
    assert_eq!(
        summaries(&sent),
        refused(503),
        "one response and nothing else: no 100, no call, no dial"
    );
    assert_eq!(reason_phrase(&sent[0]), "Service Unavailable");
    assert_eq!(retry_after(&sent[0]), Some("1"));
    assert_eq!(dispatcher.state.admission.active(), 1);
    assert_eq!(
        dispatcher.state.call_actors.count(),
        1,
        "the refused INVITE never became a call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_past_the_rate_is_refused_and_holds_no_slot() {
    let dispatcher = limited(DIAL, limits(0, 1));
    assert_eq!(summaries(&place(&dispatcher, 1)), admitted());
    assert_eq!(summaries(&place(&dispatcher, 2)), refused(503));
    assert_eq!(dispatcher.state.admission.active(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_carries_the_configured_code_and_no_retry_after_at_zero() {
    let dispatcher = limited(
        DIAL,
        InboundLimits {
            max_concurrent_calls: 1,
            max_calls_per_second: 0,
            reject_code: 486,
            retry_after_secs: 0,
        },
    );
    assert_eq!(summaries(&place(&dispatcher, 1)), admitted());
    let sent = place(&dispatcher, 2);
    assert_eq!(summaries(&sent), refused(486));
    assert_eq!(reason_phrase(&sent[0]), "Busy Here");
    assert_eq!(retry_after(&sent[0]), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_no_limit_set_nothing_is_refused_and_calls_are_still_counted() {
    let dispatcher = test_dispatcher_with_script(DIAL);
    for index in 1..=25 {
        assert_eq!(summaries(&place(&dispatcher, index)), admitted());
    }
    assert_eq!(dispatcher.state.admission.active(), 25);
}

/// However an admitted call ends, its slot is free for the next caller.
#[tokio::test(flavor = "multi_thread")]
async fn the_slot_comes_back_on_every_way_a_call_ends() {
    for ending in ENDINGS {
        let dispatcher = limited(DIAL, limits(1, 0));
        let sent = place(&dispatcher, 1);
        assert_eq!(summaries(&sent), admitted(), "{ending:?}");
        assert_eq!(
            summaries(&place(&dispatcher, 2)),
            refused(503),
            "{ending:?}"
        );

        end_call(&dispatcher, 1, sent, ending);
        assert_eq!(dispatcher.state.admission.active(), 0, "{ending:?}");
        assert_eq!(dispatcher.state.call_actors.count(), 0, "{ending:?}");
        assert_eq!(summaries(&place(&dispatcher, 3)), admitted(), "{ending:?}");
    }
}

/// A call the script turns away, or says nothing about, never held a slot past
/// the handler.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_the_script_does_not_dial_gives_its_slot_straight_back() {
    let dispatcher = limited(REJECT, limits(1, 0));
    for index in 1..=3 {
        assert_eq!(
            summaries(&place(&dispatcher, index)),
            [format!("100 to {CALLER}"), format!("403 to {CALLER}")]
        );
        assert_eq!(dispatcher.state.admission.active(), 0);
    }

    let dispatcher = limited(SILENT, limits(1, 0));
    for index in 1..=3 {
        let sent = place(&dispatcher, index);
        assert!(
            !summaries(&sent).contains(&format!("503 to {CALLER}")),
            "call {index} was refused: the silent drop before it kept its slot"
        );
        assert_eq!(dispatcher.state.admission.active(), 0);
    }
}

/// RFC 5031 §4.1: `urn:service:sos` and its sub-services name emergency
/// services. Such a call is counted and never refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_emergency_call_is_admitted_at_the_ceiling() {
    let dispatcher = limited(DIAL, limits(1, 0));
    assert_eq!(summaries(&place(&dispatcher, 1)), admitted());
    assert_eq!(summaries(&place(&dispatcher, 2)), refused(503));

    for (index, ruri) in [(3, "urn:service:sos"), (4, "urn:service:sos.ambulance")] {
        let sent = send_invite(&dispatcher, &caller_invite(index, ruri, ""));
        assert_eq!(summaries(&sent), admitted(), "{ruri}");
    }
    assert_eq!(
        dispatcher.state.admission.active(),
        3,
        "an emergency call still holds a slot"
    );
    let sent = send_invite(&dispatcher, &caller_invite(5, "urn:service:counseling", ""));
    assert_eq!(
        summaries(&sent),
        refused(503),
        "only the sos services are exempt"
    );
}

/// A call siphon places counts toward the instance's total, so the ceiling it
/// passes refuses the next inbound caller, and it is never refused itself.
#[tokio::test(flavor = "multi_thread")]
async fn an_originated_call_takes_a_slot_and_is_never_refused() {
    let dispatcher = limited(DIAL, limits(1, 0));
    let originate = || {
        prepare_originate(
            &dispatcher.state,
            OriginateParams {
                to: "sip:15550100042@198.51.100.7:5060".to_string(),
                to_display: None,
                from: Some("sip:1000@siphon.example.com".to_string()),
                from_display: None,
                next_hop: None,
                p_asserted_identity: None,
                privacy: None,
                headers: Vec::new(),
                timeout_secs: 30,
                media: OriginateMedia::Offer {
                    body: OFFER.as_bytes().to_vec(),
                    content_type: "application/sdp".to_string(),
                },
                session_timer: None,
            },
        )
        .expect("an originate is never refused by the inbound limit")
    };
    let first = originate();
    let second = originate();
    assert_eq!(dispatcher.state.admission.active(), 2);
    assert_eq!(summaries(&place(&dispatcher, 1)), refused(503));

    for prepared in [first, second] {
        dispatcher
            .state
            .call_actors
            .remove_call(&prepared.internal_call_id);
    }
    assert_eq!(dispatcher.state.admission.active(), 0);
    assert_eq!(summaries(&place(&dispatcher, 2)), admitted());
}

/// RFC 3891 §3: an INVITE whose `Replaces` matches a dialog takes that dialog
/// over. It replaces a call that already holds a slot, so the ceiling does not
/// turn it away.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_taking_over_a_dialog_is_admitted_at_the_ceiling() {
    let mut dispatcher = limited(DIAL, limits(1, 0));
    dispatcher.state.accept_replaces = true;

    let sent = place(&dispatcher, 1);
    let invite = callee_invite(sent);
    callee_responds(&dispatcher, 1, &invite, 200, "OK", ANSWER);
    let relayed_200 = wire(&dispatcher)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("siphon relayed the 200 to the caller")
        .message;
    let local_tag = relayed_200
        .headers
        .to()
        .and_then(|to| to.split(";tag=").nth(1))
        .expect("siphon tagged the To")
        .to_string();
    assert_eq!(summaries(&place(&dispatcher, 2)), refused(503));

    let replaces = format!(
        "Replaces: {};to-tag={local_tag};from-tag=caller-tag-1\r\n",
        sip_call_id(1)
    );
    let sent = send_invite(&dispatcher, &caller_invite(3, RURI, &replaces));
    assert_eq!(
        summaries(&sent).first(),
        Some(&format!("100 to {CALLER}")),
        "the takeover was admitted, sent: {:?}",
        summaries(&sent)
    );
}

/// RFC 3261 §17.2.1: a retransmitted request gets the response the original
/// did. The retransmission of a refused INVITE is answered again, and is not a
/// second refusal: one entry, one CDR, and no second place in the rate.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_refused_invite_is_answered_again_and_counted_once() {
    let records = crate::cdr::capture_auto_emitted_cdrs();
    let dispatcher = limited(DIAL, limits(1, 0));
    let first = place(&dispatcher, 1);
    let refused_call_id = "admission-retransmit@192.0.2.10";
    let raw = caller_invite(2, RURI, "").replace(&sip_call_id(2), refused_call_id);

    for attempt in 0..3 {
        let sent = send_invite(&dispatcher, &raw);
        assert_eq!(summaries(&sent), refused(503), "attempt {attempt}");
        assert_eq!(retry_after(&sent[0]), Some("1"), "attempt {attempt}");
    }
    assert_eq!(dispatcher.state.refused_invites.len(), 1);
    let written = records
        .lock()
        .expect("the captured CDRs")
        .iter()
        .filter(|cdr| cdr.call_id == refused_call_id)
        .count();
    assert_eq!(written, 1, "one refusal, one record");

    // The same INVITE is the same transaction: once refused it stays refused,
    // even after the slot it wanted has come free.
    end_call(&dispatcher, 1, first, Ending::CalleeRefuses);
    assert_eq!(dispatcher.state.admission.active(), 0);
    assert_eq!(summaries(&send_invite(&dispatcher, &raw)), refused(503));
    // A new INVITE from the same caller is a new transaction and is admitted.
    assert_eq!(summaries(&place(&dispatcher, 3)), admitted());
}

/// RFC 3261 §17.1.1.2: a client that has the final response ACKs it and stops
/// retransmitting the INVITE. Once the refusal is ACKed there is nothing left
/// to re-answer, so the same Call-ID and branch arriving again is a request in
/// its own right. Driven through [`handle_request`], which is where an ACK that
/// matches no transaction or call ends up.
#[tokio::test(flavor = "multi_thread")]
async fn an_acked_refusal_is_forgotten_and_the_invite_is_judged_afresh() {
    let dispatcher = limited(DIAL, limits(1, 0));
    let held = place(&dispatcher, 1);
    let raw = caller_invite(2, RURI, "");
    let refusal = send_invite(&dispatcher, &raw);
    assert_eq!(summaries(&refusal), refused(503));
    assert_eq!(dispatcher.state.refused_invites.len(), 1);

    let ack_raw = format!(
        concat!(
            "ACK {ruri} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag-2\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ruri = RURI,
        branch = branch(2),
        to = refusal[0].message.headers.to().expect("the 503 has a To"),
        call_id = sip_call_id(2),
    );
    let ack = parse_sip_message_bytes(ack_raw.as_bytes()).expect("the caller's ACK parses");
    let inbound = from_caller(&dispatcher, &ack_raw);
    let TestDispatcher { state, udp } = dispatcher;
    let state = Arc::new(state);
    handle_request(inbound, ack, "ACK".to_string(), &state);
    let state = Arc::try_unwrap(state)
        .ok()
        .expect("nothing else holds the dispatcher state");
    let dispatcher = TestDispatcher { state, udp };

    assert_eq!(
        summaries(&wire(&dispatcher)),
        Vec::<String>::new(),
        "an ACK is never answered"
    );
    assert_eq!(dispatcher.state.refused_invites.len(), 0);

    // Still at the ceiling: judged afresh, and refused afresh.
    assert_eq!(summaries(&send_invite(&dispatcher, &raw)), refused(503));
    end_call(&dispatcher, 1, held, Ending::CalleeRefuses);
    // The refusal just given is remembered and unACKed, so this one is its
    // retransmission. ACKed, the INVITE would be admitted, as the next is.
    assert_eq!(summaries(&send_invite(&dispatcher, &raw)), refused(503));
    assert_eq!(summaries(&place(&dispatcher, 3)), admitted());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_call_writes_a_cdr_naming_the_refusal() {
    let records = crate::cdr::capture_auto_emitted_cdrs();
    let dispatcher = limited(
        DIAL,
        InboundLimits {
            max_concurrent_calls: 0,
            max_calls_per_second: 1,
            reject_code: 480,
            retry_after_secs: 1,
        },
    );
    assert_eq!(summaries(&place(&dispatcher, 1)), admitted());
    let refused_call_id = "admission-cdr@192.0.2.10";
    let raw = caller_invite(2, RURI, "").replace(&sip_call_id(2), refused_call_id);
    assert_eq!(summaries(&send_invite(&dispatcher, &raw)), refused(480));

    let cdr = records
        .lock()
        .expect("the captured CDRs")
        .iter()
        .find(|cdr| cdr.call_id == refused_call_id)
        .cloned()
        .expect("the refused call wrote a CDR");
    assert_eq!(cdr.method, "INVITE");
    assert_eq!(cdr.response_code, 480);
    assert_eq!(cdr.disconnect_initiator.as_deref(), Some("local"));
    assert_eq!(cdr.source_ip, "192.0.2.10");
    assert_eq!(cdr.ruri, RURI);
    assert_eq!(
        cdr.extra.get("refusal_scope").map(String::as_str),
        Some("global")
    );
    assert_eq!(
        cdr.extra.get("refusal_reason").map(String::as_str),
        Some("rate")
    );
    assert_eq!(cdr.timestamp_answer, None);
    assert!(
        !dispatcher
            .state
            .cdr_sessions
            .iter()
            .any(|session| session.key().contains("admission-cdr")),
        "a refused call leaves no session behind"
    );
}

/// The per-module leak gate. Complete calls, ended every way a call can end
/// and with a refused caller alongside each, leave no slot held and no call
/// behind; the refusals remembered for retransmission drain once they age out.
#[tokio::test(flavor = "multi_thread")]
async fn calls_drain_to_baseline_through_every_ending() {
    let dispatcher = limited(DIAL, limits(1, 0));
    for round in 0..200usize {
        let index = round * 2;
        let sent = place(&dispatcher, index);
        assert_eq!(summaries(&sent), admitted(), "round {round}");
        assert_eq!(
            summaries(&place(&dispatcher, index + 1)),
            refused(503),
            "round {round}"
        );
        end_call(&dispatcher, index, sent, ENDINGS[round % ENDINGS.len()]);
        assert_eq!(dispatcher.state.admission.active(), 0, "round {round}");
        assert_eq!(dispatcher.state.call_actors.count(), 0, "round {round}");
    }
    assert_eq!(dispatcher.state.refused_invites.len(), 200);
    dispatcher
        .state
        .refused_invites
        .prune(Instant::now() + crate::admission::refused::REFUSAL_TTL);
    assert_eq!(dispatcher.state.refused_invites.len(), 0);
}
