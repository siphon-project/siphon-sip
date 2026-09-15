//! siphon owns RFC 3262 on the A-leg, the way it owns it on the B-leg.
//!
//! Toward a caller that supports `100rel` a provisional the callee sent
//! reliably goes out reliably, and toward a caller that requires it every
//! provisional does. Each carries siphon's own `RSeq`, one more than the last on
//! the caller's dialog, is retransmitted until the caller's PRACK, and that PRACK
//! is answered by siphon, matched on its `RAck`. A final response stops the
//! retransmits, a 2xx waits for the PRACK of a reliable provisional that carried
//! SDP, and a caller that never PRACKs is refused.
//!
//! Driven through the INVITE handler, the B-leg response handler and the request
//! handler, with what siphon sent read back off the UDP egress.

use super::lcr_ring_timeout_tests::{invite_to, summaries, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use std::time::{Duration, Instant};

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";
const SIP_CALL_ID: &str = "a-leg-100rel@192.0.2.10";

/// The caller offers `100rel`.
const SUPPORTS: &str = "Supported: 100rel, timer\r\n";
/// The caller requires `100rel`.
const REQUIRES: &str = "Supported: timer\r\nRequire: 100rel\r\n";
/// The caller knows nothing of `100rel`.
const PLAIN: &str = "Supported: timer\r\n";

const PRESETS: [&str; 4] = [
    "transparent-b2bua@2026",
    "ims-intra-trust-domain@2026",
    "ims-trust-domain-boundary@2026",
    "sip-trunk-edge@2026",
];

const CALLER_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

const CALLEE_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 50000 RTP/AVP 0\r\n",
);

/// The callee's reliable provisional: `Require: 100rel` and its own `RSeq`.
const RELIABLY: &[(&str, &str)] = &[("Require", "100rel"), ("RSeq", "42")];

fn caller_invite(capability: &str) -> String {
    format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-a-leg-100rel\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "{capability}",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        call_id = SIP_CALL_ID,
        capability = capability,
        length = CALLER_SDP.len(),
        sdp = CALLER_SDP,
    )
}

/// A script that dials the callee under `policy`, with `extra` appended.
fn dial_script(policy: &str, extra: &str) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    call.dial(\"sip:15550100042@198.51.100.7:5060\", header_policy=\"{policy}\")\n",
            "{extra}",
        ),
        policy = policy,
        extra = extra,
    )
}

fn default_dial() -> String {
    dial_script("transparent-b2bua@2026", "")
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the test message parses")
}

fn caller() -> SocketAddr {
    CALLER.parse().expect("a literal address")
}

fn rseq(message: &SipMessage) -> Option<String> {
    message
        .headers
        .get("RSeq")
        .map(|value| value.trim().to_string())
}

/// Sent reliably: `Require: 100rel` and an `RSeq` (RFC 3262 §3, §7.1).
fn is_reliable(message: &SipMessage) -> bool {
    crate::sip::headers::rseq::requires_100rel(&message.headers) && rseq(message).is_some()
}

fn rseq_number(message: &SipMessage) -> u32 {
    rseq(message)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("no numeric RSeq on {:?}", message.status_code()))
}

/// A caller's call through a real dispatcher, dialled to the callee.
struct Call {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    invite: SipMessage,
    callee_invite: SipMessage,
}

impl Call {
    fn place(capability: &str, script: &str) -> Call {
        let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
        let state = Arc::new(state);
        let raw = caller_invite(capability);
        let invite = parse(&raw);
        let inbound = InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: caller(),
            data: Bytes::from(raw.into_bytes()),
        };
        // The dispatcher runs its handlers on blocking threads: the response
        // path waits on the leg actor's classification.
        tokio::task::block_in_place(|| handle_b2bua_invite(inbound, invite.clone(), &state));
        let call_id = state
            .call_actors
            .find_by_sip_call_id(SIP_CALL_ID)
            .expect("the call was placed");
        let callee_invite = invite_to(drain(&udp), CALLEE);
        Call {
            state,
            udp,
            call_id,
            invite,
            callee_invite,
        }
    }

    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// What went to the caller since the last look, in order.
    fn to_caller(&self) -> Vec<SipMessage> {
        self.wire()
            .into_iter()
            .filter(|sent| sent.destination == caller())
            .map(|sent| sent.message)
            .collect()
    }

    /// The callee answers its INVITE with `status_code`, `headers` added, and
    /// `body` as SDP.
    fn callee_sends(
        &self,
        status_code: u16,
        reason: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) {
        let invite = &self.callee_invite;
        let header = |name: &str| {
            invite
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("the callee INVITE has no {name}"))
        };
        let mut raw = format!("SIP/2.0 {status_code} {reason}\r\n");
        for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {};tag=callee-tag\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
        raw.push_str("Contact: <sip:callee@198.51.100.7:5060>\r\n");
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        match body {
            Some(sdp) => raw.push_str(&format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            )),
            None => raw.push_str("Content-Length: 0\r\n\r\n"),
        }
        let mut response = parse(&raw);
        let handled = tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.call_id,
                &top_via_branch(invite),
                &mut response,
                status_code,
                CALLEE.parse().expect("a literal address"),
                &self.state,
            )
        });
        assert!(
            handled,
            "the call was gone when the callee's {status_code} arrived"
        );
    }

    /// The caller PRACKs `provisional` with `RAck: <response_number> 1 INVITE`,
    /// on the dialog `to` names, as its request with CSeq `cseq`.
    fn caller_sends_prack(&self, to: &str, response_number: u32, cseq_number: u32, cseq: u32) {
        let raw = format!(
            concat!(
                "PRACK sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-prack-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} PRACK\r\n",
                "RAck: {response_number} {cseq_number} INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            cseq = cseq,
            to = to,
            call_id = SIP_CALL_ID,
            response_number = response_number,
            cseq_number = cseq_number,
        );
        let inbound = InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: caller(),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::request::handle_request(inbound, parse(&raw), "PRACK".to_string(), &self.state)
        });
    }

    /// The caller PRACKs `provisional` as its request with CSeq `cseq`.
    fn caller_pracks(&self, provisional: &SipMessage, cseq: u32) {
        let to = provisional
            .headers
            .get("To")
            .cloned()
            .expect("the provisional has a To");
        self.caller_sends_prack(&to, rseq_number(provisional), 1, cseq);
    }
}

impl Call {
    /// The callee hangs up with a BYE on the dialog its 2xx opened.
    fn callee_sends_bye(&self) {
        let invite = &self.callee_invite;
        let header = |name: &str| {
            invite
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("the callee INVITE has no {name}"))
        };
        let raw = format!(
            concat!(
                "BYE sip:siphon@192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-callee-bye\r\n",
                "Max-Forwards: 70\r\n",
                "From: {to};tag=callee-tag\r\n",
                "To: {from}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 BYE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            to = header("To"),
            from = header("From"),
            call_id = header("Call-ID"),
        );
        let inbound = InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: CALLEE.parse().expect("a literal address"),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| handle_b2bua_bye(inbound, parse(&raw), &self.state));
    }

    /// The caller CANCELs its INVITE.
    fn caller_cancels(&self) {
        let raw = concat!(
            "CANCEL sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-a-leg-100rel\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: a-leg-100rel@192.0.2.10\r\n",
            "CSeq: 1 CANCEL\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let inbound = InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: caller(),
            data: Bytes::from_static(raw.as_bytes()),
        };
        tokio::task::block_in_place(|| handle_b2bua_cancel(inbound, parse(raw), &self.state));
    }

    /// The callee answers after a reliable 183 with SDP, so the caller's 2xx
    /// waits for its PRACK. Returns that 183 as the caller got it.
    fn answered_while_the_caller_owes_a_prack(&self) -> SipMessage {
        self.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
        let progress = only(self.to_caller(), 183);
        self.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
        let listed = summaries(&self.wire());
        assert!(
            listed.contains(&format!("ACK to {CALLEE}")),
            "the callee's 2xx is ACKed on arrival: {listed:?}"
        );
        progress
    }
}

/// Everything siphon put on the wire, in order, the frames of an ordered group
/// (a response and what it released, an ACK and its BYE) included.
fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        let frames = std::iter::once(outbound.data).chain(outbound.followups.unwrap_or_default());
        for frame in frames {
            sent.push(Sent {
                destination: outbound.destination,
                message: parse_sip_message_bytes(&frame)
                    .expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

fn statuses(messages: &[SipMessage]) -> Vec<u16> {
    messages
        .iter()
        .map(|message| message.status_code().unwrap_or_default())
        .collect()
}

fn cseq_method(message: &SipMessage) -> String {
    message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

fn only(messages: Vec<SipMessage>, status_code: u16) -> SipMessage {
    let listed = statuses(&messages);
    let mut matching: Vec<SipMessage> = messages
        .into_iter()
        .filter(|message| message.status_code() == Some(status_code))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "one {status_code} to the caller, sent: {listed:?}"
    );
    matching.remove(0)
}

/// A callee's reliable 183 reaches a caller that supports `100rel` reliably,
/// under every preset, and the `RSeq` is siphon's: the callee's numbering is
/// the B-leg's, which siphon PRACKs itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_reaches_a_caller_that_supports_100rel_with_siphons_own_rseq() {
    for preset in PRESETS {
        let call = Call::place(SUPPORTS, &dial_script(preset, ""));
        call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
        let progress = only(call.to_caller(), 183);
        assert!(is_reliable(&progress), "under {preset}: {progress:?}");
        assert_ne!(rseq(&progress).as_deref(), Some("42"), "under {preset}");
        assert!(
            (1..=0x7FFF_FFFF).contains(&rseq_number(&progress)),
            "under {preset}"
        );
    }
}

/// A caller that only supports `100rel` gets an unreliable provisional as it
/// was sent, and a caller that knows nothing of `100rel` gets no reliable one at
/// all.
#[tokio::test(flavor = "multi_thread")]
async fn a_provisional_is_not_made_reliable_toward_a_caller_that_does_not_require_it() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(180, "Ringing", &[], None);
    assert!(!is_reliable(&only(call.to_caller(), 180)));

    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(rseq(&progress).is_none());
    assert!(!crate::sip::headers::rseq::requires_100rel(
        &progress.headers
    ));
}

/// RFC 3262 §3: a UAS MUST send every non-100 provisional reliably when the
/// request required `100rel`, whether or not the callee sent it reliably.
#[tokio::test(flavor = "multi_thread")]
async fn every_provisional_is_reliable_toward_a_caller_that_requires_100rel() {
    for preset in PRESETS {
        let call = Call::place(REQUIRES, &dial_script(preset, ""));
        call.callee_sends(180, "Ringing", &[], None);
        assert!(is_reliable(&only(call.to_caller(), 180)), "under {preset}");
    }
}

/// RFC 3262 §3: no second reliable provisional before the first is PRACKed,
/// and the next `RSeq` on the dialog is exactly one more.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_reliable_provisional_waits_for_the_prack_of_the_first() {
    let call = Call::place(REQUIRES, &default_dial());
    call.callee_sends(180, "Ringing", &[], None);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let sent = call.to_caller();
    assert_eq!(statuses(&sent), [180], "the 183 waits for the 180's PRACK");
    let ringing = sent.into_iter().next().expect("the 180");

    call.caller_pracks(&ringing, 2);
    let sent = call.to_caller();
    assert_eq!(statuses(&sent), [200, 183]);
    assert_eq!(cseq_method(&sent[0]), "PRACK");
    assert!(is_reliable(&sent[1]));
    assert_eq!(rseq_number(&sent[1]), rseq_number(&ringing) + 1);
}

/// siphon answers the caller's PRACK itself, matched on its `RAck` and dialog
/// (RFC 3262 §3): 200 for the provisional it acknowledges, again for a
/// retransmission of that PRACK, 481 for one that matches nothing. None of them
/// is relayed to the callee.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_prack_is_answered_by_siphon_on_its_rack() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    let to = progress.headers.get("To").cloned().expect("a To");
    let number = rseq_number(&progress);

    call.caller_sends_prack(&to, number + 1, 1, 2);
    call.caller_sends_prack(&to, number, 7, 3);
    call.caller_sends_prack(
        "<sip:15550100042@siphon.example.com>;tag=another-dialog",
        number,
        1,
        4,
    );
    let sent = call.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("481 to {CALLER}"),
            format!("481 to {CALLER}"),
            format!("481 to {CALLER}")
        ],
        "an RSeq never sent, the wrong INVITE CSeq, another dialog"
    );

    call.caller_pracks(&progress, 5);
    call.caller_pracks(&progress, 5);
    let sent = call.wire();
    assert_eq!(
        summaries(&sent),
        [format!("200 to {CALLER}"), format!("200 to {CALLER}")],
        "the PRACK and its retransmission, neither relayed"
    );
    assert!(
        call.state.reliable_provisionals.is_empty(),
        "the acknowledged provisional is no longer tracked"
    );
}

/// RFC 3262 §3: the reliable provisional is retransmitted on T1 doubling until
/// its PRACK, byte for byte, and not after.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_is_retransmitted_until_the_callers_prack() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);

    tokio::time::sleep(Duration::from_millis(700)).await;
    let retransmitted = only(call.to_caller(), 183);
    assert_eq!(retransmitted.to_bytes(), progress.to_bytes());

    call.caller_pracks(&progress, 2);
    assert_eq!(statuses(&call.to_caller()), [200]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(statuses(&call.to_caller()), Vec::<u16>::new());
}

/// RFC 3262 §3 and §5: a 2xx MUST NOT go out while a reliable provisional that
/// carried SDP is unacknowledged. It follows the PRACK's 200.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_waits_for_the_prack_of_a_reliable_provisional_with_sdp() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    assert_eq!(
        statuses(&call.to_caller()),
        Vec::<u16>::new(),
        "the 2xx is held"
    );

    call.caller_pracks(&progress, 2);
    let sent = call.to_caller();
    assert_eq!(statuses(&sent), [200, 200]);
    assert_eq!(cseq_method(&sent[0]), "PRACK");
    assert_eq!(cseq_method(&sent[1]), "INVITE");
}

/// A reliable provisional without SDP does not hold the 2xx, and once the 2xx is
/// out it is not retransmitted; its PRACK is still answered.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_ends_the_retransmits_of_a_provisional_without_sdp() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(180, "Ringing", RELIABLY, None);
    let ringing = only(call.to_caller(), 180);
    assert!(is_reliable(&ringing));

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    assert_eq!(statuses(&call.to_caller()), [200]);

    tokio::time::sleep(Duration::from_millis(700)).await;
    let later = call.to_caller();
    assert!(
        !statuses(&later).contains(&180),
        "no 180 after the final: {:?}",
        statuses(&later)
    );

    call.caller_pracks(&ringing, 2);
    let answered: Vec<SipMessage> = call
        .to_caller()
        .into_iter()
        .filter(|message| cseq_method(message) == "PRACK")
        .collect();
    assert_eq!(statuses(&answered), [200]);
}

/// A final failure ends the retransmits too (RFC 3262 §3), and a PRACK for the
/// provisional that arrives after it is still answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_final_failure_ends_the_retransmits_and_a_late_prack_is_answered() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);

    call.callee_sends(486, "Busy Here", &[], None);
    assert_eq!(statuses(&call.to_caller()), [486]);

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(statuses(&call.to_caller()), Vec::<u16>::new());

    call.caller_pracks(&progress, 2);
    assert_eq!(statuses(&call.to_caller()), [200]);
}

/// RFC 3262 §3: a reliable provisional unacknowledged for 64*T1 has the UAS
/// reject the request with a 5xx. The callee still ringing is CANCELled.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_never_pracks_is_refused() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    only(call.to_caller(), 183);

    check_b2bua_prack_timeouts_at(&call.state, Instant::now() + Duration::from_secs(33));
    let sent = call.wire();
    let listed = summaries(&sent);
    assert!(
        listed.contains(&format!("CANCEL to {CALLEE}")),
        "{listed:?}"
    );
    assert!(listed.contains(&format!("500 to {CALLER}")), "{listed:?}");
    assert!(call.state.call_actors.get_call(&call.call_id).is_none());
    assert!(call.state.reliable_provisionals.is_empty());
}

/// The same when the callee has already answered and the 2xx is held for the
/// PRACK: the callee's 2xx was ACKed when it arrived, its dialog is BYEd, and
/// the caller gets the 5xx, never the 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_never_pracks_an_answered_call_is_refused_and_the_callee_released() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    only(call.to_caller(), 183);
    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    let listed = summaries(&call.wire());
    assert!(listed.contains(&format!("ACK to {CALLEE}")), "{listed:?}");

    check_b2bua_prack_timeouts_at(&call.state, Instant::now() + Duration::from_secs(33));
    let sent = call.wire();
    let listed = summaries(&sent);
    assert!(listed.contains(&format!("BYE to {CALLEE}")), "{listed:?}");
    assert!(listed.contains(&format!("500 to {CALLER}")), "{listed:?}");
    assert!(!listed.contains(&format!("200 to {CALLER}")), "{listed:?}");
    assert!(call.state.call_actors.get_call(&call.call_id).is_none());
}

/// The reliability of a provisional is siphon's, not the script's: an `RSeq` a
/// script sets in `@b2bua.on_early_media` does not reach the caller, and a
/// `Require: 100rel` it sets toward a caller without `100rel` does not either.
#[tokio::test(flavor = "multi_thread")]
async fn siphon_owns_rseq_and_100rel_over_a_script_on_the_response() {
    let script = dial_script(
        "sip-trunk-edge@2026",
        concat!(
            "\n",
            "@b2bua.on_early_media\n",
            "def on_early_media(call, reply):\n",
            "    reply.set_header(\"RSeq\", \"7\")\n",
            "    reply.set_header(\"Require\", \"100rel\")\n",
        ),
    );
    let call = Call::place(SUPPORTS, &script);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(is_reliable(&progress));
    assert_ne!(rseq(&progress).as_deref(), Some("7"));

    let call = Call::place(PLAIN, &script);
    call.callee_sends(183, "Session Progress", &[], Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(rseq(&progress).is_none());
    assert!(!crate::sip::headers::rseq::requires_100rel(
        &progress.headers
    ));
}

/// siphon's own provisional on the UAS path (`call.progress()`) is reliable
/// toward a caller that requires `100rel`, and its own 2xx (`call.answer()`)
/// waits for the PRACK when that provisional carried SDP.
#[tokio::test(flavor = "multi_thread")]
async fn a_uas_provisional_is_reliable_toward_a_caller_that_requires_100rel() {
    let call = Call::place(REQUIRES, &default_dial());
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        183,
        "Session Progress",
        Some(CALLER_SDP.as_bytes().to_vec()),
        Some("application/sdp"),
        false,
    ));
    let progress = only(call.to_caller(), 183);
    assert!(is_reliable(&progress));

    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        200,
        "OK",
        Some(CALLER_SDP.as_bytes().to_vec()),
        Some("application/sdp"),
        true,
    ));
    assert_eq!(
        statuses(&call.to_caller()),
        Vec::<u16>::new(),
        "the 2xx is held"
    );

    call.caller_pracks(&progress, 2);
    let sent = call.to_caller();
    assert_eq!(statuses(&sent), [200, 200]);
    assert_eq!(cseq_method(&sent[1]), "INVITE");
}

/// A 2xx held for a PRACK is not yet an answer the caller has: it is not in the
/// unACKed-answer store, so neither its retransmission nor the 64*T1 sweep runs
/// until it is actually sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_answer_starts_its_retransmission_only_when_it_is_sent() {
    let call = Call::place(SUPPORTS, &default_dial());
    let progress = call.answered_while_the_caller_owes_a_prack();
    assert!(!call.state.uas_2xx_retransmits.contains_key(SIP_CALL_ID));

    call.caller_pracks(&progress, 2);
    assert_eq!(statuses(&call.to_caller()), [200, 200]);
    assert!(call.state.uas_2xx_retransmits.contains_key(SIP_CALL_ID));
}

/// A teardown while the caller's 2xx waits for its PRACK: the caller's INVITE has
/// no final response yet, so the call ends for it with `487 Request Terminated`
/// (RFC 3261 §21.4.26) rather than a BYE on a dialog it never saw confirmed, and
/// the held 2xx is never sent, even when the PRACK comes after all.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_bye_while_the_answer_waits_for_the_prack_ends_the_caller_with_487() {
    let call = Call::place(SUPPORTS, &default_dial());
    let progress = call.answered_while_the_caller_owes_a_prack();

    call.callee_sends_bye();
    let listed = summaries(&call.wire());
    assert!(listed.contains(&format!("200 to {CALLEE}")), "{listed:?}");
    assert!(listed.contains(&format!("487 to {CALLER}")), "{listed:?}");
    assert!(!listed.contains(&format!("BYE to {CALLER}")), "{listed:?}");

    call.caller_pracks(&progress, 2);
    let invite_answers: Vec<SipMessage> = call
        .to_caller()
        .into_iter()
        .filter(|message| cseq_method(message) == "INVITE")
        .collect();
    assert_eq!(statuses(&invite_answers), Vec::<u16>::new());
}

/// A CANCEL while the caller's 2xx waits for its PRACK: the caller has had no
/// final response, so the CANCEL ends the call (RFC 3261 §9.2) with a 487 to the
/// INVITE, and the callee, which answered, gets a BYE.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_while_the_answer_waits_for_the_prack_ends_the_call() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.answered_while_the_caller_owes_a_prack();

    call.caller_cancels();
    let sent = call.wire();
    let listed = summaries(&sent);
    assert!(listed.contains(&format!("487 to {CALLER}")), "{listed:?}");
    assert!(listed.contains(&format!("BYE to {CALLEE}")), "{listed:?}");
    assert!(
        sent.iter()
            .any(|sent| sent.message.status_code() == Some(200)
                && cseq_method(&sent.message) == "CANCEL"),
        "{listed:?}"
    );
    assert!(call.state.call_actors.get_call(&call.call_id).is_none());
}

/// The PRACK timeout takes the call through the teardown claim: a call another
/// teardown already has is left to that teardown, which sends what is owed.
#[tokio::test(flavor = "multi_thread")]
async fn a_prack_timeout_leaves_a_call_another_teardown_has_claimed() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    only(call.to_caller(), 183);
    assert!(call.state.call_actors.claim_teardown(&call.call_id));

    check_b2bua_prack_timeouts_at(&call.state, Instant::now() + Duration::from_secs(33));
    assert_eq!(summaries(&call.wire()), Vec::<String>::new());
    assert!(call.state.call_actors.get_call(&call.call_id).is_some());
}

/// Once the PRACK has released it, the caller's 2xx is an ordinary answer: a
/// callee BYE before the caller's ACK is held until that ACK (RFC 3261 §15).
#[tokio::test(flavor = "multi_thread")]
async fn a_released_answer_holds_a_callee_bye_until_the_callers_ack() {
    let call = Call::place(SUPPORTS, &default_dial());
    let progress = call.answered_while_the_caller_owes_a_prack();
    call.caller_pracks(&progress, 2);
    assert_eq!(statuses(&call.to_caller()), [200, 200]);

    call.callee_sends_bye();
    let listed = summaries(&call.wire());
    assert!(!listed.contains(&format!("BYE to {CALLER}")), "{listed:?}");
    assert!(call.state.held_byes.contains_key(SIP_CALL_ID));
}

/// RFC 3262 §3 lets a UAS send any provisional to an INVITE reliably when the
/// caller supports `100rel`. siphon does for one that carries SDP, even when the
/// callee sent it unreliably, so the caller does not lose the early media it is
/// told about. One without SDP stays as the callee sent it.
#[tokio::test(flavor = "multi_thread")]
async fn an_18x_with_sdp_reaches_a_caller_that_supports_100rel_reliably_whatever_the_callee_did() {
    for preset in PRESETS {
        let call = Call::place(SUPPORTS, &dial_script(preset, ""));
        call.callee_sends(183, "Session Progress", &[], Some(CALLEE_SDP));
        let progress = only(call.to_caller(), 183);
        assert!(is_reliable(&progress), "under {preset}: {progress:?}");
    }

    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(180, "Ringing", &[], None);
    assert!(!is_reliable(&only(call.to_caller(), 180)));
}

/// The same for siphon's own provisional (`call.progress()`): a 183 with SDP to a
/// caller that supports `100rel` is reliable, a 180 without SDP is not.
#[tokio::test(flavor = "multi_thread")]
async fn siphons_own_18x_with_sdp_is_reliable_toward_a_caller_that_supports_100rel() {
    let call = Call::place(SUPPORTS, &default_dial());
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        180,
        "Ringing",
        None,
        None,
        false,
    ));
    assert!(!is_reliable(&only(call.to_caller(), 180)));

    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        183,
        "Session Progress",
        Some(CALLER_SDP.as_bytes().to_vec()),
        Some("application/sdp"),
        false,
    ));
    assert!(is_reliable(&only(call.to_caller(), 183)));
}
