//! An INVITE that returns to the instance that dialled it (RFC 3261 §17.2.3,
//! §8.2.2.2, §16.3).
//!
//! siphon takes a call, dials a proxy on a new Call-ID, and the proxy's routing
//! brings that INVITE back to the same instance as a call for the next party:
//! one element visited twice, a spiral. The request that comes back is a new
//! transaction (a Via on top with a branch of the proxy's own), not a
//! retransmission, and siphon serves it as a new call with its own caller
//! dialog. Two calls then share one Call-ID, one as the dialog it dialled and
//! one as the dialog it answers, and every later request on that Call-ID has to
//! reach the right one of the two: they are told apart by the tags.
//!
//! Driven through the dispatcher's entry point, with a proxy in the test that
//! sends every request siphon gives it back to siphon and every response back
//! down the Via it added.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use std::collections::HashMap;
use std::time::Duration;

/// The hop that delivers the caller's INVITE.
const CALLER: &str = "192.0.2.10:5060";
/// The proxy siphon dials, whose routing returns the request to siphon.
const PROXY: &str = "192.0.2.50:5060";
const CALLEE: &str = "198.51.100.70:5060";
const FIRST_CALL_ID: &str = "spiral-first@192.0.2.10";

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.10\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const SECOND_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 4 IN IP4 192.0.2.10\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40002 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.70\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.70\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const SECOND_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 8 IN IP4 198.51.100.70\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.70\r\n",
    "t=0 0\r\n",
    "m=audio 30002 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

/// The first pass dials the proxy, the second the callee.
const SPIRAL: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    if call.ruri.user == \"second-pass\":\n",
    "        call.dial(\"sip:15550100042@198.51.100.70:5060\")\n",
    "    else:\n",
    "        call.dial(\"sip:second-pass@192.0.2.50:5060\")\n",
);

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

fn header(message: &SipMessage, name: &str) -> String {
    message
        .headers
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("the message has no {name}"))
}

fn call_id(message: &SipMessage) -> String {
    header(message, "Call-ID")
}

fn cseq_method(message: &SipMessage) -> String {
    message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

fn top_via_branch(message: &SipMessage) -> String {
    header(message, "Via")
        .split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("branch="))
        .map(str::to_string)
        .expect("a Via branch")
}

fn via_count(message: &SipMessage) -> usize {
    message
        .headers
        .get_all("Via")
        .map(|lines| lines.iter().map(|line| line.split(',').count()).sum())
        .unwrap_or(0)
}

fn push_body(raw: &mut String, body: &str) {
    if body.is_empty() {
        raw.push_str("Content-Length: 0\r\n\r\n");
    } else {
        raw.push_str(&format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
    }
}

/// One message siphon put on the wire.
#[derive(Clone)]
struct Sent {
    destination: SocketAddr,
    raw: String,
    message: SipMessage,
}

impl Sent {
    fn summary(&self) -> String {
        let what = match self.message.status_code() {
            Some(status_code) => format!("{status_code} ({})", cseq_method(&self.message)),
            None => cseq_method(&self.message),
        };
        format!(
            "{what} [{}] to {}",
            call_id(&self.message),
            self.destination
        )
    }

    fn is_request(&self, method: &str) -> bool {
        self.message.status_code().is_none() && cseq_method(&self.message) == method
    }

    fn is_response(&self, status_code: u16, method: &str) -> bool {
        self.message.status_code() == Some(status_code) && cseq_method(&self.message) == method
    }
}

fn summaries(sent: &[Sent]) -> Vec<String> {
    sent.iter().map(Sent::summary).collect()
}

/// siphon, the caller, the callee, and the proxy between siphon and itself.
struct Spiral {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    /// Everything siphon has sent, in order, whoever it went to.
    wire: Vec<Sent>,
    /// The branch the proxy forwarded each INVITE on, by Call-ID: its CANCEL
    /// and its ACK to a failure go on the same one (RFC 3261 §9.1, §17.1.1.3).
    proxy_invite_branches: HashMap<String, String>,
    proxy_branches: u32,
}

impl Spiral {
    fn new() -> Spiral {
        let TestDispatcher { state, udp } = test_dispatcher_with_script(SPIRAL);
        Spiral {
            state: Arc::new(state),
            udp,
            wire: Vec::new(),
            proxy_invite_branches: HashMap::new(),
            proxy_branches: 0,
        }
    }

    /// A datagram from `source` through the dispatcher's entry point.
    fn deliver(&self, source: &str, raw: &str) {
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(source),
            data: Bytes::from(raw.as_bytes().to_vec()),
        };
        tokio::task::block_in_place(|| super::inbound::handle_inbound(inbound, &self.state));
    }

    fn drain(&mut self) -> Vec<Sent> {
        let mut sent = Vec::new();
        while let Ok(outbound) = self.udp.try_recv() {
            for frame in outbound.frames() {
                sent.push(Sent {
                    destination: outbound.destination,
                    raw: String::from_utf8_lossy(frame).into_owned(),
                    message: parse_sip_message_bytes(frame)
                        .expect("siphon sent a message that parses"),
                });
            }
        }
        sent
    }

    /// Let the proxy do its work until siphon has nothing more to say, and
    /// return what siphon sent meanwhile, the proxy's share included.
    async fn settle(&mut self) -> Vec<Sent> {
        let start = self.wire.len();
        let mut quiet = 0;
        while quiet < 3 {
            let sent = self.drain();
            if sent.is_empty() {
                quiet += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            quiet = 0;
            for frame in sent {
                self.wire.push(frame.clone());
                if frame.destination == address(PROXY) {
                    self.proxy_handles(&frame);
                }
            }
        }
        self.wire[start..].to_vec()
    }

    fn next_proxy_branch(&mut self) -> String {
        self.proxy_branches += 1;
        format!("z9hG4bK-proxy-{}", self.proxy_branches)
    }

    /// What a record-routing stateful proxy whose routing points back at siphon
    /// does with a message siphon sent it.
    fn proxy_handles(&mut self, frame: &Sent) {
        let message = &frame.message;
        let dialog = call_id(message);
        if let Some(status_code) = message.status_code() {
            // A response to a request the proxy sent on. One Via means the
            // proxy's own CANCEL, which ends here, as a 100 does at each hop.
            if via_count(message) < 2 || status_code == 100 {
                return;
            }
            if status_code >= 300 && cseq_method(message) == "INVITE" {
                // The proxy ACKs a failure itself (RFC 3261 §17.1.1.3).
                let branch = self.proxy_invite_branches[&dialog].clone();
                let mut ack = format!(
                    "ACK sip:second-pass@192.0.2.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP {PROXY};branch={branch}\r\nMax-Forwards: 70\r\n"
                );
                for name in ["From", "To", "Call-ID"] {
                    ack.push_str(&format!("{name}: {}\r\n", header(message, name)));
                }
                let number = header(message, "CSeq");
                let number = number.split_whitespace().next().unwrap_or("1");
                ack.push_str(&format!("CSeq: {number} ACK\r\n"));
                push_body(&mut ack, "");
                self.deliver(PROXY, &ack);
            }
            self.deliver(PROXY, &without_top_via(&frame.raw));
            return;
        }
        match cseq_method(message).as_str() {
            "INVITE" => {
                let branch = self.next_proxy_branch();
                self.proxy_invite_branches.insert(dialog, branch.clone());
                self.deliver(PROXY, &forwarded(&frame.raw, &branch, true));
            }
            "CANCEL" => {
                // Hop by hop (RFC 3261 §9.2): the proxy answers it, and cancels
                // the INVITE it sent on, on that INVITE's branch.
                let mut ok = "SIP/2.0 200 OK\r\n".to_string();
                for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                    ok.push_str(&format!("{name}: {}\r\n", header(message, name)));
                }
                push_body(&mut ok, "");
                self.deliver(PROXY, &ok);
                let branch = self.proxy_invite_branches[&dialog].clone();
                self.deliver(PROXY, &replacing_via(&frame.raw, &branch));
            }
            "ACK" if !self.acknowledges_a_2xx(message) => {}
            _ => {
                let branch = self.next_proxy_branch();
                self.deliver(PROXY, &forwarded(&frame.raw, &branch, false));
            }
        }
    }

    /// An ACK on a branch of its own is the ACK to a 2xx, which the proxy
    /// forwards. One on the INVITE's branch acknowledges a failure and ends at
    /// the proxy.
    fn acknowledges_a_2xx(&self, ack: &SipMessage) -> bool {
        let branch = top_via_branch(ack);
        !self.wire.iter().any(|sent| {
            sent.is_request("INVITE")
                && call_id(&sent.message) == call_id(ack)
                && top_via_branch(&sent.message) == branch
        })
    }

    fn caller_invite(&self) -> String {
        self.caller_invite_with_hops(70)
    }

    fn caller_invite_with_hops(&self, max_forwards: u32) -> String {
        let mut raw = format!(
            concat!(
                "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
                "Max-Forwards: {max_forwards}\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.10:5060>\r\n",
                "Supported: 100rel\r\n",
                "Allow: INVITE, ACK, CANCEL, BYE, PRACK, UPDATE\r\n",
            ),
            call_id = FIRST_CALL_ID,
            max_forwards = max_forwards,
        );
        push_body(&mut raw, OFFER);
        raw
    }

    /// The caller calls, and the INVITE siphon dials comes back to it. Returns
    /// the INVITE the callee receives.
    async fn place(&mut self) -> SipMessage {
        self.deliver(CALLER, &self.caller_invite());
        let sent = self.settle().await;
        sent.iter()
            .find(|sent| sent.destination == address(CALLEE) && sent.is_request("INVITE"))
            .map(|sent| sent.message.clone())
            .unwrap_or_else(|| {
                panic!(
                    "the returning INVITE never reached the callee: {:?}",
                    summaries(&sent)
                )
            })
    }

    /// The callee's response to `invite`, reliable when `rseq` is given.
    fn callee_responds(
        &self,
        invite: &SipMessage,
        status_code: u16,
        rseq: Option<u32>,
        body: &str,
    ) {
        let mut raw = format!("SIP/2.0 {status_code} Reason\r\n");
        for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
        raw.push_str(&format!("To: {};tag=callee-tag\r\n", header(invite, "To")));
        raw.push_str(&format!("Call-ID: {}\r\n", call_id(invite)));
        raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
        raw.push_str("Contact: <sip:callee@198.51.100.70:5060>\r\n");
        raw.push_str("Allow: INVITE, ACK, CANCEL, BYE, PRACK, UPDATE\r\n");
        if let Some(rseq) = rseq {
            raw.push_str(&format!("Require: 100rel\r\nRSeq: {rseq}\r\n"));
        }
        push_body(&mut raw, body);
        self.deliver(CALLEE, &raw);
    }

    /// `party` answers `request`, one siphon sent it, with 200 and `body`.
    fn answers(&self, party: &str, request: &SipMessage, body: &str) {
        let mut raw = "SIP/2.0 200 OK\r\n".to_string();
        for via in request.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        for name in ["From", "To", "Call-ID", "CSeq"] {
            raw.push_str(&format!("{name}: {}\r\n", header(request, name)));
        }
        push_body(&mut raw, body);
        self.deliver(party, &raw);
    }

    /// The caller's in-dialog `method` numbered `cseq`, on the dialog the
    /// `response` to its INVITE names.
    fn caller_request(
        &self,
        method: &str,
        response: &SipMessage,
        cseq: u32,
        extra: &str,
        body: &str,
    ) {
        let mut raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-{method}-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} {method}\r\n",
                "Contact: <sip:caller@192.0.2.10:5060>\r\n",
                "{extra}",
            ),
            method = method,
            cseq = cseq,
            to = header(response, "To"),
            call_id = FIRST_CALL_ID,
            extra = extra,
        );
        push_body(&mut raw, body);
        self.deliver(CALLER, &raw);
    }

    /// The call answered end to end and acknowledged by the caller. Returns the
    /// callee's INVITE and the 200 the caller got.
    async fn answered(&mut self) -> (SipMessage, SipMessage) {
        let callee_invite = self.place().await;
        self.callee_responds(&callee_invite, 200, None, ANSWER);
        let sent = self.settle().await;
        let ok = to_the_caller(&sent, 200, "INVITE");
        self.caller_request("ACK", &ok, 1, "", "");
        self.settle().await;
        (callee_invite, ok)
    }

    fn calls(&self) -> usize {
        self.state.call_actors.count()
    }
}

/// `raw` as the proxy sends a request on: its own Via on top, one hop spent,
/// and its Record-Route on a request that opens a dialog.
fn forwarded(raw: &str, branch: &str, record_route: bool) -> String {
    let (start_line, rest) = raw.split_once("\r\n").expect("a start line");
    let mut forwarded = format!("{start_line}\r\nVia: SIP/2.0/UDP {PROXY};branch={branch}\r\n");
    if record_route {
        forwarded.push_str(&format!("Record-Route: <sip:{PROXY};lr>\r\n"));
    }
    let (head, body) = rest.split_once("\r\n\r\n").expect("a header section");
    for line in head.split("\r\n") {
        match line.strip_prefix("Max-Forwards:") {
            Some(hops) => {
                let hops: u32 = hops.trim().parse().expect("a Max-Forwards number");
                forwarded.push_str(&format!("Max-Forwards: {}\r\n", hops - 1));
            }
            None => forwarded.push_str(&format!("{line}\r\n")),
        }
    }
    forwarded.push_str("\r\n");
    forwarded.push_str(body);
    forwarded
}

/// `raw` with every Via replaced by the proxy's own on `branch`.
fn replacing_via(raw: &str, branch: &str) -> String {
    let (start_line, rest) = raw.split_once("\r\n").expect("a start line");
    let mut replaced = format!("{start_line}\r\nVia: SIP/2.0/UDP {PROXY};branch={branch}\r\n");
    for line in rest.split_inclusive("\r\n") {
        if !line.starts_with("Via:") {
            replaced.push_str(line);
        }
    }
    replaced
}

/// `raw` as the proxy sends a response on: without the Via it added.
fn without_top_via(raw: &str) -> String {
    let mut dropped = false;
    let mut forwarded = String::new();
    for line in raw.split_inclusive("\r\n") {
        if !dropped && line.starts_with("Via:") {
            dropped = true;
            assert!(line.contains(PROXY), "the top Via is the proxy's: {line}");
            continue;
        }
        forwarded.push_str(line);
    }
    forwarded
}

#[track_caller]
fn to_the_caller(sent: &[Sent], status_code: u16, method: &str) -> SipMessage {
    sent.iter()
        .find(|sent| sent.destination == address(CALLER) && sent.is_response(status_code, method))
        .map(|sent| sent.message.clone())
        .unwrap_or_else(|| {
            panic!(
                "no {status_code} to the caller's {method}: {:?}",
                summaries(sent)
            )
        })
}

#[track_caller]
fn request_to(sent: &[Sent], party: &str, method: &str) -> SipMessage {
    let matching: Vec<&Sent> = sent
        .iter()
        .filter(|sent| sent.destination == address(party) && sent.is_request(method))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "exactly one {method} to {party}: {:?}",
        summaries(sent)
    );
    matching[0].message.clone()
}

fn position(sent: &[Sent], party: &str, method: &str) -> usize {
    sent.iter()
        .position(|sent| sent.destination == address(party) && sent.is_request(method))
        .unwrap_or_else(|| panic!("no {method} to {party}: {:?}", summaries(sent)))
}

/// RFC 3261 §17.2.3 matches a request to a server transaction by the branch of
/// its top Via, the sent-by there and the method. The INVITE that comes back
/// carries the proxy's branch on top, so it is a new request, and the element
/// it spirals through serves it as a new call: three dialogs, three Call-IDs,
/// two calls.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_returning_to_its_dialler_is_a_new_call() {
    let mut spiral = Spiral::new();
    let callee_invite = spiral.place().await;

    let dialled = request_to(&spiral.wire, PROXY, "INVITE");
    let second = call_id(&dialled);
    let third = call_id(&callee_invite);
    assert_ne!(second, FIRST_CALL_ID);
    assert_ne!(third, FIRST_CALL_ID);
    assert_ne!(third, second);
    assert_eq!(spiral.calls(), 2, "one call per pass");
    // Each pass spends a hop of its own and the proxy one between them, so a
    // request that kept coming back would run out (RFC 7332).
    assert_eq!(header(&dialled, "Max-Forwards").trim(), "69");
    assert_eq!(header(&callee_invite, "Max-Forwards").trim(), "67");

    // The proxy that delivered the returning INVITE hears it is being served.
    assert!(
        spiral
            .wire
            .iter()
            .any(|sent| sent.destination == address(PROXY)
                && sent.is_response(100, "INVITE")
                && call_id(&sent.message) == second),
        "no 100 Trying for the returning INVITE: {:?}",
        summaries(&spiral.wire)
    );
}

/// The callee's 180 and 200 cross both calls back to the caller, each on the
/// dialog of the call it belongs to, and the caller's ACK confirms all three.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_crosses_both_passes() {
    let mut spiral = Spiral::new();
    let callee_invite = spiral.place().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));

    spiral.callee_responds(&callee_invite, 180, None, "");
    let sent = spiral.settle().await;
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(180, "INVITE")
            && call_id(&sent.message) == second),
        "no 180 on the middle dialog: {:?}",
        summaries(&sent)
    );
    let ringing = to_the_caller(&sent, 180, "INVITE");
    assert_eq!(call_id(&ringing), FIRST_CALL_ID);

    spiral.callee_responds(&callee_invite, 200, None, ANSWER);
    let sent = spiral.settle().await;
    let ok = to_the_caller(&sent, 200, "INVITE");
    assert_eq!(call_id(&ok), FIRST_CALL_ID);
    assert!(!ok.body.is_empty(), "the caller's 200 carries the answer");
    // Each 2xx siphon received is acknowledged: the callee's, and through the
    // proxy the one the second pass sent the first.
    assert_eq!(
        call_id(&request_to(&sent, CALLEE, "ACK")),
        call_id(&callee_invite)
    );
    assert_eq!(call_id(&request_to(&sent, PROXY, "ACK")), second);

    spiral.caller_request("ACK", &ok, 1, "", "");
    spiral.settle().await;
    assert_eq!(spiral.calls(), 2);
    // Nothing is left retransmitting an answer: every dialog siphon answered is
    // confirmed.
    assert!(
        spiral.state.uas_2xx_retransmits.is_empty(),
        "a 2xx is still waiting for its ACK"
    );
}

/// The caller hangs up: its BYE is answered, the first call ends the dialog it
/// dialled, that BYE reaches the second call as its caller's and ends the
/// callee's dialog. One BYE per dialog, in that order, and no call left.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_from_the_caller_ends_all_three_dialogs() {
    let mut spiral = Spiral::new();
    let (callee_invite, ok) = spiral.answered().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));

    spiral.caller_request("BYE", &ok, 2, "", "");
    let sent = spiral.settle().await;
    to_the_caller(&sent, 200, "BYE");
    let middle = request_to(&sent, PROXY, "BYE");
    assert_eq!(call_id(&middle), second);
    let last = request_to(&sent, CALLEE, "BYE");
    assert_eq!(call_id(&last), call_id(&callee_invite));
    assert!(position(&sent, PROXY, "BYE") < position(&sent, CALLEE, "BYE"));
    // The middle BYE is answered by the call it reached, not refused.
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(200, "BYE")
            && call_id(&sent.message) == second),
        "the middle BYE was not answered 200: {:?}",
        summaries(&sent)
    );
    assert!(
        !sent
            .iter()
            .any(|sent| sent.destination == address(CALLER) && sent.is_request("BYE")),
        "the caller that hung up was sent a BYE: {:?}",
        summaries(&sent)
    );

    spiral.answers(CALLEE, &last, "");
    spiral.settle().await;
    assert_eq!(spiral.calls(), 0, "both calls are over");
}

/// The callee hangs up: the second call ends its caller's dialog, and that BYE
/// reaches the first call as its callee's, which ends the caller's dialog.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_from_the_callee_ends_all_three_dialogs() {
    let mut spiral = Spiral::new();
    let (callee_invite, _) = spiral.answered().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));

    let mut bye = format!(
        concat!(
            "BYE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.70:5060;branch=z9hG4bK-callee-bye\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from};tag=callee-tag\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 BYE\r\n",
        ),
        from = header(&callee_invite, "To"),
        to = header(&callee_invite, "From"),
        call_id = call_id(&callee_invite),
    );
    push_body(&mut bye, "");
    spiral.deliver(CALLEE, &bye);
    let sent = spiral.settle().await;

    assert!(
        sent.iter()
            .any(|sent| sent.destination == address(CALLEE) && sent.is_response(200, "BYE")),
        "the callee's BYE was not answered: {:?}",
        summaries(&sent)
    );
    let middle = request_to(&sent, PROXY, "BYE");
    assert_eq!(call_id(&middle), second);
    let first = request_to(&sent, CALLER, "BYE");
    assert_eq!(call_id(&first), FIRST_CALL_ID);
    assert!(position(&sent, PROXY, "BYE") < position(&sent, CALLER, "BYE"));
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(200, "BYE")
            && call_id(&sent.message) == second),
        "the middle BYE was not answered 200: {:?}",
        summaries(&sent)
    );
    assert!(
        !sent
            .iter()
            .any(|sent| sent.destination == address(CALLEE) && sent.is_request("BYE")),
        "the callee that hung up was sent a BYE: {:?}",
        summaries(&sent)
    );

    spiral.answers(CALLER, &first, "");
    spiral.settle().await;
    assert_eq!(spiral.calls(), 0, "both calls are over");
}

/// RFC 3261 §9.1: the caller gives up while the callee rings. Its CANCEL ends
/// the first call, the CANCEL that call sends reaches the second as its
/// caller's, and the callee's INVITE is cancelled in turn.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_from_the_caller_cancels_all_the_way_through() {
    let mut spiral = Spiral::new();
    let callee_invite = spiral.place().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));
    spiral.callee_responds(&callee_invite, 180, None, "");
    spiral.settle().await;

    let mut cancel = format!(
        concat!(
            "CANCEL sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 CANCEL\r\n",
        ),
        call_id = FIRST_CALL_ID,
    );
    push_body(&mut cancel, "");
    spiral.deliver(CALLER, &cancel);
    let sent = spiral.settle().await;

    to_the_caller(&sent, 200, "CANCEL");
    to_the_caller(&sent, 487, "INVITE");
    assert_eq!(call_id(&request_to(&sent, PROXY, "CANCEL")), second);
    let last = request_to(&sent, CALLEE, "CANCEL");
    assert_eq!(call_id(&last), call_id(&callee_invite));
    assert_eq!(top_via_branch(&last), top_via_branch(&callee_invite));
    // The second call answers the CANCEL it was sent and ends its INVITE.
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(200, "CANCEL")
            && call_id(&sent.message) == second),
        "the middle CANCEL was not answered 200: {:?}",
        summaries(&sent)
    );
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(487, "INVITE")
            && call_id(&sent.message) == second),
        "the returning INVITE was not ended with 487: {:?}",
        summaries(&sent)
    );

    spiral.answers(CALLEE, &last, "");
    spiral.callee_responds(&callee_invite, 487, None, "");
    spiral.settle().await;
    assert_eq!(spiral.calls(), 0, "both calls are over");
}

/// RFC 3261 §17.2.1: a retransmission, the same INVITE on the same branch, is
/// still absorbed on either pass. It opens no call and dials nothing, and gets
/// the provisional the transaction last sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_invite_is_absorbed_on_either_pass() {
    let mut spiral = Spiral::new();
    spiral.place().await;
    let returning = spiral
        .wire
        .iter()
        .find(|sent| sent.destination == address(PROXY) && sent.is_request("INVITE"))
        .map(|sent| forwarded(&sent.raw, "z9hG4bK-proxy-1", true))
        .expect("siphon dialled the proxy");

    spiral.deliver(CALLER, &spiral.caller_invite());
    let sent = spiral.settle().await;
    assert!(
        !sent.iter().any(|sent| sent.is_request("INVITE")),
        "the caller's retransmission dialled again: {:?}",
        summaries(&sent)
    );
    to_the_caller(&sent, 100, "INVITE");

    spiral.deliver(PROXY, &returning);
    let sent = spiral.settle().await;
    assert!(
        !sent.iter().any(|sent| sent.is_request("INVITE")),
        "the proxy's retransmission dialled again: {:?}",
        summaries(&sent)
    );
    assert!(
        sent.iter()
            .any(|sent| sent.destination == address(PROXY) && sent.is_response(100, "INVITE")),
        "the proxy's retransmission was not answered: {:?}",
        summaries(&sent)
    );
    assert_eq!(spiral.calls(), 2);
}

/// RFC 3261 §8.2.2.2: "If the From tag, Call-ID, and CSeq exactly match those
/// associated with an ongoing transaction, but the request does not match that
/// transaction (based on the matching rules in Section 17.2.3), the UAS core
/// SHOULD generate a 482 (Loop Detected) response". The caller's INVITE arriving
/// a second time over another path is such a merged request: not a new call,
/// and not left unanswered.
#[tokio::test(flavor = "multi_thread")]
async fn a_merged_invite_is_answered_482() {
    let mut spiral = Spiral::new();
    spiral.place().await;

    let merged = spiral
        .caller_invite()
        .replace("z9hG4bK-caller-invite", "z9hG4bK-another-path");
    spiral.deliver(CALLER, &merged);
    let sent = spiral.settle().await;

    let refusal = to_the_caller(&sent, 482, "INVITE");
    assert_eq!(top_via_branch(&refusal), "z9hG4bK-another-path");
    assert!(
        !sent.iter().any(|sent| sent.is_request("INVITE")),
        "a merged request dialled: {:?}",
        summaries(&sent)
    );
    assert_eq!(spiral.calls(), 2);
}

/// RFC 3262 §3, RFC 3311 §5.1: a reliable 183 with the answer crosses both
/// passes, each PRACK acknowledges the provisional of its own dialog, and the
/// caller's UPDATE with a new offer is answered by the callee through both.
#[tokio::test(flavor = "multi_thread")]
async fn early_prack_and_update_cross_both_passes() {
    let mut spiral = Spiral::new();
    let callee_invite = spiral.place().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));

    spiral.callee_responds(&callee_invite, 183, Some(7), ANSWER);
    let sent = spiral.settle().await;
    // Reliable on each dialog, on siphon's own numbering.
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(183, "INVITE")
            && call_id(&sent.message) == second
            && sent.message.headers.get("RSeq").is_some()),
        "no reliable 183 on the middle dialog: {:?}",
        summaries(&sent)
    );
    let progress = to_the_caller(&sent, 183, "INVITE");

    // The caller's PRACK releases the first call's PRACK, which reaches the
    // second call as its caller's and releases the one the callee is owed.
    let rack = format!("RAck: {} 1 INVITE\r\n", header(&progress, "RSeq").trim());
    spiral.caller_request("PRACK", &progress, 2, &rack, "");
    let sent = spiral.settle().await;
    to_the_caller(&sent, 200, "PRACK");
    assert_eq!(call_id(&request_to(&sent, PROXY, "PRACK")), second);
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(200, "PRACK")
            && call_id(&sent.message) == second),
        "the middle PRACK was not answered 200: {:?}",
        summaries(&sent)
    );
    let callee_prack = request_to(&sent, CALLEE, "PRACK");
    assert_eq!(call_id(&callee_prack), call_id(&callee_invite));
    spiral.answers(CALLEE, &callee_prack, "");
    spiral.settle().await;

    spiral.caller_request("UPDATE", &progress, 3, "", SECOND_OFFER);
    let sent = spiral.settle().await;
    assert_eq!(call_id(&request_to(&sent, PROXY, "UPDATE")), second);
    let callee_update = request_to(&sent, CALLEE, "UPDATE");
    assert_eq!(call_id(&callee_update), call_id(&callee_invite));
    assert!(
        !callee_update.body.is_empty(),
        "the callee's UPDATE carries the offer"
    );

    spiral.answers(CALLEE, &callee_update, SECOND_ANSWER);
    let sent = spiral.settle().await;
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(200, "UPDATE")
            && call_id(&sent.message) == second),
        "the middle UPDATE was not answered 200: {:?}",
        summaries(&sent)
    );
    let answer = to_the_caller(&sent, 200, "UPDATE");
    assert!(
        String::from_utf8_lossy(&answer.body).contains("m=audio"),
        "the caller's 200 to its UPDATE carries the callee's answer"
    );
    assert_eq!(spiral.calls(), 2);
}

/// Once answered, a request from either end crosses both calls while both are
/// up: the middle dialog's Call-ID names two calls, and the To tag of each
/// request on it names the one it is for. The caller's goes to the call that
/// answers that dialog, the callee's to the call that dialled it.
#[tokio::test(flavor = "multi_thread")]
async fn an_in_dialog_request_from_either_end_crosses_both_passes() {
    let mut spiral = Spiral::new();
    let (callee_invite, ok) = spiral.answered().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));

    spiral.caller_request(
        "INFO",
        &ok,
        2,
        "Content-Type: application/dtmf-relay\r\nContent-Length: 24\r\n\r\nSignal=5\r\nDuration=160\r\n",
        "",
    );
    let sent = spiral.settle().await;
    assert_eq!(call_id(&request_to(&sent, PROXY, "INFO")), second);
    let callee_info = request_to(&sent, CALLEE, "INFO");
    assert_eq!(call_id(&callee_info), call_id(&callee_invite));
    spiral.answers(CALLEE, &callee_info, "");
    let sent = spiral.settle().await;
    to_the_caller(&sent, 200, "INFO");

    let mut info = format!(
        concat!(
            "INFO sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.70:5060;branch=z9hG4bK-callee-info\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from};tag=callee-tag\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INFO\r\n",
            "Content-Type: application/dtmf-relay\r\n",
        ),
        from = header(&callee_invite, "To"),
        to = header(&callee_invite, "From"),
        call_id = call_id(&callee_invite),
    );
    info.push_str("Content-Length: 24\r\n\r\nSignal=7\r\nDuration=160\r\n");
    spiral.deliver(CALLEE, &info);
    let sent = spiral.settle().await;
    assert_eq!(call_id(&request_to(&sent, PROXY, "INFO")), second);
    let caller_info = request_to(&sent, CALLER, "INFO");
    assert_eq!(call_id(&caller_info), FIRST_CALL_ID);
    assert!(
        String::from_utf8_lossy(&caller_info.body).contains("Signal=7"),
        "the caller's INFO carries the callee's digit"
    );
    spiral.answers(CALLER, &caller_info, "");
    let sent = spiral.settle().await;
    assert!(
        sent.iter()
            .any(|sent| sent.destination == address(CALLEE) && sent.is_response(200, "INFO")),
        "the callee's INFO was not answered: {:?}",
        summaries(&sent)
    );
    assert_eq!(spiral.calls(), 2);
}

/// A request the callee sends on its dialog, as the callee's UAC would.
fn callee_request(callee_invite: &SipMessage, method: &str, cseq: u32, body: &str) -> String {
    let mut raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.70:5060;branch=z9hG4bK-callee-{method}-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from};tag=callee-tag\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Contact: <sip:callee@198.51.100.70:5060>\r\n",
        ),
        method = method,
        cseq = cseq,
        from = header(callee_invite, "To"),
        to = header(callee_invite, "From"),
        call_id = call_id(callee_invite),
    );
    push_body(&mut raw, body);
    raw
}

/// RFC 3261 §14: a re-INVITE from the callee crosses both calls to the caller,
/// the caller's answer crosses back, and the callee's ACK confirms it on every
/// dialog. Then the same from the caller. The re-INVITE, its 2xx and its ACK
/// each travel the middle dialog in the direction of the call they belong to.
#[tokio::test(flavor = "multi_thread")]
async fn a_reinvite_from_either_end_crosses_both_passes() {
    let mut spiral = Spiral::new();
    let (callee_invite, ok) = spiral.answered().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));

    spiral.deliver(
        CALLEE,
        &callee_request(&callee_invite, "INVITE", 1, SECOND_ANSWER),
    );
    let sent = spiral.settle().await;
    assert_eq!(call_id(&request_to(&sent, PROXY, "INVITE")), second);
    let caller_reinvite = request_to(&sent, CALLER, "INVITE");
    assert_eq!(call_id(&caller_reinvite), FIRST_CALL_ID);
    assert!(
        !sent
            .iter()
            .any(|sent| sent.destination == address(CALLEE) && sent.is_request("INVITE")),
        "the callee's re-INVITE came back to it: {:?}",
        summaries(&sent)
    );

    spiral.answers(CALLER, &caller_reinvite, SECOND_OFFER);
    let sent = spiral.settle().await;
    assert!(
        sent.iter().any(|sent| sent.destination == address(CALLEE)
            && sent.is_response(200, "INVITE")
            && !sent.message.body.is_empty()),
        "the callee's re-INVITE was not answered: {:?}",
        summaries(&sent)
    );
    // siphon ACKs each 2xx as it receives it (RFC 3261 §13.2.2.4): the
    // caller's, and through the proxy the one the first call sent the second.
    assert_eq!(call_id(&request_to(&sent, CALLER, "ACK")), FIRST_CALL_ID);
    assert_eq!(call_id(&request_to(&sent, PROXY, "ACK")), second);
    spiral.deliver(CALLEE, &callee_request(&callee_invite, "ACK", 1, ""));
    let sent = spiral.settle().await;
    assert!(
        sent.is_empty(),
        "the callee's ACK ends there: {:?}",
        summaries(&sent)
    );

    spiral.caller_request("INVITE", &ok, 2, "", SECOND_OFFER);
    let sent = spiral.settle().await;
    assert_eq!(call_id(&request_to(&sent, PROXY, "INVITE")), second);
    let callee_reinvite = request_to(&sent, CALLEE, "INVITE");
    assert_eq!(call_id(&callee_reinvite), call_id(&callee_invite));
    assert!(
        !sent
            .iter()
            .any(|sent| sent.destination == address(CALLER) && sent.is_request("INVITE")),
        "the caller's re-INVITE came back to it: {:?}",
        summaries(&sent)
    );
    spiral.answers(CALLEE, &callee_reinvite, SECOND_ANSWER);
    let sent = spiral.settle().await;
    let answer = to_the_caller(&sent, 200, "INVITE");
    assert!(
        !answer.body.is_empty(),
        "the caller's re-INVITE is answered with SDP"
    );
    assert_eq!(
        call_id(&request_to(&sent, CALLEE, "ACK")),
        call_id(&callee_invite)
    );
    assert_eq!(call_id(&request_to(&sent, PROXY, "ACK")), second);
    spiral.caller_request("ACK", &ok, 2, "", "");
    let sent = spiral.settle().await;
    assert!(
        sent.is_empty(),
        "the caller's ACK ends there: {:?}",
        summaries(&sent)
    );
    assert_eq!(spiral.calls(), 2);
}

/// RFC 3261 §8.1.1.6: a request whose Max-Forwards reaches 0 before it reaches
/// its destination is rejected with 483 Too Many Hops. An INVITE siphon dialled
/// that comes back with no hops left has looped through it, and is refused,
/// not dialled once more: the first call's leg fails on the 483 and the caller
/// hears it.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_returning_with_no_hops_left_is_refused_483() {
    let mut spiral = Spiral::new();
    // One hop for siphon's own pass and one for the proxy: 0 on return.
    spiral.deliver(CALLER, &spiral.caller_invite_with_hops(2));
    let sent = spiral.settle().await;

    let second = call_id(&request_to(&sent, PROXY, "INVITE"));
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(483, "INVITE")
            && call_id(&sent.message) == second),
        "the returning INVITE was not refused 483: {:?}",
        summaries(&sent)
    );
    assert!(
        !sent.iter().any(|sent| sent.destination == address(CALLEE)),
        "an INVITE with no hops left was dialled on: {:?}",
        summaries(&sent)
    );
    to_the_caller(&sent, 483, "INVITE");
    assert_eq!(spiral.calls(), 0, "the looping call is over");
}

/// RFC 3261 §12.2.2: a request with a To tag that matches no dialog is
/// answered 481. The first call is over and the second is not yet: a request
/// the second sends on the middle dialog comes back to the node with no dialog
/// left to arrive on. The second call does not take its own request for its
/// caller's and send it to the callee again.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_the_call_that_ended_is_answered_481() {
    let mut spiral = Spiral::new();
    let (callee_invite, _) = spiral.answered().await;
    let second = call_id(&request_to(&spiral.wire, PROXY, "INVITE"));
    let first = spiral
        .state
        .call_actors
        .find_by_sip_call_id(FIRST_CALL_ID)
        .expect("the first call is up");
    spiral.state.call_actors.remove_call(&first);

    let mut info = callee_request(&callee_invite, "INFO", 1, "");
    info = info.replace(
        "Content-Length: 0\r\n\r\n",
        "Content-Type: application/dtmf-relay\r\nContent-Length: 24\r\n\r\nSignal=7\r\nDuration=160\r\n",
    );
    spiral.deliver(CALLEE, &info);
    let sent = spiral.settle().await;

    assert_eq!(call_id(&request_to(&sent, PROXY, "INFO")), second);
    assert!(
        sent.iter().any(|sent| sent.destination == address(PROXY)
            && sent.is_response(481, "INFO")
            && call_id(&sent.message) == second),
        "the INFO for a dialog that is gone was not answered 481: {:?}",
        summaries(&sent)
    );
    assert!(
        !sent
            .iter()
            .any(|sent| sent.destination == address(CALLEE) && sent.is_request("INFO")),
        "the callee was sent its own INFO: {:?}",
        summaries(&sent)
    );
}
