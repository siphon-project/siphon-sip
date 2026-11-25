//! `@b2bua.on_info` on a bridged call, driven end to end through a script: the
//! `leg` keyword, `call.state` in the hook, and an RFC 6086 Info-Package
//! toggle (the package advertised in `Recv-Info`, an INFO of that package
//! answered locally, one of another package refused with 469, one before the
//! answer refused with 403, DTMF still relayed).

use super::lcr_ring_timeout_tests::{carrier_response, invite_to, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const CALLEE: &str = "198.51.100.7:5060";
const PACKAGE: &str = "example-package";

/// The caller's INVITE, offering the package in `Recv-Info` (RFC 6086 §5.2.3).
fn caller_invite(sip_call_id: &str) -> String {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
    );
    format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{id}-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Recv-Info: {package}\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        id = sip_call_id,
        package = PACKAGE,
        length = sdp.len(),
        sdp = sdp,
    )
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the message parses")
}

fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data)
                .expect("siphon sent a message that parses"),
        });
    }
    sent
}

fn inbound(from: &str, raw: &str) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: from.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string()),
    }
}

/// Which party sends an INFO.
#[derive(Clone, Copy)]
enum Party {
    Caller,
    Callee,
}

/// A caller's call through a dispatcher running a script, dialled to a callee.
struct Flow {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    sip_call_id: String,
    /// The INVITE siphon sent the callee.
    callee_invite: SipMessage,
    /// The callee's 200, once it has answered.
    callee_answer: Option<SipMessage>,
    /// The 200 siphon sent the caller.
    caller_answer: Option<SipMessage>,
}

impl Flow {
    fn start(sip_call_id: &str, script: &str) -> Flow {
        let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
        let state = Arc::new(state);
        let raw = caller_invite(sip_call_id);
        tokio::task::block_in_place(|| {
            handle_b2bua_invite(inbound(CALLER, &raw), parse(&raw), &state)
        });
        let callee_invite = invite_to(drain(&udp), CALLEE);
        Flow {
            state,
            udp,
            sip_call_id: sip_call_id.to_string(),
            callee_invite,
            callee_answer: None,
            caller_answer: None,
        }
    }

    fn callee_rings(&self) {
        let mut ringing = carrier_response(&self.callee_invite, 180, "Ringing");
        let handled = tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.internal_call_id(),
                &top_via_branch(&self.callee_invite),
                &mut ringing,
                180,
                CALLEE.parse().expect("a literal address"),
                &self.state,
            )
        });
        assert!(handled);
        drain(&self.udp);
    }

    fn callee_answers(&mut self) {
        let mut answer = carrier_response(&self.callee_invite, 200, "OK");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 2 2 IN IP4 198.51.100.7\r\n",
            "s=-\r\n",
            "c=IN IP4 198.51.100.7\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        );
        answer
            .headers
            .set("Contact", "<sip:callee@198.51.100.7:5060>".to_string());
        answer
            .headers
            .set("Content-Type", "application/sdp".to_string());
        answer.headers.set("Content-Length", sdp.len().to_string());
        answer.body = sdp.as_bytes().to_vec();
        let handled = tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.internal_call_id(),
                &top_via_branch(&self.callee_invite),
                &mut answer,
                200,
                CALLEE.parse().expect("a literal address"),
                &self.state,
            )
        });
        assert!(handled);
        self.caller_answer = drain(&self.udp)
            .into_iter()
            .find(|sent| {
                sent.destination == CALLER.parse().expect("a literal address")
                    && sent.message.status_code() == Some(200)
            })
            .map(|sent| sent.message);
        assert!(self.caller_answer.is_some(), "the caller is answered");
        self.callee_answer = Some(answer);
    }

    fn internal_call_id(&self) -> String {
        self.state
            .call_actors
            .find_by_sip_call_id(&self.sip_call_id)
            .expect("the call is tracked")
    }

    /// `party` sends an INFO with CSeq `cseq`, `headers` and an optional
    /// (content type, body); what siphon sent in return. Each test has its own
    /// Call-ID, so a CSeq only has to be new within a test.
    fn info(
        &self,
        party: Party,
        cseq: u32,
        headers: &[(&str, &str)],
        content: Option<(&str, &str)>,
    ) -> Vec<Sent> {
        let (from, to, call_id, address) = match party {
            Party::Caller => {
                let to = self
                    .caller_answer
                    .as_ref()
                    .and_then(|answer| answer.headers.to().cloned())
                    // Before the answer: the early dialog's tag is siphon's.
                    .unwrap_or_else(|| self.early_to_of_caller());
                (
                    "<sip:15550100001@caller.example.com>;tag=caller-tag".to_string(),
                    to,
                    self.sip_call_id.clone(),
                    CALLER,
                )
            }
            Party::Callee => {
                let answer = self
                    .callee_answer
                    .as_ref()
                    .expect("the callee has answered");
                (
                    answer.headers.to().cloned().expect("a To"),
                    self.callee_invite.headers.from().cloned().expect("a From"),
                    self.callee_invite
                        .headers
                        .call_id()
                        .cloned()
                        .expect("a Call-ID"),
                    CALLEE,
                )
            }
        };
        let mut raw = format!(
            concat!(
                "INFO sip:siphon@192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{id}-info-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} INFO\r\n",
            ),
            address = address,
            id = self.sip_call_id,
            cseq = cseq,
            from = from,
            to = to,
            call_id = call_id,
        );
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        match content {
            Some((content_type, body)) => raw.push_str(&format!(
                "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )),
            None => raw.push_str("Content-Length: 0\r\n\r\n"),
        }
        let message = parse(&raw);
        let arrived = inbound(address, &raw);
        tokio::task::block_in_place(|| handle_b2bua_info(arrived, message, &self.state));
        drain(&self.udp)
    }

    /// The To siphon gave the caller on its early dialog, with siphon's tag.
    fn early_to_of_caller(&self) -> String {
        let call = self
            .state
            .call_actors
            .get_call(&self.internal_call_id())
            .expect("the call");
        format!(
            "<sip:15550100042@siphon.example.com>;tag={}",
            call.a_leg.dialog.local_tag
        )
    }
}

/// What a handler answering with its own text reads: the status line's body.
fn answer_body(sent: &[Sent], address: &str) -> String {
    let answer = sent
        .iter()
        .find(|each| {
            each.destination == address.parse().expect("a literal address")
                && each.message.status_code().is_some()
        })
        .unwrap_or_else(|| panic!("no answer to {address}"));
    String::from_utf8_lossy(&answer.message.body).into_owned()
}

fn infos_to(sent: &[Sent], address: &str) -> usize {
    sent.iter()
        .filter(|each| {
            each.destination == address.parse().expect("a literal address")
                && each.message.method() == Some(&Method::Info)
        })
        .count()
}

/// A handler that answers every INFO 200 and writes what `expression` reads.
fn answering_with(signature: &str, expression: &str, keep_call_id: bool) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "{keep}",
            "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
            "\n",
            "@b2bua.on_info\n",
            "{signature}:\n",
            "    request.set_reply_body(str({expression}).encode(), \"text/plain\")\n",
            "    request.reply(200, \"OK\")\n",
        ),
        keep = if keep_call_id {
            "    call.keep_call_id()\n"
        } else {
            ""
        },
        signature = signature,
        expression = expression,
    )
}

// ----- call.state in the hook -----

/// An INFO on an answered call: the hook's `call.state` is `answered`, not the
/// `calling` a freshly built `Call` starts at.
#[tokio::test(flavor = "multi_thread")]
async fn on_info_sees_an_answered_call_as_answered() {
    let script = answering_with("def on_info(call, request)", "call.state", false);
    let mut flow = Flow::start("info-state-answered@192.0.2.10", &script);
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(Party::Caller, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLER), "answered");
}

/// Before the callee answers, the hook sees the call as not answered: `calling`
/// until a provisional response, `ringing` after one.
#[tokio::test(flavor = "multi_thread")]
async fn on_info_sees_an_unanswered_call_as_not_answered() {
    let script = answering_with("def on_info(call, request)", "call.state", false);
    let flow = Flow::start("info-state-early@192.0.2.10", &script);
    let sent = flow.info(Party::Caller, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLER), "calling");
    flow.callee_rings();
    let sent = flow.info(Party::Caller, 3, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLER), "ringing");
}

// ----- the leg keyword -----

#[tokio::test(flavor = "multi_thread")]
async fn on_info_is_told_which_leg_an_info_came_from() {
    let script = answering_with("def on_info(call, request, leg)", "leg", false);
    let mut flow = Flow::start("info-leg@192.0.2.10", &script);
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(Party::Caller, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLER), "caller");
    let sent = flow.info(Party::Callee, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLEE), "callee");
}

/// With `keep_call_id()` both legs carry one Call-ID, so a script comparing the
/// INFO's Call-ID to the call's cannot tell them apart; `leg` can.
#[tokio::test(flavor = "multi_thread")]
async fn leg_is_right_when_both_legs_share_a_call_id() {
    let script = answering_with("def on_info(call, request, leg)", "leg", true);
    let mut flow = Flow::start("info-leg-kept@192.0.2.10", &script);
    assert_eq!(
        flow.callee_invite
            .headers
            .call_id()
            .map(|value| value.to_string()),
        Some("info-leg-kept@192.0.2.10".to_string()),
        "keep_call_id() puts the caller's Call-ID on the B-leg"
    );
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(Party::Caller, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLER), "caller");
    // Both legs share a Call-ID, and a retransmission is told by Call-ID, CSeq
    // and branch: this one has a CSeq of its own.
    let sent = flow.info(Party::Callee, 3, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLEE), "callee");
}

/// A handler written before `leg` existed takes two arguments and still runs,
/// plain or `async`.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_argument_handler_still_runs() {
    for (name, signature) in [
        ("sync", "def on_info(call, request)"),
        ("async", "async def on_info(call, request)"),
    ] {
        let script = answering_with(signature, "'two-arguments'", false);
        let mut flow = Flow::start(&format!("info-legacy-{name}@192.0.2.10"), &script);
        flow.callee_rings();
        flow.callee_answers();
        let sent = flow.info(Party::Caller, 2, &[], Some(("text/plain", "x")));
        assert_eq!(answer_body(&sent, CALLER), "two-arguments", "{name}");
    }
}

/// An `async` handler that declares `leg` gets it too.
#[tokio::test(flavor = "multi_thread")]
async fn an_async_handler_may_declare_leg() {
    let script = answering_with("async def on_info(call, request, leg)", "leg", false);
    let mut flow = Flow::start("info-leg-async@192.0.2.10", &script);
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(Party::Callee, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLEE), "callee");
}

/// `**kwargs` takes it as well.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_with_keyword_arguments_gets_leg() {
    let script = answering_with("def on_info(call, request, **extra)", "extra['leg']", false);
    let mut flow = Flow::start("info-leg-kwargs@192.0.2.10", &script);
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(Party::Caller, 2, &[], Some(("text/plain", "x")));
    assert_eq!(answer_body(&sent, CALLER), "caller");
}

// ----- the Info-Package toggle -----

/// The routing script for the toggle: the package is advertised on the relayed
/// 200, kept off the callee's INVITE, answered locally, refused with 469 for
/// another package and with 403 before the answer. The follow-up work after the
/// 200 is a task that marks the call, so the test can see it ran.
const TOGGLE: &str = concat!(
    "import asyncio\n",
    "from siphon import b2bua\n",
    "\n",
    "PACKAGE = \"example-package\"\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.7:5060\",\n",
    "              strip=[\"Recv-Info\", \"Info-Package\"])\n",
    "\n",
    "@b2bua.on_answer\n",
    "def on_answer(call, reply):\n",
    "    reply.set_header(\"Recv-Info\", PACKAGE)\n",
    "\n",
    "async def follow_up(call, leg):\n",
    "    call.set_header(\"X-Follow-Up\", leg)\n",
    "\n",
    "@b2bua.on_info\n",
    "async def on_info(call, request, leg):\n",
    "    package = request.get_header(\"Info-Package\")\n",
    "    if package is None:\n",
    "        return\n",
    "    if call.state != \"answered\":\n",
    "        request.reply(403, \"Forbidden\")\n",
    "        return\n",
    "    if package != PACKAGE:\n",
    "        request.set_reply_header(\"Recv-Info\", PACKAGE)\n",
    "        request.reply(469, \"Bad Info Package\")\n",
    "        return\n",
    "    request.reply(200, \"OK\")\n",
    "    asyncio.create_task(follow_up(call, leg))\n",
);

const PACKAGE_INFO: &[(&str, &str)] = &[
    ("Info-Package", PACKAGE),
    ("Content-Disposition", "Info-Package"),
];

fn toggle(sip_call_id: &str) -> Flow {
    Flow::start(sip_call_id, TOGGLE)
}

/// The package reaches the caller in the relayed 200 and never the callee's
/// INVITE, though the caller offered it and the presets pass it through.
#[tokio::test(flavor = "multi_thread")]
async fn the_package_is_advertised_to_the_caller_and_not_to_the_callee() {
    let mut flow = toggle("toggle-advert@192.0.2.10");
    assert_eq!(flow.callee_invite.headers.get("Recv-Info"), None);
    flow.callee_rings();
    flow.callee_answers();
    let answer = flow.caller_answer.expect("the caller's 200");
    assert_eq!(
        answer.headers.get("Recv-Info").map(String::as_str),
        Some(PACKAGE)
    );
}

/// An INFO of the package is answered here and not relayed.
#[tokio::test(flavor = "multi_thread")]
async fn an_info_of_the_package_is_answered_locally_and_not_relayed() {
    let mut flow = toggle("toggle-local@192.0.2.10");
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(
        Party::Caller,
        2,
        PACKAGE_INFO,
        Some(("application/example+json", "{}")),
    );
    let answers: Vec<_> = sent
        .iter()
        .filter(|each| each.message.status_code().is_some())
        .collect();
    assert_eq!(answers.len(), 1, "one answer");
    assert_eq!(answers[0].message.status_code(), Some(200));
    assert_eq!(infos_to(&sent, CALLEE), 0, "nothing relayed to the callee");
}

/// A package the script did not advertise is a 469 listing what is accepted
/// (RFC 6086 §4.2.2), and is not relayed.
#[tokio::test(flavor = "multi_thread")]
async fn an_unadvertised_package_is_a_469_with_the_accepted_list() {
    let mut flow = toggle("toggle-469@192.0.2.10");
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(
        Party::Caller,
        2,
        &[("Info-Package", "other-package")],
        Some(("application/example+json", "{}")),
    );
    let answer = sent
        .iter()
        .find(|each| each.message.status_code().is_some())
        .expect("an answer");
    assert_eq!(answer.message.status_code(), Some(469));
    assert_eq!(
        answer.message.headers.get("Recv-Info").map(String::as_str),
        Some(PACKAGE)
    );
    assert_eq!(infos_to(&sent, CALLEE), 0);
}

/// A 469 that lists no package (siphon advertised none to that leg) carries an
/// empty `Recv-Info`, which RFC 6086 allows (section 5.2.2): the header is on
/// the wire and empty, not dropped.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_recv_info_reaches_the_wire_as_an_empty_header() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
        "\n",
        "@b2bua.on_info\n",
        "def on_info(call, request):\n",
        "    request.set_reply_header(\"Recv-Info\", \"\")\n",
        "    request.reply(469, \"Bad Info Package\")\n",
    );
    let mut flow = Flow::start("toggle-empty@192.0.2.10", script);
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(Party::Caller, 2, PACKAGE_INFO, None);
    let answer = sent
        .iter()
        .find(|each| each.message.status_code().is_some())
        .expect("an answer");
    assert_eq!(answer.message.status_code(), Some(469));
    assert_eq!(
        answer.message.headers.get("Recv-Info").map(String::as_str),
        Some("")
    );
}

/// Before the answer the script refuses with 403, using `call.state`.
#[tokio::test(flavor = "multi_thread")]
async fn a_package_info_before_the_answer_is_a_403() {
    let flow = toggle("toggle-403@192.0.2.10");
    flow.callee_rings();
    let sent = flow.info(
        Party::Caller,
        2,
        PACKAGE_INFO,
        Some(("application/example+json", "{}")),
    );
    let answer = sent
        .iter()
        .find(|each| each.message.status_code().is_some())
        .expect("an answer");
    assert_eq!(answer.message.status_code(), Some(403));
}

/// DTMF in an INFO has no package: the handler leaves it, and it is relayed.
#[tokio::test(flavor = "multi_thread")]
async fn a_dtmf_info_is_still_relayed() {
    let mut flow = toggle("toggle-dtmf@192.0.2.10");
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(
        Party::Caller,
        2,
        &[],
        Some(("application/dtmf-relay", "Signal=5\r\nDuration=160\r\n")),
    );
    assert_eq!(infos_to(&sent, CALLEE), 1, "relayed to the callee");
    assert!(
        sent.iter().all(|each| each.message.status_code().is_none()),
        "no local answer"
    );
}

/// Poll `read` until it has a value, as the async driver runs the task on its
/// own thread. A plain sleep on a blocking-safe thread: the guard on the shared
/// pool is a std mutex and is held for the whole test.
fn eventually<T>(mut read: impl FnMut() -> Option<T>) -> Option<T> {
    tokio::task::block_in_place(|| {
        for _ in 0..200 {
            if let Some(value) = read() {
                return Some(value);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    })
}

fn header_on_call(flow: &Flow, name: &str) -> Option<String> {
    let call = flow.internal_call_id();
    flow.state
        .call_actors
        .get_call(&call)
        .and_then(|actor| actor.a_leg_invite.clone())
        .and_then(|invite| {
            invite
                .lock()
                .ok()
                .and_then(|message| message.headers.get(name).cloned())
        })
}

/// A handler with no `await` that replies and starts a task goes the driver
/// way (the inline path has no event loop): the reply goes out and the task
/// runs, under the real driver pool.
#[tokio::test(flavor = "multi_thread")]
async fn follow_up_work_started_after_the_reply_runs() {
    let _serial = crate::script::async_pool::pool_test_guard();
    crate::script::async_pool::ensure_test_pools();
    let mut flow = toggle("toggle-task@192.0.2.10");
    flow.callee_rings();
    flow.callee_answers();
    let sent = flow.info(
        Party::Caller,
        2,
        PACKAGE_INFO,
        Some(("application/example+json", "{}")),
    );
    let answer = sent
        .iter()
        .find(|each| each.message.status_code().is_some())
        .expect("the reply goes out");
    assert_eq!(answer.message.status_code(), Some(200));
    let marked = eventually(|| header_on_call(&flow, "X-Follow-Up"));
    assert_eq!(marked.as_deref(), Some("caller"), "the task ran");
}

/// The whole loop from a script: a package INFO is answered, a task sends the
/// state INFO to the party that asked with `b2bua.send_info`, that party
/// answers it, and the task reads the status back.
#[tokio::test(flavor = "multi_thread")]
async fn a_task_sends_the_state_info_and_reads_the_status() {
    let _serial = crate::script::async_pool::pool_test_guard();
    crate::script::async_pool::ensure_test_pools();
    let script = TOGGLE.replace(
        "async def follow_up(call, leg):\n    call.set_header(\"X-Follow-Up\", leg)\n",
        concat!(
            "async def follow_up(call, leg):\n",
            "    status = await b2bua.send_info(\n",
            "        call.call_id, b\"{}\", \"application/example+json\",\n",
            "        headers={\"Info-Package\": PACKAGE, \"Content-Disposition\": \"Info-Package\"},\n",
            "        leg=leg)\n",
            "    call.set_header(\"X-Push-Status\", str(status))\n",
        ),
    );
    assert_ne!(script, TOGGLE, "the follow-up is replaced");
    // What `b2bua.send_info()` reaches the dispatcher through goes in before
    // the script engine is built, which is when it is injected.
    pyo3::Python::attach(crate::script::api::set_b2bua_control_singleton)
        .expect("the script reaches the dispatcher");
    let mut flow = Flow::start("toggle-push@192.0.2.10", &script);
    register_test_control(&flow.sip_call_id, Arc::clone(&flow.state));
    flow.callee_rings();
    flow.callee_answers();
    // The task may send its INFO before `info` has read the wire back, so what
    // that read returned is searched too.
    let mut seen = flow.info(
        Party::Caller,
        2,
        PACKAGE_INFO,
        Some(("application/example+json", "{}")),
    );
    let pushed = eventually(|| {
        seen.extend(drain(&flow.udp));
        seen.iter()
            .position(|each| each.message.method() == Some(&Method::Info))
            .map(|index| seen.remove(index))
    })
    .expect("the task sends the INFO");
    assert_eq!(pushed.destination, CALLER.parse().expect("an address"));
    assert_eq!(
        pushed
            .message
            .headers
            .get("Info-Package")
            .map(String::as_str),
        Some(PACKAGE)
    );
    let reply = parse(&format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n\r\n",
        ),
        via = pushed.message.headers.get("Via").expect("Via"),
        from = pushed.message.headers.from().expect("From"),
        to = pushed.message.headers.to().expect("To"),
        call_id = flow.sip_call_id,
        cseq = pushed.message.headers.get("CSeq").expect("CSeq"),
    ));
    assert!(take_sent_info_response(&reply, 200));
    let status = eventually(|| header_on_call(&flow, "X-Push-Status"));
    assert_eq!(status.as_deref(), Some("200"));
}

/// The package INFO a script sends from a task is in the caller's dialog with
/// the package's headers, and the caller's response status comes back.
#[tokio::test(flavor = "multi_thread")]
async fn a_package_info_sent_to_the_caller_returns_its_status() {
    let mut flow = toggle("toggle-send@192.0.2.10");
    flow.callee_rings();
    flow.callee_answers();
    let internal = flow.internal_call_id();
    let mut sent = send_info_on_leg(
        &flow.state,
        &internal,
        true,
        Some("application/example+json"),
        b"{}".to_vec(),
        &[
            ("Info-Package".to_string(), PACKAGE.to_string()),
            (
                "Content-Disposition".to_string(),
                "Info-Package".to_string(),
            ),
        ],
    )
    .expect("sent");
    let wire = drain(&flow.udp);
    let info = wire
        .iter()
        .find(|each| each.message.method() == Some(&Method::Info))
        .expect("an INFO on the wire");
    assert_eq!(info.destination, CALLER.parse().expect("an address"));
    assert_eq!(
        info.message.headers.get("Info-Package").map(String::as_str),
        Some(PACKAGE)
    );
    assert_eq!(
        info.message
            .headers
            .get("Content-Disposition")
            .map(String::as_str),
        Some("Info-Package")
    );
    let reply = parse(&format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n\r\n",
        ),
        via = info.message.headers.get("Via").expect("Via"),
        from = info.message.headers.from().expect("From"),
        to = info.message.headers.to().expect("To"),
        call_id = flow.sip_call_id,
        cseq = info.message.headers.get("CSeq").expect("CSeq"),
    ));
    assert!(take_sent_info_response(&reply, 200));
    assert_eq!(sent.response.try_recv().expect("answered").status, 200);
}

/// The `Call` the hooks on an existing call share is built from the call's
/// actor: its state is the actor's, whatever stage the call is at.
#[tokio::test(flavor = "multi_thread")]
async fn the_call_a_hook_is_shown_carries_the_actors_state() {
    use crate::b2bua::actor::CallState;
    let flow = toggle("toggle-built@192.0.2.10");
    let internal = flow.internal_call_id();
    for (state, name) in [
        (CallState::Calling, "calling"),
        (CallState::Ringing, "ringing"),
        (CallState::Answered, "answered"),
        (CallState::Terminated, "terminated"),
    ] {
        flow.state.call_actors.set_state(&internal, state);
        let built = py_call_for(&internal, None, &flow.state).expect("the call is tracked");
        let read = pyo3::Python::attach(|python| {
            pyo3::Py::new(python, built)
                .and_then(|object| object.bind(python).getattr("state")?.extract::<String>())
        })
        .expect("the state reads back");
        assert_eq!(read, name);
    }
}
