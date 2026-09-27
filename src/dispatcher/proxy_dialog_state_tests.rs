//! `DialogStateChanged` for INVITEs the proxy relays.
//!
//! Driven through the dispatcher's own entry points on a test dispatcher
//! running a proxy script: requests through [`handle_request`], responses
//! through [`handle_response`], the liveness pass through
//! [`dialog_state_sweep_at`]. Phones are registered in the registrar the
//! scripting API saves into, each test with AoRs and Contacts of its own, and
//! every Call-ID, tag and probe header is checked against the message siphon
//! actually put on the UDP egress.

use std::time::{Duration, Instant};

use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::control::app_event_capture;

/// A proxy script: in-dialog requests follow their route set; an initial
/// request runs `routing`. It never calls `record_route()` — siphon adds it for
/// a tracked dialog.
fn proxy_script(routing: &str, in_dialog: &str) -> String {
    format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    if request.in_dialog:\n",
            "        {in_dialog}\n",
            "        return\n",
            "    {routing}\n",
        ),
        routing = routing,
        in_dialog = in_dialog,
    )
}

const FOLLOW_ROUTE: &str = "request.loose_route()\n        request.relay()";

fn register(aor: &str, address: &str) {
    let user = aor
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .expect("an AoR with a user part");
    let contact = parse_uri_standalone(&format!("sip:{user}@{address}")).expect("a contact URI");
    crate::script::api::test_registrar()
        .save_with_source(
            aor,
            contact,
            3600,
            1.0,
            format!("register-{aor}"),
            1,
            Some(address.parse().expect("a literal address")),
            Some(Transport::Udp),
        )
        .expect("the binding saves");
    app_event_capture::watch(aor);
}

fn unregister(aor: &str, address: &str) {
    let user = aor
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    crate::script::api::test_registrar().remove_contact(aor, &format!("sip:{user}@{address}"));
}

fn dialog_events(aor: &str) -> Vec<serde_json::Value> {
    app_event_capture::take(aor)
        .into_iter()
        .filter(|(event, _)| event == "DialogStateChanged")
        .map(|(_, payload)| payload)
        .collect()
}

fn states(events: &[serde_json::Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event["state"].as_str().expect("a state"))
        .collect()
}

/// Wait for `aor`'s next events, for what settles on a spawned task (a probe).
async fn events_within(aor: &str, wait: Duration) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + wait;
    loop {
        let events = dialog_events(aor);
        if !events.is_empty() || Instant::now() >= deadline {
            return events;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn text<'a>(payload: &'a serde_json::Value, field: &str) -> &'a str {
    payload[field]
        .as_str()
        .unwrap_or_else(|| panic!("no string `{field}` in {payload}"))
}

struct Sent {
    destination: String,
    message: SipMessage,
}

struct Proxy {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
}

/// siphon knows its own address, so `loose_route()` consumes the Route entry
/// it Record-Routed.
fn knows_itself(state: &mut DispatcherState) {
    let mut identity = crate::proxy::core::SelfIdentity::new();
    identity.add_host("192.0.2.1", &[5060]);
    state.self_identity = Arc::new(identity);
}

fn proxy(routing: &str, in_dialog: &str) -> Proxy {
    let mut dispatcher = test_dispatcher_with_script(&proxy_script(routing, in_dialog));
    knows_itself(&mut dispatcher.state);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn proxy_with(routing: &str, configure: impl FnOnce(&mut DispatcherState)) -> Proxy {
    let mut dispatcher = test_dispatcher_with_script(&proxy_script(routing, FOLLOW_ROUTE));
    knows_itself(&mut dispatcher.state);
    configure(&mut dispatcher.state);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn header(message: &SipMessage, name: &str) -> String {
    message
        .headers
        .get(name)
        .map(|value| value.to_string())
        .unwrap_or_else(|| panic!("no {name} header"))
}

fn headers(message: &SipMessage, name: &str) -> Vec<String> {
    message.headers.get_all(name).cloned().unwrap_or_default()
}

fn tag_of(value: &str) -> String {
    value
        .split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("tag="))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no tag in {value}"))
}

fn inbound(source: &str, raw: &str) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: source.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string()),
    }
}

impl Proxy {
    fn wire(&self) -> Vec<Sent> {
        let mut sent = Vec::new();
        while let Ok(outbound) = self.udp.try_recv() {
            for frame in outbound.frames() {
                sent.push(Sent {
                    destination: outbound.destination.to_string(),
                    message: parse_sip_message_bytes(frame)
                        .expect("siphon sent a message that parses"),
                });
            }
        }
        sent
    }

    fn request(&self, source: &str, raw: &str) {
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        let method = message.method().expect("a request").as_str().to_string();
        tokio::task::block_in_place(|| {
            handle_request(inbound(source, raw), message, method, &self.state)
        });
    }

    fn response(&self, source: &str, message: SipMessage) {
        let status_code = message.status_code().expect("a response");
        let raw = String::from_utf8(message.to_bytes()).expect("UTF-8");
        tokio::task::block_in_place(|| {
            handle_response(inbound(source, &raw), message, status_code, &self.state)
        });
    }

    fn sweep(&self, after: Duration) {
        tokio::task::block_in_place(|| dialog_state_sweep_at(&self.state, Instant::now() + after));
    }
}

/// The phone at `source` sends an INVITE for `to` (a URI).
fn invite(source: &str, call_id: &str, from: &str, to: &str) -> String {
    format!(
        concat!(
            "INVITE {to} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: <{to}>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 5 INVITE\r\n",
            "Contact: <sip:phone@{source}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        source = source,
        call_id = call_id,
        from = from,
        to = to,
    )
}

/// A UAS's response to the INVITE it received: the INVITE's Via stack and
/// Record-Route (RFC 3261 §8.2.6.2, §12.1.1), a tagged To, its Contact and
/// `extra` headers.
fn response_to(
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
    to_tag: &str,
    contact: &str,
    extra: &str,
) -> SipMessage {
    let mut raw = format!("SIP/2.0 {status_code} {reason}\r\n");
    for via in headers(invite, "Via") {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    for record_route in headers(invite, "Record-Route") {
        raw.push_str(&format!("Record-Route: {record_route}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag={to_tag}\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str(&format!("Contact: <{contact}>\r\n"));
    raw.push_str(extra);
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message_bytes(raw.as_bytes()).expect("the response parses")
}

/// An in-dialog request along the route set the dialog's 2xx established.
fn in_dialog(
    method: &str,
    target: &str,
    source: &str,
    from: &str,
    to: &str,
    call_id: &str,
    route: &[String],
    cseq: u32,
) -> String {
    let mut raw = format!(
        "{method} {target} SIP/2.0\r\nVia: SIP/2.0/UDP {source};branch=z9hG4bK-{method}-{cseq}-{branch}\r\nMax-Forwards: 70\r\n",
        // Unique per dialog: a retransmission is recognised by its branch.
        branch = call_id.replace(['@', '.'], "-"),
    );
    for entry in route {
        raw.push_str(&format!("Route: {entry}\r\n"));
    }
    raw.push_str(&format!(
        "From: {from}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {cseq} {method}\r\nContent-Length: 0\r\n\r\n"
    ));
    raw
}

/// The INVITEs among `sent` by destination.
fn invites_by_destination(sent: &[Sent]) -> Vec<(String, SipMessage)> {
    sent.iter()
        .filter(|sent| sent.message.method() == Some(&Method::Invite))
        .map(|sent| (sent.destination.clone(), sent.message.clone()))
        .collect()
}

fn find<'a>(sent: &'a [(String, SipMessage)], address: &str) -> &'a SipMessage {
    sent.iter()
        .find(|(destination, _)| destination == address)
        .map(|(_, message)| message)
        .unwrap_or_else(|| panic!("nothing to {address}"))
}

/// A registered phone calls a ring group of two registered phones through a
/// proxy fork. siphon Record-Routes the INVITE the script did not, each member
/// is reported ringing on its own branch, the one that answers confirmed, the
/// other terminated when siphon CANCELs it, and the callee's BYE — which comes
/// back through siphon along the route set — ends both phones' dialogs.
#[tokio::test(flavor = "multi_thread")]
async fn a_proxied_ring_group_reports_each_member_and_the_bye_ends_it() {
    let (caller_aor, caller) = ("sip:3101@example.com", "192.0.2.91:5060");
    let (first_aor, first) = ("sip:3102@example.com", "198.51.100.92:5060");
    let (second_aor, second) = ("sip:3103@example.com", "198.51.100.93:5060");
    for (aor, address) in [
        (caller_aor, caller),
        (first_aor, first),
        (second_aor, second),
    ] {
        register(aor, address);
    }
    let proxy = proxy(
        &format!("request.fork([\"sip:3102@{first}\", \"sip:3103@{second}\"])"),
        FOLLOW_ROUTE,
    );
    let call_id = "proxied-ring-group@192.0.2.91";
    proxy.request(
        caller,
        &invite(
            caller,
            call_id,
            "\"Front Desk\" <sip:3101@example.com>;tag=caller-tag",
            "sip:3100@example.com",
        ),
    );

    let sent = invites_by_destination(&proxy.wire());
    let (to_first, to_second) = (find(&sent, first).clone(), find(&sent, second).clone());
    for relayed in [&to_first, &to_second] {
        assert!(
            !headers(relayed, "Record-Route").is_empty(),
            "siphon Record-Routes a tracked INVITE the script did not"
        );
        assert!(
            headers(relayed, "Record-Route")[0].contains(";dlgw"),
            "and marks the entry as its own"
        );
    }
    let caller_events = dialog_events(caller_aor);
    assert_eq!(states(&caller_events), ["proceeding"]);
    assert_eq!(text(&caller_events[0], "direction"), "initiator");
    assert_eq!(text(&caller_events[0], "call_id"), call_id);
    assert_eq!(text(&caller_events[0], "local_tag"), "caller-tag");
    for (aor, relayed) in [(first_aor, &to_first), (second_aor, &to_second)] {
        let events = dialog_events(aor);
        assert_eq!(states(&events), ["trying"], "{aor}");
        assert_eq!(text(&events[0], "direction"), "recipient");
        assert_eq!(text(&events[0], "call_id"), header(relayed, "Call-ID"));
        assert_eq!(text(&events[0], "remote_tag"), "caller-tag");
        assert_eq!(events[0]["remote_identity"]["display_name"], "Front Desk");
    }

    proxy.response(
        first,
        response_to(
            &to_first,
            180,
            "Ringing",
            "first-tag",
            &format!("sip:3102@{first}"),
            "",
        ),
    );
    proxy.response(
        second,
        response_to(
            &to_second,
            180,
            "Ringing",
            "second-tag",
            &format!("sip:3103@{second}"),
            "",
        ),
    );
    let early = dialog_events(first_aor);
    assert_eq!(states(&early), ["early"]);
    assert_eq!(text(&early[0], "local_tag"), "first-tag");
    assert_eq!(states(&dialog_events(second_aor)), ["early"]);
    let caller_early = dialog_events(caller_aor);
    assert_eq!(
        states(&caller_early),
        ["early"],
        "one early dialog is enough to ring"
    );
    assert_eq!(text(&caller_early[0], "remote_tag"), "first-tag");
    let _ = proxy.wire();

    let answer = response_to(
        &to_second,
        200,
        "OK",
        "second-tag",
        &format!("sip:3103@{second}"),
        "",
    );
    proxy.response(second, answer.clone());
    let wire = proxy.wire();
    assert!(
        wire.iter()
            .any(|sent| sent.destination == first && sent.message.method() == Some(&Method::Cancel)),
        "the member that lost was CANCELled"
    );
    let relayed_answer = wire
        .iter()
        .find(|sent| sent.destination == caller && sent.message.status_code() == Some(200))
        .map(|sent| sent.message.clone())
        .expect("the 200 reached the caller");
    assert_eq!(states(&dialog_events(second_aor)), ["confirmed"]);
    assert_eq!(states(&dialog_events(first_aor)), ["terminated"]);
    let caller_confirmed = dialog_events(caller_aor);
    assert_eq!(states(&caller_confirmed), ["confirmed"]);
    assert_eq!(
        text(&caller_confirmed[0], "remote_tag"),
        tag_of(&header(&relayed_answer, "To")),
        "the caller's dialog is the answering member's"
    );

    // The member hangs up along its route set: siphon's Record-Route, in order.
    proxy.request(
        second,
        &in_dialog(
            "BYE",
            "sip:phone@192.0.2.91:5060",
            second,
            &format!("{};tag=second-tag", header(&to_second, "To")),
            &header(&to_second, "From"),
            call_id,
            &headers(&answer, "Record-Route"),
            1,
        ),
    );
    let after_bye = proxy.wire();
    assert!(
        after_bye
            .iter()
            .any(|sent| sent.destination == caller && sent.message.method() == Some(&Method::Bye)),
        "the BYE was relayed to the caller: {:?}",
        after_bye
            .iter()
            .map(|sent| format!(
                "{} {}",
                sent.destination,
                String::from_utf8_lossy(&sent.message.to_bytes())
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(states(&dialog_events(second_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(caller_aor)), ["terminated"]);
    assert!(proxy.state.proxy_dialogs.is_empty());
}

/// A two-phone proxied call answered, for the BYE tests below: `routing` and
/// `in_dialog` are the script's.
fn answered(
    caller: (&'static str, &'static str),
    callee: (&'static str, &'static str),
    routing: &str,
    in_dialog_policy: &str,
    call_id: &str,
) -> (Proxy, SipMessage, SipMessage) {
    register(caller.0, caller.1);
    register(callee.0, callee.1);
    let callee_user = callee
        .0
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    let caller_user = caller
        .0
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    let proxy = proxy(routing, in_dialog_policy);
    proxy.request(
        caller.1,
        &invite(
            caller.1,
            call_id,
            &format!("<sip:{caller_user}@example.com>;tag=a-tag"),
            &format!("sip:{callee_user}@{}", callee.1),
        ),
    );
    let relayed = find(&invites_by_destination(&proxy.wire()), callee.1).clone();
    let answer = response_to(
        &relayed,
        200,
        "OK",
        "b-tag",
        &format!("sip:{callee_user}@{}", callee.1),
        "",
    );
    proxy.response(callee.1, answer.clone());
    let _ = proxy.wire();
    assert_eq!(
        states(&dialog_events(caller.0)),
        ["proceeding", "confirmed"]
    );
    assert_eq!(states(&dialog_events(callee.0)), ["trying", "confirmed"]);
    (proxy, relayed, answer)
}

fn caller_bye(
    proxy: &Proxy,
    caller: &str,
    callee: &str,
    relayed: &SipMessage,
    answer: &SipMessage,
    call_id: &str,
) {
    let callee_to = header(relayed, "To");
    proxy.request(
        caller,
        &in_dialog(
            "BYE",
            &format!("sip:phone@{callee}"),
            caller,
            &header(relayed, "From"),
            &format!("{callee_to};tag=b-tag"),
            call_id,
            // The caller's route set is the 2xx Record-Route reversed.
            &headers(answer, "Record-Route")
                .into_iter()
                .rev()
                .collect::<Vec<_>>(),
            6,
        ),
    );
}

/// A script that Record-Routes itself and answers the BYE itself, rather than
/// relaying it: the dialog still ends, because siphon saw the BYE before the
/// script ran. siphon adds no Record-Route of its own on top of the script's.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_the_script_answers_itself_ends_the_dialog() {
    let (caller, callee) = (
        ("sip:3201@example.com", "192.0.2.94:5060"),
        ("sip:3202@example.com", "198.51.100.95:5060"),
    );
    let call_id = "script-bye@192.0.2.94";
    let (proxy, relayed, answer) = answered(
        caller,
        callee,
        &format!(
            "request.record_route()\n    request.relay(\"sip:3202@{}\")",
            callee.1
        ),
        "request.reply(200, \"OK\")",
        call_id,
    );
    let record_routes = headers(&relayed, "Record-Route");
    assert_eq!(record_routes.len(), 1, "the script's own, and only that");
    assert!(
        !record_routes[0].contains(";dlgw"),
        "not marked as siphon's own: {record_routes:?}"
    );

    caller_bye(&proxy, caller.1, callee.1, &relayed, &answer, call_id);
    let sent = proxy.wire();
    assert!(
        sent.iter()
            .any(|sent| sent.destination == caller.1 && sent.message.status_code() == Some(200)),
        "the script answered the BYE"
    );
    assert!(
        !sent
            .iter()
            .any(|sent| sent.message.method() == Some(&Method::Bye)),
        "and did not relay it"
    );
    assert_eq!(states(&dialog_events(caller.0)), ["terminated"]);
    assert_eq!(states(&dialog_events(callee.0)), ["terminated"]);
    assert!(proxy.state.proxy_dialogs.is_empty());
}

/// A script that never Record-Routes and cannot route an in-dialog request
/// (it answers them all 404): siphon's own Record-Route is marked as such, and
/// the BYE that follows it is routed by siphon along the route set without
/// the script, so the call behaves exactly as it did before and still ends.
#[tokio::test(flavor = "multi_thread")]
async fn siphon_routes_the_in_dialog_requests_of_a_dialog_it_record_routed_itself() {
    let (caller, callee) = (
        ("sip:3211@example.com", "192.0.2.84:5060"),
        ("sip:3212@example.com", "198.51.100.85:5060"),
    );
    let call_id = "own-route@192.0.2.84";
    let (proxy, relayed, answer) = answered(
        caller,
        callee,
        &format!("request.relay(\"sip:3212@{}\")", callee.1),
        "request.reply(404, \"Not Found\")",
        call_id,
    );
    let record_routes = headers(&relayed, "Record-Route");
    assert_eq!(record_routes.len(), 1);
    assert!(
        record_routes[0].contains(";dlgw"),
        "marked as siphon's own: {record_routes:?}"
    );

    caller_bye(&proxy, caller.1, callee.1, &relayed, &answer, call_id);
    let sent = proxy.wire();
    let bye = sent
        .iter()
        .find(|sent| sent.destination == callee.1 && sent.message.method() == Some(&Method::Bye))
        .map(|sent| sent.message.clone())
        .expect("siphon relayed the BYE to the callee");
    assert!(
        bye.headers.get("Route").is_none(),
        "its own Route entry consumed"
    );
    assert!(
        !sent
            .iter()
            .any(|sent| sent.message.status_code() == Some(404)),
        "the script never saw it"
    );
    assert_eq!(states(&dialog_events(caller.0)), ["terminated"]);
    assert_eq!(states(&dialog_events(callee.0)), ["terminated"]);
}

/// The caller CANCELs a proxied INVITE ringing a registered phone.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_proxied_invite_terminates_both_phones() {
    let (caller_aor, caller) = ("sip:3301@example.com", "192.0.2.96:5060");
    let (callee_aor, callee) = ("sip:3302@example.com", "198.51.100.97:5060");
    register(caller_aor, caller);
    register(callee_aor, callee);
    let proxy = proxy(
        &format!("request.relay(\"sip:3302@{callee}\")"),
        FOLLOW_ROUTE,
    );
    let call_id = "proxied-cancel@192.0.2.96";
    let raw = invite(
        caller,
        call_id,
        "<sip:3301@example.com>;tag=c-tag",
        &format!("sip:3302@{callee}"),
    );
    proxy.request(caller, &raw);
    let relayed = find(&invites_by_destination(&proxy.wire()), callee).clone();
    proxy.response(
        callee,
        response_to(
            &relayed,
            180,
            "Ringing",
            "d-tag",
            &format!("sip:3302@{callee}"),
            "",
        ),
    );
    assert_eq!(states(&dialog_events(caller_aor)), ["proceeding", "early"]);
    assert_eq!(states(&dialog_events(callee_aor)), ["trying", "early"]);

    let cancel = raw
        .replacen("INVITE", "CANCEL", 1)
        .replace("CSeq: 5 INVITE", "CSeq: 5 CANCEL")
        .replace(&format!("Contact: <sip:phone@{caller}>\r\n"), "");
    proxy.request(caller, &cancel);
    assert!(
        proxy.wire().iter().any(
            |sent| sent.destination == callee && sent.message.method() == Some(&Method::Cancel)
        ),
        "the CANCEL went downstream"
    );
    assert_eq!(states(&dialog_events(caller_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(callee_aor)), ["terminated"]);
    assert!(proxy.state.proxy_dialogs.is_empty());
}

/// A proxied fork branch that declines is terminated while the other rings on.
#[tokio::test(flavor = "multi_thread")]
async fn a_declining_proxied_branch_terminates_alone() {
    let (busy_aor, busy) = ("sip:3401@example.com", "198.51.100.98:5060");
    let (free_aor, free) = ("sip:3402@example.com", "198.51.100.99:5060");
    register(busy_aor, busy);
    register(free_aor, free);
    let proxy = proxy(
        &format!("request.fork([\"sip:3401@{busy}\", \"sip:3402@{free}\"])"),
        FOLLOW_ROUTE,
    );
    let call_id = "proxied-busy@192.0.2.10";
    proxy.request(
        "192.0.2.10:5060",
        &invite(
            "192.0.2.10:5060",
            call_id,
            "<sip:15550100042@example.com>;tag=o-tag",
            "sip:3400@example.com",
        ),
    );
    let sent = invites_by_destination(&proxy.wire());
    let (to_busy, to_free) = (find(&sent, busy).clone(), find(&sent, free).clone());
    proxy.response(
        busy,
        response_to(
            &to_busy,
            486,
            "Busy Here",
            "busy-tag",
            &format!("sip:3401@{busy}"),
            "",
        ),
    );
    assert_eq!(states(&dialog_events(busy_aor)), ["trying", "terminated"]);
    assert_eq!(states(&dialog_events(free_aor)), ["trying"]);
    proxy.response(
        free,
        response_to(
            &to_free,
            200,
            "OK",
            "free-tag",
            &format!("sip:3402@{free}"),
            "",
        ),
    );
    assert_eq!(states(&dialog_events(free_aor)), ["confirmed"]);
    assert!(dialog_events(busy_aor).is_empty());
}

/// Nobody registered on either side: nothing is tracked and siphon adds no
/// Record-Route the script did not ask for.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_with_no_registered_party_is_left_as_the_script_relayed_it() {
    let proxy = proxy(
        "request.relay(\"sip:15550100077@198.51.100.7:5060\")",
        FOLLOW_ROUTE,
    );
    proxy.request(
        "203.0.113.5:5060",
        &invite(
            "203.0.113.5:5060",
            "untracked@203.0.113.5",
            "<sip:15550100042@example.com>;tag=x",
            "sip:15550100077@198.51.100.7:5060",
        ),
    );
    let relayed = find(&invites_by_destination(&proxy.wire()), "198.51.100.7:5060").clone();
    assert!(headers(&relayed, "Record-Route").is_empty());
    assert!(proxy.state.proxy_dialogs.is_empty());
}

/// A confirmed proxied call between two registered phones, returned with the
/// relayed INVITE and the 2xx.
struct Confirmed {
    proxy: Proxy,
    caller_aor: &'static str,
    caller: &'static str,
    callee_aor: &'static str,
    callee: &'static str,
    relayed: SipMessage,
}

fn confirmed(
    caller_aor: &'static str,
    caller: &'static str,
    callee_aor: &'static str,
    callee: &'static str,
    extra: &str,
    configure: impl FnOnce(&mut DispatcherState),
) -> Confirmed {
    register(caller_aor, caller);
    register(callee_aor, callee);
    let callee_user = callee_aor
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    let caller_user = caller_aor
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    let proxy = proxy_with(
        &format!("request.relay(\"sip:{callee_user}@{callee}\")"),
        configure,
    );
    let call_id = format!("confirmed-{caller_user}@{caller}");
    proxy.request(
        caller,
        &invite(
            caller,
            &call_id,
            &format!("<sip:{caller_user}@example.com>;tag=caller-tag"),
            &format!("sip:{callee_user}@{callee}"),
        ),
    );
    let relayed = find(&invites_by_destination(&proxy.wire()), callee).clone();
    proxy.response(
        callee,
        response_to(
            &relayed,
            200,
            "OK",
            "callee-tag",
            &format!("sip:{callee_user}@{callee}"),
            extra,
        ),
    );
    let _ = proxy.wire();
    assert_eq!(
        states(&dialog_events(caller_aor)),
        ["proceeding", "confirmed"]
    );
    assert_eq!(states(&dialog_events(callee_aor)), ["trying", "confirmed"]);
    Confirmed {
        proxy,
        caller_aor,
        caller,
        callee_aor,
        callee,
        relayed,
    }
}

fn probing(state: &mut DispatcherState) {
    state.dialog_state_config.probe_interval_secs = 30;
    state.dialog_state_config.probe_timeout_secs = 1;
    state.dialog_state_config.probe_failures = 1;
}

/// The in-dialog OPTIONS probes each end as the other end would, along the
/// route set, reusing the CSeq it last received. A 481 ends that end's dialog
/// and only that end's; an unanswered probe ends the other.
#[tokio::test(flavor = "multi_thread")]
async fn in_dialog_probes_end_the_dialog_of_an_end_that_lost_it() {
    let call = confirmed(
        "sip:3501@example.com",
        "192.0.2.101:5060",
        "sip:3502@example.com",
        "198.51.100.102:5060",
        "",
        probing,
    );
    call.proxy.sweep(Duration::from_secs(31));
    let probes: Vec<Sent> = call
        .proxy
        .wire()
        .into_iter()
        .filter(|sent| sent.message.method() == Some(&Method::Options))
        .collect();
    assert_eq!(probes.len(), 2, "one to each end");
    let to_callee = probes
        .iter()
        .find(|sent| sent.destination == call.callee)
        .expect("callee probe");
    let to_caller = probes
        .iter()
        .find(|sent| sent.destination == call.caller)
        .expect("caller probe");
    assert_eq!(
        header(&to_callee.message, "Call-ID"),
        header(&call.relayed, "Call-ID")
    );
    assert_eq!(
        header(&to_callee.message, "CSeq"),
        "5 OPTIONS",
        "the INVITE's CSeq, not past it"
    );
    assert_eq!(tag_of(&header(&to_callee.message, "From")), "caller-tag");
    assert_eq!(tag_of(&header(&to_callee.message, "To")), "callee-tag");
    assert_eq!(
        header(&to_caller.message, "CSeq"),
        "0 OPTIONS",
        "the callee has sent nothing"
    );
    assert_eq!(tag_of(&header(&to_caller.message, "From")), "callee-tag");
    assert_eq!(tag_of(&header(&to_caller.message, "To")), "caller-tag");
    let request_uri = |message: &SipMessage| match &message.start_line {
        StartLine::Request(line) => line.request_uri.to_string(),
        StartLine::Response(_) => String::new(),
    };
    assert_eq!(
        request_uri(&to_caller.message),
        format!("sip:phone@{}", call.caller)
    );

    // The callee has lost the dialog.
    call.proxy.response(
        call.callee,
        response_to(
            &to_callee.message,
            481,
            "Call/Transaction Does Not Exist",
            "callee-tag",
            "sip:x@198.51.100.102",
            "",
        ),
    );
    let callee_events = events_within(call.callee_aor, Duration::from_secs(3)).await;
    assert_eq!(states(&callee_events), ["terminated"]);
    // The caller never answers.
    let caller_events = events_within(call.caller_aor, Duration::from_secs(4)).await;
    assert_eq!(states(&caller_events), ["terminated"]);
    assert!(call.proxy.state.proxy_dialogs.is_empty());
}

/// An answered probe keeps the dialog.
#[tokio::test(flavor = "multi_thread")]
async fn an_answered_probe_keeps_the_dialog() {
    let call = confirmed(
        "sip:3601@example.com",
        "192.0.2.103:5060",
        "sip:3602@example.com",
        "198.51.100.104:5060",
        "",
        probing,
    );
    call.proxy.sweep(Duration::from_secs(31));
    for sent in call
        .proxy
        .wire()
        .into_iter()
        .filter(|sent| sent.message.method() == Some(&Method::Options))
    {
        let destination = sent.destination.clone();
        call.proxy.response(
            &destination,
            response_to(&sent.message, 200, "OK", "t", "sip:x@192.0.2.103", ""),
        );
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(dialog_events(call.caller_aor).is_empty());
    assert!(dialog_events(call.callee_aor).is_empty());
    assert!(!call.proxy.state.proxy_dialogs.is_empty());
}

/// A negotiated session interval with no refresh ends the dialog.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_interval_that_runs_out_ends_the_proxied_dialog() {
    let call = confirmed(
        "sip:3701@example.com",
        "192.0.2.105:5060",
        "sip:3702@example.com",
        "198.51.100.106:5060",
        "Session-Expires: 90;refresher=uac\r\n",
        |_| {},
    );
    call.proxy.sweep(Duration::from_secs(100));
    assert!(
        dialog_events(call.caller_aor).is_empty(),
        "inside the grace"
    );
    call.proxy.sweep(Duration::from_secs(123));
    assert_eq!(states(&dialog_events(call.caller_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(call.callee_aor)), ["terminated"]);
}

/// A phone whose binding goes — de-registered, expired, reaped — is no longer
/// reachable through siphon: its dialog ends, the other phone's stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_binding_that_goes_ends_that_phones_proxied_dialog() {
    let call = confirmed(
        "sip:3801@example.com",
        "192.0.2.107:5060",
        "sip:3802@example.com",
        "198.51.100.108:5060",
        "",
        |_| {},
    );
    unregister(call.callee_aor, call.callee);
    call.proxy.sweep(Duration::from_secs(1));
    assert_eq!(states(&dialog_events(call.callee_aor)), ["terminated"]);
    assert!(dialog_events(call.caller_aor).is_empty());
    unregister(call.caller_aor, call.caller);
    call.proxy.sweep(Duration::from_secs(2));
    assert_eq!(states(&dialog_events(call.caller_aor)), ["terminated"]);
    assert!(call.proxy.state.proxy_dialogs.is_empty());
}

/// A proxied INVITE that rings past the bound, and a confirmed one past the
/// hard lifetime, are ended.
#[tokio::test(flavor = "multi_thread")]
async fn ringing_past_the_bound_and_the_hard_lifetime_end_proxied_dialogs() {
    let (caller_aor, caller) = ("sip:3901@example.com", "192.0.2.109:5060");
    let (callee_aor, callee) = ("sip:3902@example.com", "198.51.100.110:5060");
    register(caller_aor, caller);
    register(callee_aor, callee);
    let proxy = proxy(
        &format!("request.relay(\"sip:3902@{callee}\")"),
        FOLLOW_ROUTE,
    );
    proxy.request(
        caller,
        &invite(
            caller,
            "rings-long@192.0.2.109",
            "<sip:3901@example.com>;tag=r",
            &format!("sip:3902@{callee}"),
        ),
    );
    let _ = dialog_events(caller_aor);
    let _ = dialog_events(callee_aor);
    proxy.sweep(Duration::from_secs(301));
    assert_eq!(states(&dialog_events(caller_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(callee_aor)), ["terminated"]);

    let call = confirmed(
        "sip:3903@example.com",
        "192.0.2.111:5060",
        "sip:3904@example.com",
        "198.51.100.112:5060",
        "",
        |state| state.dialog_state_config.probe_interval_secs = 0,
    );
    call.proxy.sweep(Duration::from_secs(43_199));
    assert!(dialog_events(call.caller_aor).is_empty());
    call.proxy.sweep(Duration::from_secs(43_200));
    assert_eq!(states(&dialog_events(call.caller_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(call.callee_aor)), ["terminated"]);
}

/// Steady state: complete proxied calls leave the tracking store at its
/// baseline, whether a BYE, a probe that found the dialog gone, or a binding
/// that expired ended them.
#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_dialog_store_drains_to_baseline() {
    let (caller_aor, caller) = ("sip:4001@example.com", "192.0.2.113:5060");
    let (callee_aor, callee) = ("sip:4002@example.com", "198.51.100.114:5060");
    register(caller_aor, caller);
    register(callee_aor, callee);
    let proxy = proxy_with(&format!("request.relay(\"sip:4002@{callee}\")"), probing);
    for round in 0..12u32 {
        let call_id = format!("drain-{round}@192.0.2.113");
        proxy.request(
            caller,
            &invite(
                caller,
                &call_id,
                &format!("<sip:4001@example.com>;tag=t{round}"),
                &format!("sip:4002@{callee}"),
            ),
        );
        let relayed = find(&invites_by_destination(&proxy.wire()), callee).clone();
        let answer = response_to(
            &relayed,
            200,
            "OK",
            "callee-tag",
            &format!("sip:4002@{callee}"),
            "",
        );
        proxy.response(callee, answer.clone());
        let _ = proxy.wire();
        match round % 3 {
            0 => proxy.request(
                callee,
                &in_dialog(
                    "BYE",
                    &format!("sip:phone@{caller}"),
                    callee,
                    &format!("{};tag=callee-tag", header(&relayed, "To")),
                    &header(&relayed, "From"),
                    &call_id,
                    &headers(&answer, "Record-Route"),
                    1,
                ),
            ),
            1 => {
                proxy.sweep(Duration::from_secs(31));
                for sent in proxy
                    .wire()
                    .into_iter()
                    .filter(|sent| sent.message.method() == Some(&Method::Options))
                {
                    let destination = sent.destination.clone();
                    proxy.response(
                        &destination,
                        response_to(
                            &sent.message,
                            481,
                            "Call/Transaction Does Not Exist",
                            "t",
                            "sip:x@192.0.2.113",
                            "",
                        ),
                    );
                }
                let deadline = Instant::now() + Duration::from_secs(3);
                while !proxy.state.proxy_dialogs.is_empty() && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            _ => {
                unregister(caller_aor, caller);
                unregister(callee_aor, callee);
                proxy.sweep(Duration::from_secs(1));
                register(caller_aor, caller);
                register(callee_aor, callee);
            }
        }
        let leftover = proxy.wire();
        assert_eq!(
            proxy.state.proxy_dialogs.len(),
            0,
            "round {round}: caller {:?} callee {:?} wire {:?}",
            dialog_events(caller_aor),
            dialog_events(callee_aor),
            leftover
                .iter()
                .map(|sent| format!(
                    "{} {}",
                    sent.destination,
                    String::from_utf8_lossy(&sent.message.to_bytes())
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proxy.state.proxy_dialogs.branch_index_len(),
            0,
            "round {round}"
        );
        let _ = dialog_events(caller_aor);
        let _ = dialog_events(callee_aor);
    }
}
