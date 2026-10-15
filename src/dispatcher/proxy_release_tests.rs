//! `proxy.release`: a proxy ending a session it Record-Routed (TS 24.229
//! §5.2.8.1), driven through the dispatcher's own entry points on a proxy
//! script that Record-Routes, with every BYE, CANCEL and response checked
//! against what siphon put on the UDP egress.

use std::time::{Duration, Instant};

use super::proxy_dialog_state_tests::{header, headers, knows_itself, Proxy, Sent};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::proxy::dialog_state::{Hop, ReleaseBye, Toward};

const CALLER: &str = "192.0.2.91:5060";
const EDGE: &str = "192.0.2.50:5060";
const NEXT_HOP: &str = "198.51.100.20:5060";
const CALLEE_CONTACT: &str = "sip:bob@203.0.113.5:5060";
const REASON: &str = "SIP;cause=503;text=\"Bearer released\"";

/// A proxy script that Record-Routes every initial request and relays it to
/// `target`, and routes in-dialog requests along their route set.
/// `@proxy.on_cancel` records each run on `sys.<runs>`.
fn script(target: &str, runs: &str) -> String {
    format!(
        concat!(
            "import sys\n",
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    if request.in_dialog:\n",
            "        request.loose_route()\n",
            "        request.relay()\n",
            "        return\n",
            "    request.record_route()\n",
            "    request.relay(\"{target}\")\n",
            "\n",
            "@proxy.on_cancel\n",
            "def cancelled(request):\n",
            "    sys.{runs} = getattr(sys, \"{runs}\", 0) + 1\n",
        ),
        target = target,
        runs = runs,
    )
}

fn releasing_proxy(source: &str) -> Proxy {
    let mut dispatcher = test_dispatcher_with_script(source);
    knows_itself(&mut dispatcher.state);
    dispatcher.state.proxy_release = true;
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn on_cancel_runs(runs: &str) -> i64 {
    Python::attach(|python| {
        python
            .import("sys")
            .and_then(|sys| sys.getattr(runs))
            .and_then(|count| count.extract::<i64>())
            .unwrap_or(0)
    })
}

fn tag_of(value: &str) -> String {
    value
        .split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("tag="))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no tag in {value}"))
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the message parses")
}

/// The caller's INVITE, reaching siphon through an edge proxy that
/// Record-Routed it.
fn caller_invite(call_id: &str) -> String {
    format!(
        concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {edge};branch=z9hG4bK-edge-{call_id}\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-phone-{call_id}\r\n",
            "Record-Route: <sip:{edge};lr>\r\n",
            "Max-Forwards: 69\r\n",
            "From: <sip:alice@example.com>;tag=caller-tag\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 5 INVITE\r\n",
            "Contact: <sip:alice@{caller}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        edge = EDGE,
        caller = CALLER,
        call_id = call_id,
    )
}

/// The callee's response to `invite` as it reaches siphon: the next hop
/// Record-Routed it too, so the 2xx carries that entry above siphon's.
fn callee_response(invite: &SipMessage, status: u16, reason: &str) -> SipMessage {
    let mut raw = format!("SIP/2.0 {status} {reason}\r\n");
    for via in headers(invite, "Via") {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("Record-Route: <sip:{NEXT_HOP};lr>\r\n"));
    for record_route in headers(invite, "Record-Route") {
        raw.push_str(&format!("Record-Route: {record_route}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag=callee-tag\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str(&format!("Contact: <{CALLEE_CONTACT}>\r\n"));
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse(&raw)
}

/// A response to `request` as its peer would send it.
fn answer(request: &SipMessage, status: u16, reason: &str) -> SipMessage {
    let mut raw = format!("SIP/2.0 {status} {reason}\r\n");
    for via in headers(request, "Via") {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    for name in ["From", "To", "Call-ID", "CSeq"] {
        raw.push_str(&format!("{name}: {}\r\n", header(request, name)));
    }
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse(&raw)
}

fn requests(sent: &[Sent], method: Method) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.message.method() == Some(&method))
        .collect()
}

fn responses(sent: &[Sent], status: u16) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.message.status_code() == Some(status))
        .collect()
}

/// A confirmed call through siphon: INVITE, 200, ACK, and one in-dialog INFO
/// each way (CSeq 6 from the caller, 100 from the callee). Returns the 200 as
/// the caller got it and siphon's Record-Route entry.
struct Established {
    answer_to_caller: SipMessage,
    own_record_route: String,
}

fn establish(proxy: &Proxy, call_id: &str) -> Established {
    proxy.request(EDGE, &caller_invite(call_id));
    let wire = proxy.wire();
    let relayed = requests(&wire, Method::Invite)
        .into_iter()
        .find(|sent| sent.destination == NEXT_HOP)
        .map(|sent| sent.message.clone())
        .expect("the INVITE was relayed to the next hop");
    let own_record_route = headers(&relayed, "Record-Route")[0].clone();

    proxy.response(NEXT_HOP, callee_response(&relayed, 200, "OK"));
    let answer_to_caller = proxy
        .wire()
        .into_iter()
        .find(|sent| sent.destination == EDGE && sent.message.status_code() == Some(200))
        .map(|sent| sent.message)
        .expect("the 200 reached the caller's side");

    let to = header(&answer_to_caller, "To");
    let from = header(&answer_to_caller, "From");
    let caller_route = vec![own_record_route.clone(), format!("<sip:{NEXT_HOP};lr>")];
    let callee_route = vec![own_record_route.clone(), format!("<sip:{EDGE};lr>")];
    for (method, cseq) in [("ACK", 5), ("INFO", 6)] {
        proxy.request(
            EDGE,
            &super::proxy_dialog_state_tests::in_dialog(
                method,
                CALLEE_CONTACT,
                EDGE,
                &from,
                &to,
                call_id,
                &caller_route,
                cseq,
            ),
        );
    }
    proxy.request(
        NEXT_HOP,
        &super::proxy_dialog_state_tests::in_dialog(
            "INFO",
            &format!("sip:alice@{CALLER}"),
            NEXT_HOP,
            &to,
            &from,
            call_id,
            &callee_route,
            100,
        ),
    );
    let relayed_infos = proxy.wire();
    assert_eq!(
        requests(&relayed_infos, Method::Info).len(),
        2,
        "both INFOs crossed siphon"
    );
    Established {
        answer_to_caller,
        own_record_route,
    }
}

fn release(proxy: &Proxy, call_id: &str, toward: Toward) -> bool {
    tokio::task::block_in_place(|| proxy_release(&proxy.state, call_id, Some(REASON), toward, 487))
}

/// Wait until the store has let every released dialog go.
async fn drained(proxy: &Proxy) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if proxy.state.proxy_dialogs.is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// TS 24.229 §5.2.8.1.2: one BYE toward each end, built from the dialog
/// siphon stored: the Request-URI from that end's Contact, the dialog's tags
/// and Call-ID, the CSeq one above the last one seen in that direction, the
/// route set toward that end, and the script's Reason (RFC 3326).
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmed_dialog_gets_one_bye_toward_each_end_from_its_stored_state() {
    let call_id = "release-confirmed@192.0.2.91";
    let proxy = releasable(call_id);
    let established = establish(&proxy, call_id);
    let caller_from = "<sip:alice@example.com>;tag=caller-tag".to_string();
    let callee_to = header(&established.answer_to_caller, "To");
    assert_eq!(tag_of(&callee_to), "callee-tag");

    assert!(release(&proxy, call_id, Toward::Both));
    let wire = proxy.wire();
    let byes = requests(&wire, Method::Bye);
    assert_eq!(byes.len(), 2, "exactly one BYE to each end");

    let to_caller = byes
        .iter()
        .find(|sent| sent.destination == EDGE)
        .expect("a BYE toward the caller, through the proxy that Record-Routed it");
    assert_eq!(
        to_caller.message.request_uri().map(|uri| uri.to_string()),
        Some(format!("sip:alice@{CALLER}")),
        "Request-URI from the caller's Contact"
    );
    assert_eq!(
        headers(&to_caller.message, "Route"),
        [format!("<sip:{EDGE};lr>")]
    );
    assert_eq!(header(&to_caller.message, "From"), callee_to);
    assert_eq!(header(&to_caller.message, "To"), caller_from);
    assert_eq!(header(&to_caller.message, "Call-ID"), call_id);
    assert_eq!(
        header(&to_caller.message, "CSeq"),
        "101 BYE",
        "one above the callee's last"
    );
    assert_eq!(header(&to_caller.message, "Reason"), REASON);

    let to_callee = byes
        .iter()
        .find(|sent| sent.destination == NEXT_HOP)
        .expect("a BYE toward the callee, through its route set");
    assert_eq!(
        to_callee.message.request_uri().map(|uri| uri.to_string()),
        Some(CALLEE_CONTACT.to_string())
    );
    assert_eq!(
        headers(&to_callee.message, "Route"),
        [format!("<sip:{NEXT_HOP};lr>")],
        "the route set toward the callee, without siphon's own entry"
    );
    assert_eq!(header(&to_callee.message, "From"), caller_from);
    assert_eq!(header(&to_callee.message, "To"), callee_to);
    assert_eq!(
        header(&to_callee.message, "CSeq"),
        "7 BYE",
        "one above the caller's last"
    );
    assert_eq!(header(&to_callee.message, "Reason"), REASON);
    assert!(
        !headers(&to_callee.message, "Route").contains(&established.own_record_route),
        "siphon does not route the BYE to itself"
    );

    // Released once: the Call-ID names nothing to end any more.
    assert!(!release(&proxy, call_id, Toward::Both));
    assert!(proxy.wire().is_empty());

    for bye in [to_caller, to_callee] {
        proxy.response(&bye.destination, answer(&bye.message, 200, "OK"));
    }
    assert!(
        drained(&proxy).await,
        "the dialog is forgotten once both BYEs are answered"
    );
}

fn releasable(call_id: &str) -> Proxy {
    let runs = format!(
        "runs_{}",
        call_id
            .split('@')
            .next()
            .unwrap_or_default()
            .replace('-', "_")
    );
    releasing_proxy(&script(&format!("sip:bob@{NEXT_HOP}"), &runs))
}

/// TS 24.229 §5.2.8.1.2 has a P-CSCF that lost the bearer of the user it
/// serves send its BYE toward the other user only.
#[tokio::test(flavor = "multi_thread")]
async fn toward_one_end_sends_that_end_its_bye_only() {
    let call_id = "release-one-end@192.0.2.91";
    let proxy = releasable(call_id);
    establish(&proxy, call_id);
    assert!(release(&proxy, call_id, Toward::Callee));
    let wire = proxy.wire();
    let byes = requests(&wire, Method::Bye);
    assert_eq!(byes.len(), 1);
    assert_eq!(byes[0].destination, NEXT_HOP);
    proxy.response(NEXT_HOP, answer(&byes[0].message, 200, "OK"));
    assert!(drained(&proxy).await);
}

/// An unknown Call-ID is `false` and puts nothing on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_call_id_is_false_and_sends_nothing() {
    let proxy = releasable("release-unknown@192.0.2.91");
    assert!(!release(&proxy, "nobody@192.0.2.91", Toward::Both));
    assert!(proxy.wire().is_empty());
}

/// Without `dialog.proxy_release` no dialog is kept, so there is nothing to
/// release, and a Record-Routed call leaves nothing behind in the store.
#[tokio::test(flavor = "multi_thread")]
async fn without_proxy_release_nothing_is_kept() {
    let call_id = "release-off@192.0.2.91";
    let mut dispatcher =
        test_dispatcher_with_script(&script(&format!("sip:bob@{NEXT_HOP}"), "runs_off"));
    knows_itself(&mut dispatcher.state);
    let proxy = Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    };
    proxy.request(EDGE, &caller_invite(call_id));
    assert!(proxy.state.proxy_dialogs.is_empty());
    assert!(!release(&proxy, call_id, Toward::Both));
}

/// TS 24.229 §5.2.8.1.1: a session still being established has its branch
/// CANCELled (with the Reason) and the caller answered; `@proxy.on_cancel`
/// runs once, and the branch's 487 is not forwarded as a second final.
#[tokio::test(flavor = "multi_thread")]
async fn a_ringing_session_is_cancelled_downstream_and_answered_upstream() {
    let call_id = "release-ringing@192.0.2.91";
    let runs = "runs_release_ringing";
    let proxy = releasing_proxy(&script(&format!("sip:bob@{NEXT_HOP}"), runs));
    proxy.request(EDGE, &caller_invite(call_id));
    let relayed = requests(&proxy.wire(), Method::Invite)
        .first()
        .map(|sent| sent.message.clone())
        .expect("the INVITE was relayed");
    proxy.response(NEXT_HOP, callee_response(&relayed, 180, "Ringing"));
    let _ = proxy.wire();

    assert!(release(&proxy, call_id, Toward::Both));
    let wire = proxy.wire();
    let cancels = requests(&wire, Method::Cancel);
    assert_eq!(cancels.len(), 1, "the ringing branch is CANCELled");
    assert_eq!(cancels[0].destination, NEXT_HOP);
    assert_eq!(header(&cancels[0].message, "Reason"), REASON);
    let finals = responses(&wire, 487);
    assert_eq!(finals.len(), 1, "the caller is answered");
    assert_eq!(finals[0].destination, EDGE);
    assert_eq!(on_cancel_runs(runs), 1, "@proxy.on_cancel runs once");

    // The branch answers its CANCEL and its INVITE: neither reaches the caller.
    proxy.response(NEXT_HOP, answer(&cancels[0].message, 200, "OK"));
    proxy.response(
        NEXT_HOP,
        callee_response(&relayed, 487, "Request Terminated"),
    );
    let after = proxy.wire();
    assert!(
        after
            .iter()
            .all(|sent| sent.destination != EDGE || sent.message.status_code() != Some(487)),
        "one final response upstream"
    );
    assert!(!release(&proxy, call_id, Toward::Both), "released once");
    assert_eq!(on_cancel_runs(runs), 1);
    assert!(drained(&proxy).await);
}

/// TS 24.229 §5.2.8.1.3: a request on the released dialog is answered 481 —
/// here the far end's own BYE crossing siphon's — while the release's own BYE
/// coming back through siphon (a spiral) is routed on.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_on_a_released_dialog_is_answered_481() {
    let call_id = "release-crossing@192.0.2.91";
    let proxy = releasable(call_id);
    let established = establish(&proxy, call_id);
    assert!(release(&proxy, call_id, Toward::Both));
    let byes: Vec<SipMessage> = requests(&proxy.wire(), Method::Bye)
        .into_iter()
        .map(|sent| sent.message.clone())
        .collect();

    let to = header(&established.answer_to_caller, "To");
    let from = header(&established.answer_to_caller, "From");
    let crossing = super::proxy_dialog_state_tests::in_dialog(
        "BYE",
        &format!("sip:alice@{CALLER}"),
        NEXT_HOP,
        &to,
        &from,
        call_id,
        &[
            established.own_record_route.clone(),
            format!("<sip:{EDGE};lr>"),
        ],
        101,
    );
    proxy.request(NEXT_HOP, &crossing);
    let wire = proxy.wire();
    assert_eq!(
        responses(&wire, 481).len(),
        1,
        "the crossing BYE is answered 481"
    );
    assert!(
        requests(&wire, Method::Bye).is_empty(),
        "and not relayed to the caller"
    );

    // siphon's BYE toward the callee, back at siphon on another leg: its Via is
    // under the next hop's.
    let to_callee = byes
        .iter()
        .find(|bye| {
            bye.request_uri().map(|uri| uri.to_string()) == Some(CALLEE_CONTACT.to_string())
        })
        .expect("the BYE toward the callee");
    let mut raw = format!("BYE {CALLEE_CONTACT} SIP/2.0\r\n");
    raw.push_str(&format!(
        "Via: SIP/2.0/UDP {NEXT_HOP};branch=z9hG4bK-spiral-{call_id}\r\n"
    ));
    for via in headers(to_callee, "Via") {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("Route: {}\r\n", established.own_record_route));
    for name in ["From", "To", "Call-ID", "CSeq", "Reason"] {
        raw.push_str(&format!("{name}: {}\r\n", header(to_callee, name)));
    }
    raw.push_str("Max-Forwards: 69\r\nContent-Length: 0\r\n\r\n");
    proxy.request(NEXT_HOP, &raw);
    let wire = proxy.wire();
    assert!(
        responses(&wire, 481).is_empty(),
        "siphon's own BYE is not refused"
    );
    assert_eq!(requests(&wire, Method::Bye).len(), 1, "it is routed on");
}

/// The on-net case: one proxy on both legs of one Call-ID. The INVITE leaves
/// toward the core and spirals back to siphon, which relays it to the callee.
/// The release is the first leg's: a BYE to the caller and a BYE into the
/// core along that leg's route set, which brings it back through siphon to
/// the callee. Nothing goes to the callee directly.
#[tokio::test(flavor = "multi_thread")]
async fn an_on_net_spiral_is_released_from_its_first_leg() {
    const CORE: &str = "198.51.100.40:5060";
    const CALLEE: &str = "203.0.113.7:5060";
    let call_id = "release-spiral@192.0.2.91";
    let source = concat!(
        "from siphon import proxy\n",
        "\n",
        "@proxy.on_request\n",
        "def route(request):\n",
        "    if request.in_dialog:\n",
        "        request.loose_route()\n",
        "        request.relay()\n",
        "        return\n",
        "    request.record_route()\n",
        "    if request.source_ip == \"198.51.100.40\":\n",
        "        request.relay(\"sip:bob@203.0.113.7:5060\")\n",
        "    else:\n",
        "        request.relay(\"sip:core@198.51.100.40:5060\")\n",
    );
    let proxy = releasing_proxy(source);
    proxy.request(EDGE, &caller_invite(call_id));
    let first_leg = requests(&proxy.wire(), Method::Invite)
        .first()
        .map(|sent| sent.message.clone())
        .expect("the first leg's INVITE");
    let first_record_route = headers(&first_leg, "Record-Route")[0].clone();

    // The core sends it back, with its own Via and Record-Route on top.
    let mut raw = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
    raw.push_str(&format!(
        "Via: SIP/2.0/UDP {CORE};branch=z9hG4bK-core-{call_id}\r\n"
    ));
    for via in headers(&first_leg, "Via") {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("Record-Route: <sip:{CORE};lr>\r\n"));
    for record_route in headers(&first_leg, "Record-Route") {
        raw.push_str(&format!("Record-Route: {record_route}\r\n"));
    }
    for name in ["From", "To", "Call-ID", "CSeq", "Contact"] {
        raw.push_str(&format!("{name}: {}\r\n", header(&first_leg, name)));
    }
    raw.push_str("Max-Forwards: 67\r\nContent-Length: 0\r\n\r\n");
    proxy.request(CORE, &raw);
    let second_leg = requests(&proxy.wire(), Method::Invite)
        .into_iter()
        .find(|sent| sent.destination == CALLEE)
        .map(|sent| sent.message.clone())
        .expect("the second leg's INVITE");

    // The callee answers; the 2xx goes up the second leg, through the core,
    // and back down the first.
    let mut raw = String::from("SIP/2.0 200 OK\r\n");
    for via in headers(&second_leg, "Via") {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    for record_route in headers(&second_leg, "Record-Route") {
        raw.push_str(&format!("Record-Route: {record_route}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(&second_leg, "From")));
    raw.push_str(&format!(
        "To: {};tag=callee-tag\r\n",
        header(&second_leg, "To")
    ));
    for name in ["Call-ID", "CSeq"] {
        raw.push_str(&format!("{name}: {}\r\n", header(&second_leg, name)));
    }
    raw.push_str(&format!(
        "Contact: <sip:bob@{CALLEE}>\r\nContent-Length: 0\r\n\r\n"
    ));
    let answer_on_second = parse(&raw);
    proxy.response(CALLEE, answer_on_second.clone());
    let up_to_core = proxy
        .wire()
        .into_iter()
        .find(|sent| sent.destination == CORE && sent.message.status_code() == Some(200))
        .map(|sent| sent.message)
        .expect("the 200 went up to the core");
    let mut answer_on_first = up_to_core.clone();
    answer_on_first.headers.remove("Via");
    let vias: Vec<String> = headers(&up_to_core, "Via").into_iter().skip(1).collect();
    for via in vias {
        answer_on_first.headers.add("Via", via);
    }
    proxy.response(CORE, answer_on_first);
    assert!(
        proxy
            .wire()
            .iter()
            .any(|sent| sent.destination == EDGE && sent.message.status_code() == Some(200)),
        "the 200 reached the caller"
    );

    assert!(release(&proxy, call_id, Toward::Both));
    let wire = proxy.wire();
    let byes = requests(&wire, Method::Bye);
    assert_eq!(
        byes.len(),
        2,
        "{:?}",
        byes.iter()
            .map(|sent| &sent.destination)
            .collect::<Vec<_>>()
    );
    assert!(
        byes.iter().any(|sent| sent.destination == EDGE),
        "a BYE to the caller"
    );
    let into_core = byes
        .iter()
        .find(|sent| sent.destination == CORE)
        .expect("a BYE into the core");
    let route = headers(&into_core.message, "Route");
    assert_eq!(
        route.first().map(String::as_str),
        Some(format!("<sip:{CORE};lr>").as_str())
    );
    assert_eq!(
        route.len(),
        2,
        "then siphon's second-leg entry, which brings it back: {route:?}"
    );
    assert_eq!(
        route[1], first_record_route,
        "siphon's own entry: {route:?}"
    );
    assert!(
        byes.iter().all(|sent| sent.destination != CALLEE),
        "the callee is reached through the core, not directly"
    );
}

/// The Rf ACR-STOP of a released session goes out once, and the far end's BYE
/// crossing siphon's is refused rather than stopping it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_session_is_stopped_once_in_rf() {
    let call_id = "release-rf@192.0.2.91";
    let mut dispatcher =
        test_dispatcher_with_script(&script(&format!("sip:bob@{NEXT_HOP}"), "runs_release_rf"));
    knows_itself(&mut dispatcher.state);
    dispatcher.state.proxy_release = true;
    let (manager, received) = super::rf_reinvite_tests::mock_cdf().await;
    dispatcher.state.local_domains = Arc::new(vec!["example.com".to_string()]);
    dispatcher.state.rf_charger = Some(crate::diameter::rf_service::RfChargingService::new(
        manager,
        crate::config::RfConfig {
            enabled: true,
            node_functionality: "pcscf".to_string(),
            ..Default::default()
        },
    ));
    let proxy = Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    };
    let established = establish(&proxy, call_id);
    let records = |count: usize| {
        let received = Arc::clone(&received);
        async move {
            for _ in 0..300 {
                if received.lock().expect("the ACR log").len() >= count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            received.lock().expect("the ACR log").clone()
        }
    };
    let started = records(1).await;
    assert_eq!(started.len(), 1, "the answered call opened its Rf session");

    assert!(release(&proxy, call_id, Toward::Both));
    let stopped = records(2).await;
    assert_eq!(stopped.len(), 2);
    assert_eq!(stopped[1]["Accounting-Record-Type"], 4, "STOP_RECORD");

    let crossing = super::proxy_dialog_state_tests::in_dialog(
        "BYE",
        &format!("sip:alice@{CALLER}"),
        NEXT_HOP,
        &header(&established.answer_to_caller, "To"),
        &header(&established.answer_to_caller, "From"),
        call_id,
        &[
            established.own_record_route.clone(),
            format!("<sip:{EDGE};lr>"),
        ],
        101,
    );
    proxy.request(NEXT_HOP, &crossing);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(records(3).await.len(), 2, "no second ACR-STOP");
}

/// Per-module leak gate: complete releases leave the store, its indexes and
/// the UAC's pending map as they found them.
#[tokio::test(flavor = "multi_thread")]
async fn completed_releases_leave_nothing_behind() {
    let proxy = releasable("release-leak@192.0.2.91");
    let pending_before = proxy.state.uac_sender.pending_count();
    for call in 0..20 {
        let call_id = format!("release-leak-{call}@192.0.2.91");
        establish(&proxy, &call_id);
        assert!(release(&proxy, &call_id, Toward::Both));
        for sent in proxy.wire() {
            if sent.message.method() == Some(&Method::Bye) {
                proxy.response(&sent.destination, answer(&sent.message, 200, "OK"));
            }
        }
    }
    assert!(drained(&proxy).await);
    assert_eq!(proxy.state.proxy_dialogs.len(), 0);
    assert_eq!(proxy.state.proxy_dialogs.branch_index_len(), 0);
    assert_eq!(proxy.state.proxy_dialogs.call_id_index_len(), 0);
    assert_eq!(proxy.state.uac_sender.pending_count(), pending_before);
}

/// A call that ends with its own BYE is forgotten too: the store keeps a
/// Record-Routed dialog only until something ends it.
#[tokio::test(flavor = "multi_thread")]
async fn a_dialog_ended_by_its_own_bye_is_forgotten() {
    let call_id = "release-own-bye@192.0.2.91";
    let proxy = releasable(call_id);
    let established = establish(&proxy, call_id);
    let bye = super::proxy_dialog_state_tests::in_dialog(
        "BYE",
        CALLEE_CONTACT,
        EDGE,
        &header(&established.answer_to_caller, "From"),
        &header(&established.answer_to_caller, "To"),
        call_id,
        &[
            established.own_record_route.clone(),
            format!("<sip:{NEXT_HOP};lr>"),
        ],
        7,
    );
    proxy.request(EDGE, &bye);
    assert!(proxy.state.proxy_dialogs.is_empty());
    assert!(!release(&proxy, call_id, Toward::Both));
}

fn sa(protocol: crate::ipsec::SaProtocol) -> crate::ipsec::SecurityAssociationPair {
    crate::ipsec::SecurityAssociationPair {
        ue_addr: "198.51.100.20".parse().expect("a literal address"),
        pcscf_addr: "192.0.2.10".parse().expect("a literal address"),
        ue_port_c: 50001,
        ue_port_s: 50002,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: 1000,
        spi_us: 1001,
        spi_pc: 10000,
        spi_ps: 10001,
        ealg: crate::ipsec::EncryptionAlgorithm::Null,
        aalg: crate::ipsec::IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
        hard_lifetime_secs: None,
        protocol,
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: crate::ipsec::SaRole::PCscf,
        impi: None,
        security_server: None,
    }
}

/// Toward a UE on an IPsec SA the BYE goes where a relayed in-dialog request
/// to it goes (TS 33.203 §7.4): to the Contact on the UE's protected server
/// port, from the P-CSCF's protected client port, over the SA's transport —
/// not back to the port the UE's INVITE came from.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_to_a_ue_on_ipsec_leaves_from_the_sa_port() {
    let proxy = releasable("release-ipsec@192.0.2.91");
    let association = sa(crate::ipsec::SaProtocol::Tcp);
    let lookup = |destination: SocketAddr, transport: Transport| {
        (destination.ip() == association.ue_addr)
            .then(|| {
                crate::script::api::ipsec::outbound_for_sa(
                    &association,
                    destination.port(),
                    transport,
                )
            })
            .flatten()
    };
    let bye = ReleaseBye {
        end: crate::proxy::dialog_state::End::Caller,
        request_uri: "sip:001010000000001@198.51.100.20:50002".to_string(),
        route: Vec::new(),
        from: "<sip:callee@example.com>;tag=callee-tag".to_string(),
        to: "<sip:caller@example.com>;tag=caller-tag".to_string(),
        call_id: "release-ipsec@192.0.2.91".to_string(),
        cseq: 1,
        hop: Hop {
            // The UE's INVITE came from its protected client port to ours.
            destination: "198.51.100.20:50001".parse().expect("a literal address"),
            transport: Transport::Udp,
            connection_id: ConnectionId(7),
            local_addr: Some("192.0.2.10:5066".parse().expect("a literal address")),
        },
        branch: "z9hG4bK-uac-ipsec".to_string(),
    };
    let egress = release_egress(&bye, &proxy.state.dns_resolver, &lookup);
    assert_eq!(
        egress.destination,
        "198.51.100.20:50002".parse().expect("a literal address")
    );
    assert_eq!(
        egress.source,
        Some("192.0.2.10:5064".parse().expect("a literal address"))
    );
    assert_eq!(egress.transport, Transport::Tcp, "the SA's transport");
    let request =
        release_bye_request(&bye, &egress, Some(REASON), &proxy.state).expect("the BYE builds");
    assert!(
        header(&request, "Via").starts_with("SIP/2.0/TCP 192.0.2.10:5064;"),
        "the Via names the SA port: {}",
        header(&request, "Via")
    );

    // With no SA the BYE goes back the way the dialog came.
    let plain = release_egress(&bye, &proxy.state.dns_resolver, &|_, _| None);
    assert_eq!(plain.destination, bye.hop.destination);
    assert_eq!(plain.connection_id, ConnectionId(7));
    assert_eq!(plain.source, bye.hop.local_addr);
}
