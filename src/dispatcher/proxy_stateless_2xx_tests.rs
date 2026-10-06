//! RFC 3261 §16.7 step 9: a 2xx to an INVITE that matches nothing the proxy
//! still holds is forwarded statelessly, by its Via stack.
//!
//! The proxy drops its state for an answered INVITE with the first 2xx, so a
//! retransmission of that 2xx (the callee repeats it until it is ACKed,
//! §13.3.1.4) matches no transaction and no session. Dropped, a `200` lost on
//! its way to the caller was lost for good: the caller never heard the answer,
//! never ACKed, and the call that both sides wanted failed. The same goes for
//! a 2xx to an INVITE whose state went for another reason, such as a branch
//! the proxy had timed out.
//!
//! Only a response this proxy can show to be its own to forward is: the top
//! Via is one this instance generates (its sent-by and its branch form), and a
//! second Via says where the request came from. Anything else is dropped as
//! before. On the proxy harness of
//! [`super::proxy_cancel_awaits_provisional_tests`], read off the egress.

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, caller_invite, fire, requests_to, responses_to_caller, CALLER, DECIDING,
    RINGING, SILENT,
};
use super::proxy_dialog_state_tests::{
    find, header, headers, inbound, invites_by_destination, response_to, Proxy, Sent,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// A proxy that Record-Routes and relays every INVITE to `target`, and whose
/// `@proxy.on_reply` handler marks every response it sees. `fix_contact` turns
/// `nat.fix_contact` on.
fn marking_proxy(target: &str, fix_contact: bool) -> Proxy {
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.record_route()\n",
            "    request.relay(\"sip:callee@{target}\")\n",
            "\n",
            "@proxy.on_reply\n",
            "def answered(request, reply):\n",
            "    reply.set_header(\"X-Reply-Handler\", \"ran\")\n",
            "    reply.relay()\n",
        ),
        target = target,
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    dispatcher.state.nat_fix_contact = fix_contact;
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn answers_to_caller(sent: &[Sent]) -> Vec<SipMessage> {
    sent.iter()
        .filter(|sent| sent.destination == CALLER && sent.message.status_code() == Some(200))
        .map(|sent| sent.message.clone())
        .collect()
}

/// The callee's `200` is lost on its way to the caller, or its ACK is: the
/// callee sends it again, and each copy reaches the caller, with everything
/// the caller's dialog is built from as the first one had it.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_answer_reaches_the_caller_each_time() {
    for fix_contact in [false, true] {
        let proxy = marking_proxy(RINGING, fix_contact);
        let call_id = format!("lost-200-{fix_contact}@example.com");
        let (_, invites) = call(&proxy, &call_id);
        let to_ringing = find(&invites, RINGING).clone();
        // The callee answers from behind a NAT: its Contact is not where it is.
        let answer = response_to(
            &to_ringing,
            200,
            "OK",
            "callee-tag",
            "sip:callee@10.0.0.7:5060",
            "",
        );
        proxy.response(RINGING, answer.clone());
        let first = answers_to_caller(&proxy.wire());
        assert_eq!(first.len(), 1, "the answer");
        let first = &first[0];
        assert_eq!(header(first, "X-Reply-Handler"), "ran");
        let expected_contact = if fix_contact {
            format!("<sip:callee@{RINGING}>")
        } else {
            "<sip:callee@10.0.0.7:5060>".to_string()
        };
        assert_eq!(header(first, "Contact"), expected_contact);
        assert_eq!(proxy.state.session_store.client_key_count(), 0);

        for copy in 1..=3 {
            proxy.response(RINGING, answer.clone());
            let again = answers_to_caller(&proxy.wire());
            assert_eq!(again.len(), 1, "copy {copy} reaches the caller");
            let again = &again[0];
            assert_eq!(
                headers(again, "Via"),
                headers(first, "Via"),
                "the caller's Via stack, ours removed"
            );
            assert_eq!(
                headers(again, "Record-Route"),
                headers(first, "Record-Route")
            );
            assert_eq!(header(again, "Contact"), expected_contact);
            for name in ["From", "To", "Call-ID", "CSeq"] {
                assert_eq!(header(again, name), header(first, name), "{name}");
            }
            assert!(
                again.headers.get("X-Reply-Handler").is_none(),
                "the script saw this request end with the first 200"
            );
        }
        // Nothing was brought back for them.
        assert_eq!(proxy.state.session_store.session_count(), 0);
        assert_eq!(proxy.state.session_store.client_key_count(), 0);
        assert_eq!(proxy.state.session_store.late_dialog_count(), 0);
    }
}

/// A callee the proxy had given up on as timed out answers after all: the
/// branch and its session are gone, and the 2xx is forwarded by its Via stack
/// for the caller to ACK and release (RFC 3261 §16.7 steps 5 and 9).
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_whose_session_is_gone_is_forwarded_by_its_via() {
    let proxy = marking_proxy(SILENT, false);
    let (_, invites) = call(&proxy, "answer-after-timeout@example.com");
    let to_silent = find(&invites, SILENT).clone();
    fire(&proxy, &to_silent, TimerName::B);
    assert_eq!(responses_to_caller(&proxy.wire()), [408]);
    assert_eq!(proxy.state.session_store.session_count(), 0);

    answers(&proxy, SILENT, &to_silent, 200, "OK");
    let sent = proxy.wire();
    let forwarded = answers_to_caller(&sent);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(
        headers(&forwarded[0], "Via"),
        ["SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bK-answer-after-timeout@example.com"]
    );
    assert!(
        requests_to(&sent, SILENT, Method::Ack).is_empty(),
        "the ACK of a 2xx is the caller's"
    );
}

/// What is not shown to be this proxy's to forward is dropped, as before: a
/// top Via that is another element's, a branch this instance does not
/// generate, no second Via to forward to, a response that is not a 2xx to an
/// INVITE.
#[tokio::test(flavor = "multi_thread")]
async fn a_stray_response_that_is_not_ours_to_forward_is_dropped() {
    let proxy = marking_proxy(RINGING, false);
    let (_, invites) = call(&proxy, "strays@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    let answer = response_to(
        &to_ringing,
        200,
        "OK",
        "callee-tag",
        &format!("sip:callee@{RINGING}"),
        "",
    );
    proxy.response(RINGING, answer.clone());
    let _ = proxy.wire();
    let vias = headers(&answer, "Via");
    let (ours, callers) = (vias[0].clone(), vias[1].clone());
    let own_branch = ours.rsplit("branch=").next().expect("a branch").to_string();

    let with_vias = |vias: Vec<String>| {
        let mut stray = answer.clone();
        stray.headers.set_all("Via", vias);
        stray
    };
    let strays = [
        (
            "another element's sent-by",
            with_vias(vec![
                format!("SIP/2.0/UDP 203.0.113.9:5060;branch={own_branch}"),
                callers.clone(),
            ]),
        ),
        (
            "a branch this instance does not generate",
            with_vias(vec![
                "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds".to_string(),
                callers.clone(),
            ]),
        ),
        (
            "not an RFC 3261 branch",
            with_vias(vec![
                "SIP/2.0/UDP 192.0.2.1:5060;branch=1234abcd".to_string(),
                callers.clone(),
            ]),
        ),
        (
            "no second Via, and a sent-by that is not ours",
            with_vias(vec![format!(
                "SIP/2.0/UDP 203.0.113.9:5060;branch={own_branch}"
            )]),
        ),
    ];
    for (what, stray) in strays {
        proxy.response(RINGING, stray);
        assert!(proxy.wire().is_empty(), "{what}: dropped");
    }

    // Our own Via alone: nothing to forward it to.
    proxy.response(RINGING, with_vias(vec![ours.clone()]));
    assert!(
        proxy.wire().iter().all(|sent| sent.destination != CALLER),
        "nothing reaches the caller"
    );

    // Not a 2xx to an INVITE.
    for (status_code, reason, cseq) in [
        (180, "Ringing", "5 INVITE"),
        (486, "Busy Here", "5 INVITE"),
        (200, "OK", "6 BYE"),
    ] {
        let mut stray = response_to(
            &to_ringing,
            status_code,
            reason,
            "callee-tag",
            &format!("sip:callee@{RINGING}"),
            "",
        );
        stray.headers.set("CSeq", cseq.to_string());
        proxy.response(RINGING, stray);
        assert!(
            proxy.wire().iter().all(|sent| sent.destination != CALLER),
            "{status_code} {cseq}: not forwarded"
        );
    }
}

/// The connection the caller's INVITE arrived on.
const CALLER_CONNECTION: ConnectionId = ConnectionId(77);

/// A caller on TCP. The answer that settles its fork, the answer of the other
/// branch arriving after it (RFC 3261 §16.7 step 5), and a retransmission of
/// that one, forwarded by its Via (step 9), all go back over the connection
/// its INVITE came in on (§18.2.2).
#[tokio::test(flavor = "multi_thread")]
async fn every_answer_reaches_a_caller_on_a_stream_over_its_own_connection() {
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.fork([\"sip:callee@{first};transport=udp\", ",
            "\"sip:callee@{second};transport=udp\"])\n",
        ),
        first = DECIDING,
        second = SILENT,
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    let (udp_sender, udp) = flume::unbounded();
    let (tcp_sender, tcp) = flume::unbounded();
    let (other_sender, _) = flume::unbounded();
    dispatcher.state.outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: std::collections::HashMap::new(),
        tcp: tcp_sender,
        tls: other_sender.clone(),
        ws: other_sender.clone(),
        wss: other_sender.clone(),
        sctp: Some(other_sender),
    });
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    dispatcher
        .state
        .stream_connections
        .register(caller, Transport::Tcp, CALLER_CONNECTION);
    let proxy = Proxy {
        state: Arc::new(dispatcher.state),
        udp,
    };

    let raw = caller_invite("stream-caller@example.com").replace(
        &format!("Via: SIP/2.0/UDP {CALLER}"),
        &format!("Via: SIP/2.0/TCP {CALLER}"),
    );
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let mut arrived = inbound(CALLER, &raw);
    arrived.transport = Transport::Tcp;
    arrived.connection_id = CALLER_CONNECTION;
    tokio::task::block_in_place(|| {
        handle_request(arrived, invite, "INVITE".to_string(), &proxy.state)
    });
    let invites = invites_by_destination(&proxy.wire());
    let (to_deciding, to_silent) = (
        find(&invites, DECIDING).clone(),
        find(&invites, SILENT).clone(),
    );

    // What the caller was sent since the last look, as it left.
    let to_caller = || {
        let mut answers = Vec::new();
        while let Ok(outbound) = tcp.try_recv() {
            let message = parse_sip_message_bytes(&outbound.data).expect("a SIP message");
            if message.status_code() == Some(200) {
                answers.push((outbound, message));
            }
        }
        answers
    };
    let assert_one_answer_on_the_connection = |what: &str, to_tag: &str| {
        let answers = to_caller();
        assert_eq!(answers.len(), 1, "{what}");
        let (left, message) = &answers[0];
        assert_eq!(left.transport, Transport::Tcp, "{what}");
        assert_eq!(left.destination, caller, "{what}");
        assert_eq!(left.connection_id, CALLER_CONNECTION, "{what}");
        assert_eq!(
            headers(message, "Via"),
            [format!(
                "SIP/2.0/TCP {CALLER};branch=z9hG4bK-stream-caller@example.com"
            )],
            "{what}"
        );
        assert!(header(message, "To").ends_with(to_tag), "{what}");
    };

    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    assert_one_answer_on_the_connection("the answer that settles the fork", "-14-5060");
    answers(&proxy, SILENT, &to_silent, 200, "OK");
    assert_one_answer_on_the_connection("the other branch's answer, after it", "-12-5060");
    answers(&proxy, SILENT, &to_silent, 200, "OK");
    assert_one_answer_on_the_connection("its retransmission, by its Via", "-12-5060");
    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    assert_one_answer_on_the_connection("the first answer's retransmission", "-14-5060");
}
