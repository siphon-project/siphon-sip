//! `call.session_timer()` followed by `call.answer()` in the same
//! `@b2bua.on_invite` handler: a call siphon answers itself, with no callee
//! and no controller, runs the RFC 4028 session timer the script asked for on
//! the caller's dialog, the only one the call has.
//!
//! RFC 4028 §9: the 2xx carries `Session-Expires` with the refresher, and
//! `Require: timer` when the caller is to refresh (Table 2: a UAS may ask
//! that only of a UAC that listed `timer` in `Supported`). §10: a caller that
//! lets the session run out is released `min(32, interval / 3)` seconds
//! before it expires.
//!
//! Driven once below the script, on the dispatcher's own send and sweep
//! paths, and once from a real script, in a process of its own because
//! `call.answer()` reaches the dispatcher through a process-wide handle.

use std::time::Duration;

use super::sdp_strip_tests::{
    caller_call, caller_invite, endpoint_sdp, inbound_from, response_to, A_LEG_CALL_ID, CALLER,
};
use super::session_timer_tests::{
    age, caller_acks, lists_option_tag, requests, sweep, timer_dispatcher, wire,
};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::script::api::call::SessionTimerOverride;

/// Whether a BYE says a timer ended the call (Q.850 cause 102, "recovery on
/// timer expiry").
fn ended_by_a_timer(bye: &SipMessage) -> bool {
    bye.headers.get("Reason").is_some_and(|reason| {
        let mut parts = reason.split(';').map(str::trim);
        parts.next() == Some("Q.850") && parts.any(|part| part == "cause=102")
    })
}

/// The caller's INVITE of a UA that supports the session timer extension and
/// asks for none itself.
fn invite_supporting_timer() -> SipMessage {
    let mut invite = caller_invite(&endpoint_sdp("192.0.2.10"));
    invite.headers.set("Supported", "timer".to_string());
    invite
}

fn assert_the_caller_refreshes_every_1800(answer: &SipMessage) {
    assert_eq!(
        answer.headers.get("Session-Expires").map(String::as_str),
        Some("1800;refresher=uac")
    );
    assert!(
        lists_option_tag(answer, "Require", "timer"),
        "a 2xx naming the caller the refresher requires the extension (RFC 4028 §9)"
    );
}

/// The timer the script set reaches the 2xx siphon gives the caller, names
/// the caller the refresher as asked, and then runs: siphon sends no refresh
/// of its own, and ends the call 32 s before a session nobody refreshed runs
/// out.
#[tokio::test(flavor = "multi_thread")]
async fn a_per_call_timer_the_caller_refreshes_is_required_and_ends_the_call_unrefreshed() {
    let dispatcher = timer_dispatcher(None);
    let call_id = caller_call(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.session_timer_override = Some(SessionTimerOverride {
            session_expires: 1800,
            min_se: 90,
            refresher: crate::config::SessionRefresher::Uac,
        });
    }

    let _ = wire(&dispatcher);
    assert!(send_uas_response(
        &dispatcher.state,
        &call_id,
        &invite_supporting_timer(),
        200,
        "OK",
        Some(endpoint_sdp("203.0.113.70").into_bytes()),
        Some("application/sdp"),
        true,
        &[]
    ));
    let answer = response_to(&wire(&dispatcher), CALLER, 200);
    assert_the_caller_refreshes_every_1800(&answer);
    let timer = dispatcher
        .state
        .call_actors
        .leg_session_timer(&call_id, true)
        .expect("the caller's dialog runs the session timer");
    assert!(!timer.siphon_refreshes);
    caller_acks(&dispatcher, &answer);

    // 1800 - min(32, 1800 / 3) = 1768 s (RFC 4028 §10). Looked at a few
    // seconds short of it, so a slow run does not carry the clock across.
    age(&dispatcher, &call_id, true, 1760);
    let sent = sweep(&dispatcher);
    assert!(requests(&sent, CALLER, Method::Bye).is_empty());
    assert!(
        requests(&sent, CALLER, Method::Invite).is_empty(),
        "the caller is the refresher: siphon sends no refresh"
    );

    age(&dispatcher, &call_id, true, 1769);
    let byes = requests(&sweep(&dispatcher), CALLER, Method::Bye);
    assert_eq!(byes.len(), 1, "the unrefreshed session ends the call");
    assert!(ended_by_a_timer(&byes[0]));
}

const SCRIPTED: &str = "dispatcher::uas_answer_session_timer_tests::a_script_that_sets_the_timer_and_answers_gets_it_on_its_200_and_running";

/// The same from a script: `call.session_timer(...)` then `call.answer(...)`
/// in one `@b2bua.on_invite` handler, nothing dialled and nothing handed over.
#[test]
fn a_script_that_sets_the_timer_and_answers_gets_it_on_its_200_and_running() {
    super::own_process_test::run_in_own_process(SCRIPTED, Duration::from_secs(60), scripted);
}

fn sent(udp: &flume::Receiver<OutboundMessage>) -> Vec<(SocketAddr, SipMessage)> {
    udp.try_iter()
        .flat_map(|sent| {
            sent.frames()
                .map(|frame| {
                    (
                        sent.destination,
                        parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn scripted() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "ANSWER = (\n",
        "    \"v=0\\r\\no=- 1 1 IN IP4 203.0.113.70\\r\\ns=-\\r\\n\"\n",
        "    \"c=IN IP4 203.0.113.70\\r\\nt=0 0\\r\\nm=audio 40000 RTP/AVP 0\\r\\n\"\n",
        ")\n",
        "\n",
        "@b2bua.on_invite\n",
        "def invite(call):\n",
        "    call.session_timer(expires=1800, min_se=90, refresher=\"uac\")\n",
        "    call.answer(200, \"OK\", body=ANSWER, content_type=\"application/sdp\")\n",
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
        let state = Arc::new(state);
        install_charging_hooks(&state);

        handle_b2bua_invite(inbound_from(CALLER), invite_supporting_timer(), &state);
        let answer = response_to(&sent(&udp), CALLER, 200);
        assert_the_caller_refreshes_every_1800(&answer);
        assert!(!answer.body.is_empty());

        let call_id = state
            .call_actors
            .find_by_sip_call_id(A_LEG_CALL_ID)
            .expect("the answered call");
        let ack = parse_sip_message_bytes(
            format!(
                concat!(
                    "ACK sip:192.0.2.1:5060 SIP/2.0\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-ack\r\n",
                    "Max-Forwards: 70\r\n",
                    "From: {from}\r\n",
                    "To: {to}\r\n",
                    "Call-ID: {call_id}\r\n",
                    "CSeq: 1 ACK\r\n",
                    "Content-Length: 0\r\n",
                    "\r\n",
                ),
                from = answer.headers.from().expect("the 200 has a From"),
                to = answer.headers.to().expect("the 200 has a To"),
                call_id = A_LEG_CALL_ID,
            )
            .as_bytes(),
        )
        .expect("the caller's ACK parses");
        assert!(absorb_b2bua_ack(A_LEG_CALL_ID, &ack, &state));

        let age = |seconds: u64| {
            let then = std::time::Instant::now()
                .checked_sub(Duration::from_secs(seconds))
                .expect("the clock reaches back that far");
            assert!(state
                .call_actors
                .update_leg_session_timer(&call_id, true, |timer| timer.last_refresh = then));
        };
        let _ = sent(&udp);
        age(1760);
        session_timer_sweep(&state);
        assert!(sent(&udp).is_empty(), "nothing is due 1760 s in");

        age(1769);
        session_timer_sweep(&state);
        let byes: Vec<_> = sent(&udp)
            .into_iter()
            .filter(|(_, message)| message.method() == Some(&Method::Bye))
            .collect();
        assert_eq!(byes.len(), 1, "the unrefreshed session ends the call");
        assert!(ended_by_a_timer(&byes[0].1));
    });
}
