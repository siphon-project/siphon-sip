//! A CANCEL for an INVITE whose `async def` `@proxy.on_request` is still
//! awaiting (RFC 3261 §9.2, §16.10).
//!
//! The INVITE has a server transaction from its arrival but no proxy session
//! until the script's decision is acted on, so the CANCEL used to match nothing
//! and was answered `481`, and the INVITE was forwarded once the script
//! returned: to a callee that then answered a call the caller had abandoned.
//! A CANCEL that matches the INVITE's server transaction is answered `200`, no
//! branch has been forwarded so none is cancelled, the INVITE is answered `487`
//! and is never forwarded.

use std::time::{Duration, Instant};

use super::proxy_cancel_awaits_provisional_tests::{
    caller_cancels, caller_invite, requests_to, responses_to_caller, CALLER, DECIDING,
};
use super::proxy_dialog_state_tests::{inbound, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// A proxy whose handler awaits before it relays to [`DECIDING`].
fn awaiting_proxy() -> Proxy {
    let script = format!(
        concat!(
            "import asyncio\n",
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "async def route(request):\n",
            "    await asyncio.sleep(0.6)\n",
            "    request.relay(\"sip:callee@{target}\")\n",
        ),
        target = DECIDING,
    );
    let dispatcher = test_dispatcher_with_script(&script);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// The caller's INVITE reaches the executor, and returns once the script is
/// awaiting.
fn invite_reaches_the_script(proxy: &Proxy, raw: &str) {
    let state = Arc::clone(&proxy.state);
    let raw_owned = raw.to_string();
    crate::script::py_executor::spawn(move || {
        let parsed = parse_sip_message_bytes(raw_owned.as_bytes()).expect("the INVITE parses");
        handle_request(
            inbound(CALLER, &raw_owned),
            parsed,
            "INVITE".to_string(),
            &state,
        );
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while proxy.state.scripted_invites.is_empty() {
        assert!(Instant::now() < deadline, "the INVITE reached the script");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_while_on_request_awaits_is_answered_and_the_invite_is_never_forwarded() {
    let _serial = crate::script::async_pool::pool_test_guard();
    super::async_request_handler_tests::ensure_pools();
    let proxy = awaiting_proxy();
    let raw = caller_invite("cancel-while-awaiting@example.com");
    invite_reaches_the_script(&proxy, &raw);
    let _ = proxy.wire();

    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    let statuses: Vec<(String, u16)> = sent
        .iter()
        .filter(|sent| sent.destination == CALLER)
        .filter_map(|sent| {
            sent.message.status_code().map(|code| {
                (
                    sent.message
                        .headers
                        .get("CSeq")
                        .cloned()
                        .unwrap_or_default(),
                    code,
                )
            })
        })
        .filter(|(_, code)| *code != 100)
        .collect();
    assert_eq!(
        statuses,
        [("5 CANCEL".to_string(), 200), ("5 INVITE".to_string(), 487)],
        "200 for the CANCEL, 487 for the INVITE"
    );

    // The script returns and relays: nothing goes out.
    tokio::task::block_in_place(|| std::thread::sleep(Duration::from_millis(1500)));
    let later = proxy.wire();
    assert!(
        requests_to(&later, DECIDING, Method::Invite).is_empty(),
        "the abandoned INVITE is not forwarded"
    );
    assert!(
        responses_to_caller(&later).is_empty(),
        "the INVITE has its one final response, got {:?}",
        responses_to_caller(&later)
    );
    assert!(proxy.state.scripted_invites.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_cancel_while_on_request_awaits_is_answered_200_again() {
    let _serial = crate::script::async_pool::pool_test_guard();
    super::async_request_handler_tests::ensure_pools();
    let proxy = awaiting_proxy();
    let raw = caller_invite("cancel-twice-awaiting@example.com");
    invite_reaches_the_script(&proxy, &raw);
    caller_cancels(&proxy, &raw);
    let _ = proxy.wire();

    caller_cancels(&proxy, &raw);
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
}

/// A CANCEL that lands after the handlers have returned and before the session
/// exists (the hook stands in that window) is answered 200, and the INVITE,
/// by then forwarded, is abandoned once the session is there: 487, and the
/// branch's CANCEL kept for its first provisional (RFC 3261 §9.1, §16.10).
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_between_the_decision_and_the_session_is_answered_and_abandons_the_invite() {
    let proxy = super::proxy_cancel_awaits_provisional_tests::relaying_proxy(DECIDING, "");
    let raw = caller_invite("cancel-in-the-window@example.com");
    let branch = "z9hG4bK-cancel-in-the-window@example.com".to_string();
    let hook_proxy = Proxy {
        state: Arc::clone(&proxy.state),
        udp: proxy.udp.clone(),
    };
    let hook_raw = raw.clone();
    *super::request_script::RELAY_WINDOW_HOOK
        .lock()
        .expect("hook lock") = Some((
        branch,
        Arc::new(move || caller_cancels(&hook_proxy, &hook_raw)),
    ));

    proxy.request(CALLER, &raw);
    *super::request_script::RELAY_WINDOW_HOOK
        .lock()
        .expect("hook lock") = None;

    let sent = proxy.wire();
    assert_eq!(
        responses_to_caller(&sent),
        [200, 487],
        "200 for the CANCEL, 487 for the INVITE, no 481"
    );
    assert!(proxy.state.scripted_invites.is_empty());
}
