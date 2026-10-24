//! Expiries the timer sweep finds run their script handlers as executor jobs
//! of their own, never on the sweep's tokio task.
//!
//! One task drives every SIP transaction timer in the process. When it ran a
//! Timer F expiry's `@proxy.on_failure` itself, an `async def` handler that
//! awaited held the task for the whole await (up to the coroutine timeout), and
//! every other timer, retransmission and timeout in the process waited behind
//! it. It also parked a tokio worker behind every garbage collection.

use std::time::{Duration, Instant};

use super::proxy_cancel_awaits_provisional_tests::CALLER;
use super::proxy_dialog_state_tests::Proxy;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::transaction::timer::TimerConfig;

/// Relays everything to a next hop that never answers; on the resulting 408
/// the handler answers 504, after awaiting 3 s for the `slow-` calls.
const SCRIPT: &str = concat!(
    "import asyncio\n",
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    request.relay(\"sip:registrar@198.51.100.12:5060\")\n",
    "\n",
    "@proxy.on_failure\n",
    "async def failed(request, reply):\n",
    "    if request.call_id.startswith(\"slow-\"):\n",
    "        await asyncio.sleep(3)\n",
    "    request.reply(504, \"Gave Up\")\n",
);

fn register(call_id: &str) -> String {
    format!(
        concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:alice@example.com>;tag=alice-tag\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Contact: <sip:alice@{caller}>\r\n",
            "Expires: 600\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = CALLER,
        call_id = call_id,
    )
}

fn proxy_timing_out_after_one_second() -> Proxy {
    let transaction: crate::config::TransactionConfig =
        crate::config::yaml::from_str("timeout_secs: 1").expect("the transaction block parses");
    let timers: TimerConfig = transaction_timers(Some(&transaction));
    let mut dispatcher = test_dispatcher_with_script(SCRIPT);
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// Wait until the caller has been sent a response to `call_id`.
fn answered(proxy: &Proxy, call_id: &str, within: Duration) -> Option<u16> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        for sent in proxy.wire() {
            let to_caller = sent.destination == CALLER;
            let for_call = sent.message.headers.call_id().map(String::as_str) == Some(call_id);
            if to_caller && for_call {
                if let Some(code) = sent.message.status_code().filter(|code| *code >= 200) {
                    return Some(code);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

#[test]
fn a_slow_failure_handler_does_not_hold_up_other_transactions_timeouts() {
    let _serial = crate::script::async_pool::pool_test_guard();
    crate::script::async_pool::ensure_test_pools();
    // The sweep's own runtime, dropped with the test so its task goes too.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let proxy = proxy_timing_out_after_one_second();
        spawn_timer_sweep(&proxy.state);

        proxy.request(CALLER, &register("slow-sweep@example.com"));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let fast_sent = Instant::now();
        proxy.request(CALLER, &register("fast-sweep@example.com"));

        // Its Timer F fires a second later; its handler answers at once.
        let fast = tokio::task::block_in_place(|| {
            answered(&proxy, "fast-sweep@example.com", Duration::from_secs(10))
        });
        let fast_took = fast_sent.elapsed();
        assert_eq!(fast, Some(504), "the fast call is answered");
        assert!(
            fast_took < Duration::from_millis(2_500),
            "the fast call's timeout was answered {fast_took:?} after it was sent: it \
             waited for the other call's failure handler to finish awaiting"
        );
    });
}
