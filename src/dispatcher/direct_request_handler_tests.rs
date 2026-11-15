//! An `async def` request handler with `script.direct_dispatch` on and off:
//! the same reply or relay either way; with it on, the handler is stepped by
//! its asyncio driver's runner, a request no runner has room for is answered
//! 503, and nothing of a handler is left behind however it ends.

use std::time::{Duration, Instant};

use super::async_request_handler_tests::{
    dispatcher, ensure_pools, message, receive_on_executor, test_runtime,
};
use super::*;
use crate::script::runner::direct_tests::{install_probe_module, settles_to, totals, Switch};

const SCRIPT: &str = concat!(
    "import _direct_probe as probe\n",
    "from siphon import proxy, tasks\n",
    "\n",
    "async def lookup(value):\n",
    "    return await probe.sleep_ms(2, value) + 1\n",
    "\n",
    "@proxy.on_request(\"MESSAGE\")\n",
    "async def handle(request):\n",
    "    kind = request.get_header(\"X-Kind\") or \"one\"\n",
    "    if kind == \"hold\":\n",
    "        await probe.sleep_ms(1500, 0)\n",
    "        request.reply(200, \"Held\")\n",
    "    elif kind == \"slow\":\n",
    "        await probe.sleep_ms(1000, 0)\n",
    "        request.reply(200, \"Slow\")\n",
    "    elif kind == \"one\":\n",
    "        value = await probe.sleep_ms(2, 7)\n",
    "        request.set_reply_header(\"X-Value\", str(value))\n",
    "        request.set_reply_header(\"X-Direct\", str(probe.direct()))\n",
    "        request.reply(200, \"OK\")\n",
    "    elif kind == \"gather\":\n",
    "        left, right = await tasks.gather(lookup(1), probe.sleep_ms(2, 5))\n",
    "        request.set_reply_header(\"X-Value\", f\"{left},{right}\")\n",
    "        request.set_reply_header(\"X-Direct\", str(probe.direct()))\n",
    "        request.reply(200, \"OK\")\n",
    "    elif kind == \"raise\":\n",
    "        await probe.ready(0)\n",
    "        raise RuntimeError(\"backend went away\")\n",
    "    elif kind == \"relay\":\n",
    "        await probe.ready(0)\n",
    "        request.relay(\"sip:registrar@198.51.100.12:5060\")\n",
    "    elif kind == \"wedged\":\n",
    "        await probe.never()\n",
    "        request.reply(200, \"OK\")\n",
    "\n",
    "@proxy.on_request(\"MESSAGE\")\n",
    "async def second(request):\n",
    "    # Runs once the first handler has finished, awaiting in its turn.\n",
    "    if request.get_header(\"X-Kind\") in (None, \"one\", \"gather\"):\n",
    "        await probe.ready(0)\n",
    "        request.set_reply_header(\"X-Second\", \"ran\")\n",
);

fn kind(name: &str, call_id: &str) -> String {
    message(call_id, &format!("X-Kind: {name}\r\n"))
}

/// The next `count` SIP messages sent, of either kind.
fn sent(udp: &flume::Receiver<OutboundMessage>, count: usize, within: Duration) -> Vec<String> {
    let deadline = Instant::now() + within;
    let mut seen = Vec::new();
    while seen.len() < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(message) = udp.recv_timeout(remaining) else {
            break;
        };
        for frame in message.frames() {
            seen.push(String::from_utf8_lossy(frame).to_string());
        }
    }
    seen
}

fn header<'a>(message: &'a str, name: &str) -> Option<&'a str> {
    message
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
}

/// What a peer can tell one answer from another by, without the parts that
/// differ from one message to the next.
fn outline(message: &str) -> (String, Option<String>, Option<String>) {
    (
        message.lines().next().unwrap_or_default().to_string(),
        header(message, "X-Value").map(str::to_string),
        header(message, "X-Second").map(str::to_string),
    )
}

fn one(
    state: &Arc<DispatcherState>,
    udp: &flume::Receiver<OutboundMessage>,
    raw: String,
) -> String {
    receive_on_executor(state, raw);
    let mut seen = sent(udp, 1, Duration::from_secs(10));
    assert_eq!(seen.len(), 1, "the request is answered or relayed");
    seen.remove(0)
}

/// A reply after one await, a reply after a gather, a script error and a
/// relay read the same with the switch on as with it off, the handler after
/// an awaiting one still runs, and on, the handlers are stepped by a runner.
#[test]
fn replies_and_relays_are_the_same_with_the_switch_on_and_off() {
    let _serial = crate::script::async_pool::pool_test_guard();
    ensure_pools();
    install_probe_module();
    let mut seen = Vec::new();
    for on in [false, true] {
        let _switch = Switch::set(on);
        let (state, udp) = dispatcher(SCRIPT);
        let before = totals();
        let demotions = crate::script::runner::demotions();
        let mut outlines = Vec::new();
        for name in ["one", "gather", "raise", "relay"] {
            let message = one(&state, &udp, kind(name, &format!("{name}-{on}")));
            if matches!(name, "one" | "gather") {
                assert_eq!(
                    header(&message, "X-Direct"),
                    Some(if on { "True" } else { "False" }),
                    "{name}: {message}"
                );
            }
            outlines.push(outline(&message));
        }
        let after = totals();
        if on {
            // Both handlers for each request but the one whose first raised.
            assert_eq!(after.direct_starts - before.direct_starts, 7);
            assert_eq!(
                crate::script::runner::demotions(),
                demotions,
                "no handler was handed to asyncio"
            );
        } else {
            assert_eq!(after.direct_starts, before.direct_starts);
        }
        test_runtime().block_on(settles_to(before, "after the requests"));
        seen.push(outlines);
    }
    assert_eq!(seen[0], seen[1], "off and on disagree");
    assert_eq!(
        seen[1],
        vec![
            (
                "SIP/2.0 200 OK".to_string(),
                Some("7".to_string()),
                Some("ran".to_string())
            ),
            (
                "SIP/2.0 200 OK".to_string(),
                Some("2,5".to_string()),
                Some("ran".to_string())
            ),
            ("SIP/2.0 500 Script Error".to_string(), None, None),
            // Relayed to the next hop with its Request-URI as it came.
            (
                "MESSAGE sip:201@siphon.example.com SIP/2.0".to_string(),
                None,
                None
            ),
        ]
    );
}

/// More handlers awaiting at once than the executor has threads all answer,
/// side by side: a direct drive holds no worker while it waits.
#[test]
fn awaiting_handlers_beyond_the_executor_size_are_answered_side_by_side() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (executor, _async_pool) = ensure_pools();
    install_probe_module();
    let _switch = Switch::set(true);
    let (state, udp) = dispatcher(SCRIPT);
    let before = totals();

    let handlers = 2 * executor.max_size() + 1;
    let started = Instant::now();
    for index in 0..handlers {
        receive_on_executor(&state, kind("slow", &format!("slow-{index}")));
    }
    let answered = sent(&udp, handlers, Duration::from_secs(15));
    let elapsed = started.elapsed();
    assert_eq!(answered.len(), handlers, "every request is answered");
    assert!(
        answered
            .iter()
            .all(|message| message.starts_with("SIP/2.0 200 Slow")),
        "{answered:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "{handlers} handlers each awaiting 1 s on {} workers took {elapsed:?}",
        executor.max_size()
    );
    // Both of each request's handlers went through a runner.
    assert_eq!(
        totals().direct_starts - before.direct_starts,
        2 * handlers as u64
    );
    test_runtime().block_on(settles_to(before, "after the slow handlers"));
}

/// With every runner at its limit a new request is answered 503 with a
/// `Retry-After`, at once, its handler never runs, and the refusal is
/// counted. The requests in flight are answered as usual, and once there is
/// room requests are served again.
#[test]
fn a_request_no_runner_has_room_for_is_answered_503() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (_executor, async_pool) = ensure_pools();
    install_probe_module();
    let _switch = Switch::set(true);
    let (state, udp) = dispatcher(SCRIPT);
    let before = totals();
    crate::script::runner::set_admission_limit_for_test(1);
    let room = async_pool.size();

    for index in 0..room {
        receive_on_executor(&state, kind("hold", &format!("hold-{index}")));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while totals().in_flight < before.in_flight + room {
        assert!(Instant::now() < deadline, "every runner filled");
        std::thread::sleep(Duration::from_millis(2));
    }

    let rejected = crate::script::runner::admission_rejected();
    let started = Instant::now();
    let refused = one(&state, &udp, kind("one", "refused"));
    assert!(
        refused.starts_with("SIP/2.0 503 Service Unavailable\r\n"),
        "{refused}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the refusal waited for room: {:?}",
        started.elapsed()
    );
    assert!(header(&refused, "Retry-After").is_some(), "{refused}");
    assert_eq!(
        header(&refused, "X-Value"),
        None,
        "the handler never ran: {refused}"
    );
    assert_eq!(crate::script::runner::admission_rejected() - rejected, 1);
    assert_eq!(
        totals().in_flight,
        before.in_flight + room,
        "a refused request took no place"
    );

    let held = sent(&udp, room, Duration::from_secs(10));
    assert_eq!(held.len(), room, "the requests in flight are answered");
    assert!(
        held.iter()
            .all(|message| message.starts_with("SIP/2.0 200 Held")),
        "{held:?}"
    );
    test_runtime().block_on(settles_to(before, "after the held requests"));
    let served = one(&state, &udp, kind("one", "served"));
    assert!(served.starts_with("SIP/2.0 200 OK\r\n"), "{served}");
}

/// A handler whose awaitable never finishes is answered once the coroutine
/// timeout passes, in both modes, and on, its slab entry, its place and its
/// awaitable are given back.
#[test]
fn a_wedged_handler_is_answered_at_the_timeout_and_leaves_nothing() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (_executor, async_pool) = ensure_pools();
    install_probe_module();
    for on in [false, true] {
        let _switch = Switch::set(on);
        let (state, udp) = dispatcher(SCRIPT);
        let before = totals();
        let pending = crate::script::async_pool::pending_coroutines();
        let started = Instant::now();
        const REQUESTS: usize = 4;
        for index in 0..REQUESTS {
            receive_on_executor(&state, kind("wedged", &format!("wedged-{on}-{index}")));
            receive_on_executor(&state, kind("gather", &format!("fine-{on}-{index}")));
        }
        let answered = sent(
            &udp,
            2 * REQUESTS,
            async_pool.coroutine_timeout() + Duration::from_secs(10),
        );
        let mut lines: Vec<&str> = answered
            .iter()
            .map(|message| message.lines().next().unwrap_or_default())
            .collect();
        lines.sort_unstable();
        let mut expected = vec!["SIP/2.0 200 OK"; REQUESTS];
        expected.extend(vec!["SIP/2.0 500 Script Error"; REQUESTS]);
        assert_eq!(lines, expected, "on = {on}");
        assert!(
            started.elapsed() >= async_pool.coroutine_timeout(),
            "the wedged requests are failed by the timeout, not before it"
        );
        test_runtime().block_on(settles_to(before, "after the wedged requests"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while crate::script::async_pool::pending_coroutines() > pending {
            assert!(Instant::now() < deadline, "the pending count came back");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
