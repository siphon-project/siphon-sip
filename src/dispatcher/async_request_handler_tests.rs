//! An `async def` request handler gives its Python executor worker back while
//! it awaits.
//!
//! The executor is bounded, so a handler that parked its worker for every
//! `await` capped throughput at `workers / handler latency`: a handler awaiting
//! a slow downstream request held an OS thread for the whole wait while the
//! queue behind it grew and shed. These tests run real scripts through
//! `handle_request` on the executor, the way the dispatcher does, and check
//! both that the wait no longer costs a worker and that everything the
//! dispatcher does once the handlers have returned still happens.

use std::time::{Duration, Instant};

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::script::async_pool::AsyncPool;
use crate::script::py_executor::PyExecutor;

const SOURCE: &str = "192.0.2.40:5070";

/// Long-lived runtime the pools' threads enter: a per-test runtime would be
/// torn down underneath them.
pub(super) fn test_runtime() -> &'static tokio::runtime::Runtime {
    crate::script::async_pool::test_pools_runtime()
}

/// Both pools, as a running server has them.
pub(super) fn ensure_pools() -> (Arc<PyExecutor>, Arc<AsyncPool>) {
    crate::script::async_pool::ensure_test_pools()
}

fn message(call_id: &str, extra_headers: &str) -> String {
    format!(
        "MESSAGE sip:201@siphon.example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP {SOURCE};branch=z9hG4bK-{call_id}\r\n\
         From: <sip:200@siphon.example.com>;tag=sender\r\n\
         To: <sip:201@siphon.example.com>\r\n\
         Call-ID: {call_id}@example.com\r\n\
         CSeq: 1 MESSAGE\r\n\
         Max-Forwards: 70\r\n\
         {extra_headers}\
         Content-Length: 0\r\n\
         \r\n"
    )
}

/// Hand `raw` to `handle_request` on the executor, as the dispatcher's
/// inbound loop does.
fn receive_on_executor(state: &Arc<DispatcherState>, raw: String) {
    let state = Arc::clone(state);
    crate::script::py_executor::spawn(move || {
        let parsed = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: SOURCE.parse().expect("a literal address"),
            data: Bytes::from(raw.clone()),
        };
        handle_request(inbound, parsed, "MESSAGE".to_string(), &state);
    });
}

/// The next `count` responses sent, waiting up to `within` for them.
fn responses(
    udp: &flume::Receiver<OutboundMessage>,
    count: usize,
    within: Duration,
) -> Vec<String> {
    let deadline = Instant::now() + within;
    let mut seen = Vec::new();
    while seen.len() < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(message) = udp.recv_timeout(remaining) else {
            break;
        };
        for frame in message.frames() {
            let text = String::from_utf8_lossy(frame).to_string();
            if text.starts_with("SIP/2.0 ") {
                seen.push(text);
            }
        }
    }
    seen
}

/// The status lines of the next `count` responses sent.
fn status_lines(
    udp: &flume::Receiver<OutboundMessage>,
    count: usize,
    within: Duration,
) -> Vec<String> {
    responses(udp, count, within)
        .iter()
        .map(|text| text.lines().next().unwrap_or_default().to_string())
        .collect()
}

fn dispatcher(script: &str) -> (Arc<DispatcherState>, flume::Receiver<OutboundMessage>) {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
    (Arc::new(state), udp)
}

#[test]
fn handlers_awaiting_concurrently_do_not_queue_behind_the_executor() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (executor, _async_pool) = ensure_pools();
    let (state, udp) = dispatcher(concat!(
        "import asyncio\n",
        "from siphon import proxy\n",
        "\n",
        "@proxy.on_request(\"MESSAGE\")\n",
        "async def slow(request):\n",
        "    await asyncio.sleep(1.0)\n",
        "    request.reply(200, \"OK\")\n",
    ));

    // Twice the executor's ceiling and one more: parked workers would run
    // these in three waves of one second each.
    let handlers = 2 * executor.max_size() + 1;
    let started = Instant::now();
    for index in 0..handlers {
        receive_on_executor(&state, message(&format!("concurrent-{index}"), ""));
    }
    let answered = status_lines(&udp, handlers, Duration::from_secs(15));
    let elapsed = started.elapsed();

    assert_eq!(
        answered.len(),
        handlers,
        "every request is answered, got {answered:?}"
    );
    assert!(
        answered.iter().all(|line| line.starts_with("SIP/2.0 200")),
        "every handler replied 200, got {answered:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "{handlers} handlers each awaiting 1 s on {} workers took {elapsed:?}: \
         they waited for workers instead of awaiting side by side",
        executor.max_size()
    );
}

#[test]
fn a_handler_that_raises_after_awaiting_is_answered_with_a_script_error() {
    let _serial = crate::script::async_pool::pool_test_guard();
    ensure_pools();
    let (state, udp) = dispatcher(concat!(
        "import asyncio\n",
        "from siphon import proxy\n",
        "\n",
        "@proxy.on_request(\"MESSAGE\")\n",
        "async def broken(request):\n",
        "    await asyncio.sleep(0.05)\n",
        "    raise RuntimeError(\"backend went away\")\n",
    ));

    receive_on_executor(&state, message("raises-after-await", ""));

    assert_eq!(
        status_lines(&udp, 1, Duration::from_secs(10)),
        vec!["SIP/2.0 500 Script Error".to_string()]
    );
}

#[test]
fn a_handler_that_never_settles_is_answered_once_the_coroutine_timeout_passes() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (_executor, async_pool) = ensure_pools();
    let (state, udp) = dispatcher(concat!(
        "import asyncio\n",
        "from siphon import proxy\n",
        "\n",
        "@proxy.on_request(\"MESSAGE\")\n",
        "async def wedged(request):\n",
        "    await asyncio.get_running_loop().create_future()\n",
        "    request.reply(200, \"OK\")\n",
    ));

    let started = Instant::now();
    receive_on_executor(&state, message("never-settles", ""));
    let answered = status_lines(
        &udp,
        1,
        async_pool.coroutine_timeout() + Duration::from_secs(10),
    );

    assert_eq!(answered, vec!["SIP/2.0 500 Script Error".to_string()]);
    assert!(
        started.elapsed() >= async_pool.coroutine_timeout(),
        "the request is failed by the timeout, not before it"
    );
}

#[test]
fn the_handlers_after_an_awaiting_one_run_once_it_has_finished() {
    let _serial = crate::script::async_pool::pool_test_guard();
    ensure_pools();
    // The async handler decides nothing unless told to; the sync handler
    // registered after it answers. `stop_propagation()` called after the
    // await must still keep the second one from running.
    let (state, udp) = dispatcher(concat!(
        "import asyncio\n",
        "from siphon import proxy\n",
        "\n",
        "@proxy.on_request(\"MESSAGE\")\n",
        "async def first(request):\n",
        "    await asyncio.sleep(0.05)\n",
        "    request.set_reply_header(\"X-First\", \"ran\")\n",
        "    if request.get_header(\"X-Own\"):\n",
        "        request.reply(202, \"First\")\n",
        "        request.stop_propagation()\n",
        "\n",
        "@proxy.on_request(\"MESSAGE\")\n",
        "def second(request):\n",
        "    request.reply(200, \"Second\")\n",
    ));

    receive_on_executor(&state, message("continues", ""));
    let continued = responses(&udp, 1, Duration::from_secs(10));
    assert_eq!(continued.len(), 1, "one answer, got {continued:?}");
    assert!(
        continued[0].starts_with("SIP/2.0 200 Second\r\n"),
        "the handler after the awaiting one answered, got {continued:?}"
    );
    assert!(
        continued[0].contains("X-First: ran\r\n"),
        "what the awaiting handler did after its await reached the reply, got {continued:?}"
    );

    receive_on_executor(&state, message("stops", "X-Own: yes\r\n"));
    let stopped = status_lines(&udp, 1, Duration::from_secs(10));
    assert_eq!(stopped, vec!["SIP/2.0 202 First".to_string()]);
}
