//! `async def` Diameter handlers with `script.direct_dispatch` on and off:
//! the same answer either way, at each of an inbound request's three stages;
//! with it on, the handlers are stepped by an asyncio driver's runner, a
//! request no runner has room for is answered DIAMETER_TOO_BUSY, and nothing
//! of a handler is left behind however it ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;
use crate::diameter::codec::{FLAG_ERROR, FLAG_PROXIABLE, FLAG_REQUEST};
use crate::script::async_pool::{ensure_test_pools, pool_test_guard, test_pools_runtime};
use crate::script::runner::direct_tests::{install_probe_module, settles_to, totals, Switch};
use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};

/// The registry calls `@diameter.on_request` and friends make once
/// `diameter:` is configured, which an embedded test script is not. What the
/// request handler does is chosen by the first field of the Session-Id.
const SCRIPT: &str = concat!(
    "import _siphon_registry\n",
    "import _direct_probe as probe\n",
    "from siphon import tasks\n",
    "\n",
    "calls = []\n",
    "completed = []\n",
    "\n",
    "async def lookup(value):\n",
    "    return await probe.sleep_ms(2, value) + 1\n",
    "\n",
    "async def handle(request):\n",
    "    kind = request.session_id.split(';')[0]\n",
    "    calls.append(kind)\n",
    "    if kind == 'one':\n",
    "        value = await probe.sleep_ms(2, 7)\n",
    "        answer = request.answer(2001)\n",
    "        answer.set_avp('Error-Message', f'one={value}')\n",
    "        return answer\n",
    "    if kind == 'gather':\n",
    "        left, right = await tasks.gather(lookup(1), probe.sleep_ms(2, 5))\n",
    "        answer = request.answer(2001)\n",
    "        answer.set_avp('Error-Message', f'gather={left},{right}')\n",
    "        return answer\n",
    "    if kind == 'raise':\n",
    "        await probe.ready(0)\n",
    "        raise RuntimeError('backend went away')\n",
    "    if kind == 'gather-raise':\n",
    "        await tasks.gather(lookup(1), probe.fail('lookup failed'))\n",
    "    if kind == 'hold':\n",
    "        await probe.sleep_ms(1500, 0)\n",
    "    if kind == 'slow':\n",
    "        await probe.sleep_ms(1000, 0)\n",
    "    if kind == 'wedged':\n",
    "        await probe.never()\n",
    "    return request.answer(2001)\n",
    "\n",
    "async def rewrite(request, answer):\n",
    "    await probe.ready(0)\n",
    "    answer.set_avp('Origin-Host', 'rewritten.example.net')\n",
    "\n",
    "async def done(request, answer, latency_us):\n",
    "    await probe.ready(0)\n",
    "    completed.append(latency_us)\n",
    "\n",
    "_siphon_registry.register('diameter.on_request', None, handle, True)\n",
    "_siphon_registry.register('diameter.on_reply', None, rewrite, True)\n",
    "_siphon_registry.register('diameter.on_request_completed', None, done, True)\n",
);

fn peer_config() -> PeerConfig {
    PeerConfig {
        host: "192.0.2.10".to_string(),
        port: 3868,
        origin_host: "siphon.example.net".to_string(),
        origin_realm: "example.net".to_string(),
        destination_host: None,
        destination_realm: "example.net".to_string(),
        local_ip: "192.0.2.1".parse().expect("a literal address"),
        application_ids: vec![],
        watchdog_interval: 30,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: Default::default(),
        product_name: "SIPhon".to_string(),
        firmware_revision: 100,
    }
}

/// A request whose Session-Id starts with `kind`, identified by `id`.
fn incoming(kind: &str, id: u32) -> IncomingRequest {
    let request = DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code: 318,
        application_id: dictionary::S6A_APP_ID,
        hop_by_hop: id,
        end_to_end: id,
        avps: vec![
            Avp::utf8(dictionary::avp::SESSION_ID, 0, &format!("{kind};{id}")),
            Avp::utf8(dictionary::avp::ORIGIN_HOST, 0, "client.example.net"),
            Avp::utf8(dictionary::avp::ORIGIN_REALM, 0, "example.net"),
        ],
    };
    IncomingRequest {
        command_code: request.command_code,
        application_id: request.application_id,
        hop_by_hop: request.hop_by_hop,
        end_to_end: request.end_to_end,
        avps: serde_json::Value::Null,
        raw: request.to_wire(),
    }
}

/// One connection's worth of dispatch: requests go in, answers come out of
/// the peer's write channel.
struct Served {
    engine: Arc<ScriptEngine>,
    peer: Arc<DiameterPeer>,
    answers: mpsc::Receiver<Vec<u8>>,
}

impl Served {
    fn new() -> Self {
        install_probe_module();
        let engine =
            Arc::new(ScriptEngine::new_embedded(SCRIPT).expect("the test script compiles"));
        let (write_tx, answers) = mpsc::channel(256);
        let peer = Arc::new(DiameterPeer::new_for_test(peer_config(), write_tx));
        Self {
            engine,
            peer,
            answers,
        }
    }

    fn send(&self, kind: &str, id: u32) {
        tokio::spawn(dispatch_request(
            Arc::clone(&self.engine),
            Arc::clone(&self.peer),
            incoming(kind, id),
            PyInboundPeer {
                name: "client".to_string(),
                tenant: "default".to_string(),
                addr: "192.0.2.10:3868".to_string(),
                transport: "tcp".to_string(),
                host: String::new(),
            },
            "siphon.example.net".to_string(),
            "example.net".to_string(),
        ));
    }

    /// The next answer, raw and parsed.
    async fn answer(&mut self, within: Duration) -> (Vec<u8>, DiameterMsg) {
        let wire = tokio::time::timeout(within, self.answers.recv())
            .await
            .expect("every request is answered")
            .expect("the peer's write channel stays open");
        let parsed = DiameterMsg::from_wire(&wire).expect("the answer parses");
        (wire, parsed)
    }

    async fn ask(&mut self, kind: &str, id: u32) -> (Vec<u8>, DiameterMsg) {
        self.send(kind, id);
        self.answer(Duration::from_secs(10)).await
    }

    /// The length of the script's list `name`.
    fn count(&self, name: &str) -> usize {
        self.list(name).len()
    }

    fn list(&self, name: &str) -> Vec<String> {
        Python::attach(|python| {
            let state = self.engine.state();
            let handlers = state.handlers_for(&HandlerKind::DiameterOnRequestCompleted);
            let handler = handlers.first().expect("the completed hook is registered");
            handler
                .callable
                .bind(python)
                .getattr("__globals__")
                .and_then(|globals| globals.get_item(name))
                .and_then(|list| {
                    list.try_iter()?
                        .map(|item| Ok(item?.str()?.to_string()))
                        .collect::<PyResult<Vec<String>>>()
                })
                .expect("the script keeps the list")
        })
    }

    async fn completed(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.count("completed") < count {
            assert!(
                Instant::now() < deadline,
                "on_request_completed ran {} times of {count}",
                self.count("completed")
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn error_message(answer: &DiameterMsg) -> Option<String> {
    answer.get_str(dictionary::avp::ERROR_MESSAGE)
}

fn on_pools<F, Fut>(on: bool, scenario: F)
where
    F: FnOnce(Served) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        ensure_test_pools();
        let _switch = Switch::set(on);
        tokio::time::timeout(Duration::from_secs(90), scenario(Served::new()))
            .await
            .expect("the scenario finished");
    });
}

/// A handler with one await, one that gathers, one that raises and one whose
/// gather raises are answered byte for byte the same with the switch on as
/// with it off, after an awaiting `on_reply` rewrote the answer and with the
/// awaiting `on_request_completed` hook run. On, all three stages are stepped
/// by a runner and none is handed to asyncio.
#[test]
fn answers_are_identical_with_the_switch_on_and_off() {
    const KINDS: [&str; 4] = ["one", "gather", "raise", "gather-raise"];
    let seen = std::sync::Mutex::new(Vec::new());
    for on in [false, true] {
        let seen = &seen;
        on_pools(on, |mut served| async move {
            let before = totals();
            let demotions = crate::script::runner::demotions();
            let mut wires = Vec::new();
            for (index, kind) in KINDS.iter().enumerate() {
                let (wire, answer) = served.ask(kind, 0x100 + index as u32).await;
                match *kind {
                    "one" | "gather" => {
                        assert_eq!(answer.answer_result_codes().0, Some(2001));
                        assert_eq!(
                            error_message(&answer).as_deref(),
                            Some(if *kind == "one" {
                                "one=7"
                            } else {
                                "gather=2,5"
                            })
                        );
                        assert_eq!(
                            answer.get_str(dictionary::avp::ORIGIN_HOST).as_deref(),
                            Some("rewritten.example.net"),
                            "the awaiting on_reply rewrote the answer"
                        );
                    }
                    _ => {
                        assert_eq!(
                            answer.answer_result_codes().0,
                            Some(dictionary::DIAMETER_UNABLE_TO_COMPLY)
                        );
                        assert_eq!(
                            error_message(&answer).as_deref(),
                            Some("on_request handler raised")
                        );
                    }
                }
                wires.push(wire);
            }
            served.completed(2).await;
            let after = totals();
            if on {
                // The request handler of each, and the reply handler and the
                // completed hook of the two that were answered by the script.
                assert_eq!(after.direct_starts - before.direct_starts, 8);
                assert_eq!(
                    crate::script::runner::demotions(),
                    demotions,
                    "no handler was handed to asyncio"
                );
            } else {
                assert_eq!(after.direct_starts, before.direct_starts);
            }
            settles_to(before, "after the requests").await;
            seen.lock().expect("unpoisoned").push(wires);
        });
    }
    let seen = seen.into_inner().expect("unpoisoned");
    assert_eq!(seen.len(), 2);
    for (kind, (off, on)) in KINDS.iter().zip(seen[0].iter().zip(&seen[1])) {
        assert_eq!(off, on, "{kind}: off and on answer differently");
    }
}

/// More handlers awaiting at once than the executor has threads are all
/// answered, side by side: a direct drive holds no worker while it waits.
#[test]
fn awaiting_handlers_beyond_the_executor_size_are_answered_side_by_side() {
    on_pools(true, |mut served| async move {
        let (executor, _) = ensure_test_pools();
        let before = totals();
        let requests = 2 * executor.max_size() + 1;
        let started = Instant::now();
        for index in 0..requests {
            served.send("slow", 0x200 + index as u32);
        }
        for _ in 0..requests {
            let (_, answer) = served.answer(Duration::from_secs(15)).await;
            assert_eq!(answer.answer_result_codes().0, Some(2001));
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "{requests} requests whose handlers each await 1 s on {} executor workers \
             took {elapsed:?}",
            executor.max_size()
        );
        served.completed(requests).await;
        settles_to(before, "after the slow handlers").await;
    });
}

/// With every runner at its limit a new request is answered
/// DIAMETER_TOO_BUSY (3004), at once, its handler never runs and the refusal
/// is counted. The requests in flight are answered as usual, their reply and
/// completed handlers are not refused although the runners are full, and
/// once there is room requests are served again.
#[test]
fn a_request_no_runner_has_room_for_is_answered_too_busy() {
    on_pools(true, |mut served| async move {
        let (_, async_pool) = ensure_test_pools();
        let before = totals();
        crate::script::runner::set_admission_limit_for_test(1);
        let room = async_pool.size();
        for index in 0..room {
            served.send("hold", 0x300 + index as u32);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while totals().in_flight < before.in_flight + room {
            assert!(Instant::now() < deadline, "every runner filled");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        let rejected = crate::script::runner::admission_rejected();
        let started = Instant::now();
        let (_, refused) = served.ask("one", 0x3ff).await;
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the refusal waited for room: {:?}",
            started.elapsed()
        );
        assert_eq!(
            refused.answer_result_codes().0,
            Some(dictionary::DIAMETER_TOO_BUSY)
        );
        assert!(refused.flags & FLAG_ERROR != 0, "a protocol error: E bit");
        assert_eq!((refused.hop_by_hop, refused.end_to_end), (0x3ff, 0x3ff));
        assert_eq!(crate::script::runner::admission_rejected() - rejected, 1);
        assert!(
            !served.list("calls").contains(&"one".to_string()),
            "the refused handler's body never ran"
        );
        assert_eq!(
            totals().in_flight,
            before.in_flight + room,
            "a refused request took no place"
        );

        // The holders finish while the runners are still full of each other:
        // their later stages are not refused.
        for _ in 0..room {
            let (_, answer) = served.answer(Duration::from_secs(10)).await;
            assert_eq!(answer.answer_result_codes().0, Some(2001));
            assert_eq!(
                answer.get_str(dictionary::avp::ORIGIN_HOST).as_deref(),
                Some("rewritten.example.net")
            );
        }
        served.completed(room).await;
        settles_to(before, "after the held requests").await;

        let (_, answer) = served.ask("one", 0x3fe).await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(crate::script::runner::admission_rejected() - rejected, 1);
    });
}

/// The leak test: requests that are answered and requests whose handler
/// never settles. The second kind is answered 5012 at the coroutine timeout,
/// in both modes, and the slab, the gathers, the awaitables, the admissions
/// and the pending count come back to where they started.
#[test]
fn answered_and_timed_out_requests_leak_nothing() {
    for on in [false, true] {
        on_pools(on, |mut served| async move {
            let (_, async_pool) = ensure_test_pools();
            let before = totals();
            let pending = crate::script::async_pool::pending_coroutines();
            const REQUESTS: usize = 5;
            for index in 0..REQUESTS {
                served.send("wedged", 0x400 + index as u32);
                served.send("gather", 0x500 + index as u32);
                served.send("gather-raise", 0x600 + index as u32);
            }
            let mut codes = Vec::new();
            for _ in 0..3 * REQUESTS {
                let within = async_pool.coroutine_timeout() + Duration::from_secs(10);
                let (_, answer) = served.answer(within).await;
                codes.push((answer.hop_by_hop >> 8, answer.answer_result_codes().0));
            }
            codes.sort_unstable();
            let mut expected = vec![(4, Some(dictionary::DIAMETER_UNABLE_TO_COMPLY)); REQUESTS];
            expected.extend(vec![(5, Some(2001)); REQUESTS]);
            expected.extend(vec![
                (6, Some(dictionary::DIAMETER_UNABLE_TO_COMPLY));
                REQUESTS
            ]);
            assert_eq!(codes, expected, "on = {on}");
            served.completed(REQUESTS).await;
            settles_to(before, "after answered and timed-out requests").await;
            let deadline = Instant::now() + Duration::from_secs(5);
            while crate::script::async_pool::pending_coroutines() > pending {
                assert!(Instant::now() < deadline, "the pending count came back");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let after = totals();
            assert_eq!(
                (
                    after.drives,
                    after.gathers,
                    after.awaitables,
                    after.in_flight
                ),
                (
                    before.drives,
                    before.gathers,
                    before.awaitables,
                    before.in_flight
                )
            );
        });
    }
}

/// Requests keep being answered while another thread forces stop-the-world
/// collections: the direct drive of all three stages, a gather's completion
/// and the answer's send happen with the world being stopped around them,
/// and no thread on the path waits attached. Run in a child process so that
/// a deadlock is a failure, not a hung test run.
#[test]
fn serving_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::serving_survives_stop_the_world_collections"
        ),
        Duration::from_secs(150),
    ) {
        return;
    }
    on_pools(true, |mut served| async move {
        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let before = totals();
        const REQUESTS: usize = 48;
        for round in 0..3u32 {
            for index in 0..REQUESTS as u32 {
                served.send("one", 0x1000 * (round + 1) + 3 * index);
                served.send("gather", 0x1000 * (round + 1) + 3 * index + 1);
                served.send("gather-raise", 0x1000 * (round + 1) + 3 * index + 2);
            }
            let mut served_ok = 0;
            for _ in 0..3 * REQUESTS {
                let (_, answer) = served.answer(Duration::from_secs(40)).await;
                match answer.answer_result_codes().0 {
                    Some(2001) => served_ok += 1,
                    code => assert_eq!(code, Some(dictionary::DIAMETER_UNABLE_TO_COMPLY)),
                }
            }
            assert_eq!(served_ok, 2 * REQUESTS, "round {round}");
        }
        served.completed(3 * 2 * REQUESTS).await;
        settles_to(before, "under collections").await;
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}
