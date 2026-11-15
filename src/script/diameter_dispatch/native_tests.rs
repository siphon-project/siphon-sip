//! Requests with a native handler, through the dispatch every inbound
//! connection uses: answered without the script, handed to it once when the
//! handler declines, shed like any other above the admission limit, counted
//! under their own `path`, and relayed the way `request.forward_to` relays.

use std::time::Duration;

use super::*;
use crate::config::{DiameterServerEntry, DiameterTenant, DiameterTenantIdentity};
use crate::diameter::codec::{FLAG_PROXIABLE, FLAG_REQUEST, FLAG_RETRANSMITTED};
use crate::diameter::native::tests::{
    calls as native_calls, install_test_handlers, TEST_APPLICATION, TEST_COMMAND,
    TEST_NAMED_COMMAND,
};
use crate::diameter::overload::{self, Overload};
use crate::script::async_pool::{ensure_test_pools, pool_test_guard, test_pools_runtime};

/// A catch-all script handler that counts its calls by Session-Id.
const SCRIPT: &str = concat!(
    "import _siphon_registry\n",
    "\n",
    "calls = []\n",
    "\n",
    "def handle(request):\n",
    "    calls.append(request.session_id)\n",
    "    return request.answer(2001)\n",
    "\n",
    "_siphon_registry.register('diameter.on_request', None, handle, False)\n",
);

fn script_calls(engine: &ScriptEngine, session_id: &str) -> usize {
    Python::attach(|python| {
        let state = engine.state();
        let handlers = state.handlers_for(&HandlerKind::DiameterOnRequest(None));
        let handler = handlers.first().expect("the handler is registered");
        handler
            .callable
            .bind(python)
            .getattr("__globals__")
            .and_then(|globals| globals.get_item("calls"))
            .and_then(|calls| calls.call_method1("count", (session_id,)))
            .and_then(|count| count.extract::<usize>())
            .expect("the script keeps a call list")
    })
}

fn peer_config(origin_host: &str) -> PeerConfig {
    PeerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        origin_host: origin_host.to_string(),
        origin_realm: "example.com".to_string(),
        destination_host: None,
        destination_realm: "example.com".to_string(),
        local_ip: "127.0.0.1".parse().expect("a literal address"),
        application_ids: vec![(10_415, dictionary::S6A_APP_ID)],
        watchdog_interval: 30,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: Default::default(),
        product_name: "far".to_string(),
        firmware_revision: 1,
    }
}

/// A request for the test handlers, steered by its Session-Id.
fn request(session_id: &str, command_code: u32, extra: Vec<Avp>) -> DiameterMsg {
    let mut avps = vec![
        Avp::utf8(dictionary::avp::SESSION_ID, 0, session_id),
        Avp::grouped(
            dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID,
            0,
            vec![
                Avp::u32(dictionary::avp::VENDOR_ID, 0, dictionary::VENDOR_3GPP),
                Avp::u32(dictionary::avp::AUTH_APPLICATION_ID, 0, TEST_APPLICATION),
            ],
        ),
        Avp::u32(dictionary::avp::AUTH_SESSION_STATE, 0, 1),
        Avp::utf8(dictionary::avp::ORIGIN_HOST, 0, "mme-1.example.com"),
        Avp::utf8(dictionary::avp::ORIGIN_REALM, 0, "example.com"),
        Avp::utf8(dictionary::avp::DESTINATION_REALM, 0, "example.com"),
        Avp::utf8(dictionary::avp::USER_NAME, 0, "001010000000001"),
    ];
    avps.extend(extra);
    DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code,
        application_id: TEST_APPLICATION,
        hop_by_hop: 0x0A0B_0C0D,
        end_to_end: 0x0102_0304,
        avps,
    }
}

fn incoming(request: &DiameterMsg) -> IncomingRequest {
    IncomingRequest {
        command_code: request.command_code,
        application_id: request.application_id,
        hop_by_hop: request.hop_by_hop,
        end_to_end: request.end_to_end,
        avps: serde_json::Value::Null,
        raw: request.to_wire(),
    }
}

fn peer_info() -> PyInboundPeer {
    PyInboundPeer {
        name: "mme".to_string(),
        tenant: "default".to_string(),
        addr: "192.0.2.10:3868".to_string(),
        transport: "tcp".to_string(),
        host: String::new(),
    }
}

/// Dispatch `request` as a connection does and return every answer sent
/// for it: the first, and whatever else arrives shortly after.
async fn dispatch(engine: &Arc<ScriptEngine>, request: &DiameterMsg) -> Vec<Vec<u8>> {
    let (write_tx, mut write_rx) = mpsc::channel(4);
    let inbound_peer = Arc::new(DiameterPeer::new_for_test(
        peer_config("siphon.example.com"),
        write_tx,
    ));
    tokio::spawn(dispatch_request(
        Arc::clone(engine),
        inbound_peer,
        incoming(request),
        peer_info(),
        "siphon.example.com".to_string(),
        "example.com".to_string(),
    ));
    let first = tokio::time::timeout(Duration::from_secs(10), write_rx.recv())
        .await
        .expect("every request is answered")
        .expect("the peer's write channel stays open");
    let mut answers = vec![first];
    while let Ok(Some(more)) =
        tokio::time::timeout(Duration::from_millis(100), write_rx.recv()).await
    {
        answers.push(more);
    }
    answers
}

async fn dispatch_one(engine: &Arc<ScriptEngine>, request: &DiameterMsg) -> DiameterMsg {
    let answers = dispatch(engine, request).await;
    assert_eq!(answers.len(), 1, "one answer to one request");
    DiameterMsg::from_wire(&answers[0]).expect("the answer parses")
}

fn engine() -> Arc<ScriptEngine> {
    install_test_handlers();
    ensure_test_pools();
    Arc::new(ScriptEngine::new_embedded(SCRIPT).expect("the test script compiles"))
}

fn counter(vector: &prometheus::IntCounterVec, labels: &[&str]) -> u64 {
    vector.with_label_values(labels).get()
}

#[test]
fn a_request_with_a_handler_is_answered_without_the_script() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        let engine = engine();
        let session = "answer;dispatch;1";
        let answer = dispatch_one(&engine, &request(session, TEST_COMMAND, Vec::new())).await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(answer.hop_by_hop, 0x0A0B_0C0D);
        assert_eq!(answer.end_to_end, 0x0102_0304);
        assert_eq!(
            answer.get_str(dictionary::avp::ORIGIN_HOST).as_deref(),
            Some("siphon.example.com")
        );
        assert_eq!(native_calls(session), 1);
        assert_eq!(script_calls(&engine, session), 0, "the script never ran");
    });
}

/// The answer a handler builds is, byte for byte, the answer a script
/// builds with `request.answer()` for the same request.
#[test]
fn a_native_answer_is_the_script_answer_for_the_same_request() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        let engine = engine();
        let request = request("answer;dispatch;2", TEST_COMMAND, Vec::new());
        let native = dispatch(&engine, &request).await.remove(0);
        let script = Python::attach(|python| {
            build_answer_via_handler(
                python,
                &engine,
                &incoming(&request),
                &peer_info(),
                "siphon.example.com",
                "example.com",
            )
            .into_done()
            .wire
        });
        assert_eq!(native, script);
        // Not a comparison of two empty envelopes.
        let answer = DiameterMsg::from_wire(&native).expect("the answer parses");
        let codes: Vec<u32> = answer.avps.iter().map(|avp| avp.code).collect();
        assert_eq!(
            codes,
            [
                dictionary::avp::SESSION_ID,
                dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID,
                dictionary::avp::RESULT_CODE,
                dictionary::avp::AUTH_SESSION_STATE,
                dictionary::avp::ORIGIN_HOST,
                dictionary::avp::ORIGIN_REALM,
            ]
        );
    });
}

#[test]
fn a_handler_that_declines_hands_the_request_to_the_script_once() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        crate::metrics::init().ok();
        let metrics = crate::metrics::try_metrics().expect("metrics are initialised");
        let engine = engine();
        let session = "script;dispatch;3";
        let request = request(session, TEST_NAMED_COMMAND, Vec::new());
        let requests = |path: &str| {
            counter(
                &metrics.diameter_inbound_requests_total,
                &[
                    crate::diameter::codec::command_name(TEST_NAMED_COMMAND, true),
                    path,
                ],
            )
        };
        let (script_before, native_before) = (requests("script"), requests("native"));

        let answer = dispatch_one(&engine, &request).await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(native_calls(session), 1);
        assert_eq!(script_calls(&engine, session), 1, "exactly once");
        // Counted once, by the path that answered it.
        assert_eq!(requests("script"), script_before + 1);
        assert_eq!(requests("native"), native_before);

        // The script answers it as it answers a request no handler is
        // registered for: the same bytes as the script path alone gives.
        let alone = Python::attach(|python| {
            build_answer_via_handler(
                python,
                &engine,
                &incoming(&request),
                &peer_info(),
                "siphon.example.com",
                "example.com",
            )
            .into_done()
            .wire
        });
        assert_eq!(answer.to_wire(), alone);
    });
}

#[test]
fn a_request_without_a_handler_goes_to_the_script_as_before() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        let engine = engine();
        let session = "answer;dispatch;4";
        let mut other = request(session, 318, Vec::new());
        other.application_id = dictionary::S6A_APP_ID;
        let answer = dispatch_one(&engine, &other).await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(native_calls(session), 0);
        assert_eq!(script_calls(&engine, session), 1);
    });
}

#[test]
fn a_handler_that_fails_or_panics_is_answered_5012_and_the_script_is_not_asked() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        let engine = engine();
        for kind in ["error", "panic", "panic-late"] {
            let session = format!("{kind};dispatch;5");
            let answer = dispatch_one(&engine, &request(&session, TEST_COMMAND, Vec::new())).await;
            assert_eq!(answer.answer_result_codes().0, Some(5012), "{kind}");
            assert!(answer.is_error(), "{kind}");
            assert_eq!(answer.hop_by_hop, 0x0A0B_0C0D, "{kind}");
            assert_eq!(
                answer.get_str(dictionary::avp::SESSION_ID).as_deref(),
                Some(session.as_str())
            );
            assert_eq!(native_calls(&session), 1, "{kind}");
            assert_eq!(script_calls(&engine, &session), 0, "{kind}");
        }
    });
}

#[test]
fn above_the_admission_limit_the_handler_is_not_called() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        let engine = engine();
        let config: crate::config::DiameterConfig = serde_saphyr::from_str(
            "overload:\n  reporting:\n    validity: 30\n    admission_limit: 0\n",
        )
        .expect("the configuration parses");
        overload::install(Overload::from_config(config.overload.as_ref()));
        let session = "answer;dispatch;6";
        let advertising = vec![overload::supported_features_avp(overload::FEATURE_LOSS)];
        let shed = dispatch_one(
            &engine,
            &request(session, TEST_COMMAND, advertising.clone()),
        )
        .await;
        assert_eq!(shed.answer_result_codes().0, Some(3004));
        assert!(
            overload::parse_olr(&shed).is_some(),
            "the 3004 carries the OC-OLR"
        );
        assert_eq!(native_calls(session), 0, "the handler was never called");

        // Within the limit the handler serves it, and its answer carries
        // this node's DOIC features as an answer of the script path does.
        let config: crate::config::DiameterConfig =
            serde_saphyr::from_str("overload:\n  reporting:\n    admission_limit: 100\n")
                .expect("the configuration parses");
        overload::install(Overload::from_config(config.overload.as_ref()));
        let served = dispatch_one(&engine, &request(session, TEST_COMMAND, advertising)).await;
        assert_eq!(served.answer_result_codes().0, Some(2001));
        assert!(overload::supports_loss(&served));
        assert_eq!(native_calls(session), 1);

        // A requester that did not advertise DOIC is told nothing of it.
        let plain = dispatch_one(&engine, &request(session, TEST_COMMAND, Vec::new())).await;
        assert!(!overload::supports_loss(&plain));
        overload::install(Overload::new(false, None));
    });
}

#[test]
fn a_native_answer_is_counted_under_its_own_path() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        crate::metrics::init().ok();
        let metrics = crate::metrics::try_metrics().expect("metrics are initialised");
        let engine = engine();
        let request_name = crate::diameter::codec::command_name(TEST_NAMED_COMMAND, true);
        let answer_name = crate::diameter::codec::command_name(TEST_NAMED_COMMAND, false);
        let read = || {
            (
                counter(
                    &metrics.diameter_inbound_requests_total,
                    &[request_name, "native"],
                ),
                counter(
                    &metrics.diameter_inbound_answers_total,
                    &[answer_name, "2001", "native"],
                ),
                counter(
                    &metrics.diameter_inbound_answers_total,
                    &[answer_name, "5012", "native"],
                ),
                metrics
                    .diameter_inbound_duration_seconds
                    .with_label_values(&[request_name, "native"])
                    .get_sample_count(),
                counter(
                    &metrics.diameter_inbound_requests_total,
                    &[request_name, "script"],
                ),
            )
        };
        let before = read();
        dispatch_one(
            &engine,
            &request("answer;dispatch;7", TEST_NAMED_COMMAND, Vec::new()),
        )
        .await;
        dispatch_one(
            &engine,
            &request("error;dispatch;7", TEST_NAMED_COMMAND, Vec::new()),
        )
        .await;
        let after = read();
        assert_eq!(after.0, before.0 + 2, "requests, path=native");
        assert_eq!(after.1, before.1 + 1, "answers 2001, path=native");
        assert_eq!(after.2, before.2 + 1, "answers 5012, path=native");
        assert_eq!(after.3, before.3 + 2, "duration samples, path=native");
        assert_eq!(after.4, before.4, "nothing under path=script");

        // An experimental result is labelled as on the script path.
        let label = dictionary::answer_result_label(None, Some(5001));
        let labelled = || {
            counter(
                &metrics.diameter_inbound_answers_total,
                &[answer_name, label, "native"],
            )
        };
        let labelled_before = labelled();
        let answer = dispatch_one(
            &engine,
            &request("experimental;dispatch;7", TEST_NAMED_COMMAND, Vec::new()),
        )
        .await;
        assert_eq!(answer.answer_result_codes(), (None, Some(5001)));
        assert_eq!(labelled(), labelled_before + 1, "{label}");
    });
}

/// Accept one connection on a loopback port and complete its capabilities
/// exchange as `origin_host`.
async fn far_end(
    origin_host: &'static str,
) -> (
    u16,
    tokio::task::JoinHandle<(Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>)>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("bound").port();
    let accepted = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("the server connects");
        peer::accept(stream.into(), peer_config(origin_host))
            .await
            .expect("the capabilities exchange completes")
    });
    (port, accepted)
}

async fn listed(tenant: &str, host: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while crate::diameter::directory::find(tenant, host).is_none() {
        assert!(Instant::now() < deadline, "{host} is never listed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn entry(name: &str, port: u16) -> DiameterServerEntry {
    DiameterServerEntry {
        all_addresses: false,
        name: name.to_string(),
        host: "127.0.0.1".to_string(),
        port,
        transport: "tcp".to_string(),
        ..Default::default()
    }
}

/// Over real connections: a request one peer sends is answered by a handler,
/// and one the handler relays reaches the peer its Destination-Host names
/// with what `request.forward_to` gives a relayed request: the Route-Record
/// of the previous hop, a Hop-by-Hop of this node, the End-to-End it came
/// with, and this node's 3004 or 3002 when there is no answer or no peer.
#[test]
fn over_a_connection_a_handler_answers_and_relays_as_the_script_relay_does() {
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        let engine = engine();
        let tenant = DiameterTenant {
            identity: DiameterTenantIdentity {
                origin_host: "agent-1.example.com".to_string(),
                origin_realm: "example.com".to_string(),
            },
            ..DiameterTenant::default()
        };
        let applications: TenantApplications = Arc::new(|_| vec![(10_415, dictionary::S6A_APP_ID)]);
        let semaphore = Arc::new(Semaphore::new(8));

        // The client: a peer this node dials, which sends the requests.
        let (client_port, client) = far_end("client-1.example.com").await;
        spawn_backend_connection(
            "t-native",
            &tenant,
            &entry("client", client_port),
            Arc::new(DiameterManager::new()),
            Arc::clone(&engine),
            Arc::clone(&semaphore),
            Arc::clone(&applications),
            "SIPhon",
            "1.0.0",
        );
        // The server: a peer on a connection of its own, which answers.
        let (server_port, server) = far_end("server-1.example.com").await;
        spawn_serving_connection(
            "t-native".to_string(),
            ("agent-1.example.com".to_string(), "example.com".to_string()),
            entry("server", server_port),
            Arc::clone(&engine),
            Arc::clone(&semaphore),
            Arc::clone(&applications),
            "SIPhon",
            "1.0.0",
        );
        let (client_peer, _client_incoming) = client.await.expect("the client accepts");
        let (server_peer, mut server_incoming) = server.await.expect("the server accepts");
        let answering = Arc::clone(&server_peer);
        let (seen_tx, mut seen) = mpsc::channel::<DiameterMsg>(4);
        tokio::spawn(async move {
            while let Some(incoming) = server_incoming.recv().await {
                let request = DiameterMsg::from_wire(&incoming.raw).expect("the request parses");
                let silent = request.get_str(dictionary::avp::USER_NAME).as_deref()
                    == Some("001010000000002");
                let answer = forward::build_answer(
                    &request,
                    "server-1.example.com",
                    "example.com",
                    2001,
                    None,
                );
                let _ = seen_tx.send(request).await;
                // One subscriber's requests are never answered.
                if !silent {
                    let _ = answering.send_response(answer.to_wire()).await;
                }
            }
        });
        listed("t-native", "client-1.example.com").await;
        listed("t-native", "server-1.example.com").await;

        // The client's identifiers start at 0x7000_0000, apart from this
        // node's counter towards the server, which starts at 1.
        let send = |session: &'static str, user: &'static str, host: &'static str| {
            let mut message = request(
                session,
                TEST_COMMAND,
                vec![Avp::utf8(dictionary::avp::DESTINATION_HOST, 0, host)],
            );
            message
                .avps
                .retain(|avp| avp.code != dictionary::avp::USER_NAME);
            message
                .avps
                .push(Avp::utf8(dictionary::avp::USER_NAME, 0, user));
            message.hop_by_hop = 0x7000_0000 + client_peer.next_hbh();
            message.end_to_end = 0x5151;
            let client_peer = Arc::clone(&client_peer);
            async move {
                let answer = client_peer
                    .send_request_timeout(message.to_wire(), Duration::from_secs(5))
                    .await
                    .expect("every request is answered, with the Hop-by-Hop it was sent with");
                DiameterMsg::from_wire(&answer.raw).expect("the answer parses")
            }
        };

        // Answered here, by the handler.
        let session = "answer;socket;1";
        let answer = send(session, "001010000000001", "agent-1.example.com").await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(
            answer.get_str(dictionary::avp::ORIGIN_HOST).as_deref(),
            Some("agent-1.example.com")
        );
        assert_eq!(answer.end_to_end, 0x5151);
        assert_eq!(native_calls(session), 1);
        assert_eq!(script_calls(&engine, session), 0);

        // Relayed to the peer its Destination-Host names.
        let answer = send("relay;socket;2", "001010000000001", "server-1.example.com").await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(
            answer.get_str(dictionary::avp::ORIGIN_HOST).as_deref(),
            Some("server-1.example.com"),
            "the server answered"
        );
        let relayed = seen.recv().await.expect("the server saw the request");
        // RFC 6733 section 6.1.9: the peer the request was received from.
        let records: Vec<String> = relayed
            .find_all(dictionary::avp::ROUTE_RECORD, 0)
            .filter_map(Avp::as_str)
            .collect();
        assert_eq!(records, ["client-1.example.com"]);
        assert_eq!(relayed.flags & FLAG_RETRANSMITTED, 0);
        assert_eq!(relayed.end_to_end, 0x5151, "End-to-End preserved");
        assert!(
            relayed.hop_by_hop < 0x7000_0000,
            "a Hop-by-Hop of this node"
        );

        // The server stays silent: this node's 3004, matched by the client
        // on its own Hop-by-Hop Identifier (RFC 6733 section 6.2).
        let answer = send("relay;socket;3", "001010000000002", "server-1.example.com").await;
        assert_eq!(answer.answer_result_codes().0, Some(3004));
        assert_eq!(
            answer.get_str(dictionary::avp::ORIGIN_HOST).as_deref(),
            Some("agent-1.example.com")
        );
        seen.recv()
            .await
            .expect("the server saw the second request");

        // A retransmission carries T (RFC 6733 section 5.5.4).
        let answer = send("relay;socket;4", "001010000000003", "server-1.example.com").await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        let again = seen
            .recv()
            .await
            .expect("the server saw the retransmission");
        assert_ne!(again.flags & FLAG_RETRANSMITTED, 0);
        assert_eq!(again.end_to_end, 0x5151);

        // A host no connection has: the handler's 3002.
        let answer = send("relay;socket;5", "001010000000001", "server-9.example.com").await;
        assert_eq!(answer.answer_result_codes().0, Some(3002));

        // A request back through this node is a loop (RFC 6733 section 6.3).
        let mut looping = request(
            "relay;socket;6",
            TEST_COMMAND,
            vec![
                Avp::utf8(dictionary::avp::DESTINATION_HOST, 0, "server-1.example.com"),
                Avp::utf8(dictionary::avp::ROUTE_RECORD, 0, "agent-1.example.com"),
            ],
        );
        looping.hop_by_hop = 0x7000_0000 + client_peer.next_hbh();
        let answer = client_peer
            .send_request_timeout(looping.to_wire(), Duration::from_secs(5))
            .await
            .expect("the loop is answered");
        let answer = DiameterMsg::from_wire(&answer.raw).expect("the answer parses");
        assert_eq!(answer.answer_result_codes().0, Some(3005));

        server_peer.shutdown();
        client_peer.shutdown();
    });
}

/// A catch-all handler through the dispatch every connection uses. In a
/// process of its own, with its own set of handlers in force: the other
/// tests of this binary share a set that has no catch-all.
#[test]
fn a_catch_all_handler_serves_what_no_keyed_handler_takes() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_catch_all_handler_serves_what_no_keyed_handler_takes"
        ),
        catch_all_through_dispatch,
    );
}

fn catch_all_through_dispatch() {
    use crate::diameter::native::{self, NativeHandlers, NativeOutcome};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static KEYED: AtomicUsize = AtomicUsize::new(0);
    static ANY: AtomicUsize = AtomicUsize::new(0);

    let handlers = NativeHandlers::new()
        .handle(TEST_APPLICATION, TEST_COMMAND, |request| async move {
            KEYED.fetch_add(1, Ordering::SeqCst);
            Ok(NativeOutcome::Answer(
                request.answer_with_message(2001, "keyed"),
            ))
        })
        .and_then(|handlers| {
            handlers.handle_any(|request| async move {
                ANY.fetch_add(1, Ordering::SeqCst);
                let session = request.session_id().unwrap_or_default();
                match session.split(';').next().unwrap_or_default() {
                    "script" => Ok(NativeOutcome::Script),
                    "error" => Err("no route".into()),
                    "panic" => panic!("a catch-all bug"),
                    _ => Ok(NativeOutcome::Answer(
                        request.answer_with_message(2001, "catch-all"),
                    )),
                }
            })
        })
        .expect("one keyed handler and one catch-all");
    native::install(handlers).expect("nothing installed in this process yet");
    // An application the dictionary knows, served only by the catch-all, is
    // not advertised on its account.
    assert!(native::served_applications().is_empty());

    let made_by = |answer: &DiameterMsg| answer.get_str(dictionary::avp::ERROR_MESSAGE);
    // A request of an application no keyed handler names.
    let unkeyed = |session: &str, extra: Vec<Avp>| {
        let mut message = request(session, dictionary::CMD_PURGE_UE, extra);
        message.application_id = dictionary::S6A_APP_ID;
        message
    };

    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        ensure_test_pools();
        crate::metrics::init().ok();
        let metrics = crate::metrics::try_metrics().expect("metrics are initialised");
        let engine =
            Arc::new(ScriptEngine::new_embedded(SCRIPT).expect("the test script compiles"));
        let request_name = crate::diameter::codec::command_name(dictionary::CMD_PURGE_UE, true);
        let answer_name = crate::diameter::codec::command_name(dictionary::CMD_PURGE_UE, false);
        let requests = |path: &str| {
            counter(
                &metrics.diameter_inbound_requests_total,
                &[request_name, path],
            )
        };

        // The keyed handler wins; the catch-all is not asked.
        let answer =
            dispatch_one(&engine, &request("script;any;1", TEST_COMMAND, Vec::new())).await;
        assert_eq!(made_by(&answer).as_deref(), Some("keyed"));
        assert_eq!(
            (KEYED.load(Ordering::SeqCst), ANY.load(Ordering::SeqCst)),
            (1, 0)
        );

        // What no keyed handler takes goes to the catch-all, not the script.
        let session = "answer;any;2";
        let answer = dispatch_one(&engine, &unkeyed(session, Vec::new())).await;
        assert_eq!(made_by(&answer).as_deref(), Some("catch-all"));
        assert_eq!(answer.application_id, dictionary::S6A_APP_ID);
        assert_eq!(answer.hop_by_hop, 0x0A0B_0C0D);
        assert_eq!(ANY.load(Ordering::SeqCst), 1);
        assert_eq!(script_calls(&engine, session), 0);
        assert_eq!((requests("native"), requests("script")), (1, 0));

        // Declined: the script's own catch-all serves it, once, and it is
        // counted under the script's path only.
        let session = "script;any;3";
        let declined = unkeyed(session, Vec::new());
        let answer = dispatch_one(&engine, &declined).await;
        assert_eq!(answer.answer_result_codes().0, Some(2001));
        assert_eq!(made_by(&answer), None, "the script's answer");
        assert_eq!(ANY.load(Ordering::SeqCst), 2);
        assert_eq!(script_calls(&engine, session), 1, "exactly once");
        assert_eq!((requests("native"), requests("script")), (1, 1));
        // The bytes the script path alone gives for it.
        let alone = Python::attach(|python| {
            build_answer_via_handler(
                python,
                &engine,
                &incoming(&declined),
                &peer_info(),
                "siphon.example.com",
                "example.com",
            )
            .into_done()
            .wire
        });
        assert_eq!(answer.to_wire(), alone);

        // A base protocol request (a capabilities exchange sent again on
        // an open connection) is not the catch-all's: the script gets it.
        let session = "answer;any;base";
        let mut base = request(session, dictionary::CMD_CAPABILITIES_EXCHANGE, Vec::new());
        base.application_id = 0;
        let before = ANY.load(Ordering::SeqCst);
        dispatch_one(&engine, &base).await;
        assert_eq!(ANY.load(Ordering::SeqCst), before);
        assert_eq!(script_calls(&engine, session), 1);

        // A failure and a panic are answered 5012, without the script.
        for kind in ["error", "panic"] {
            let session = format!("{kind};any;4");
            let answer = dispatch_one(&engine, &unkeyed(&session, Vec::new())).await;
            assert_eq!(answer.answer_result_codes().0, Some(5012), "{kind}");
            assert_eq!(script_calls(&engine, &session), 0, "{kind}");
        }
        assert_eq!(
            counter(
                &metrics.diameter_inbound_answers_total,
                &[answer_name, "5012", "native"]
            ),
            2
        );
        assert_eq!((requests("native"), requests("script")), (3, 1));

        // Above the admission limit it is not called, and the 3004 carries
        // the overload report.
        let config: crate::config::DiameterConfig = serde_saphyr::from_str(
            "overload:\n  reporting:\n    validity: 30\n    admission_limit: 0\n",
        )
        .expect("the configuration parses");
        overload::install(Overload::from_config(config.overload.as_ref()));
        let advertising = vec![overload::supported_features_avp(overload::FEATURE_LOSS)];
        let before = ANY.load(Ordering::SeqCst);
        let shed = dispatch_one(&engine, &unkeyed("answer;any;5", advertising.clone())).await;
        assert_eq!(shed.answer_result_codes().0, Some(3004));
        assert!(overload::parse_olr(&shed).is_some());
        assert_eq!(ANY.load(Ordering::SeqCst), before, "never called");

        // Within it, its answer carries this node's DOIC features.
        let config: crate::config::DiameterConfig =
            serde_saphyr::from_str("overload:\n  reporting:\n    admission_limit: 100\n")
                .expect("the configuration parses");
        overload::install(Overload::from_config(config.overload.as_ref()));
        let served = dispatch_one(&engine, &unkeyed("answer;any;6", advertising)).await;
        assert_eq!(made_by(&served).as_deref(), Some("catch-all"));
        assert!(overload::supports_loss(&served));
        overload::install(Overload::new(false, None));
    });
}
