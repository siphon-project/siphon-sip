//! A REGISTER as received (`request.wire`), and what `@registrar.on_change`
//! is told of it (`exchange=`): the request byte for byte, the 200 OK siphon
//! sent for it, delivered after that 200 is with the transport (3GPP TS 24.229
//! clause 5.4.1.7).
//!
//! Everything runs through `handle_request` with a script whose handler calls
//! the real `registrar.save()`, and the change events run through the same
//! drain and delivery the server uses. A unit test on the exchange or the hold
//! alone stays green when the dispatcher never hands the response over, or
//! publishes the event before the reply.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pyo3::types::{PyAnyMethods, PyModule, PyModuleMethods};

use super::registration_events::{drain_registrar_events, RegistrarChange};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::registrar::Registrar;
use crate::script::api::registrar::PyRegistrar;

const IMPU: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
const DEVICE: &str = "192.0.2.20:5070";

static PROBES: AtomicUsize = AtomicUsize::new(0);

/// One recorded `on_change` call: AoR, event, and the exchange's request and
/// response (`None` for no exchange, or for a response not yet known).
type Seen = (String, String, Option<Vec<u8>>, Option<Vec<u8>>);

struct Probe {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    registrar: Arc<Registrar>,
    /// How many frames were already queued for the transport each time a change
    /// reached the delivery.
    queued_at_delivery: Arc<Mutex<Vec<usize>>>,
}

/// A dispatcher whose script reaches the real registrar as `registrar` (the
/// script's `siphon.registrar` is a stub in a test process), running `body`.
fn probe(body: &str) -> Probe {
    Python::initialize();
    let registrar = Arc::new(Registrar::default());
    let module_name = format!(
        "register_exchange_probe_{}",
        PROBES.fetch_add(1, Ordering::SeqCst)
    );
    Python::attach(|python| {
        let module = PyModule::new(python, &module_name).expect("a module");
        module
            .add(
                "registrar",
                Py::new(python, PyRegistrar::new(Arc::clone(&registrar))).expect("the namespace"),
            )
            .expect("the attribute");
        let modules = python
            .import("sys")
            .and_then(|sys| sys.getattr("modules"))
            .expect("sys.modules");
        modules
            .set_item(&module_name, module)
            .expect("the module is importable");
    });
    let script = format!(
        "from siphon import proxy\nfrom {module_name} import registrar\nSEEN = []\nWIRE = []\n{body}"
    );
    let dispatcher = test_dispatcher_with_script(&script);
    let state = Arc::new(dispatcher.state);
    let queued_at_delivery = Arc::new(Mutex::new(Vec::new()));
    let runtime = super::async_request_handler_tests::test_runtime();
    {
        let state = Arc::clone(&state);
        let registrar = Arc::clone(&registrar);
        let udp = dispatcher.udp.clone();
        let queued = Arc::clone(&queued_at_delivery);
        runtime.spawn(drain_registrar_events(
            registrar.subscribe_events(),
            Arc::clone(&registrar),
            move |change| {
                queued
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(udp.len());
                super::tasks::deliver_registrar_change(
                    Arc::clone(&state),
                    Arc::clone(&registrar),
                    change,
                )
            },
        ));
    }
    Probe {
        state,
        udp: dispatcher.udp,
        registrar,
        queued_at_delivery,
    }
}

/// A REGISTER from `device` in the compact forms a real UE sends, header order
/// that is not siphon's, a folded header and a body.
fn register(call_id: &str, instance: &str, expires: u32) -> String {
    format!(
        concat!(
            "REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n",
            "Max-Forwards: 70\r\n",
            "v: SIP/2.0/UDP {device};branch=z9hG4bK-{call_id}\r\n",
            "t: <{impu}>\r\n",
            "f: <{impu}>;tag=ue-{call_id}\r\n",
            "Subject: folded\r\n",
            " across two lines\r\n",
            "i: {call_id}\r\n",
            "CSeq: 1 REGISTER\r\n",
            "m: <sip:001010000000001@192.0.2.20:5070>;+sip.instance=\"<urn:uuid:{instance}>\";expires={expires}\r\n",
            "c: text/plain\r\n",
            "l: 5\r\n",
            "\r\n",
            "hello",
        ),
        device = DEVICE,
        impu = IMPU,
        call_id = call_id,
        instance = instance,
        expires = expires,
    )
}

fn inbound(raw: &str) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: DEVICE.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string()),
    }
}

fn receive(probe: &Probe, raw: &str) {
    let _runtime = super::async_request_handler_tests::test_runtime()
        .handle()
        .enter();
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_request(inbound(raw), message, "REGISTER".to_string(), &probe.state);
}

/// A module-level list of the script's globals, `name`.
fn script_list<T>(
    probe: &Probe,
    name: &str,
    extract: impl Fn(&pyo3::Bound<'_, pyo3::PyAny>) -> T,
) -> Vec<T> {
    let engine_state = probe.state.engine.state();
    let handlers = engine_state.handlers_for(&crate::script::engine::HandlerKind::ProxyRequest(
        Some("REGISTER".to_string()),
    ));
    let handler = handlers.first().expect("the script has a REGISTER handler");
    pyo3::Python::attach(|python| {
        let globals = handler
            .callable
            .bind(python)
            .getattr("__globals__")
            .expect("globals");
        let list = globals.get_item(name).expect("the list");
        list.try_iter()
            .expect("iterable")
            .map(|item| extract(&item.expect("an item")))
            .collect()
    })
}

fn seen(probe: &Probe) -> Vec<Seen> {
    script_list(probe, "SEEN", |row| {
        let (aor, event, request, response): (String, String, Option<Vec<u8>>, Option<Vec<u8>>) =
            row.extract().expect("a four-tuple");
        (aor, event, request, response)
    })
}

/// Wait until the script has recorded `count` changes.
fn wait_for_changes(probe: &Probe, count: usize) -> Vec<Seen> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = seen(probe);
        if rows.len() >= count || Instant::now() > deadline {
            return rows;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Every frame the dispatcher queued for the transport so far.
fn sent(probe: &Probe) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    while let Ok(message) = probe.udp.try_recv() {
        for frame in message.frames() {
            frames.push(frame.to_vec());
        }
    }
    frames
}

const RECORD_AND_SAVE: &str = concat!(
    "@proxy.on_request(\"REGISTER\")\n",
    "def on_register(request):\n",
    "    WIRE.append(request.wire)\n",
    "    registrar.save(request)\n",
    "\n",
    "@registrar.on_change\n",
    "def on_change(aor, event, contacts, exchange):\n",
    "    SEEN.append((aor, event,\n",
    "                 exchange.request if exchange else None,\n",
    "                 exchange.response if exchange else None))\n",
);

#[test]
fn the_script_sees_the_request_exactly_as_it_was_received() {
    let probe = probe(RECORD_AND_SAVE);
    let raw = register("wire-1", "00000000-0000-4000-8000-000000000001", 3600);
    receive(&probe, &raw);

    let wire: Vec<Option<Vec<u8>>> = script_list(&probe, "WIRE", |value| {
        value.extract().expect("bytes or None")
    });
    assert_eq!(
        wire,
        vec![Some(raw.clone().into_bytes())],
        "compact forms, order, folding and body all as sent"
    );
}

#[test]
fn the_exchange_carries_the_request_and_the_200_that_was_sent_and_arrives_after_it() {
    let probe = probe(concat!(
        "import time\n",
        "@proxy.on_request(\"REGISTER\")\n",
        "def on_register(request):\n",
        "    registrar.save(request)\n",
        "    # The handler is slow to return: a change published at save() time\n",
        "    # would be delivered while the reply is still unsent.\n",
        "    time.sleep(0.3)\n",
        "\n",
        "@registrar.on_change\n",
        "def on_change(aor, event, contacts, exchange):\n",
        "    SEEN.append((aor, event, exchange.request, exchange.response))\n",
    ));
    let raw = register("order-1", "00000000-0000-4000-8000-000000000002", 3600);
    receive(&probe, &raw);

    let rows = wait_for_changes(&probe, 1);
    assert_eq!(rows.len(), 1, "one change: {rows:?}");
    let (aor, event, request, response) = &rows[0];
    assert_eq!(aor, IMPU);
    assert_eq!(event, "registered");
    assert_eq!(request.as_deref(), Some(raw.as_bytes()));

    let frames = sent(&probe);
    let ok = frames
        .iter()
        .find(|frame| frame.starts_with(b"SIP/2.0 200"))
        .expect("the 200 OK was queued");
    assert_eq!(
        response.as_deref(),
        Some(ok.as_slice()),
        "the response is the 200 as it went out"
    );
    let text = String::from_utf8_lossy(ok);
    assert!(
        text.contains(";tag="),
        "the response carries siphon's To-tag: {text}"
    );
    assert_eq!(
        *probe
            .queued_at_delivery
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        vec![1],
        "the 200 was already queued when the change was delivered"
    );
}

#[test]
fn two_devices_give_two_changes_each_with_its_own_request() {
    let probe = probe(RECORD_AND_SAVE);
    let first = register("device-a", "00000000-0000-4000-8000-00000000000a", 3600);
    let second = register("device-b", "00000000-0000-4000-8000-00000000000b", 3600);
    receive(&probe, &first);
    receive(&probe, &second);

    let rows = wait_for_changes(&probe, 2);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].1, "registered");
    assert_eq!(rows[0].2.as_deref(), Some(first.as_bytes()));
    assert_eq!(rows[1].2.as_deref(), Some(second.as_bytes()));
}

#[test]
fn a_de_register_carries_its_own_request() {
    let probe = probe(RECORD_AND_SAVE);
    let instance = "00000000-0000-4000-8000-0000000000dd";
    receive(&probe, &register("dereg-1", instance, 3600));
    let removal = register("dereg-2", instance, 0);
    receive(&probe, &removal);

    let rows = wait_for_changes(&probe, 2);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[1].1, "deregistered");
    assert_eq!(rows[1].2.as_deref(), Some(removal.as_bytes()));
    assert!(rows[1].3.is_some(), "the 200 to the de-REGISTER");
}

#[test]
fn an_expiry_carries_no_exchange_and_a_three_argument_handler_is_unchanged() {
    let probe = probe(concat!(
        "@proxy.on_request(\"REGISTER\")\n",
        "def on_register(request):\n",
        "    registrar.save(request)\n",
        "\n",
        "@registrar.on_change\n",
        "def with_exchange(aor, event, contacts, exchange):\n",
        "    SEEN.append((aor, event, exchange.request if exchange else None, None))\n",
        "\n",
        "ARGUMENTS = []\n",
        "@registrar.on_change\n",
        "def three(aor, event, contacts):\n",
        "    ARGUMENTS.append(3)\n",
    ));
    let runtime = super::async_request_handler_tests::test_runtime();
    runtime.block_on(super::tasks::deliver_registrar_change(
        Arc::clone(&probe.state),
        Arc::clone(&probe.registrar),
        RegistrarChange {
            aor: IMPU.to_string(),
            event: "expired",
            exchange: None,
        },
    ));
    let rows = seen(&probe);
    assert_eq!(
        rows,
        vec![(IMPU.to_string(), "expired".to_string(), None, None)]
    );
    let engine_state = probe.state.engine.state();
    let handlers =
        engine_state.handlers_for(&crate::script::engine::HandlerKind::RegistrarOnChange);
    assert_eq!(handlers.len(), 2);
    assert!(handlers[0].takes_exchange);
    assert!(
        !handlers[1].takes_exchange,
        "the 3-argument handler is not passed one"
    );
    let called: Vec<i32> = pyo3::Python::attach(|python| {
        handlers[1]
            .callable
            .bind(python)
            .getattr("__globals__")
            .and_then(|globals| globals.get_item("ARGUMENTS"))
            .and_then(|list| list.extract())
            .expect("ARGUMENTS")
    });
    assert_eq!(called, vec![3], "the 3-argument handler ran, as before");
}

#[test]
fn a_handler_that_raises_after_save_still_delivers_the_change() {
    let probe = probe(concat!(
        "@proxy.on_request(\"REGISTER\")\n",
        "def on_register(request):\n",
        "    registrar.save(request)\n",
        "    raise RuntimeError(\"after the save\")\n",
        "\n",
        "@registrar.on_change\n",
        "def on_change(aor, event, contacts, exchange):\n",
        "    SEEN.append((aor, event, exchange.request, exchange.response))\n",
    ));
    let raw = register("raise-1", "00000000-0000-4000-8000-0000000000ee", 3600);
    receive(&probe, &raw);

    let rows = wait_for_changes(&probe, 1);
    assert_eq!(rows.len(), 1, "the change was not lost: {rows:?}");
    assert_eq!(rows[0].2.as_deref(), Some(raw.as_bytes()));
    assert!(
        sent(&probe)
            .iter()
            .any(|frame| frame.starts_with(b"SIP/2.0 500")),
        "the failed handler is answered 500"
    );
}

#[test]
fn every_change_is_delivered_when_some_handlers_raise_and_none_stays_held() {
    let probe = probe(concat!(
        "@proxy.on_request(\"REGISTER\")\n",
        "def on_register(request):\n",
        "    registrar.save(request)\n",
        "    if request.call_id.endswith('x'):\n",
        "        raise RuntimeError('every other one')\n",
        "\n",
        "@registrar.on_change\n",
        "def on_change(aor, event, contacts, exchange):\n",
        "    SEEN.append((aor, event, exchange.request, exchange.response))\n",
    ));
    let rounds = 20;
    for round in 0..rounds {
        let call_id = if round % 2 == 0 {
            format!("leak-{round}x")
        } else {
            format!("leak-{round}")
        };
        receive(
            &probe,
            &register(
                &call_id,
                &format!("00000000-0000-4000-8000-{round:012}"),
                3600,
            ),
        );
    }
    let rows = wait_for_changes(&probe, rounds);
    assert_eq!(rows.len(), rounds, "no change was lost");
    // Nothing is left for a later flush: the registrar's own subscriber sees no
    // event beyond the ones delivered.
    let mut late = probe.registrar.subscribe_events();
    std::thread::sleep(Duration::from_millis(100));
    assert!(late.try_recv().is_err(), "no event was still held back");
}
