//! A P-CSCF under registration load keeps serving while the interpreter's
//! garbage collector stops the world, over and over.
//!
//! The REGISTER handler is `async def` and awaits before it relays, as an IMS
//! P-CSCF's does, so every REGISTER finishes on the resumed path: the relay,
//! its DNS lookup of the next hop, and the send. The UEs reach the P-CSCF over
//! IPsec security associations on the in-memory kernel. While they register,
//! one thread collects garbage in a loop, which on free-threaded CPython stops
//! the world each time, and tokio tasks attach to the interpreter the way
//! script awaitables' completions do, so a stop-the-world parks every tokio
//! worker it reaches.
//!
//! When the resumed relay ran attached, its DNS wait (a `block_on` needing the
//! tokio I/O driver) held the next stop-the-world open; the stop-the-world
//! parked every tokio worker; nothing read the DNS answer; and the process
//! stopped for good with no CPU in use. The assertions are the symptoms that
//! node showed: REGISTERs no longer relayed, a fresh request no longer
//! answered, and `/metrics` no longer served.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::ipsec_lifecycle_tests::install;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::ipsec::IpsecManager;

/// Where the script's next hop, `scscf.ims.example.net`, resolves.
const NEXT_HOP_ADDRESS: [u8; 4] = [198, 51, 100, 12];

const SCRIPT: &str = concat!(
    "import asyncio\n",
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"REGISTER\")\n",
    "async def register(request):\n",
    "    await asyncio.sleep(0)\n",
    "    request.relay(\"sip:scscf.ims.example.net:5060\")\n",
    "\n",
    "@proxy.on_request(\"OPTIONS\")\n",
    "def options(request):\n",
    "    request.reply(200, \"OK\")\n",
);

/// A nameserver on its own OS thread (not tokio's) that answers every A query
/// after `delay`, uncached (TTL 0), so each relay resolves.
fn slow_nameserver(delay: Duration, stop: Arc<AtomicBool>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("a read timeout");
    let address = socket.local_addr().expect("a bound address");
    std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        while !stop.load(Ordering::Relaxed) {
            let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                continue;
            };
            std::thread::sleep(delay);
            if let Some(answer) = a_record_answer(&buffer[..length]) {
                let _ = socket.send_to(&answer, from);
            }
        }
    });
    address
}

/// An answer to `query` with one A record, TTL 0 (RFC 1035 section 4.1).
fn a_record_answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // The question runs from offset 12 to the end of QNAME + QTYPE + QCLASS.
    let mut end = 12;
    while *query.get(end)? != 0 {
        end += usize::from(query[end]) + 1;
    }
    let question_end = end + 1 + 4;
    let question = query.get(12..question_end)?;
    let query_type =
        u16::from_be_bytes([question[question.len() - 4], question[question.len() - 3]]);
    let mut answer = Vec::with_capacity(question_end + 16);
    answer.extend_from_slice(&query[0..2]); // ID
    answer.extend_from_slice(&[0x81, 0x80]); // response, RD, RA, NOERROR
    answer.extend_from_slice(&[0, 1]); // QDCOUNT
    answer.extend_from_slice(&[0, u8::from(query_type == 1)]); // ANCOUNT
    answer.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    answer.extend_from_slice(question);
    if query_type == 1 {
        answer.extend_from_slice(&[0xc0, 0x0c]); // the name, by pointer
        answer.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        answer.extend_from_slice(&[0, 0, 0, 0]); // TTL 0
        answer.extend_from_slice(&[0, 4]);
        answer.extend_from_slice(&NEXT_HOP_ADDRESS);
    }
    Some(answer)
}

fn register(ue: SocketAddr, index: usize) -> String {
    format!(
        concat!(
            "REGISTER sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {ue};branch=z9hG4bK-stw-{index}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:00101000000{index:04}@ims.example.invalid>;tag=ue-{index}\r\n",
            "To: <sip:00101000000{index:04}@ims.example.invalid>\r\n",
            "Call-ID: stw-{index}@ue\r\n",
            "CSeq: 2 REGISTER\r\n",
            "Contact: <sip:ue@{host}:{port_s}>\r\n",
            "Expires: 3600\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ue = ue,
        index = index,
        host = ue.ip(),
        port_s = ue.port() + 1,
    )
}

fn options(index: usize) -> String {
    format!(
        concat!(
            "OPTIONS sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.99:5070;branch=z9hG4bK-stw-options-{index}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:probe@ims.example.invalid>;tag=probe\r\n",
            "To: <sip:ims.example.invalid>\r\n",
            "Call-ID: stw-options-{index}@probe\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        index = index,
    )
}

/// Hand `raw` from `source` to the dispatcher the way its inbound loop does.
fn receive(state: &Arc<DispatcherState>, source: SocketAddr, raw: String) {
    let state = Arc::clone(state);
    crate::script::py_executor::spawn(move || {
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        let method = message.method().expect("a request").as_str().to_string();
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: source,
            data: Bytes::from(raw.clone()),
        };
        handle_request(inbound, message, method, &state);
    });
}

/// Runs the scenario in a process of its own: back-to-back collections stop
/// the world for every thread in the process, so in the shared test binary
/// any other test that happens to block while attached would wedge with it.
/// And on a build with the bug, the scenario wedges its process for good,
/// which here fails this test after the deadline instead of hanging the run.
#[test]
fn registrations_under_repeated_stop_the_world_keep_the_node_serving() {
    super::own_process_test::run_in_own_process(
        "dispatcher::stop_the_world_tests::registrations_under_repeated_stop_the_world_keep_the_node_serving",
        Duration::from_secs(45),
        scenario,
    );
}

fn scenario() {
    let _serial = crate::script::async_pool::pool_test_guard();
    crate::script::async_pool::ensure_test_pools();
    let runtime = crate::script::async_pool::test_pools_runtime();
    let stop = Arc::new(AtomicBool::new(false));

    // A P-CSCF on the in-memory IPsec kernel whose next hop resolves slowly.
    let nameserver = slow_nameserver(Duration::from_millis(50), Arc::clone(&stop));
    let mut dispatcher = test_dispatcher_with_script(SCRIPT);
    let manager = Arc::new(IpsecManager::with_test_kernel());
    dispatcher.state.ipsec_manager = Some(Arc::clone(&manager));
    dispatcher.state.ipsec_config = Some(
        crate::config::yaml::from_str("pcscf_port_s: 5060\npcscf_port_c: 5064")
            .expect("an ipsec block"),
    );
    dispatcher.state.dns_resolver =
        Arc::new(crate::dns::SipResolver::with_test_nameserver(nameserver));
    let state = Arc::new(dispatcher.state);
    let udp = dispatcher.udp;

    const UES: usize = 40;
    let ues: Vec<SocketAddr> = (0..UES)
        .map(|index| SocketAddr::from(([192, 0, 2, 100], 40_000 + 2 * index as u16)))
        .collect();
    runtime.block_on(async {
        for ue in &ues {
            install(&manager, *ue).await;
        }
    });

    // Tokio tasks attaching to the interpreter, as awaitable completions do,
    // more of them than there are workers.
    for _ in 0..8 {
        let stop = Arc::clone(&stop);
        runtime.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                Python::attach(|_| ());
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }
    // Garbage collections back to back: each one stops the world.
    let collector = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                Python::attach(|python| {
                    let _ = python
                        .import("gc")
                        .and_then(|gc| gc.call_method0("collect"));
                });
            }
        })
    };

    for (index, ue) in ues.iter().enumerate() {
        receive(&state, *ue, register(*ue, index));
    }

    // Every REGISTER is relayed to the resolved next hop.
    let deadline = Instant::now() + Duration::from_secs(15);
    let next_hop = SocketAddr::from((NEXT_HOP_ADDRESS, 5060));
    let mut relayed = 0;
    let mut other_traffic = Vec::new();
    while relayed < UES && Instant::now() < deadline {
        if let Ok(message) = udp.recv_timeout(Duration::from_millis(100)) {
            if message.destination == next_hop {
                relayed += 1;
            } else {
                for frame in message.frames() {
                    let start = String::from_utf8_lossy(frame);
                    let start = start.lines().next().unwrap_or_default().to_string();
                    other_traffic.push(format!("{} {start}", message.destination));
                }
            }
        }
    }

    // A request that arrives now is still answered.
    receive(
        &state,
        "192.0.2.99:5070".parse().expect("a literal address"),
        options(0),
    );
    let options_deadline = Instant::now() + Duration::from_secs(5);
    let mut options_answered = false;
    while !options_answered && Instant::now() < options_deadline {
        if let Ok(message) = udp.recv_timeout(Duration::from_millis(100)) {
            options_answered = message
                .frames()
                .any(|frame| frame.starts_with(b"SIP/2.0 200"));
        }
    }

    // And `/metrics`, served on tokio, still renders.
    let (metrics_tx, metrics_rx) = std::sync::mpsc::channel();
    runtime.spawn(async move {
        let _ = metrics_tx.send(crate::metrics::encode_metrics());
    });
    let metrics_served = metrics_rx.recv_timeout(Duration::from_secs(5)).is_ok();

    stop.store(true, Ordering::Relaxed);
    // Joined only when the node is serving: a collector stuck in a
    // stop-the-world that never ends would hang the test instead of failing it.
    if relayed == UES && options_answered && metrics_served {
        let _ = collector.join();
    }
    assert_eq!(
        relayed, UES,
        "REGISTERs relayed under repeated stop-the-world (the hang relays none after \
         it); also sent: {other_traffic:?}"
    );
    assert!(options_answered, "a fresh OPTIONS is answered");
    assert!(metrics_served, "/metrics is rendered on the runtime");
}
