//! Every message siphon puts on the wire reaches HEP capture, including the ones
//! it sends from a background task.
//!
//! The retransmit tasks hold the outbound channel but not the dispatcher state
//! `send_outbound_from` captures from, and wrote straight to the channel. So a 2xx
//! retransmitted to a caller that never ACKed, or a reliable 1xx waiting for its
//! PRACK, showed in a capture once however many times it went out. A request
//! relayed over a captured flow skipped capture the same way.
//!
//! Each test points the dispatcher's HEP sender at a UDP socket standing in for
//! the collector, lets the sends happen on the real clock, and checks that every
//! frame on the egress channel has a capture carrying the same bytes.

use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use std::time::Duration;

const CALLER: &str = "192.0.2.10:5060";
const SIPHON: &str = "192.0.2.1:5060";

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

/// A dispatcher whose HEP capture goes to a socket the test reads.
struct Captured {
    state: DispatcherState,
    udp: flume::Receiver<OutboundMessage>,
    collector: tokio::net::UdpSocket,
}

impl Captured {
    async fn new() -> Captured {
        let collector = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a collector socket");
        let endpoint = collector.local_addr().expect("the collector's address");
        let sender = HepSender::new(&crate::config::HepConfig {
            endpoint: endpoint.to_string(),
            version: 3,
            transport: crate::config::HepTransport::Udp,
            agent_id: None,
            ca_cert: None,
            tls_server_name: None,
            error_log_interval: 60,
        })
        .await
        .expect("a HEP sender");
        let TestDispatcher { mut state, udp } = test_dispatcher();
        state.hep_sender = Some(Arc::new(sender));
        Captured {
            state,
            udp,
            collector,
        }
    }

    /// Every frame on the egress channel so far, in order.
    fn wire(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Ok(outbound) = self.udp.try_recv() {
            for frame in outbound.frames() {
                frames.push(frame.to_vec());
            }
        }
        frames
    }

    /// Every HEP packet the collector has received, until none arrives for 300 ms.
    async fn captures(&self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut buffer = vec![0u8; 65_536];
        while let Ok(Ok(length)) =
            tokio::time::timeout(Duration::from_millis(300), self.collector.recv(&mut buffer)).await
        {
            packets.push(buffer[..length].to_vec());
        }
        packets
    }
}

fn carries(packet: &[u8], frame: &[u8]) -> bool {
    packet.windows(frame.len()).any(|window| window == frame)
}

/// One capture per frame on the wire, each carrying that frame's bytes.
fn assert_every_frame_captured(frames: &[Vec<u8>], packets: &[Vec<u8>], what: &str) {
    assert!(!frames.is_empty(), "{what}: nothing went out");
    assert_eq!(
        packets.len(),
        frames.len(),
        "{what}: one capture per frame on the wire"
    );
    for frame in frames {
        assert!(
            packets.iter().any(|packet| carries(packet, frame)),
            "{what}: a frame on the wire has no capture"
        );
    }
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the message parses")
}

/// The failure this exists for. The 2xx siphon retransmits to a caller that has
/// not ACKed (RFC 3261 §13.3.1.4) is captured every time it goes out.
#[tokio::test(flavor = "multi_thread")]
async fn every_retransmission_of_the_2xx_to_the_caller_is_captured() {
    let captured = Captured::new().await;
    let answer = parse(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-captured-invite\r\n",
        "From: <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
        "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
        "Call-ID: captured-call@192.0.2.10\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:192.0.2.1:5060;transport=udp>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    arm_b2bua_2xx_retransmit(
        "captured-call",
        answer,
        Transport::Udp,
        address(CALLER),
        ConnectionId::default(),
        None,
        &captured.state,
    );

    // T1 is 500 ms: copies go out at 0.5 s and 1.5 s.
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    // The store is keyed by the dialog the 2xx went out on.
    if let Some((_, unacked)) = captured
        .state
        .uas_2xx_retransmits
        .remove("captured-call@192.0.2.10")
    {
        unacked.cancel.notify_one();
    }

    let frames = captured.wire();
    let packets = captured.captures().await;
    assert_every_frame_captured(&frames, &packets, "2xx retransmission");
}

/// A reliable provisional retransmitted until its PRACK (RFC 3262 §3) is captured
/// every time it goes out.
#[tokio::test(flavor = "multi_thread")]
async fn every_retransmission_of_a_reliable_provisional_is_captured() {
    let captured = Captured::new().await;
    let invite = parse(concat!(
        "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-reliable-invite\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
        "To: <sip:15550100042@siphon.example.com>\r\n",
        "Call-ID: reliable-call@192.0.2.10\r\n",
        "CSeq: 1 INVITE\r\n",
        "Supported: 100rel\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    let mut provisional = build_response(&invite, 183, "Session Progress", None, &[]);
    provisional.headers.add("Require", "100rel".to_string());
    provisional.headers.add("RSeq", "1".to_string());
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: address(SIPHON),
        remote_addr: address(CALLER),
        data: Bytes::new(),
    };
    arm_reliable_provisional_retransmit(1, &invite, provisional, &inbound, &captured.state);

    tokio::time::sleep(Duration::from_millis(1_700)).await;
    if let Some((_, entry)) = captured
        .state
        .reliable_provisionals
        .remove(&("reliable-call@192.0.2.10".to_string(), 1))
    {
        entry.cancel.notify_one();
    }

    let frames = captured.wire();
    let packets = captured.captures().await;
    assert_every_frame_captured(&frames, &packets, "reliable 1xx retransmission");
}

/// A request relayed over a captured flow (`request.relay(flow=…)`) is captured
/// like every other relay. Only the fork and B-leg flow paths captured it.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_relayed_over_a_captured_flow_is_captured() {
    let captured = Captured::new().await;
    let raw = concat!(
        "OPTIONS sip:ue@198.51.100.77:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-flow-options\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
        "To: <sip:ue@siphon.example.com>\r\n",
        "Call-ID: flow-relay@192.0.2.10\r\n",
        "CSeq: 1 OPTIONS\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let message = parse(raw);
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: address(SIPHON),
        remote_addr: address(CALLER),
        data: Bytes::from_static(raw.as_bytes()),
    };
    let flow = crate::script::api::registrar::PyFlow {
        transport: "udp".to_string(),
        source_addr: address("198.51.100.77:5060"),
        local_addr: address(SIPHON),
        connection_id: 0,
    };
    relay_request(
        &message,
        None,
        false,
        &inbound,
        None,
        &captured.state,
        None,
        None,
        None,
        None,
        Some(&flow),
        None,
    );

    let frames = captured.wire();
    let packets = captured.captures().await;
    assert_every_frame_captured(&frames, &packets, "flow relay");
}

/// Without HEP a task is armed with no capture to carry: nothing is cloned or
/// resolved for it, and each of its sends costs one branch more than before.
#[tokio::test]
async fn a_task_armed_without_hep_carries_no_capture() {
    let TestDispatcher { state, .. } = test_dispatcher();
    assert!(TaskCapture::for_task(&state, Transport::Udp, Some(address(SIPHON))).is_none());
}
