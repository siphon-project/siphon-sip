//! A NOTIFY of `proxy.subscribe_state` that is over `listen.mtu` leaves over
//! TCP when the subscriber listens for it (RFC 3261 §18.1.1): the initial one a
//! SUBSCRIBE handler sends, and the one that ends an expired subscription.
//!
//! The subscriber is on loopback, with or without a TCP listener on the port
//! it sends its UDP SUBSCRIBE from (§18.2.1).

use std::net::SocketAddr;
use std::time::Duration;

use super::subscribe_test_harness::{subscribe_harness, SubscribeHarness, UAC_MTU};
use super::*;

/// A subscriber's UDP source port with a TCP listener on it.
fn listening_subscriber() -> (SocketAddr, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
    let source = listener.local_addr().expect("bound");
    // The port may be one another test saw refuse within the window.
    forget_tcp_probe(source);
    (source, listener)
}

/// A subscriber's UDP source port where a TCP connect is refused: bound and
/// not listening, held so nothing else listens there.
fn udp_only_subscriber() -> (SocketAddr, socket2::Socket) {
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).expect("a socket");
    let address: SocketAddr = "127.0.0.1:0".parse().expect("an address");
    socket.bind(&address.into()).expect("a free port");
    let source = socket
        .local_addr()
        .expect("bound")
        .as_socket()
        .expect("an inet address");
    forget_tcp_probe(source);
    (source, socket)
}

/// A SUBSCRIBE from `source` whose handler pads its initial NOTIFY by `pad`
/// bytes.
fn subscribe(source: SocketAddr, name: &str, pad: usize) -> String {
    format!(
        concat!(
            "SUBSCRIBE sip:{name}@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-{name}\r\n",
            "From: <sip:{name}@siphon.example.com>;tag=watcher\r\n",
            "To: <sip:{name}@siphon.example.com>\r\n",
            "Call-ID: {name}@example.com\r\n",
            "CSeq: 1 SUBSCRIBE\r\n",
            "Contact: <sip:{name}@{source}>\r\n",
            "Event: message-summary\r\n",
            "Expires: 60\r\n",
            "X-Pad: {pad}\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        name = name,
        source = source,
        pad = pad
    )
}

fn start_lines(frames: &[(SocketAddr, Bytes)]) -> Vec<String> {
    frames
        .iter()
        .map(|(_, frame)| {
            String::from_utf8_lossy(frame)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// The NOTIFY handed to TCP, parsed.
fn notify_over_tcp(harness: &SubscribeHarness, subscriber: SocketAddr) -> SipMessage {
    let sent = harness
        .tcp
        .recv_timeout(Duration::from_secs(5))
        .expect("a NOTIFY over TCP");
    assert_eq!(sent.transport, Transport::Tcp);
    assert_eq!(
        sent.destination, subscriber,
        "to the address the subscription was learned from"
    );
    assert!(
        sent.data.len() > usize::from(UAC_MTU) - 200,
        "over the threshold: {}",
        sent.data.len()
    );
    let notify = parse_sip_message_bytes(&sent.data).expect("a NOTIFY");
    assert_eq!(notify.method(), Some(&Method::Notify));
    let via = notify.headers.get("Via").cloned().expect("a Via");
    assert!(
        via.starts_with("SIP/2.0/TCP ") && via.contains(";branch=z9hG4bK-uac-"),
        "the top Via names the transport used and keeps its branch: {via}"
    );
    notify
}

/// The initial NOTIFY, sent from the SUBSCRIBE handler and held behind the 200
/// that accepts the subscription: the 200 answers over UDP, the NOTIFY leaves
/// over TCP whole instead of as one oversized datagram.
#[test]
fn an_initial_notify_over_the_mtu_leaves_over_tcp() {
    let (_turn, harness) = subscribe_harness();
    let (subscriber, _listener) = listening_subscriber();

    harness.receive_request(
        &subscribe(subscriber, "notify-over-mtu", 1500),
        &subscriber.to_string(),
    );

    let over_udp = harness.frames();
    let starts = start_lines(&over_udp);
    assert_eq!(starts.len(), 1, "only the 200 over UDP, got {starts:?}");
    assert!(starts[0].starts_with("SIP/2.0 200"), "{starts:?}");
    let notify = notify_over_tcp(harness, subscriber);
    assert!(notify.body.len() > 1500, "the whole body");
    // The dialog's Contact is not moved by one request's size.
    let contact = notify.headers.get("Contact").cloned().expect("a Contact");
    assert!(!contact.contains("transport=tcp"), "{contact}");
    assert!(harness.tcp.try_recv().is_err(), "sent once");
}

/// One under the threshold stays where it was: behind the 200, over UDP.
#[test]
fn an_initial_notify_under_the_mtu_stays_on_udp() {
    let (_turn, harness) = subscribe_harness();
    let (subscriber, listener) = listening_subscriber();
    listener.set_nonblocking(true).expect("non-blocking");

    harness.receive_request(
        &subscribe(subscriber, "notify-under-mtu", 600),
        &subscriber.to_string(),
    );

    let starts = start_lines(&harness.frames());
    assert_eq!(starts.len(), 2, "the 200 and the NOTIFY, got {starts:?}");
    assert!(starts[0].starts_with("SIP/2.0 200"), "{starts:?}");
    assert!(starts[1].starts_with("NOTIFY "), "{starts:?}");
    assert!(harness.tcp.try_recv().is_err(), "nothing over TCP");
    assert!(listener.accept().is_err(), "and no probe");
}

/// A subscriber with no TCP listener gets the NOTIFY over UDP (the fallback of
/// RFC 3261 §18.1.1), still behind the 200.
#[test]
fn an_initial_notify_over_the_mtu_to_a_udp_only_subscriber_stays_on_udp() {
    let (_turn, harness) = subscribe_harness();
    let (subscriber, _held) = udp_only_subscriber();

    harness.receive_request(
        &subscribe(subscriber, "notify-udp-only", 1500),
        &subscriber.to_string(),
    );

    let frames = harness.frames();
    let starts = start_lines(&frames);
    assert_eq!(starts.len(), 2, "the 200 and the NOTIFY, got {starts:?}");
    assert!(starts[0].starts_with("SIP/2.0 200"), "{starts:?}");
    assert!(starts[1].starts_with("NOTIFY "), "{starts:?}");
    assert!(frames[1].1.len() > 1500, "the whole NOTIFY");
    assert!(
        String::from_utf8_lossy(&frames[1].1).contains("\r\nVia: SIP/2.0/UDP "),
        "with its UDP Via"
    );
    assert!(harness.tcp.try_recv().is_err(), "nothing over TCP");
    forget_tcp_probe(subscriber);
}

/// The NOTIFY that ends an expired subscription takes the same decision: over
/// the MTU (here by the length of the dialog's URIs) it leaves over TCP.
#[test]
fn the_notify_of_an_expired_subscription_over_the_mtu_leaves_over_tcp() {
    let (_turn, harness) = subscribe_harness();
    let (subscriber, _listener) = listening_subscriber();
    harness.receive_request(
        &subscribe(subscriber, "expiry-over-mtu", 0),
        &subscriber.to_string(),
    );
    let _ = harness.frames();
    let mut dialog = harness
        .store
        .for_resource("sip:expiry-over-mtu@siphon.example.com", "message-summary")
        .pop()
        .expect("the accepted subscription");
    assert_eq!(dialog.received_address, Some(subscriber));
    dialog.remote_uri = format!("sip:{}@siphon.example.com", "w".repeat(1400));

    super::async_request_handler_tests::test_runtime()
        .block_on(crate::script::api::subscribe_state::notify_expired(dialog));

    let notify = notify_over_tcp(harness, subscriber);
    assert_eq!(
        notify.headers.get("Subscription-State").map(String::as_str),
        Some("terminated;reason=timeout")
    );
    assert!(harness.frames().is_empty(), "and not over UDP as well");
}
