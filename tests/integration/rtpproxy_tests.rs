//! Integration tests for the classic `rtpproxy` media backend.
//!
//! Verifies the `MediaBackend` abstraction drives the text-over-UDP rtpproxy
//! protocol end-to-end: a SIP INVITE's SDP is offered to a fake rtpproxy control
//! server (speaking the real cookie/`U`/`L`/`D`/`V` wire format), and siphon's
//! own SDP rewrite comes back through the same `MediaBackend` API the rtpengine
//! NG backend uses. Complements the unit tests in `src/rtpengine/rtpproxy.rs`.

use std::sync::Arc;

use siphon::rtpengine::profile::NgFlags;
use siphon::rtpengine::{MediaBackend, RtpProxyClientSet};
use siphon::sip::parser::parse_sip_message;

use bytes::BytesMut;
use tokio::net::UdpSocket;

/// Spawn a fake rtpproxy that allocates `reply_port`/`reply_address` for every
/// `U`/`L`, answers `V` with a version, and `D`/anything else with `0`.
/// Returns the bound control address.
async fn spawn_fake_rtpproxy(
    reply_address: &'static str,
    reply_port: u16,
) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = BytesMut::zeroed(8192);
        while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
            let data = &buffer[..size];
            let space = match data.iter().position(|&byte| byte == b' ') {
                Some(position) => position,
                None => continue,
            };
            let cookie = std::str::from_utf8(&data[..space]).unwrap();
            let command = std::str::from_utf8(&data[space + 1..]).unwrap();
            let result = if command.starts_with('V') {
                "20040107".to_string()
            } else if command.starts_with('U') || command.starts_with('L') {
                format!("{reply_port} {reply_address}")
            } else {
                "0".to_string()
            };
            let reply = format!("{cookie} {result}");
            let _ = socket.send_to(reply.as_bytes(), source).await;
        }
    });
    address
}

const INVITE_WITH_SDP: &str = concat!(
    "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n",
    "From: Alice <sip:alice@atlanta.com>;tag=alice-tag\r\n",
    "To: Bob <sip:bob@biloxi.com>\r\n",
    "Call-ID: rtpproxy-call-1@atlanta.com\r\n",
    "CSeq: 1 INVITE\r\n",
    "Content-Type: application/sdp\r\n",
    "Content-Length: 89\r\n",
    "\r\n",
    "v=0\r\n",
    "o=alice 0 0 IN IP4 10.0.0.1\r\n",
    "s=-\r\n",
    "c=IN IP4 10.0.0.1\r\n",
    "t=0 0\r\n",
    "m=audio 8000 RTP/AVP 0\r\n",
);

#[tokio::test]
async fn media_backend_rtpproxy_offer_rewrites_sdp() {
    let address = spawn_fake_rtpproxy("203.0.113.1", 30000).await;
    let set = RtpProxyClientSet::new(vec![(address, 1000, 1)], 2).await.unwrap();
    let backend = MediaBackend::RtpProxy(set);

    // Confirm the abstraction reports the rtpproxy backend's shape.
    assert_eq!(backend.instance_count(), 1);
    assert_eq!(backend.instance_addresses(), vec![address]);
    backend.ping().await.unwrap();

    // Parse a real SIP INVITE and offer its SDP body through the backend.
    let (_, message) = parse_sip_message(INVITE_WITH_SDP).unwrap();
    let call_id = "rtpproxy-call-1@atlanta.com";
    let body = &message.body;
    assert!(!body.is_empty());

    let rewritten = backend
        .offer(call_id, "alice-tag", body, &NgFlags::default())
        .await
        .unwrap();
    let rewritten = String::from_utf8_lossy(&rewritten);
    // siphon rewrote c=/m= to the relay rtpproxy returned.
    assert!(
        rewritten.contains("c=IN IP4 203.0.113.1"),
        "SDP not rewritten: {rewritten}"
    );
    assert!(rewritten.contains("m=audio 30000 RTP/AVP 0"), "SDP: {rewritten}");
    // The original endpoint must be gone from the connection line.
    assert!(!rewritten.contains("c=IN IP4 10.0.0.1"), "SDP: {rewritten}");
    assert_eq!(backend.active_sessions(), 1);

    backend.delete(call_id, "alice-tag").await.unwrap();
    assert_eq!(backend.active_sessions(), 0);
}

#[tokio::test]
async fn media_backend_rtpproxy_unsupported_op_errors_cleanly() {
    let address = spawn_fake_rtpproxy("203.0.113.1", 30000).await;
    let set = RtpProxyClientSet::new(vec![(address, 1000, 1)], 2).await.unwrap();
    let backend = MediaBackend::RtpProxy(set);

    // rtpengine-only verbs must surface a clear error, not panic or hang.
    let error = backend.silence_media("c1", "ft").await.unwrap_err();
    assert!(error.to_string().contains("does not support"), "{error}");
}

#[tokio::test]
async fn media_backend_rtpproxy_is_send_sync() {
    // The backend is shared across tokio workers as `Arc<MediaBackend>`; assert
    // it satisfies the bounds the dispatcher/PyRtpEngine rely on.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<MediaBackend>>();
}
