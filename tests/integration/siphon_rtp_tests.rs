//! Integration tests for the native `siphon-rtp` media backend.
//!
//! Verifies the `MediaBackend` abstraction drives the JSON-over-TCP engine
//! end-to-end: a SIP INVITE's SDP is offered to a fake `siphon-rtp` control
//! server (speaking the real `siphon_rtp_proto` wire format) and the rewritten
//! SDP comes back through the same `MediaBackend` API the rtpengine NG backend
//! uses. Complements the unit tests in `src/rtpengine/siphon_rtp.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use siphon::rtpengine::profile::NgFlags;
use siphon::rtpengine::{MediaBackend, RtpEngineSet, SiphonRtpClient, SiphonRtpClientSet};
use siphon::sip::parser::parse_sip_message;

use siphon_rtp_proto::{frame, CmdResult, Command, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Spawn a fake `siphon-rtp` control server that rewrites offer/answer SDP and
/// answers ping. Returns the bound address.
async fn spawn_fake_siphon_rtp() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buffer: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    // Drain whole frames already buffered.
                    while let Some((request, consumed)) =
                        frame::decode::<Request>(&buffer).expect("decode request")
                    {
                        buffer.drain(..consumed);
                        let result = match request.command {
                            Command::Offer { .. } | Command::Answer { .. } => CmdResult::Ok {
                                sdp: Some(
                                    "v=0\r\no=- 0 0 IN IP4 203.0.113.1\r\ns=-\r\nc=IN IP4 203.0.113.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n"
                                        .to_string(),
                                ),
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                            },
                            Command::Delete { .. } => CmdResult::Ok {
                                sdp: None,
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                            },
                            Command::Ping => CmdResult::Pong,
                            _ => CmdResult::Error {
                                reason: "unsupported".to_string(),
                            },
                        };
                        let response = Response {
                            id: request.id,
                            result,
                        };
                        let bytes = frame::encode(&response).expect("encode response");
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });

    address
}

const INVITE_WITH_SDP: &str = concat!(
    "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n",
    "From: Alice <sip:alice@atlanta.com>;tag=alice-tag\r\n",
    "To: Bob <sip:bob@biloxi.com>\r\n",
    "Call-ID: native-call-1@atlanta.com\r\n",
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
async fn media_backend_siphon_rtp_offer_rewrites_sdp() {
    let address = spawn_fake_siphon_rtp().await;
    let (event_tx, _event_rx) = mpsc::channel(16);
    let set = SiphonRtpClientSet::new(vec![(address, 2000, 1)], None, 5_000, event_tx).unwrap();
    let backend = MediaBackend::SiphonRtp(set);

    // Confirm the abstraction reports the native backend's shape.
    assert_eq!(backend.instance_count(), 1);
    assert_eq!(backend.instance_addresses(), vec![address]);
    backend.ping().await.unwrap();

    // Parse a real SIP INVITE and offer its SDP body through the backend.
    let (_, message) = parse_sip_message(INVITE_WITH_SDP).unwrap();
    let call_id = "native-call-1@atlanta.com";
    let body = &message.body;
    assert!(!body.is_empty());

    let rewritten = backend
        .offer(call_id, "alice-tag", body, &NgFlags::default())
        .await
        .unwrap();
    let rewritten = String::from_utf8_lossy(&rewritten);
    assert!(rewritten.contains("203.0.113.1"), "SDP not rewritten: {rewritten}");
    assert!(rewritten.contains("30000"));

    backend.delete(call_id, "alice-tag").await.unwrap();
}

#[tokio::test]
async fn media_backend_siphon_rtp_is_send_sync() {
    // The backend is shared across tokio workers as `Arc<MediaBackend>`; assert
    // it satisfies the bounds the dispatcher/PyRtpEngine rely on.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<MediaBackend>>();
}

// ---------------------------------------------------------------------------
// End-to-end smoke test against a REAL siphon-rtp daemon. `#[ignore]`d and
// gated on the `SIPHON_RTP_BIN` env var (path to a built `siphon-rtp` binary),
// since CI does not build the engine. Run with:
//   SIPHON_RTP_BIN=../siphon-rtp/target/debug/siphon-rtp \
//     cargo test --test integration_tests -- --ignored siphon_rtp
// ---------------------------------------------------------------------------

/// A spawned siphon-rtp process, killed on drop.
struct EngineProcess(std::process::Child);

impl Drop for EngineProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `siphon-rtp` with the given args, or `None` when `SIPHON_RTP_BIN` is unset.
fn spawn_engine(args: &[&str]) -> Option<EngineProcess> {
    let binary = std::env::var("SIPHON_RTP_BIN").ok()?;
    std::process::Command::new(binary)
        .args(args)
        .spawn()
        .ok()
        .map(EngineProcess)
}

/// Poll an async predicate until true or ~5s elapse.
async fn wait_until<F, Fut>(mut probe: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..50 {
        if probe().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

const SMOKE_SDP: &[u8] =
    b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a built siphon-rtp binary via SIPHON_RTP_BIN"]
async fn smoke_test_against_real_siphon_rtp() {
    let control_addr = "127.0.0.1:18080";
    let ng_addr = "127.0.0.1:22230";
    let Some(_engine) = spawn_engine(&["--control", control_addr, "--ng", ng_addr]) else {
        eprintln!("SIPHON_RTP_BIN not set — skipping siphon-rtp end-to-end smoke test");
        return;
    };
    let flags = NgFlags::default();

    // --- rtpengine NG/bencode path: siphon's existing UDP client → --ng shim ---
    let ng: SocketAddr = ng_addr.parse().unwrap();
    let set = RtpEngineSet::new(vec![(ng, 2000, 1)]).await.unwrap();
    assert!(
        wait_until(|| async { set.ping().await.is_ok() }).await,
        "siphon-rtp NG listener did not become ready"
    );
    let offered = set.offer("smoke-ng", "tag-a", SMOKE_SDP, &flags).await.unwrap();
    assert!(!offered.is_empty());
    let answered = set
        .answer("smoke-ng", "tag-a", "tag-b", SMOKE_SDP, &flags)
        .await
        .unwrap();
    assert!(!answered.is_empty());
    set.delete("smoke-ng", "tag-a").await.unwrap();

    // --- Native JSON-over-TCP path: SiphonRtpClient → --control ---
    let control: SocketAddr = control_addr.parse().unwrap();
    let (event_tx, _event_rx) = mpsc::channel(16);
    let client = SiphonRtpClient::new(control, None, 2000, 5_000, event_tx);
    assert!(
        wait_until(|| async { client.ping().await.is_ok() }).await,
        "siphon-rtp control listener did not become ready"
    );
    let offered = client
        .offer("smoke-native", "tag-a", SMOKE_SDP, &flags)
        .await
        .unwrap();
    assert!(!offered.is_empty());
    let answered = client
        .answer("smoke-native", "tag-a", "tag-b", SMOKE_SDP, &flags)
        .await
        .unwrap();
    assert!(!answered.is_empty());
    client.delete("smoke-native", "tag-a").await.unwrap();
}
