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

use siphon::rtpengine::profile::{NgFlags, WsTeeDirection};
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
                                recording_id: None,
                            },
                            Command::Delete { .. } => CmdResult::Ok {
                                sdp: None,
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                                recording_id: None,
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
    assert!(
        rewritten.contains("203.0.113.1"),
        "SDP not rewritten: {rewritten}"
    );
    assert!(rewritten.contains("30000"));

    backend.delete(call_id, "alice-tag").await.unwrap();
}

// ---------------------------------------------------------------------------
// WebSocket tee — wire shape
//
// These assert the *exact JSON* siphon puts on the control socket, not a
// decode/re-encode round-trip: the fake server hands back the raw frame body
// (`frame::HEADER_LEN` is a 4-byte big-endian length prefix, so the JSON is
// `buffer[4..consumed]`). A round-trip through the same serde impls would hide
// a field siphon failed to carry, which is precisely the class of bug the
// exhaustive `profile_flags_from_ng` exists to catch.
// ---------------------------------------------------------------------------

/// Spawn a fake control server that records the raw JSON body of every request
/// it receives and answers everything `Ok`. Returns the bound address plus the
/// receiver of recorded bodies.
async fn spawn_recording_siphon_rtp() -> (std::net::SocketAddr, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (record_tx, record_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let record_tx = record_tx.clone();
            tokio::spawn(async move {
                let mut buffer: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some((request, consumed)) =
                        frame::decode::<Request>(&buffer).expect("decode request")
                    {
                        // The raw JSON exactly as siphon serialised it.
                        let body = String::from_utf8(buffer[frame::HEADER_LEN..consumed].to_vec())
                            .expect("request body is utf-8");
                        buffer.drain(..consumed);
                        let _ = record_tx.send(body);

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
                                recording_id: None,
                            },
                            Command::Ping => CmdResult::Pong,
                            _ => CmdResult::Ok {
                                sdp: None,
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                                recording_id: None,
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

    (address, record_rx)
}

/// Build a `MediaBackend::SiphonRtp` pointed at `address`.
fn siphon_rtp_backend(address: std::net::SocketAddr) -> MediaBackend {
    let (event_tx, _event_rx) = mpsc::channel(16);
    let set = SiphonRtpClientSet::new(vec![(address, 2000, 1)], None, 5_000, event_tx).unwrap();
    MediaBackend::SiphonRtp(set)
}

#[tokio::test]
async fn attach_ws_tee_emits_the_documented_wire_shape() {
    let (address, mut records) = spawn_recording_siphon_rtp().await;
    let backend = siphon_rtp_backend(address);
    backend.ping().await.unwrap();
    records.recv().await.expect("ping recorded");

    // `channels` carries skip_serializing_if and drops out when unset;
    // `direction` does not, so the engine always receives an explicit leg
    // selection rather than relying on its own default.
    backend
        .attach_ws_tee("c", "f", "ws://h/s", WsTeeDirection::Both, None, None)
        .await
        .unwrap();
    let body = records.recv().await.expect("attach recorded");
    assert_eq!(
        body,
        r#"{"id":2,"command":"attach_ws_tee","call_id":"c","from_tag":"f","ws_uri":"ws://h/s","direction":"both"}"#,
        "attach_ws_tee wire shape drifted"
    );

    // Explicit non-default direction + channels are carried verbatim.
    backend
        .attach_ws_tee("c", "f", "wss://h/s", WsTeeDirection::Caller, Some(1), None)
        .await
        .unwrap();
    let body = records.recv().await.expect("explicit attach recorded");
    assert_eq!(
        body,
        r#"{"id":3,"command":"attach_ws_tee","call_id":"c","from_tag":"f","ws_uri":"wss://h/s","direction":"caller","channels":1}"#,
        "attach_ws_tee did not carry direction/channels"
    );
}

#[tokio::test]
async fn detach_ws_tee_emits_the_documented_wire_shape() {
    let (address, mut records) = spawn_recording_siphon_rtp().await;
    let backend = siphon_rtp_backend(address);
    backend.ping().await.unwrap();
    records.recv().await.expect("ping recorded");

    backend.detach_ws_tee("c", "f").await.unwrap();
    let body = records.recv().await.expect("detach recorded");
    assert_eq!(
        body, r#"{"id":2,"command":"detach_ws_tee","call_id":"c","from_tag":"f"}"#,
        "detach_ws_tee wire shape drifted"
    );
}

#[tokio::test]
async fn offer_without_ws_tee_carries_no_tee_keys() {
    // No wire drift for existing deployments: a profile that does not ask for a
    // tee must emit exactly what it emitted before the tee fields existed.
    let (address, mut records) = spawn_recording_siphon_rtp().await;
    let backend = siphon_rtp_backend(address);
    backend.ping().await.unwrap();
    records.recv().await.expect("ping recorded");

    backend
        .offer("call-1", "tag-a", SMOKE_SDP, &NgFlags::default())
        .await
        .unwrap();
    let body = records.recv().await.expect("offer recorded");
    for key in ["ws_tee", "ws_tee_direction", "ws_tee_channels"] {
        assert!(
            !body.contains(key),
            "default profile leaked {key} onto the wire: {body}"
        );
    }
}

#[tokio::test]
async fn offer_with_ws_tee_profile_carries_it_to_the_engine() {
    // The declarative path: a media profile carrying ws_tee reaches the engine
    // on offer, without a second round-trip.
    let (address, mut records) = spawn_recording_siphon_rtp().await;
    let backend = siphon_rtp_backend(address);
    backend.ping().await.unwrap();
    records.recv().await.expect("ping recorded");

    let flags = NgFlags {
        ws_tee: Some("wss://asr.example/stream".to_string()),
        ws_tee_direction: Some(WsTeeDirection::Callee),
        ws_tee_channels: Some(1),
        ..NgFlags::default()
    };
    backend
        .offer("call-2", "tag-a", SMOKE_SDP, &flags)
        .await
        .unwrap();
    let body = records.recv().await.expect("offer recorded");
    assert!(
        body.contains(r#""ws_tee":"wss://asr.example/stream""#),
        "ws_tee missing from offer: {body}"
    );
    assert!(
        body.contains(r#""ws_tee_direction":"callee""#),
        "ws_tee_direction missing from offer: {body}"
    );
    assert!(
        body.contains(r#""ws_tee_channels":1"#),
        "ws_tee_channels missing from offer: {body}"
    );
}

#[tokio::test]
async fn ws_tee_is_rejected_by_backends_that_cannot_stream() {
    // A hollow Ok here would read as "the tee is attached" while no audio ever
    // reaches the consumer. The rtpengine backend must say so instead.
    let ng: SocketAddr = "127.0.0.1:22239".parse().unwrap();
    let backend =
        MediaBackend::RtpEngine(RtpEngineSet::new(vec![(ng, 500, 1)]).await.unwrap().into());

    let error = backend
        .attach_ws_tee("c", "f", "ws://h/s", WsTeeDirection::Both, None, None)
        .await
        .expect_err("rtpengine cannot stream a websocket tee");
    let text = error.to_string();
    assert!(
        text.contains("attach_ws_tee"),
        "error must name the operation: {text}"
    );
    assert!(
        text.contains("rtpengine"),
        "error must name the backend: {text}"
    );
    // Never mistaken for "the call is already gone".
    assert!(!error.is_call_not_found());

    let error = backend
        .detach_ws_tee("c", "f")
        .await
        .expect_err("rtpengine cannot detach a websocket tee");
    assert!(error.to_string().contains("detach_ws_tee"));
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
// gated on the `SIPHON_RTP_BIN` env var (path to a `siphon-rtp` binary), so a
// plain `cargo test` stays hermetic. Run locally with:
//   SIPHON_RTP_BIN=../siphon-rtp/target/debug/siphon-rtp \
//     cargo test --test integration_tests -- --ignored siphon_rtp
//
// CI runs it too (the `siphon-rtp-engine-smoke` job) without building the
// engine: the published image is distroless around a *static musl* binary, so
// the job copies /usr/local/bin/siphon-rtp out of it and runs that directly.
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
    let offered = set
        .offer("smoke-ng", "tag-a", SMOKE_SDP, &flags)
        .await
        .unwrap();
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

/// G.711 µ-law (ITU-T G.711) of one linear sample.
fn mu_law(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32_635;
    let sign = if sample < 0 { 0x80 } else { 0 };
    let magnitude = (i32::from(sample).abs()).min(CLIP) + BIAS;
    let exponent = (7 - (magnitude.leading_zeros() as i32 - 17)).clamp(0, 7);
    let mantissa = (magnitude >> (exponent + 3)) & 0x0F;
    !(sign | ((exponent as u8) << 4) | mantissa as u8)
}

/// One 20 ms PCMU packet: an RTP header (RFC 3550 §5.1) and 160 samples.
fn pcmu_packet(ssrc: u32, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let timestamp = u32::from(sequence).wrapping_mul(160);
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// The engine's media address in an answer SDP: `c=` and `m=audio`'s port.
fn answered_address(sdp: &str) -> SocketAddr {
    let host = sdp
        .lines()
        .find_map(|line| line.strip_prefix("c=IN IP4 "))
        .expect("a c= line");
    let port = sdp
        .lines()
        .find_map(|line| line.strip_prefix("m=audio "))
        .and_then(|rest| rest.split(' ').next())
        .expect("an m=audio line");
    format!("{}:{}", host.trim(), port)
        .parse()
        .expect("an address")
}

/// Two seats joined to one room of a REAL engine through the media backend
/// the script API drives: the engine accepts both, the room carries one
/// seat's tone to the other, `delete` of a seated call leaves the room, and
/// the room is gone with its last seat. Also pins the engine's refusal texts
/// the script API maps (a codec it cannot decode to `ValueError`, `no such
/// conference participant` for a seat already released).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a built siphon-rtp binary via SIPHON_RTP_BIN"]
async fn two_seats_in_a_real_siphon_rtp_room_hear_each_other() {
    use siphon::rtpengine::backend::{ConferenceRole, ConferenceSeat};
    use tokio::net::UdpSocket;

    let control_addr = "127.0.0.1:18081";
    let Some(_engine) = spawn_engine(&["--control", control_addr]) else {
        eprintln!("SIPHON_RTP_BIN not set — skipping the siphon-rtp conference test");
        return;
    };
    let (event_tx, _event_rx) = mpsc::channel(64);
    let set = SiphonRtpClientSet::new(
        vec![(control_addr.parse().unwrap(), 2000, 1)],
        None,
        5_000,
        event_tx,
    )
    .unwrap();
    assert!(
        wait_until(|| async { set.ping().await.is_ok() }).await,
        "siphon-rtp control listener did not become ready"
    );
    let backend = MediaBackend::SiphonRtp(set);
    let room = "real-room-1";
    let offer = |port: u16, format: &str| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {format}\r\na=sendrecv\r\n"
        )
    };
    let seat = |from_tag: &str| ConferenceSeat {
        conference_id: room.to_string(),
        from_tag: from_tag.to_string(),
    };

    let alice = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bob = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let alice_seat = backend
        .conference_join(
            "alice@conference.example.com",
            seat("alice"),
            &offer(
                alice.local_addr().unwrap().port(),
                "0\r\na=rtpmap:0 PCMU/8000",
            ),
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("the engine seats alice");
    let bob_seat = backend
        .conference_join(
            "bob@conference.example.com",
            seat("bob"),
            &offer(
                bob.local_addr().unwrap().port(),
                "0\r\na=rtpmap:0 PCMU/8000",
            ),
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("the engine seats bob");
    let (alice_engine, bob_engine) = (answered_address(&alice_seat), answered_address(&bob_seat));
    assert_ne!(alice_engine, bob_engine, "one engine endpoint per seat");

    // Alice talks (a 1 kHz tone, loud enough for the room's VAD); Bob sends
    // silence, so each seat's source is the one its SDP signalled.
    let tone: Vec<u8> = (0..160)
        .map(|index| {
            let phase = 2.0 * std::f64::consts::PI * 1000.0 * f64::from(index) / 8000.0;
            mu_law((phase.sin() * 12_000.0) as i16)
        })
        .collect();
    let silence = vec![0xFFu8; 160];
    let mut heard = Vec::new();
    let mut buffer = [0u8; 2048];
    for sequence in 0..100u16 {
        alice
            .send_to(&pcmu_packet(0x0A11_CE00, sequence, &tone), alice_engine)
            .await
            .unwrap();
        bob.send_to(&pcmu_packet(0x0B0B_0000, sequence, &silence), bob_engine)
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        while let Ok(Ok((read, from))) =
            tokio::time::timeout_at(deadline, bob.recv_from(&mut buffer)).await
        {
            if from == bob_engine && read > 12 {
                heard.extend_from_slice(&buffer[12..read]);
            }
        }
    }
    assert!(!heard.is_empty(), "bob's seat was sent nothing by the room");
    let audible = heard
        .iter()
        .filter(|byte| !matches!(byte, 0xFF | 0x7F | 0xFE | 0x7E))
        .count();
    assert!(
        audible * 4 > heard.len(),
        "bob heard the room, but not alice's tone in it ({audible} of {} samples above silence)",
        heard.len()
    );

    // A participant whose codec the room cannot mix is refused, with the text
    // the script API turns into a ValueError (AMR needs an `amr` build).
    let carol = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let refused = backend
        .conference_join(
            "carol@conference.example.com",
            seat("carol"),
            &offer(
                carol.local_addr().unwrap().port(),
                "97\r\na=rtpmap:97 AMR-WB/16000",
            ),
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await;
    assert!(
        matches!(&refused, Err(siphon::rtpengine::RtpEngineError::EngineError(reason)) if reason.contains("conference_join: decoder")),
        "{refused:?}"
    );

    // `delete` of a seated call leaves its room, and the room ends with its
    // last seat.
    backend
        .delete("alice@conference.example.com", "alice")
        .await
        .expect("alice leaves");
    backend
        .delete("bob@conference.example.com", "bob")
        .await
        .expect("bob leaves");
    let unseated = backend
        .conference_leave("bob@conference.example.com", &seat("bob"))
        .await;
    assert!(
        matches!(&unseated, Err(siphon::rtpengine::RtpEngineError::EngineError(reason)) if reason.contains("no such conference participant")),
        "{unseated:?}"
    );
    let gone = backend
        .conference_play(
            room,
            &siphon::rtpengine::client::PlayMediaSource::Tone("ringback_eu".into()),
            None,
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(&gone, Err(siphon::rtpengine::RtpEngineError::EngineError(reason)) if reason.contains("unknown conference")),
        "{gone:?}"
    );
}
