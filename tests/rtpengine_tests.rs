//! Standalone integration tests for RTPEngine module.
//!
//! Tests the full flow: SIP message with SDP → RTPEngine client → rewritten SDP.
//! Uses mock UDP servers to simulate RTPEngine instances.
//!
//! Separated from integration_tests.rs to avoid coupling with other test modules.

use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::net::UdpSocket;

use siphon::rtpengine::bencode::{self, BencodeValue};
use siphon::rtpengine::client::{PlayMediaSource, RtpEngineClient, RtpEngineSet};
use siphon::rtpengine::profile::{NgFlags, ProfileRegistry};
use siphon::rtpengine::session::{MediaSession, MediaSessionStore};
use siphon::sip::parser::parse_sip_message;

/// Spawn a mock RTPEngine that rewrites SDP c-line and m-line port.
async fn spawn_mock_rtpengine() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buffer = BytesMut::zeroed(65535);
        while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
            let data = &buffer[..size];
            let space = data.iter().position(|&b| b == b' ').unwrap();
            let cookie = std::str::from_utf8(&data[..space]).unwrap().to_string();

            let payload = &data[space + 1..];
            let command = bencode::decode_full_dict(payload).unwrap();
            let command_name = command.dict_get_str("command").unwrap_or("unknown");

            let response = match command_name {
                "ping" => BencodeValue::dict(vec![
                    ("result", BencodeValue::string("pong")),
                ]),
                "offer" | "answer" => {
                    // Rewrite SDP: replace c-line IP and m-line port.
                    let rewritten_sdp = concat!(
                        "v=0\r\n",
                        "o=- 0 0 IN IP4 203.0.113.1\r\n",
                        "s=-\r\n",
                        "c=IN IP4 203.0.113.1\r\n",
                        "t=0 0\r\n",
                        "m=audio 30000 RTP/AVP 0 8 101\r\n",
                        "a=rtpmap:0 PCMU/8000\r\n",
                        "a=rtpmap:8 PCMA/8000\r\n",
                        "a=rtpmap:101 telephone-event/8000\r\n",
                    );
                    BencodeValue::dict(vec![
                        ("result", BencodeValue::string("ok")),
                        ("sdp", BencodeValue::string(rewritten_sdp)),
                    ])
                }
                "delete" => BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                ]),
                "query" => BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("totals", BencodeValue::dict(vec![
                        ("RTP", BencodeValue::dict(vec![
                            ("packets", BencodeValue::from_integer(1000)),
                            ("bytes", BencodeValue::from_integer(160000)),
                        ])),
                    ])),
                ]),
                "play media" => BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("duration", BencodeValue::from_integer(3500)),
                ]),
                "stop media" | "play DTMF"
                | "silence media" | "unsilence media"
                | "block media" | "unblock media" => BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                ]),
                _ => BencodeValue::dict(vec![
                    ("result", BencodeValue::string("error")),
                    ("error-reason", BencodeValue::string("unknown command")),
                ]),
            };

            let encoded = bencode::encode(&response);
            let mut reply = Vec::new();
            reply.extend_from_slice(cookie.as_bytes());
            reply.push(b' ');
            reply.extend_from_slice(&encoded);
            let _ = socket.send_to(&reply, source).await;
        }
    });

    address
}

/// Build a sample INVITE with SDP body.
fn make_invite_with_sdp() -> String {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 0 0 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 8000 RTP/AVP 0 8 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
    );
    format!(
        concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test-1\r\n",
            "From: <sip:alice@atlanta.com>;tag=from-tag-1\r\n",
            "To: <sip:bob@biloxi.com>\r\n",
            "Call-ID: call-rtpengine-test-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:alice@10.0.0.1:5060>\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        sdp.len(),
        sdp
    )
}

/// Build a 200 OK response with SDP body.
fn make_200ok_with_sdp() -> String {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 0 0 IN IP4 10.0.0.2\r\n",
        "s=-\r\n",
        "c=IN IP4 10.0.0.2\r\n",
        "t=0 0\r\n",
        "m=audio 9000 RTP/AVP 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
    );
    format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test-1\r\n",
            "From: <sip:alice@atlanta.com>;tag=from-tag-1\r\n",
            "To: <sip:bob@biloxi.com>;tag=to-tag-1\r\n",
            "Call-ID: call-rtpengine-test-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:bob@10.0.0.2:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        sdp.len(),
        sdp
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_offer_answer_delete_flow() {
    let mock_addr = spawn_mock_rtpengine().await;
    let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();

    // Offer — extract SDP from INVITE, send to RTPEngine.
    let invite_raw = make_invite_with_sdp();
    let invite = parse_sip_message(&invite_raw).unwrap().1;
    let original_sdp = &invite.body;
    assert!(!original_sdp.is_empty());

    let registry = ProfileRegistry::new();
    let offer_flags = &registry.get("srtp_to_rtp").unwrap().offer;
    let rewritten_sdp = client
        .offer("call-rtpengine-test-1", "from-tag-1", original_sdp, offer_flags)
        .await
        .unwrap();

    let rewritten_str = std::str::from_utf8(&rewritten_sdp).unwrap();
    assert!(rewritten_str.contains("203.0.113.1"), "SDP should be rewritten to RTPEngine IP");
    assert!(rewritten_str.contains("30000"), "SDP should have RTPEngine port");
    assert!(!rewritten_str.contains("10.0.0.1"), "Original IP should be gone");

    // Answer — extract SDP from 200 OK, send to RTPEngine.
    let ok_raw = make_200ok_with_sdp();
    let ok_msg = parse_sip_message(&ok_raw).unwrap().1;
    let answer_sdp = &ok_msg.body;

    let answer_flags = &registry.get("srtp_to_rtp").unwrap().answer;
    let rewritten_answer = client
        .answer("call-rtpengine-test-1", "from-tag-1", "to-tag-1", answer_sdp, answer_flags)
        .await
        .unwrap();

    let answer_str = std::str::from_utf8(&rewritten_answer).unwrap();
    assert!(answer_str.contains("203.0.113.1"));

    // Query — get session stats.
    let stats = client
        .query("call-rtpengine-test-1", "from-tag-1")
        .await
        .unwrap();
    assert_eq!(stats.dict_get_str("result"), Some("ok"));

    // Delete — tear down.
    client
        .delete("call-rtpengine-test-1", "from-tag-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn session_store_tracks_offer_and_answer() {
    let store = MediaSessionStore::new();

    // Offer creates a session.
    store.insert(MediaSession {
        call_id: "call-1".to_string(),
        from_tag: "tag-a".to_string(),
        to_tag: None,
        profile: "srtp_to_rtp".to_string(),
        created_at: std::time::Instant::now(),
    });

    let session = store.get("call-1").unwrap();
    assert!(session.to_tag.is_none());

    // Answer sets the to-tag.
    store.set_to_tag("call-1", "tag-b".to_string());
    let session = store.get("call-1").unwrap();
    assert_eq!(session.to_tag.as_deref(), Some("tag-b"));

    // Delete removes it.
    store.remove("call-1");
    assert!(store.get("call-1").is_none());
}

#[tokio::test]
async fn multi_instance_weighted_round_robin() {
    let addr1 = spawn_mock_rtpengine().await;
    let addr2 = spawn_mock_rtpengine().await;

    // Instance 1 has weight 3, instance 2 has weight 1.
    let set = RtpEngineSet::new(vec![
        (addr1, 2000, 3),
        (addr2, 2000, 1),
    ])
    .await
    .unwrap();

    assert_eq!(set.instance_count(), 2);

    // Ping all instances.
    set.ping_all().await.unwrap();

    // Multiple offers to different call-ids.
    let flags = NgFlags::default();
    for index in 0..10 {
        let call_id = format!("call-weighted-{index}");
        set.offer(&call_id, "tag-a", b"v=0\r\n", &flags)
            .await
            .unwrap();
    }

    // All should be tracked with affinity.
    assert_eq!(set.active_sessions(), 10);

    // Delete cleans up affinity.
    for index in 0..10 {
        let call_id = format!("call-weighted-{index}");
        set.delete(&call_id, "tag-a").await.unwrap();
    }
    assert_eq!(set.active_sessions(), 0);
}

#[tokio::test]
async fn profile_flags_produce_valid_bencode() {
    // Verify that NgFlags for each profile produce valid bencode dictionaries.
    let registry = ProfileRegistry::new();
    for name in &["srtp_to_rtp", "ws_to_rtp", "wss_to_rtp", "rtp_passthrough"] {
        let entry = registry.get(name).unwrap();
        let offer_flags = &entry.offer;
        let answer_flags = &entry.answer;

        // Convert to bencode pairs and build a dict.
        let offer_pairs = offer_flags.to_bencode_pairs();
        let answer_pairs = answer_flags.to_bencode_pairs();

        // Build full offer command dict.
        let mut all_pairs = vec![
            ("command", BencodeValue::string("offer")),
            ("call-id", BencodeValue::string("test")),
            ("from-tag", BencodeValue::string("tag")),
            ("sdp", BencodeValue::string("v=0\r\n")),
        ];
        all_pairs.extend(offer_pairs);
        let dict = BencodeValue::dict(all_pairs);

        // Encode → decode roundtrip.
        let encoded = bencode::encode(&dict);
        let decoded = bencode::decode_full_dict(&encoded).unwrap();
        assert_eq!(decoded.dict_get_str("command"), Some("offer"));

        // Same for answer.
        let mut answer_all = vec![
            ("command", BencodeValue::string("answer")),
            ("call-id", BencodeValue::string("test")),
            ("from-tag", BencodeValue::string("tag")),
            ("to-tag", BencodeValue::string("tag-b")),
            ("sdp", BencodeValue::string("v=0\r\n")),
        ];
        answer_all.extend(answer_pairs);
        let dict = BencodeValue::dict(answer_all);
        let encoded = bencode::encode(&dict);
        let decoded = bencode::decode_full_dict(&encoded).unwrap();
        assert_eq!(decoded.dict_get_str("command"), Some("answer"));
    }
}

/// Full MMTEL-style announcement flow: offer → answer → play_media → stop_media → delete.
///
/// Simulates the TAS announcement pattern — a B2BUA leg anchored via RTPEngine
/// plays a prompt via the audio player, then cleans up.
#[tokio::test]
async fn announcement_flow_play_stop_delete() {
    let mock_addr = spawn_mock_rtpengine().await;
    let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();

    let invite_raw = make_invite_with_sdp();
    let invite = parse_sip_message(&invite_raw).unwrap().1;
    let registry = ProfileRegistry::new();
    let offer_flags = &registry.get("srtp_to_rtp").unwrap().offer;

    // 1. Anchor media via offer
    let rewritten_offer = client
        .offer(
            "call-announce-1",
            "caller-tag",
            &invite.body,
            offer_flags,
        )
        .await
        .unwrap();
    assert!(std::str::from_utf8(&rewritten_offer).unwrap().contains("30000"));

    // 2. Complete 200 OK via answer
    let ok_raw = make_200ok_with_sdp();
    let ok_msg = parse_sip_message(&ok_raw).unwrap().1;
    let answer_flags = &registry.get("srtp_to_rtp").unwrap().answer;
    client
        .answer(
            "call-announce-1",
            "caller-tag",
            "announce-tag",
            &ok_msg.body,
            answer_flags,
        )
        .await
        .unwrap();

    // 3. Play announcement — caller's from-tag selects monologue;
    //    per rtpengine semantics the peer (announcement player) is unused
    //    and the caller hears the prompt replacing their own outgoing stream.
    let duration = client
        .play_media(
            "call-announce-1",
            "caller-tag",
            &PlayMediaSource::File("/var/lib/siphon/prompts/welcome.wav".to_string()),
            Some(1),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(duration, Some(3500));

    // 4. Stop announcement (e.g. caller pressed a key, or we're swapping prompts)
    client.stop_media("call-announce-1", "caller-tag").await.unwrap();

    // 5. Tear down
    client.delete("call-announce-1", "caller-tag").await.unwrap();
}

/// Silence / block gating flow — the hold-music / LI-warning pattern.
#[tokio::test]
async fn gating_silence_block_cycle() {
    let mock_addr = spawn_mock_rtpengine().await;
    let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();

    client.silence_media("call-gate-1", "tag-a").await.unwrap();
    client.unsilence_media("call-gate-1", "tag-a").await.unwrap();
    client.block_media("call-gate-1", "tag-a").await.unwrap();
    client.unblock_media("call-gate-1", "tag-a").await.unwrap();
}

/// DTMF injection — CCBS tones and IVR.
#[tokio::test]
async fn dtmf_injection_with_sequence() {
    let mock_addr = spawn_mock_rtpengine().await;
    let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();

    client
        .play_dtmf(
            "call-dtmf-1",
            "tag-a",
            "*21*1234#",
            Some(100),
            Some(-8),
            Some(60),
            None,
        )
        .await
        .unwrap();
}

/// Multi-instance affinity for media commands: once a call-id is bound via
/// offer, all media-injection commands for that call-id go to the same
/// instance.
#[tokio::test]
async fn media_commands_honor_affinity() {
    let addr1 = spawn_mock_rtpengine().await;
    let addr2 = spawn_mock_rtpengine().await;
    let set = RtpEngineSet::new(vec![
        (addr1, 2000, 1),
        (addr2, 2000, 1),
    ])
    .await
    .unwrap();

    let flags = NgFlags::default();
    set.offer("call-mm-1", "tag-a", b"v=0\r\n", &flags).await.unwrap();

    // These all succeed via the affinity-bound instance.
    set.play_media(
        "call-mm-1",
        "tag-a",
        &PlayMediaSource::File("/a.wav".to_string()),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    set.stop_media("call-mm-1", "tag-a").await.unwrap();
    set.play_dtmf("call-mm-1", "tag-a", "5", None, None, None, None)
        .await
        .unwrap();
    set.silence_media("call-mm-1", "tag-a").await.unwrap();
    set.unsilence_media("call-mm-1", "tag-a").await.unwrap();
    set.block_media("call-mm-1", "tag-a").await.unwrap();
    set.unblock_media("call-mm-1", "tag-a").await.unwrap();
    set.delete("call-mm-1", "tag-a").await.unwrap();
    assert_eq!(set.active_sessions(), 0);
}

#[tokio::test]
async fn config_media_section_backward_compatible() {
    use siphon::config::Config;

    // Config without media section should parse fine.
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
    );
    let config = Config::from_str(yaml).unwrap();
    assert!(config.media.is_none());

    // Config with media section should parse with the RTPEngine addresses.
    let yaml_with_media = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "media:\n",
        "  rtpengine:\n",
        "    address: \"127.0.0.1:22222\"\n",
    );
    let config = Config::from_str(yaml_with_media).unwrap();
    let media = config.media.unwrap();
    let instances = media.rtpengine.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].address, "127.0.0.1:22222");
}
