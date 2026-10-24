use super::*;
use crate::rtpengine::test_engine::TestEngine;

fn scope(name: &str) -> CallScope {
    CallScope::per_call(name).expect("a valid scope")
}

#[test]
fn a_scoped_leg_is_its_own_engine_call_id() {
    assert_eq!(engine_call_id("call-1", None), "call-1");
    assert_eq!(
        engine_call_id("call-1", Some(&scope("orig"))),
        "call-1;orig"
    );
    assert_ne!(
        engine_call_id("call-1", Some(&scope("orig"))),
        engine_call_id("call-1", Some(&scope("term")))
    );
}

#[tokio::test]
async fn rtpengine_addresses_each_scoped_leg_by_its_own_call_id() {
    let engine = TestEngine::start(false).await;
    let backend = engine.backend().await;
    let flags = NgFlags::default();
    let orig = scope("orig");
    assert!(!backend.is_node_scope(&orig), "rtpengine has no node scope");

    backend
        .offer_in(None, "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("unscoped offer");
    backend
        .offer_in(Some(&orig), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig offer");
    backend
        .reoffer_in(Some(&orig), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig re-offer");
    backend
        .answer_in(Some(&orig), "call-1", "tag-a", "tag-b", b"v=0\r\n", &flags)
        .await
        .expect("orig answer");
    backend
        .delete_in(Some(&orig), "call-1", "tag-a")
        .await
        .expect("orig delete");
    backend
        .delete_call_in(Some(&orig), "call-1")
        .await
        .expect("orig delete by id");

    let sent: Vec<(String, Option<String>)> = engine
        .all_commands()
        .into_iter()
        .map(|command| (command.name, command.call_id))
        .collect();
    let named = |name: &str, call_id: &str| (name.to_string(), Some(call_id.to_string()));
    assert_eq!(
        sent,
        vec![
            named("offer", "call-1"),
            named("offer", "call-1;orig"),
            named("offer", "call-1;orig"),
            named("answer", "call-1;orig"),
            named("delete", "call-1;orig"),
            named("delete", "call-1;orig"),
        ]
    );
}

#[test]
fn an_engine_call_id_splits_back_into_the_call_id_and_the_scope() {
    let (call_id, leg) = split_engine_call_id("call-1@192.0.2.10;orig");
    assert_eq!(call_id, "call-1@192.0.2.10");
    assert_eq!(leg, Some(scope("orig")));
    // A Call-ID of its own: no `;`, a suffix that is no scope, nothing before it.
    for unscoped in ["call-1@192.0.2.10", "call-1;has space", "call-1;", ";orig"] {
        assert_eq!(
            split_engine_call_id(unscoped),
            (unscoped, None),
            "{unscoped}"
        );
    }
    let composed = engine_call_id("call-1", Some(&scope("term")));
    assert_eq!(
        split_engine_call_id(&composed),
        ("call-1", Some(scope("term")))
    );
}

#[test]
fn a_scoped_legs_event_names_the_call_id_and_returns_the_scope() {
    let mut event = RtpEngineEvent::MediaTimeout {
        call_id: "call-1;orig".to_string(),
        from_tag: "tag-a".to_string(),
        reason: "no_media",
    };
    assert_eq!(split_event_scope(&mut event), Some(scope("orig")));
    let RtpEngineEvent::MediaTimeout { call_id, .. } = &event else {
        panic!("still a media timeout");
    };
    assert_eq!(call_id, "call-1");
    // The node's own call: unchanged, no scope.
    assert_eq!(split_event_scope(&mut event), None);
    let mut room = RtpEngineEvent::ActiveSpeaker(crate::rtpengine::events::ActiveSpeakerEvent {
        conference_id: "room;orig".to_string(),
        from_tag: None,
    });
    assert_eq!(split_event_scope(&mut room), None, "a room is no leg");
}

/// Every media verb a script runs on a scoped leg reaches rtpengine under the
/// leg's engine call-id, and the leg's playback bookkeeping goes with its
/// delete.
#[tokio::test]
async fn rtpengine_media_verbs_address_a_scoped_leg_by_its_engine_call_id() {
    let engine = TestEngine::start(false).await;
    let backend = engine.backend().await;
    let orig = scope("orig");
    let leg = backend.leg("call-1", Some(&orig));
    assert_eq!(leg.call_id(), "call-1;orig");
    assert_eq!(leg.scope(), Some(&orig));
    let source = crate::rtpengine::client::PlayMediaSource::File("/prompts/hold.wav".into());
    leg.run(backend.play_media(
        leg.call_id(),
        "tag-a",
        &source,
        None,
        None,
        None,
        None,
        false,
        None,
        false,
    ))
    .await
    .expect("prompt");
    assert!(MediaBackend::playback_started("call-1;orig", "tag-a"));
    assert!(!MediaBackend::playback_started("call-1", "tag-a"));
    leg.run(backend.play_dtmf(leg.call_id(), "tag-a", "5", None, None, None, None))
        .await
        .expect("dtmf");
    leg.run(backend.silence_media(leg.call_id(), "tag-a"))
        .await
        .expect("silence");
    leg.run(backend.block_media(leg.call_id(), "tag-a"))
        .await
        .expect("block");
    leg.run(backend.subscribe_request(leg.call_id(), "tag-a", "tag-s", None, &NgFlags::default()))
        .await
        .expect("subscribe");
    backend
        .delete_in(Some(&orig), "call-1", "tag-a")
        .await
        .expect("delete");
    assert!(!MediaBackend::playback_started("call-1;orig", "tag-a"));

    let named: Vec<Option<String>> = engine
        .all_commands()
        .into_iter()
        .map(|command| command.call_id)
        .collect();
    assert_eq!(named.len(), 6);
    assert!(
        named
            .iter()
            .all(|call_id| call_id.as_deref() == Some("call-1;orig")),
        "{named:?}"
    );
    // The node's call is the Call-ID itself, as before.
    assert_eq!(backend.leg("call-1", None).call_id(), "call-1");
}

/// On siphon-rtp a scoped leg keeps the Call-ID and its verbs carry the scope
/// in the frame; the leg's playback bookkeeping still goes with its delete.
#[tokio::test]
async fn siphon_rtp_media_verbs_address_a_scoped_leg_by_its_frame_scope() {
    use crate::rtpengine::test_native_engine::NativeTestEngine;
    let engine = NativeTestEngine::start().await;
    let backend = engine.backend();
    let orig = scope("orig");
    let flags = NgFlags::default();
    backend
        .offer_in(Some(&orig), "call-2", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig offered");
    let leg = backend.leg("call-2", Some(&orig));
    assert_eq!(leg.call_id(), "call-2");
    let source = crate::rtpengine::client::PlayMediaSource::Tone("ringback_eu".into());
    leg.run(backend.play_media(
        leg.call_id(),
        "tag-a",
        &source,
        None,
        None,
        None,
        None,
        false,
        None,
        false,
    ))
    .await
    .expect("prompt on the leg's own engine call");
    assert!(MediaBackend::playback_started("call-2;orig", "tag-a"));
    leg.run(backend.stop_media(leg.call_id(), "tag-a", None))
        .await
        .expect("stopped on the leg's own engine call");
    // The node's call was never anchored, so the same verb without the leg
    // goes to another engine call, which the engine does not hold.
    assert!(backend.stop_media("call-2", "tag-a", None).await.is_err());
    leg.run(backend.play_media(
        leg.call_id(),
        "tag-a",
        &source,
        None,
        None,
        None,
        None,
        false,
        None,
        false,
    ))
    .await
    .expect("a second prompt");
    backend
        .delete_in(Some(&orig), "call-2", "tag-a")
        .await
        .expect("delete");
    assert!(!MediaBackend::playback_started("call-2;orig", "tag-a"));
    let scopes = |name: &str| {
        engine
            .commands(name)
            .into_iter()
            .map(|command| (command.scope, command.refused))
            .collect::<Vec<_>>()
    };
    let on_leg = (Some("orig".to_string()), false);
    assert_eq!(scopes("play_media"), vec![on_leg.clone(), on_leg.clone()]);
    assert_eq!(scopes("stop_media"), vec![on_leg, (None, true)]);
    assert_eq!(engine.held_count(), 0);
}

/// A minimal rtpproxy for the scoped path: it records every command line it
/// is sent and answers `U` / `L` with a relay port and address, `D` with `0`,
/// as the rtpproxy client tests' engine does.
async fn rtpproxy_recording_lines() -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a loopback socket");
    let address = socket.local_addr().expect("the socket's address");
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = std::sync::Arc::clone(&lines);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
            let Ok(datagram) = std::str::from_utf8(&buffer[..size]) else {
                continue;
            };
            let Some((cookie, command)) = datagram.split_once(' ') else {
                continue;
            };
            let result = if command.starts_with('U') || command.starts_with('L') {
                "30000 203.0.113.1"
            } else if command.starts_with('V') {
                "20040107"
            } else {
                "0"
            };
            recorded
                .lock()
                .expect("the command log")
                .push(command.to_string());
            let _ = socket
                .send_to(format!("{cookie} {result}").as_bytes(), source)
                .await;
        }
    });
    (address, lines)
}

/// rtpproxy knows a call by its call-id alone, so each scoped leg is the
/// engine call `<call-id>;<scope>`: offer, answer and delete of one leg name
/// it, and the other leg and the node's call are never touched.
#[tokio::test]
async fn rtpproxy_anchors_offers_answers_and_deletes_a_scoped_leg_under_its_engine_call_id() {
    let (address, lines) = rtpproxy_recording_lines().await;
    let set = crate::rtpengine::rtpproxy::RtpProxyClientSet::new(vec![(address, 1000, 1)], 1)
        .await
        .expect("an rtpproxy set");
    let backend = MediaBackend::RtpProxy(set);
    let flags = NgFlags::default();
    let offer = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 20000 RTP/AVP 0\r\n",
    );
    let answer = offer.replace("192.0.2.10", "198.51.100.7");
    let (orig, term) = (scope("orig"), scope("term"));

    for leg in [&orig, &term] {
        let rewritten = backend
            .offer_in(Some(leg), "call-1", "tag-a", offer.as_bytes(), &flags)
            .await
            .expect("offered");
        let rewritten = String::from_utf8(rewritten).expect("utf-8");
        assert!(rewritten.contains("c=IN IP4 203.0.113.1"), "{rewritten}");
        assert!(rewritten.contains("m=audio 30000 RTP/AVP 0"), "{rewritten}");
    }
    backend
        .answer_in(
            Some(&orig),
            "call-1",
            "tag-a",
            "tag-b",
            answer.as_bytes(),
            &flags,
        )
        .await
        .expect("answered");
    backend
        .delete_in(Some(&orig), "call-1", "tag-a")
        .await
        .expect("deleted");
    assert_eq!(backend.active_sessions(), 1, "the term leg stays");
    backend
        .delete_in(Some(&term), "call-1", "tag-a")
        .await
        .expect("deleted");
    assert_eq!(backend.active_sessions(), 0, "both legs drained");

    let lines = lines.lock().expect("the command log").clone();
    let words: Vec<(String, String)> = lines
        .iter()
        .map(|line| {
            let mut words = line.split(' ');
            let verb = words.next().unwrap_or_default();
            let call_id = words.next().unwrap_or_default();
            (verb.chars().take(1).collect(), call_id.to_string())
        })
        .collect();
    let named = |verb: &str, call_id: &str| (verb.to_string(), call_id.to_string());
    assert_eq!(
        words,
        vec![
            named("U", "call-1;orig"),
            named("U", "call-1;term"),
            named("L", "call-1;orig"),
            named("D", "call-1;orig"),
            named("D", "call-1;term"),
        ],
        "{lines:?}"
    );
}
