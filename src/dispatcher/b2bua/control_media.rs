//! Media anchoring for a controller-owned unanswered dial.

use crate::dispatcher::*;

/// Allocate a two-party media path, retaining the original caller offer.
/// Nothing is sent to either SIP party until the allocation succeeds.
///
/// One allocation serves the whole dial, however many branches it has. Each
/// phone is offered the same anchored SDP, exactly as a forking proxy offers
/// one body to every branch, and whichever branch sends SDP is answered against
/// it — the media engine re-points the far side of the relay on each answer, so
/// the last SDP to arrive is what the caller hears and the 2xx settles it on
/// the branch that won (RFC 3261 §16.7). What a single allocation cannot do is
/// give two *simultaneously* ringing branches separate early-media paths; that
/// needs one allocation per branch and is not what this is.
pub fn control_dial_media_offer(
    invite: &SipMessage,
    source_ip: std::net::IpAddr,
    profile_name: &str,
    state: &DispatcherState,
) -> Result<SipMessage, String> {
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or("dial profile requires a media backend")?;
    let profiles = state
        .rtpengine_profiles
        .as_ref()
        .ok_or("dial profile requires media profiles")?;
    let sessions = state
        .rtpengine_sessions
        .as_ref()
        .ok_or("dial profile requires a media session store")?;
    let profile = profiles
        .get(profile_name)
        .ok_or_else(|| format!("unknown media profile '{profile_name}'"))?;
    let call_id = invite
        .headers
        .call_id()
        .ok_or("dial offer has no Call-ID")?;
    if sessions.get(call_id).is_some() {
        return Err("dial profile cannot replace an existing media session".into());
    }
    if sdp_in_body(message_content_type(invite), &invite.body).is_none() {
        return Err("dial profile requires a caller SDP offer".into());
    }
    let from_tag = invite
        .headers
        .from()
        .and_then(|value| crate::sip::headers::nameaddr::NameAddr::parse(value).ok())
        .and_then(|value| value.tag)
        .ok_or("dial offer has no From tag")?;
    let mut flags = profile.offer.clone();
    if flags.carry_received_from {
        flags.received_from = Some(source_ip);
    }
    for half in [&flags, &profile.answer] {
        let unsupported = backend.unsupported_flags(half);
        if !unsupported.is_empty() {
            return Err(format!(
                "media backend cannot honour profile flags: {}",
                unsupported.join(", ")
            ));
        }
        if half.ws_uri.is_some() || half.ws_tee.is_some() {
            return Err("dial profiles cannot attach a WebSocket bridge or tee".into());
        }
    }
    // A later voicemail anchor uses the SIP Call-ID. A late deletion of this
    // failed attempt must never delete that newly allocated media session.
    let engine_call_id = crate::b2bua::actor::generate_call_id();
    let body = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.offer(
            &engine_call_id,
            &from_tag,
            &invite.body,
            &flags,
        ))
    })
    .map_err(|error| format!("dial media offer failed: {error}"))?;
    sessions.insert(crate::rtpengine::MediaSession {
        call_id: call_id.clone(),
        rtpengine_call_id: engine_call_id,
        from_tag,
        to_tag: None,
        profile: profile_name.to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        created_at: std::time::Instant::now(),
    });
    let mut rewritten = invite.clone();
    rewritten.body = body;
    rewritten
        .headers
        .set("Content-Length", rewritten.body.len().to_string());
    Ok(rewritten)
}

/// Rewrite a dialled phone's early/final answer for the caller using the
/// opposite half of the selected profile. Once a call is known to own an
/// allocation, a missing session fails closed.
///
/// Every B-leg answer and every provisional carrying SDP comes through here, so
/// the two "this is not a profiled dial" exits have to be plain no-ops: a call
/// that never asked for a profile, and one whose actor a concurrent teardown has
/// already removed. Reporting the second as a media failure would abandon a 2xx
/// or cancel the ringing branches of a call the control plane never touched.
pub fn control_dial_media_answer(
    call_id: &str,
    response: &mut SipMessage,
    source_ip: std::net::IpAddr,
    state: &DispatcherState,
) -> Result<(), String> {
    let Some(call) = state.call_actors.get_call(call_id) else {
        return Ok(());
    };
    if !call.control_dial_media {
        return Ok(());
    }
    let sip_call_id = call.a_leg.dialog.call_id.clone();
    drop(call);
    let sessions = state
        .rtpengine_sessions
        .as_ref()
        .ok_or("dial media store is gone")?;
    let session = sessions
        .get(&sip_call_id)
        .ok_or("dial media session is gone")?;
    // A final response may repeat an early answer without carrying SDP, but
    // cannot establish a media session that the phone never answered.
    if response.body.is_empty() {
        return if session.to_tag.is_some() {
            Ok(())
        } else {
            Err("dial final response has no SDP answer".into())
        };
    }
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or("dial media backend is gone")?;
    let profile = state
        .rtpengine_profiles
        .as_ref()
        .and_then(|profiles| profiles.get(&session.profile))
        .ok_or("dial media profile is gone")?;
    let to_tag = response
        .headers
        .to()
        .and_then(|value| crate::sip::headers::nameaddr::NameAddr::parse(value).ok())
        .and_then(|value| value.tag)
        .ok_or("dial answer has no To tag")?;
    let mut flags = profile.answer.clone();
    if flags.carry_received_from {
        flags.received_from = Some(source_ip);
    }
    let body = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer(
            session.rtpengine_id(),
            &session.from_tag,
            &to_tag,
            &response.body,
            &flags,
        ))
    })
    .map_err(|error| format!("dial media answer failed: {error}"))?;
    sessions.set_to_tag(&sip_call_id, to_tag);
    response.body = body;
    response
        .headers
        .set("Content-Length", response.body.len().to_string());
    Ok(())
}

/// Release a failed attempt before the controller starts its next flow step.
pub fn release_control_dial_media(call_id: &str, state: &DispatcherState) {
    let sip_call_id = state
        .call_actors
        .get_call_mut(call_id)
        .and_then(|mut call| {
            if !call.control_dial_media {
                return None;
            }
            call.control_dial_media = false;
            call.control_dial_offer = None;
            Some(call.a_leg.dialog.call_id.clone())
        });
    if let Some(sip_call_id) = sip_call_id {
        release_failed_call_media(&sip_call_id, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::test_dispatcher::test_dispatcher;
    use crate::rtpengine::test_engine::{TestEngine, ENGINE_SDP};

    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0\r\n",
    );

    fn invite() -> SipMessage {
        parse_sip_message_bytes(
            format!(
                concat!(
                    "INVITE sip:201@example.com SIP/2.0\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-media\r\n",
                    "From: <sip:caller@example.com>;tag=caller\r\n",
                    "To: <sip:201@example.com>\r\n",
                    "Call-ID: control-media@example.com\r\n",
                    "CSeq: 1 INVITE\r\n",
                    "Content-Type: application/sdp\r\n",
                    "Content-Length: {}\r\n\r\n{}"
                ),
                OFFER.len(),
                OFFER
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dial_media_rewrites_the_offer_without_answering_the_caller() {
        let engine = TestEngine::start(false).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        dispatcher.state.rtpengine_sessions =
            Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        let original = invite();
        let rewritten = control_dial_media_offer(
            &original,
            "192.0.2.10".parse().unwrap(),
            "rtp_to_srtp",
            &dispatcher.state,
        )
        .unwrap();
        assert_eq!(rewritten.body, ENGINE_SDP.as_bytes());
        assert_eq!(
            original.body,
            OFFER.as_bytes(),
            "keep the caller offer for voicemail fallback"
        );
        assert!(
            dispatcher.udp.try_recv().is_err(),
            "anchoring must not answer the caller"
        );
        let session = dispatcher
            .state
            .rtpengine_sessions
            .as_ref()
            .unwrap()
            .get("control-media@example.com")
            .unwrap();
        assert_ne!(
            session.rtpengine_id(),
            session.call_id,
            "a failed dial delete cannot delete the next voicemail anchor"
        );
        assert_eq!(engine.commands("offer")[0].sdp.as_deref(), Some(OFFER));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dial_media_refuses_a_missing_backend_before_sending_anything() {
        let dispatcher = test_dispatcher();
        assert!(control_dial_media_offer(
            &invite(),
            "192.0.2.10".parse().unwrap(),
            "rtp_to_srtp",
            &dispatcher.state
        )
        .is_err());
        assert!(dispatcher.udp.try_recv().is_err());
    }

    /// An answer for a call this module has no allocation for is not a media
    /// failure. Both callers abandon the call on `Err`, so a plain B2BUA call
    /// racing its own teardown must come back through here untouched.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_for_a_call_without_a_profiled_dial_is_left_alone() {
        let dispatcher = test_dispatcher();
        let original = response(&invite(), 200);

        let mut gone = original.clone();
        assert_eq!(
            control_dial_media_answer(
                "a-call-that-has-been-torn-down",
                &mut gone,
                "192.0.2.10".parse().unwrap(),
                &dispatcher.state,
            ),
            Ok(())
        );
        assert_eq!(gone.body, original.body);

        let call_id = park(&dispatcher.state);
        let mut unprofiled = original.clone();
        assert_eq!(
            control_dial_media_answer(
                &call_id,
                &mut unprofiled,
                "192.0.2.10".parse().unwrap(),
                &dispatcher.state,
            ),
            Ok(())
        );
        assert_eq!(unprofiled.body, original.body);
    }

    fn park(state: &DispatcherState) -> String {
        let call_id = state.call_actors.create_call(Leg::new_a_leg(
            "control-media@example.com".into(),
            "caller".into(),
            "z9hG4bK-media".into(),
            LegTransport {
                remote_addr: "192.0.2.10:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ));
        state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(invite())));
        call_id
    }

    /// Four desk phones, the shape the reported ring-group fault had.
    const RING_GROUP: &[&str] = &[
        "198.51.100.7:5060",
        "198.51.100.8:5060",
        "198.51.100.9:5060",
        "198.51.100.10:5060",
    ];

    /// The caller's own media, as its offer names it — what a branch must not
    /// be given once a profile has promised a relay in the middle.
    const CALLER_MEDIA_PORT: &str = "m=audio 40000";

    /// This INVITE was offered the relay's media, not the caller's.
    ///
    /// Checked on fields rather than against the engine's reply verbatim: the
    /// B-leg builder rewrites the SDP origin line (`o=`) on the way out, so the
    /// body on the wire is never byte-identical to what the engine returned.
    fn assert_anchored(body: &[u8], label: &str) {
        let sdp = String::from_utf8_lossy(body);
        assert!(
            sdp.contains("c=IN IP4 203.0.113.50\r\n"),
            "{label}: not the relay's address: {sdp}"
        );
        assert!(
            !sdp.contains(CALLER_MEDIA_PORT),
            "{label}: the caller's own media reached the phone, around the relay: {sdp}"
        );
    }

    /// A profiled dial across several targets, parallel or sequential.
    fn fork(
        state: &DispatcherState,
        addresses: &[&str],
        parallel: bool,
        profile: &str,
    ) -> Result<bool, DialError> {
        b2bua_dial_call_with_state(
            "control-media@example.com",
            addresses
                .iter()
                .map(|address| DialTarget {
                    uri: format!("sip:201@{address}"),
                    ..Default::default()
                })
                .collect(),
            parallel,
            30,
            &[],
            &DialShaping {
                profile: Some(profile.to_string()),
                ..Default::default()
            },
            state,
        )
    }

    fn dial(state: &DispatcherState, profile: &str) -> Result<bool, DialError> {
        b2bua_dial_call_with_state(
            "control-media@example.com",
            vec![DialTarget {
                uri: "sip:201@198.51.100.7:5060".into(),
                ..Default::default()
            }],
            true,
            30,
            &[],
            &DialShaping {
                profile: Some(profile.to_string()),
                ..Default::default()
            },
            state,
        )
    }

    fn response(invite: &SipMessage, code: u16) -> SipMessage {
        let mut response = build_response(invite, code, "Test", None, &[]);
        response
            .headers
            .set("To", format!("{};tag=phone", invite.headers.to().unwrap()));
        response
            .headers
            .set("Contact", "<sip:201@198.51.100.7:5060>".into());
        response
            .headers
            .set("Content-Type", "application/sdp".into());
        response.body = OFFER.replace("RTP/AVP", "RTP/SAVP").into_bytes();
        response
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn directional_dial_rewrites_both_wire_sdps_and_keeps_the_caller_unanswered_until_the_phone_answers(
    ) {
        let engine = TestEngine::start(false).await;
        for (profile, offer_protocol, answer_protocol) in [
            ("rtp_to_srtp", "RTP/SAVP", "RTP/AVP"),
            ("srtp_to_rtp", "RTP/AVP", "RTP/SAVP"),
        ] {
            let mut dispatcher = test_dispatcher();
            dispatcher.state.rtpengine_set = Some(engine.backend().await);
            dispatcher.state.rtpengine_sessions =
                Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
            dispatcher.state.rtpengine_profiles =
                Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
            let call_id = park(&dispatcher.state);
            assert!(dial(&dispatcher.state, profile).unwrap());
            let outbound = dispatcher.udp.try_recv().unwrap();
            assert_eq!(outbound.destination, "198.51.100.7:5060".parse().unwrap());
            let sent_invite = parse_sip_message_bytes(&outbound.data).unwrap();
            assert!(
                String::from_utf8_lossy(&sent_invite.body).contains("c=IN IP4 203.0.113.50\r\n")
            );
            assert!(
                dispatcher.udp.try_recv().is_err(),
                "caller remains unanswered"
            );
            assert_eq!(
                engine
                    .commands("offer")
                    .last()
                    .unwrap()
                    .transport_protocol
                    .as_deref(),
                Some(offer_protocol)
            );
            let branch = sent_invite
                .headers
                .get("Via")
                .unwrap()
                .split("branch=")
                .nth(1)
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let mut answer = response(&sent_invite, 200);
            assert!(handle_b2bua_response(
                &call_id,
                branch,
                &mut answer,
                200,
                "198.51.100.7:5060".parse().unwrap(),
                &dispatcher.state
            ));
            let mut received_answer = false;
            while let Ok(outbound) = dispatcher.udp.try_recv() {
                let message = parse_sip_message_bytes(&outbound.data).unwrap();
                if message.status_code() == Some(200) {
                    assert_eq!(outbound.destination, "192.0.2.10:5060".parse().unwrap());
                    assert!(String::from_utf8_lossy(&message.body).contains("203.0.113.50"));
                    received_answer = true;
                }
            }
            assert!(received_answer);
            assert_eq!(
                engine
                    .commands("answer")
                    .last()
                    .unwrap()
                    .transport_protocol
                    .as_deref(),
                Some(answer_protocol)
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_dials_release_the_media_store_before_fallback_and_drain_to_baseline() {
        let engine = TestEngine::start(false).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        dispatcher.state.rtpengine_sessions = Some(sessions.clone());
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        for _ in 0..20 {
            let call_id = park(&dispatcher.state);
            assert!(dial(&dispatcher.state, "rtp_to_srtp").unwrap());
            let engine_id = sessions
                .get("control-media@example.com")
                .unwrap()
                .rtpengine_id()
                .to_string();
            assert!(report_control_dial_failure(
                &call_id,
                488,
                "Not Acceptable Here",
                false,
                &dispatcher.state
            ));
            assert_eq!(
                sessions.len(),
                0,
                "fallback must not reuse failed phone media"
            );
            let call = dispatcher.state.call_actors.get_call(&call_id).unwrap();
            assert_eq!(
                call.a_leg_invite.as_ref().unwrap().lock().unwrap().body,
                OFFER.as_bytes()
            );
            assert!(!call.control_dial_media);
            drop(call);
            dispatcher.state.call_actors.remove_call(&call_id);
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while !engine
                    .commands("delete")
                    .iter()
                    .any(|command| command.call_id.as_deref() == Some(&engine_id))
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(engine.commands("delete").len(), 20);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_media_answer_failure_never_sends_the_caller_a_success_response() {
        let engine = TestEngine::start(true).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        dispatcher.state.rtpengine_sessions =
            Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        let call_id = park(&dispatcher.state);
        assert!(dial(&dispatcher.state, "rtp_to_srtp").unwrap());
        let sent_invite =
            parse_sip_message_bytes(&dispatcher.udp.try_recv().unwrap().data).unwrap();
        let branch = sent_invite
            .headers
            .get("Via")
            .unwrap()
            .split("branch=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut answer = response(&sent_invite, 200);
        assert!(handle_b2bua_response(
            &call_id,
            branch,
            &mut answer,
            200,
            "198.51.100.7:5060".parse().unwrap(),
            &dispatcher.state
        ));
        let mut refused_caller = false;
        while let Ok(outbound) = dispatcher.udp.try_recv() {
            let message = parse_sip_message_bytes(&outbound.data).unwrap();
            if outbound.destination == "192.0.2.10:5060".parse().unwrap() {
                assert_ne!(message.status_code(), Some(200));
                refused_caller |= message.status_code().is_some_and(|code| code >= 400);
            }
        }
        assert!(
            refused_caller,
            "every caller still receives a final response"
        );
        assert_eq!(
            dispatcher.state.rtpengine_sessions.as_ref().unwrap().len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_profile_fails_before_allocating_or_ringing() {
        let engine = TestEngine::start(false).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        dispatcher.state.rtpengine_sessions =
            Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        park(&dispatcher.state);
        assert!(dial(&dispatcher.state, "absent-profile").is_err());
        assert!(engine.commands("offer").is_empty());
        assert!(dispatcher.udp.try_recv().is_err());
    }

    /// A ring group is the case a profile is needed for *most*: the carrier
    /// hands over plain RTP at a routable address and every phone answers from
    /// an address on its own LAN, so the two ends cannot reach each other
    /// without the relay in the middle. One allocation serves the whole fork —
    /// each branch is offered the same anchored body, exactly as a forking
    /// proxy offers one to every branch (RFC 3261 §16.7).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_profiled_fork_offers_every_branch_the_same_anchored_sdp() {
        let engine = TestEngine::start(false).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        dispatcher.state.rtpengine_sessions = Some(sessions.clone());
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        park(&dispatcher.state);

        assert!(fork(&dispatcher.state, RING_GROUP, true, "rtp_to_srtp").unwrap());

        let mut rung: Vec<std::net::SocketAddr> = Vec::new();
        while let Ok(outbound) = dispatcher.udp.try_recv() {
            let invite = parse_sip_message_bytes(&outbound.data).unwrap();
            assert_anchored(&invite.body, "fork branch");
            rung.push(outbound.destination);
        }
        rung.sort();
        assert_eq!(
            rung,
            RING_GROUP
                .iter()
                .map(|address| address.parse().unwrap())
                .collect::<Vec<std::net::SocketAddr>>(),
            "every member of the group rang"
        );
        assert_eq!(
            engine.commands("offer").len(),
            1,
            "one allocation, not four"
        );
        assert_eq!(sessions.len(), 1);
    }

    /// The fork's competing answers, settled on one allocation: a branch that
    /// opens early media is answered against it, and the branch that actually
    /// answers takes it over — the engine re-points the far side of the relay on
    /// each answer, and the fork aggregation has by then picked exactly one
    /// winner (RFC 3261 §16.7). The caller is answered with the winner's
    /// rewritten SDP, never with a phone's own.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_branch_that_answers_takes_the_relay_from_one_that_only_opened_early_media() {
        let engine = TestEngine::start(false).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        dispatcher.state.rtpengine_sessions = Some(sessions.clone());
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        let call_id = park(&dispatcher.state);

        assert!(fork(&dispatcher.state, &RING_GROUP[..2], true, "rtp_to_srtp").unwrap());
        let branches: Vec<SipMessage> = std::iter::from_fn(|| dispatcher.udp.try_recv().ok())
            .map(|outbound| parse_sip_message_bytes(&outbound.data).unwrap())
            .collect();
        assert_eq!(branches.len(), 2);

        // The first phone opens early media; the second answers.
        let ringing = tagged_response(&branches[0], 183, "ringing-phone");
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(&branches[0]),
            &mut ringing.clone(),
            183,
            RING_GROUP[0].parse().unwrap(),
            &dispatcher.state
        ));
        let mut answered = tagged_response(&branches[1], 200, "answering-phone");
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(&branches[1]),
            &mut answered,
            200,
            RING_GROUP[1].parse().unwrap(),
            &dispatcher.state
        ));

        let answers = engine.commands("answer");
        assert_eq!(
            answers
                .iter()
                .filter_map(|command| command.to_tag.clone())
                .collect::<Vec<String>>(),
            vec!["ringing-phone".to_string(), "answering-phone".to_string()],
            "both branches were answered against the one allocation, winner last"
        );
        assert_eq!(
            sessions
                .get("control-media@example.com")
                .and_then(|session| session.to_tag.clone())
                .as_deref(),
            Some("answering-phone"),
            "the relay is settled on the branch that answered"
        );

        let mut caller_got_a_relayed_answer = false;
        while let Ok(outbound) = dispatcher.udp.try_recv() {
            let message = parse_sip_message_bytes(&outbound.data).unwrap();
            if outbound.destination == "192.0.2.10:5060".parse().unwrap()
                && !message.body.is_empty()
            {
                let sdp = String::from_utf8_lossy(&message.body);
                assert!(
                    sdp.contains("203.0.113.50"),
                    "the caller was handed a phone's own media: {sdp}"
                );
                caller_got_a_relayed_answer = true;
            }
        }
        assert!(caller_got_a_relayed_answer);
    }

    /// The `branch` parameter of a response, read off the Via siphon sent.
    fn via_branch(invite: &SipMessage) -> String {
        invite
            .headers
            .get("Via")
            .unwrap()
            .split("branch=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// A response to `invite` from a phone that stamps `to_tag` — a fork's
    /// branches each answer in their own dialog, so their To-tags differ.
    fn tagged_response(invite: &SipMessage, code: u16, to_tag: &str) -> SipMessage {
        let mut message = response(invite, code);
        message.headers.set(
            "To",
            format!("{};tag={to_tag}", invite.headers.to().unwrap()),
        );
        message
    }

    /// The attempts a sequential hunt makes after the first are built from the
    /// stored A-leg INVITE, which deliberately keeps the caller's own offer so a
    /// failed dial is still answerable into voicemail. Every one of them still
    /// has to be offered the anchored body: handing the next phone the caller's
    /// raw SDP would take its audio around the relay the profile asked for.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_profiled_sequential_hunt_anchors_every_attempt() {
        let engine = TestEngine::start(false).await;
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        dispatcher.state.rtpengine_sessions =
            Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        let call_id = park(&dispatcher.state);

        assert!(fork(&dispatcher.state, RING_GROUP, false, "rtp_to_srtp").unwrap());
        let first = parse_sip_message_bytes(&dispatcher.udp.try_recv().unwrap().data).unwrap();
        assert_anchored(&first.body, "first attempt");
        assert!(
            dispatcher.udp.try_recv().is_err(),
            "a sequential hunt rings one target at a time"
        );

        // What the B-leg failure path does when an attempt fails.
        let invite_arc = dispatcher
            .state
            .call_actors
            .get_call(&call_id)
            .and_then(|call| call.a_leg_invite.clone())
            .unwrap();
        let stored = invite_arc.lock().unwrap();
        assert_eq!(
            stored.body,
            OFFER.as_bytes(),
            "the caller's own offer is kept for a voicemail fallback"
        );
        assert!(b2bua_advance_route(&call_id, &stored, &dispatcher.state).dialed);
        drop(stored);

        let second = parse_sip_message_bytes(&dispatcher.udp.try_recv().unwrap().data).unwrap();
        assert_anchored(&second.body, "second attempt");
        assert_eq!(
            second.headers.get("Content-Length").map(String::as_str),
            Some(second.body.len().to_string().as_str()),
            "the substituted body has to bring its own length with it",
        );
        assert_eq!(
            engine.commands("offer").len(),
            1,
            "the hunt re-uses its one allocation rather than re-anchoring per attempt"
        );
    }
}
