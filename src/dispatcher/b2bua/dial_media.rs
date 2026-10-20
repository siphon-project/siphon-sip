//! Per-branch media profiles on a controller `dial` that connects its caller.
//!
//! A `dial` target may name a media `profile` of its own, over the dial's. The
//! media a peer can take is a property of that peer: one ring can reach a desk
//! phone behind NAT that needs a latching relay and a trunk that asks for
//! SDES-SRTP, and no single profile serves both.
//!
//! The media engine shapes the side of an allocation that faces the branches
//! with the profile's offer flags, and an allocation has one such side, so the
//! branches are grouped by profile and each group gets one allocation: the
//! first profile in target order is the call's own media session, anchored as a
//! single-profile dial's is, and every other profile an allocation of its own,
//! offered the caller's same SDP and held beside it
//! ([`crate::rtpengine::MediaSessionStore::insert_dial_branch`]). Each branch is
//! sent its group's anchored offer, records the profile on its branch
//! ([`crate::b2bua::actor::DialBranch::media_profile`]), and has its early and
//! final answers put through that allocation ([`control_dial_media_answer`]).
//! The branch that answers settles the dial: its allocation becomes the call's
//! session and every other is deleted ([`settle_control_dial_media`]).
//!
//! The caller sees one dialog whichever branch it is answered from, as on any
//! fork a B2BUA collapses. Early media from a branch on one allocation and a
//! 2xx from a branch on another reach it with different session descriptions,
//! the same as the raw SDP of two phones on an unanchored fork.

use crate::dispatcher::*;

/// Resolve every target's media profile — its own, else the dial's — onto the
/// target, and return the profile the call's own media session is anchored
/// with: the first target's. `None` when no branch is anchored.
///
/// A dial anchors all of its branches or none of them. A branch left on the
/// caller's own SDP beside anchored ones would answer the caller with the
/// phone's own media while the others answer it with the relay's, so a mix is
/// refused before anything is allocated or sent.
pub(super) fn resolve_branch_profiles(
    targets: &mut [DialTarget],
    shaping: &DialShaping,
) -> Result<Option<String>, DialError> {
    for target in targets.iter_mut() {
        target.profile = target.shaping_over(shaping).profile;
    }
    let anchored = targets
        .iter()
        .filter(|target| target.profile.is_some())
        .count();
    if anchored != 0 && anchored != targets.len() {
        return Err(DialError::InvalidMedia(
            "a dial anchors every branch's media or none: name a profile on the dial, or on \
             every target"
                .to_string(),
        ));
    }
    Ok(targets.first().and_then(|target| target.profile.clone()))
}

/// Anchor a connecting dial's media, one allocation per profile its targets
/// name, and shape `template` with the call's own (`primary`).
///
/// Every profile — the dial's own included, even when every target overrides
/// it — is checked to exist before the first allocation, so a name siphon does
/// not define refuses the dial exactly as an unknown dial-level profile does,
/// with nothing allocated and nothing rung. An allocation that fails after the
/// first releases every one made. `Ok(false)` when the call went away.
pub(super) fn anchor_dial_media(
    internal_call_id: &str,
    template: &mut SipMessage,
    targets: &[DialTarget],
    primary: &str,
    dial_profile: Option<&str>,
    state: &DispatcherState,
) -> Result<bool, DialError> {
    let mut others: Vec<&str> = Vec::new();
    for profile in targets
        .iter()
        .filter_map(|target| target.profile.as_deref())
    {
        if profile != primary && !others.contains(&profile) {
            others.push(profile);
        }
    }
    check_profiles_defined(
        std::iter::once(primary)
            .chain(others.iter().copied())
            .chain(dial_profile),
        state,
    )
    .map_err(DialError::Media)?;

    let source_ip = state
        .call_actors
        .get_call(internal_call_id)
        .map(|call| call.a_leg.transport.remote_addr.ip())
        .ok_or_else(|| DialError::Media("call is gone".into()))?;
    // Every allocation answers the caller's own offer.
    let caller_offer = template.clone();
    *template = control_dial_media_offer(&caller_offer, source_ip, primary, state)
        .map_err(DialError::Media)?;
    {
        let Some(mut call) = state.call_actors.get_call_mut(internal_call_id) else {
            if let Some(sip_call_id) = caller_offer.headers.call_id() {
                release_failed_call_media(sip_call_id, state);
            }
            return Ok(false);
        };
        call.control_dial_media = true;
        // One allocation serves every branch offered this profile: they are
        // all sent this body, and the attempts a sequential hunt makes later
        // are rebuilt from the stored A-leg INVITE, which keeps the caller's
        // own offer so a failed dial is still answerable into voicemail.
        call.control_dial_offer = Some(template.body.clone());
        call.dial_media = crate::b2bua::actor::DialMedia::default();
    }
    for profile in others {
        match control_dial_branch_media_offer(&caller_offer, source_ip, profile, state) {
            Ok(offer) => {
                state.call_actors.add_dial_branch_offer(
                    internal_call_id,
                    profile.to_string(),
                    offer,
                );
            }
            Err(error) => {
                release_control_dial_media(internal_call_id, state);
                return Err(DialError::Media(error));
            }
        }
    }
    Ok(true)
}

/// Refuse the first profile siphon does not define, with the error the
/// allocation itself would give, before any is allocated.
fn check_profiles_defined<'a>(
    names: impl Iterator<Item = &'a str>,
    state: &DispatcherState,
) -> Result<(), String> {
    state
        .rtpengine_set
        .as_ref()
        .ok_or("dial profile requires a media backend")?;
    let profiles = state
        .rtpengine_profiles
        .as_ref()
        .ok_or("dial profile requires media profiles")?;
    for name in names {
        if profiles.get(name).is_none() {
            return Err(format!("unknown media profile '{name}'"));
        }
    }
    Ok(())
}

/// Shape one branch's INVITE with the media its target's profile was
/// allocated, just before it is sent.
///
/// The profile is named on the call first, so the branch records it when its
/// leg is created. A branch offered the call's own session's profile keeps the
/// template's body; one offered another profile is sent that allocation's
/// offer, on `branch_template` (cloned from `template` when the branch had no
/// template of its own yet).
pub(super) fn offer_branch_media(
    call_id: &str,
    profile: Option<&str>,
    branch_template: &mut Option<SipMessage>,
    template: &SipMessage,
    state: &DispatcherState,
) {
    let Some(profile) = profile else {
        return;
    };
    state
        .call_actors
        .set_dial_sending_profile(call_id, Some(profile.to_string()));
    if let Some(offer) = state.call_actors.dial_branch_offer(call_id, profile) {
        let invite = branch_template.get_or_insert_with(|| template.clone());
        with_offer(invite, offer);
    }
}

/// The attempt a sequential `dial` route is sent, when the route's target named
/// a profile other than the call's own session's: `request` carrying that
/// profile's anchored offer. `None` keeps `request` as it is.
///
/// Every route of an anchored dial names its profile on the call before it is
/// sent, so the leg records it as a parallel branch does. An LCR or `route`
/// attempt names none and is left alone.
pub(crate) fn route_media_request(
    call_id: &str,
    route: &crate::lcr::Route,
    request: &SipMessage,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let profile = route.media_profile.as_deref()?;
    let mut shaped = None;
    offer_branch_media(call_id, Some(profile), &mut shaped, request, state);
    shaped
}

fn with_offer(invite: &mut SipMessage, offer: Vec<u8>) {
    invite
        .headers
        .set("Content-Length", offer.len().to_string());
    invite.body = offer;
}

/// Settle a connecting dial's media on the branch that answered (Via
/// `branch`): the allocation it was answered through becomes the call's media
/// session, and every other allocation the dial made is deleted from the
/// engine. A dial that made one allocation has nothing to settle.
pub fn settle_control_dial_media(call_id: &str, branch: &str, state: &DispatcherState) {
    let Some(call) = state.call_actors.get_call(call_id) else {
        return;
    };
    if !call.control_dial_media || call.dial_media.branch_offers.is_empty() {
        return;
    }
    let sip_call_id = call.a_leg.dialog.call_id.clone();
    let profile = call.dial_branch_media_profile(branch);
    drop(call);
    state.call_actors.clear_dial_media(call_id);
    let Some(sessions) = state.rtpengine_sessions.as_ref() else {
        return;
    };
    let settled = sessions.promote_dial_branch(&sip_call_id, profile.as_deref());
    info!(
        %call_id,
        profile = ?profile,
        released = settled.released.len() + usize::from(settled.replaced.is_some()),
        "control plane: dial — media settled on the answering branch's profile"
    );
    delete_engine_sessions(
        settled
            .replaced
            .into_iter()
            .chain(settled.released)
            .collect(),
        state,
    );
}

/// Delete from the engine every allocation a connecting dial holds beside the
/// call's own session. Every teardown that releases the call's session calls
/// this first; it is a no-op for a call with none.
pub fn release_dial_branch_media(sip_call_id: &str, state: &DispatcherState) {
    let Some(sessions) = state.rtpengine_sessions.as_ref() else {
        return;
    };
    delete_engine_sessions(sessions.take_dial_branches(sip_call_id), state);
}

fn delete_engine_sessions(sessions: Vec<crate::rtpengine::MediaSession>, state: &DispatcherState) {
    let Some(rtpengine_set) = state.rtpengine_set.as_ref() else {
        return;
    };
    for session in sessions {
        let set = Arc::clone(rtpengine_set);
        tokio::spawn(async move {
            if let Err(error) = set.delete(session.rtpengine_id(), &session.from_tag).await {
                if error.is_call_not_found() {
                    debug!(call_id = %session.call_id, "dial branch media release: already gone ({error})");
                } else {
                    warn!(call_id = %session.call_id, "dial branch media release failed: {error}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(uri: &str, profile: Option<&str>) -> DialTarget {
        DialTarget {
            uri: uri.to_string(),
            profile: profile.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn a_target_profile_overrides_the_dials_and_one_without_inherits_it() {
        let mut targets = vec![
            target("sip:201@198.51.100.7", None),
            target("sip:+15550100@trunk.example.com", Some("sdes_srtp")),
        ];
        let dial = DialShaping {
            profile: Some("latching".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_branch_profiles(&mut targets, &dial).unwrap(),
            Some("latching".to_string()),
            "the first target's profile anchors the call's own session"
        );
        assert_eq!(targets[0].profile.as_deref(), Some("latching"));
        assert_eq!(targets[1].profile.as_deref(), Some("sdes_srtp"));
    }

    #[test]
    fn every_target_naming_its_own_profile_needs_none_on_the_dial() {
        let mut targets = vec![
            target("sip:+15550100@trunk.example.com", Some("sdes_srtp")),
            target("sip:201@198.51.100.7", Some("latching")),
        ];
        assert_eq!(
            resolve_branch_profiles(&mut targets, &DialShaping::default()).unwrap(),
            Some("sdes_srtp".to_string())
        );
    }

    #[test]
    fn a_dial_naming_no_profile_anywhere_anchors_nothing() {
        let mut targets = vec![target("sip:201@198.51.100.7", None)];
        assert_eq!(
            resolve_branch_profiles(&mut targets, &DialShaping::default()).unwrap(),
            None
        );
        assert_eq!(targets[0].profile, None);
    }

    #[test]
    fn anchoring_some_branches_and_not_others_is_refused() {
        let mut targets = vec![
            target("sip:201@198.51.100.7", None),
            target("sip:+15550100@trunk.example.com", Some("sdes_srtp")),
        ];
        assert!(matches!(
            resolve_branch_profiles(&mut targets, &DialShaping::default()),
            Err(DialError::InvalidMedia(_))
        ));
    }
    // ---- End to end, against a media engine in the test process ----

    use crate::dispatcher::test_dispatcher::test_dispatcher;
    use crate::rtpengine::test_engine::TestEngine;

    const CALLER: &str = "198.51.100.40:5060";
    const DESK_PHONE: &str = "198.51.100.7:5060";
    const TRUNK: &str = "198.51.100.8:5060";
    const SIP_CALL_ID: &str = "dial-media@example.com";

    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 198.51.100.40\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.40\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0\r\n",
    );

    fn caller_invite() -> SipMessage {
        parse_sip_message_bytes(
            format!(
                concat!(
                    "INVITE sip:201@example.com SIP/2.0\r\n",
                    "Via: SIP/2.0/UDP 198.51.100.40:5060;branch=z9hG4bK-dial-media\r\n",
                    "From: <sip:caller@example.com>;tag=caller\r\n",
                    "To: <sip:201@example.com>\r\n",
                    "Call-ID: dial-media@example.com\r\n",
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

    async fn anchored_dispatcher(
        engine: &TestEngine,
    ) -> (
        crate::dispatcher::test_dispatcher::TestDispatcher,
        Arc<crate::rtpengine::MediaSessionStore>,
        String,
    ) {
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        let call_id = park(&dispatcher.state);
        (dispatcher, sessions, call_id)
    }

    fn park(state: &DispatcherState) -> String {
        let call_id = state.call_actors.create_call(Leg::new_a_leg(
            SIP_CALL_ID.into(),
            "caller".into(),
            "z9hG4bK-dial-media".into(),
            LegTransport {
                remote_addr: CALLER.parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ));
        state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(caller_invite())));
        call_id
    }

    /// The desk phone on the dial's own profile, the trunk on one of its own.
    fn mixed_ring() -> Vec<DialTarget> {
        vec![
            target(&format!("sip:201@{DESK_PHONE}"), None),
            target(&format!("sip:+15550100@{TRUNK}"), Some("srtp_to_rtp")),
        ]
    }

    fn dial(
        state: &DispatcherState,
        targets: Vec<DialTarget>,
        parallel: bool,
    ) -> Result<bool, DialError> {
        b2bua_dial_call_with_state(
            SIP_CALL_ID,
            targets,
            parallel,
            30,
            &[],
            &DialShaping {
                profile: Some("rtp_to_srtp".to_string()),
                ..Default::default()
            },
            state,
        )
    }

    /// Every INVITE on the wire, by where it went.
    fn sent_invites(
        dispatcher: &crate::dispatcher::test_dispatcher::TestDispatcher,
    ) -> std::collections::HashMap<std::net::SocketAddr, SipMessage> {
        std::iter::from_fn(|| dispatcher.udp.try_recv().ok())
            .map(|outbound| {
                (
                    outbound.destination,
                    parse_sip_message_bytes(&outbound.data).unwrap(),
                )
            })
            .filter(|(_, message)| message.status_code().is_none())
            .collect()
    }

    /// The engine call-id each profile's `offer` went out on.
    fn offered_on(engine: &TestEngine) -> std::collections::HashMap<String, String> {
        engine
            .commands("offer")
            .into_iter()
            .map(|command| {
                let profile = match command.transport_protocol.as_deref() {
                    Some("RTP/SAVP") => "rtp_to_srtp",
                    _ => "srtp_to_rtp",
                };
                (profile.to_string(), command.call_id.unwrap_or_default())
            })
            .collect()
    }

    /// The engine call whose offer this INVITE carries.
    fn offered_allocation(invite: &SipMessage) -> String {
        String::from_utf8_lossy(&invite.body)
            .lines()
            .find_map(|line| line.strip_prefix("a=label:").map(str::to_string))
            .unwrap_or_default()
    }

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

    fn answer(invite: &SipMessage, code: u16, to_tag: &str, contact: &str) -> SipMessage {
        let mut response = build_response(invite, code, "Test", None, &[]);
        response.headers.set(
            "To",
            format!("{};tag={to_tag}", invite.headers.to().unwrap()),
        );
        response
            .headers
            .set("Contact", format!("<sip:201@{contact}>"));
        response
            .headers
            .set("Content-Type", "application/sdp".into());
        response.body = OFFER.as_bytes().to_vec();
        response
    }

    async fn deleted(engine: &TestEngine, engine_call_id: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !engine
                .commands("delete")
                .iter()
                .any(|command| command.call_id.as_deref() == Some(engine_call_id))
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("engine call {engine_call_id} was never deleted"));
    }

    /// The case per-branch profiles exist for: one parallel ring reaching a
    /// desk phone on one profile and a trunk on another. Each is offered from
    /// an allocation shaped by its own profile, and the trunk answering settles
    /// the call on the trunk's allocation, answered with the trunk's profile;
    /// the desk phone's allocation is deleted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_two_profile_fork_offers_each_branch_its_own_allocation_and_answers_through_the_winners(
    ) {
        let engine = TestEngine::start_naming_offers().await;
        let (dispatcher, sessions, call_id) = anchored_dispatcher(&engine).await;

        assert!(dial(&dispatcher.state, mixed_ring(), true).unwrap());

        let offered = offered_on(&engine);
        assert_eq!(
            engine.commands("offer").len(),
            2,
            "one allocation per profile"
        );
        assert_ne!(offered["rtp_to_srtp"], offered["srtp_to_rtp"]);
        assert!(
            engine
                .commands("offer")
                .iter()
                .all(|command| command.sdp.as_deref() == Some(OFFER)),
            "every allocation answers the caller's own offer"
        );
        let invites = sent_invites(&dispatcher);
        let desk = &invites[&DESK_PHONE.parse().unwrap()];
        let trunk = &invites[&TRUNK.parse().unwrap()];
        assert_eq!(offered_allocation(desk), offered["rtp_to_srtp"]);
        assert_eq!(offered_allocation(trunk), offered["srtp_to_rtp"]);
        assert_eq!(
            trunk.headers.get("Content-Length").map(String::as_str),
            Some(trunk.body.len().to_string().as_str())
        );

        let mut answered = answer(trunk, 200, "trunk", TRUNK);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(trunk),
            &mut answered,
            200,
            TRUNK.parse().unwrap(),
            &dispatcher.state
        ));

        let answers = engine.commands("answer");
        let last = answers.last().expect("the trunk's answer");
        assert_eq!(
            last.call_id.as_deref(),
            Some(offered["srtp_to_rtp"].as_str())
        );
        assert_eq!(
            last.transport_protocol.as_deref(),
            Some("RTP/SAVP"),
            "answered with the trunk's own profile's answer half"
        );
        let own = sessions.get(SIP_CALL_ID).expect("the call's session");
        assert_eq!(own.rtpengine_id(), offered["srtp_to_rtp"]);
        assert_eq!(own.profile, "srtp_to_rtp");
        assert_eq!(own.to_tag.as_deref(), Some("trunk"));
        assert_eq!(sessions.dial_branch_calls(), 0);
        deleted(&engine, &offered["rtp_to_srtp"]).await;
        assert!(
            !engine
                .commands("delete")
                .iter()
                .any(|command| command.call_id.as_deref() == Some(offered["srtp_to_rtp"].as_str())),
            "the winner's media stays up"
        );
        let caller_answered = std::iter::from_fn(|| dispatcher.udp.try_recv().ok()).any(|out| {
            out.destination == CALLER.parse().unwrap()
                && parse_sip_message_bytes(&out.data).unwrap().status_code() == Some(200)
        });
        assert!(caller_answered);
    }

    /// The desk phone answering keeps the call's own session and deletes the
    /// trunk's allocation; early media from the trunk before that went through
    /// the trunk's allocation, not the desk phone's.
    #[tokio::test(flavor = "multi_thread")]
    async fn early_media_goes_through_its_branchs_allocation_and_the_own_session_can_win() {
        let engine = TestEngine::start_naming_offers().await;
        let (dispatcher, sessions, call_id) = anchored_dispatcher(&engine).await;
        assert!(dial(&dispatcher.state, mixed_ring(), true).unwrap());
        let offered = offered_on(&engine);
        let invites = sent_invites(&dispatcher);
        let desk = &invites[&DESK_PHONE.parse().unwrap()];
        let trunk = &invites[&TRUNK.parse().unwrap()];

        let mut early = answer(trunk, 183, "trunk", TRUNK);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(trunk),
            &mut early,
            183,
            TRUNK.parse().unwrap(),
            &dispatcher.state
        ));
        let early_answer = engine.commands("answer");
        assert_eq!(
            early_answer[0].call_id.as_deref(),
            Some(offered["srtp_to_rtp"].as_str())
        );
        assert_eq!(
            sessions
                .dial_branch(SIP_CALL_ID, "srtp_to_rtp")
                .and_then(|held| held.to_tag),
            Some("trunk".to_string())
        );
        assert_eq!(
            sessions.get(SIP_CALL_ID).and_then(|own| own.to_tag),
            None,
            "the call's own session was not answered by the trunk"
        );

        let mut answered = answer(desk, 200, "desk", DESK_PHONE);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(desk),
            &mut answered,
            200,
            DESK_PHONE.parse().unwrap(),
            &dispatcher.state
        ));
        let last = engine.commands("answer").last().cloned().unwrap();
        assert_eq!(
            last.call_id.as_deref(),
            Some(offered["rtp_to_srtp"].as_str())
        );
        let own = sessions.get(SIP_CALL_ID).unwrap();
        assert_eq!(own.rtpengine_id(), offered["rtp_to_srtp"]);
        assert_eq!(own.to_tag.as_deref(), Some("desk"));
        assert_eq!(sessions.dial_branch_calls(), 0);
        deleted(&engine, &offered["srtp_to_rtp"]).await;
    }

    /// A sequential hunt offers each attempt its own target's profile: the
    /// attempt after the first is rebuilt from the stored A-leg INVITE and
    /// still carries the trunk's allocation, and its answer goes through it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sequential_hunt_offers_each_attempt_its_targets_profile() {
        let engine = TestEngine::start_naming_offers().await;
        let (dispatcher, sessions, call_id) = anchored_dispatcher(&engine).await;
        assert!(dial(&dispatcher.state, mixed_ring(), false).unwrap());
        let offered = offered_on(&engine);
        let first = sent_invites(&dispatcher);
        assert_eq!(first.len(), 1);
        assert_eq!(
            offered_allocation(&first[&DESK_PHONE.parse().unwrap()]),
            offered["rtp_to_srtp"]
        );

        let invite_arc = dispatcher
            .state
            .call_actors
            .get_call(&call_id)
            .and_then(|call| call.a_leg_invite.clone())
            .unwrap();
        let stored = invite_arc.lock().unwrap().clone();
        assert_eq!(stored.body, OFFER.as_bytes(), "the caller's offer is kept");
        assert!(b2bua_advance_route(&call_id, &stored, &dispatcher.state).dialed);
        let second = sent_invites(&dispatcher);
        let trunk = &second[&TRUNK.parse().unwrap()];
        assert_eq!(offered_allocation(trunk), offered["srtp_to_rtp"]);
        assert_eq!(
            engine.commands("offer").len(),
            2,
            "no re-anchoring per attempt"
        );

        let mut answered = answer(trunk, 200, "trunk", TRUNK);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(trunk),
            &mut answered,
            200,
            TRUNK.parse().unwrap(),
            &dispatcher.state
        ));
        assert_eq!(
            engine.commands("answer").last().unwrap().call_id.as_deref(),
            Some(offered["srtp_to_rtp"].as_str())
        );
        assert_eq!(
            sessions.get(SIP_CALL_ID).unwrap().rtpengine_id(),
            offered["srtp_to_rtp"]
        );
    }

    /// A target naming a profile siphon does not define refuses the dial as an
    /// unknown dial-level profile does: nothing allocated, nothing rung.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_target_profile_fails_before_allocating_or_ringing() {
        let engine = TestEngine::start(false).await;
        let (dispatcher, sessions, _) = anchored_dispatcher(&engine).await;
        let error = dial(
            &dispatcher.state,
            vec![
                target(&format!("sip:201@{DESK_PHONE}"), None),
                target(&format!("sip:+15550100@{TRUNK}"), Some("absent-profile")),
            ],
            true,
        )
        .unwrap_err();
        assert!(
            matches!(&error, DialError::Media(reason) if reason == "unknown media profile 'absent-profile'")
        );
        assert!(engine.commands("offer").is_empty());
        assert!(dispatcher.udp.try_recv().is_err());
        assert_eq!(sessions.len(), 0);
        assert_eq!(sessions.dial_branch_calls(), 0);
    }

    /// Per-module leak gate: dials that fail release every allocation they
    /// made, the call's own and the per-profile ones, and the store drains to
    /// its baseline.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_two_profile_dials_release_every_allocation_and_drain_to_baseline() {
        let engine = TestEngine::start(false).await;
        let (dispatcher, sessions, parked) = anchored_dispatcher(&engine).await;
        dispatcher.state.call_actors.remove_call(&parked);
        for _ in 0..20 {
            let call_id = park(&dispatcher.state);
            assert!(dial(&dispatcher.state, mixed_ring(), true).unwrap());
            let _ = sent_invites(&dispatcher);
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions.dial_branch_calls(), 1);
            assert!(report_control_dial_failure(
                &call_id,
                480,
                "Temporarily Unavailable",
                false,
                &dispatcher.state
            ));
            assert_eq!(sessions.len(), 0);
            assert_eq!(sessions.dial_branch_calls(), 0);
            assert!(dispatcher
                .state
                .call_actors
                .get_call(&call_id)
                .is_some_and(|call| call.dial_media.branch_offers.is_empty()));
            dispatcher.state.call_actors.remove_call(&call_id);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while engine.commands("delete").len() < 40 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both allocations of every dial deleted");
        assert_eq!(engine.commands("offer").len(), 40);
    }
    /// The caller giving up while the branches ring releases every allocation
    /// the dial made: no BYE will ever come to release them.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_caller_cancel_releases_every_allocation_of_a_ringing_dial() {
        let engine = TestEngine::start(false).await;
        let (dispatcher, sessions, _) = anchored_dispatcher(&engine).await;
        assert!(dial(&dispatcher.state, mixed_ring(), true).unwrap());
        let _ = sent_invites(&dispatcher);
        let engine_calls: Vec<String> = engine
            .commands("offer")
            .into_iter()
            .filter_map(|command| command.call_id)
            .collect();
        assert_eq!(engine_calls.len(), 2);

        let raw = concat!(
            "CANCEL sip:201@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.40:5060;branch=z9hG4bK-dial-media\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:caller@example.com>;tag=caller\r\n",
            "To: <sip:201@example.com>\r\n",
            "Call-ID: dial-media@example.com\r\n",
            "CSeq: 1 CANCEL\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: dispatcher.state.local_addr,
            remote_addr: CALLER.parse().unwrap(),
            data: bytes::Bytes::from_static(raw.as_bytes()),
        };
        tokio::task::block_in_place(|| {
            handle_b2bua_cancel(
                inbound,
                parse_sip_message_bytes(raw.as_bytes()).unwrap(),
                &dispatcher.state,
            )
        });

        assert_eq!(sessions.len(), 0);
        assert_eq!(sessions.dial_branch_calls(), 0);
        for engine_call in &engine_calls {
            deleted(&engine, engine_call).await;
        }
    }
}
