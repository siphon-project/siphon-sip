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
/// A profile with a `webrtc: auto` half is resolved per branch
/// ([`crate::rtpengine::ProfileRegistry::resolve_webrtc`]): the half facing a
/// forked contact turns WebRTC when the target's binding registered over
/// `ws`/`wss`, and the half facing the caller when `caller_webrtc` (the
/// caller's offer is UDP/TLS/RTP/SAVPF with ICE and a fingerprint). The branch
/// then carries the resolved name, so it is grouped, allocated, answered and
/// settled as any other profile, and an `{aor}` ringing a browser and a desk
/// phone gets one allocation of each kind from one profile.
///
/// A dial anchors all of its branches or none of them. A branch left on the
/// caller's own SDP beside anchored ones would answer the caller with the
/// phone's own media while the others answer it with the relay's, so a mix is
/// refused before anything is allocated or sent.
pub(super) fn resolve_branch_profiles(
    targets: &mut [DialTarget],
    shaping: &DialShaping,
    caller_offer: &[u8],
    state: &DispatcherState,
) -> Result<Option<String>, DialError> {
    resolve_profiles_with(
        targets,
        shaping,
        state.rtpengine_profiles.as_deref(),
        crate::rtpengine::webrtc_auto::offer_is_webrtc(caller_offer),
    )
}

/// The profile an originated leg to `target` is anchored with, `webrtc: auto`
/// resolved for the contact it rings.
///
/// `originate {aor}` and a bridging `dial` place each contact as a call of its
/// own with a media session of its own, so each leg is anchored per contact
/// already. Both halves of the profile then describe that one contact: the
/// `answer` half answers an offerless leg's 2xx offer, and the `offer` half
/// shapes an early offer or the bridge's offer to the phone. A contact that
/// registered over `ws`/`wss` therefore turns every `webrtc: auto` half
/// WebRTC, and any other contact (or a URI dialled as written) leaves the
/// profile as written. A leg that carries an offer of its own is not anchored
/// by a profile and is left alone.
pub(super) fn resolve_leg_profile(
    params: &mut OriginateParams,
    target: &DialTarget,
    state: &DispatcherState,
) {
    let (Some(registry), OriginateMedia::Anchor { profile, .. }) =
        (state.rtpengine_profiles.as_deref(), &mut params.media)
    else {
        return;
    };
    let webrtc = target
        .binding_transport
        .is_some_and(crate::rtpengine::webrtc_auto::transport_is_webrtc);
    *profile = registry.resolve_webrtc(profile, webrtc, webrtc);
}

/// [`resolve_branch_profiles`] against a registry and a verdict on the
/// caller's offer.
fn resolve_profiles_with(
    targets: &mut [DialTarget],
    shaping: &DialShaping,
    registry: Option<&crate::rtpengine::ProfileRegistry>,
    caller_webrtc: bool,
) -> Result<Option<String>, DialError> {
    // The dial's own `profile` is a typed name even when every target
    // overrides it, so it is checked on its own, before any override applies.
    if let (Some(registry), Some(name)) = (registry, shaping.profile.as_deref()) {
        if !registry.is_defined(name) {
            return Err(DialError::Media(format!("unknown media profile '{name}'")));
        }
    }
    for target in targets.iter_mut() {
        target.profile = target.shaping_over(shaping).profile;
        if let (Some(registry), Some(name)) = (registry, target.profile.as_deref()) {
            // A name the caller gave must be one that is defined: a generated
            // `base#webrtc-...` form is picked by the resolution below, never
            // named.
            if !registry.is_defined(name) {
                return Err(DialError::Media(format!("unknown media profile '{name}'")));
            }
            let contact_webrtc = target
                .binding_transport
                .is_some_and(crate::rtpengine::webrtc_auto::transport_is_webrtc);
            target.profile = Some(registry.resolve_webrtc(name, contact_webrtc, caller_webrtc));
        }
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

    // A caller that sent no SDP has no offer to anchor: the phone's 2xx makes
    // it, and is anchored when it arrives (`control_dial_media_answer`).
    if sdp_in_body(message_content_type(template), &template.body).is_none() {
        return expect_delayed_offer(
            internal_call_id,
            std::iter::once(primary).chain(others.iter().copied()),
            primary,
            state,
        );
    }
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

/// Record the media session the engine has just made for `internal_call_id`,
/// unless that call ended while the engine was making it.
///
/// A teardown claims the call first and only then takes its sessions, so one
/// that lands while an engine round trip is out finds no session to take. The
/// session is therefore recorded first and the call checked afterwards: either
/// the teardown has not yet taken sessions and takes this one, or it has
/// claimed already and this releases the engine call itself. `false` when the
/// call had ended and the session was released.
pub(super) fn commit_media_session(
    state: &DispatcherState,
    internal_call_id: &str,
    session: crate::rtpengine::MediaSession,
) -> bool {
    let Some(sessions) = state.rtpengine_sessions.as_ref() else {
        return false;
    };
    let key = session.call_id.clone();
    sessions.insert(session);
    let ended = state
        .call_actors
        .get_call(internal_call_id)
        .is_none_or(|call| call.teardown_claimed);
    if !ended {
        return true;
    }
    if let Some(session) = sessions.remove(&key) {
        warn!(call_id = %key, "the call ended while the media engine was allocating for it; releasing the allocation");
        delete_engine_sessions(vec![session], state);
    }
    false
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
            resolve_profiles_with(&mut targets, &dial, None, false).unwrap(),
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
            resolve_profiles_with(&mut targets, &DialShaping::default(), None, false).unwrap(),
            Some("sdes_srtp".to_string())
        );
    }

    #[test]
    fn a_dial_naming_no_profile_anywhere_anchors_nothing() {
        let mut targets = vec![target("sip:201@198.51.100.7", None)];
        assert_eq!(
            resolve_profiles_with(&mut targets, &DialShaping::default(), None, false).unwrap(),
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
            resolve_profiles_with(&mut targets, &DialShaping::default(), None, false),
            Err(DialError::InvalidMedia(_))
        ));
    }

    // ---- `webrtc: auto`, resolved per forked contact ----

    /// A desk-phone profile whose `offer` half (toward each contact) and
    /// `answer` half (toward the caller) are both `webrtc: auto`.
    fn extension_profiles() -> Arc<crate::rtpengine::ProfileRegistry> {
        use crate::config::{MediaProfileConfig, NgFlagsConfig, WebrtcMode};
        let half = |protocol: &str| NgFlagsConfig {
            transport_protocol: Some(protocol.into()),
            ice: Some("remove".into()),
            dtls: Some("off".into()),
            rtcp_mux: vec!["demux".into()],
            replace: vec!["origin".into()],
            webrtc: Some(WebrtcMode::Auto),
            ..NgFlagsConfig::default()
        };
        let custom = std::collections::HashMap::from([(
            "extension".to_string(),
            MediaProfileConfig {
                offer: half("RTP/AVP"),
                answer: half("RTP/AVP"),
            },
        )]);
        Arc::new(crate::rtpengine::ProfileRegistry::from_config(&custom))
    }

    fn bound(uri: &str, transport: Option<Transport>) -> DialTarget {
        DialTarget {
            binding_transport: transport,
            ..target(uri, None)
        }
    }

    fn extension_dial() -> DialShaping {
        DialShaping {
            profile: Some("extension".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn each_contact_takes_the_profile_its_binding_transport_calls_for() {
        let registry = extension_profiles();
        let mut targets = vec![
            bound("sip:201@198.51.100.7", Some(Transport::Udp)),
            bound("sip:201@198.51.100.8", Some(Transport::WebSocketSecure)),
            bound("sip:201@198.51.100.9", Some(Transport::WebSocket)),
            bound("sip:201@198.51.100.10", Some(Transport::Tls)),
            bound("sip:201@198.51.100.11", Some(Transport::Tcp)),
            bound("sip:201@198.51.100.12", None),
        ];
        let primary =
            resolve_profiles_with(&mut targets, &extension_dial(), Some(&registry), false).unwrap();
        let profiles: Vec<_> = targets
            .iter()
            .map(|target| target.profile.clone().unwrap())
            .collect();
        assert_eq!(primary.as_deref(), Some("extension"));
        assert_eq!(profiles[0], "extension");
        assert_eq!(profiles[1], "extension#webrtc-offer");
        assert_eq!(profiles[2], "extension#webrtc-offer");
        assert_eq!(profiles[3], "extension");
        assert_eq!(profiles[4], "extension");
        assert_eq!(
            profiles[5], "extension",
            "a URI dialled as written has no binding"
        );
    }

    /// `base#webrtc-offer` is what resolution makes of `base`, never something
    /// a dial may name.
    #[test]
    fn a_dial_cannot_name_a_generated_variant() {
        let registry = extension_profiles();
        for name in [
            "extension#webrtc-offer",
            "extension#webrtc-answer",
            "extension#webrtc-both",
        ] {
            let mut targets = vec![bound("sip:201@198.51.100.7", Some(Transport::Udp))];
            let shaping = DialShaping {
                profile: Some(name.to_string()),
                ..Default::default()
            };
            let error = resolve_profiles_with(&mut targets, &shaping, Some(&registry), false)
                .expect_err("a generated name is not selectable");
            assert!(error.to_string().contains(name), "{error}");
        }
    }

    /// A profile a single target names is typed too: the dial's own is a
    /// defined one, the target's override is a generated form.
    /// Every target names a valid profile of its own, so the dial's is never
    /// applied; it is still a typed name and is refused.
    #[test]
    fn a_dial_level_generated_name_is_refused_even_when_every_target_overrides_it() {
        let registry = extension_profiles();
        let mut targets = vec![DialTarget {
            profile: Some("extension".to_string()),
            ..bound("sip:201@198.51.100.7", Some(Transport::Udp))
        }];
        let shaping = DialShaping {
            profile: Some("extension#webrtc-answer".to_string()),
            ..Default::default()
        };
        let error = resolve_profiles_with(&mut targets, &shaping, Some(&registry), false)
            .expect_err("a generated name is not selectable");
        assert!(
            error.to_string().contains("extension#webrtc-answer"),
            "{error}"
        );
    }

    #[test]
    fn a_target_cannot_name_a_generated_variant() {
        let registry = extension_profiles();
        let mut targets = vec![DialTarget {
            profile: Some("extension#webrtc-both".to_string()),
            ..bound("sip:201@198.51.100.7", Some(Transport::Udp))
        }];
        let error = resolve_profiles_with(&mut targets, &extension_dial(), Some(&registry), false)
            .expect_err("a generated name is not selectable");
        assert!(
            error.to_string().contains("extension#webrtc-both"),
            "{error}"
        );
    }

    #[test]
    fn a_webrtc_caller_turns_the_answer_half_for_every_branch() {
        let registry = extension_profiles();
        let mut targets = vec![
            bound("sip:201@198.51.100.7", Some(Transport::Udp)),
            bound("sip:201@198.51.100.8", Some(Transport::WebSocketSecure)),
        ];
        resolve_profiles_with(&mut targets, &extension_dial(), Some(&registry), true).unwrap();
        assert_eq!(
            targets[0].profile.as_deref(),
            Some("extension#webrtc-answer")
        );
        assert_eq!(targets[1].profile.as_deref(), Some("extension#webrtc-both"));
    }

    #[test]
    fn a_target_profile_without_auto_halves_is_untouched_by_a_webrtc_binding() {
        let registry = extension_profiles();
        let mut targets = vec![DialTarget {
            profile: Some("srtp_to_rtp".to_string()),
            ..bound("sip:201@198.51.100.8", Some(Transport::WebSocketSecure))
        }];
        resolve_profiles_with(&mut targets, &DialShaping::default(), Some(&registry), true)
            .unwrap();
        assert_eq!(targets[0].profile.as_deref(), Some("srtp_to_rtp"));
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

    // ---- One `{aor}` ring reaching a browser and a desk phone ----

    use crate::rtpengine::test_native_engine::{NativeCommand, NativeTestEngine};

    const BROWSER: &str = "198.51.100.9:5060";

    /// What a browser offers: DTLS-SRTP over ICE.
    const BROWSER_OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 198.51.100.40\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.40\r\n",
        "t=0 0\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "a=ice-ufrag:abcd\r\n",
        "a=ice-pwd:0123456789abcdef01234567\r\n",
        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n",
        "a=setup:actpass\r\n",
    );

    async fn native_dispatcher(
        engine: &NativeTestEngine,
        caller_offer: &str,
    ) -> (
        crate::dispatcher::test_dispatcher::TestDispatcher,
        Arc<crate::rtpengine::MediaSessionStore>,
        String,
    ) {
        let mut dispatcher = test_dispatcher();
        dispatcher.state.rtpengine_set = Some(engine.backend());
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));
        dispatcher.state.rtpengine_profiles = Some(extension_profiles());
        let call_id = park(&dispatcher.state);
        let mut invite = caller_invite();
        invite.body = caller_offer.as_bytes().to_vec();
        invite
            .headers
            .set("Content-Length", caller_offer.len().to_string());
        dispatcher
            .state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(invite)));
        (dispatcher, sessions, call_id)
    }

    /// The browser first, so its allocation is the call's own session and the
    /// desk phone's the held one: the winner may be either.
    fn browser_and_desk_phone() -> Vec<DialTarget> {
        vec![
            bound(
                &format!("sip:201@{BROWSER}"),
                Some(Transport::WebSocketSecure),
            ),
            bound(&format!("sip:201@{DESK_PHONE}"), Some(Transport::Udp)),
        ]
    }

    fn ring(state: &DispatcherState, targets: Vec<DialTarget>) -> Result<bool, DialError> {
        b2bua_dial_call_with_state(
            SIP_CALL_ID,
            targets,
            true,
            30,
            &[],
            &extension_dial(),
            state,
        )
    }

    fn media_line(invite: &SipMessage) -> String {
        String::from_utf8_lossy(&invite.body)
            .lines()
            .find(|line| line.starts_with("m=audio"))
            .unwrap_or_default()
            .to_string()
    }

    /// The engine call each offer was made on, by whether it asked for WebRTC.
    fn offers_by_flavour(engine: &NativeTestEngine) -> (NativeCommand, NativeCommand) {
        let offers = engine.commands("offer");
        assert_eq!(offers.len(), 2, "one allocation per flavour: {offers:?}");
        let webrtc = |command: &&NativeCommand| {
            command
                .profile
                .as_ref()
                .and_then(|profile| profile.transport_protocol.as_deref())
                == Some("UDP/TLS/RTP/SAVPF")
        };
        let browser = offers.iter().find(webrtc).cloned().expect("a WebRTC offer");
        let plain = offers
            .iter()
            .find(|command| !webrtc(command))
            .cloned()
            .expect("a plain offer");
        (browser, plain)
    }

    async fn native_deleted(engine: &NativeTestEngine, engine_call_id: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !engine
                .commands("delete")
                .iter()
                .any(|command| command.call_id == engine_call_id)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("engine call {engine_call_id} was never deleted"));
    }

    /// The point of `webrtc: auto`: one profile, one dial, and each branch is
    /// offered the SDP its contact can take. The browser's allocation forces
    /// ICE and requires RTCP multiplexing over `UDP/TLS/RTP/SAVPF`; the desk
    /// phone's stays plain RTP with ICE removed.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_dial_offers_a_browser_and_a_desk_phone_each_its_own_flavour() {
        let engine = NativeTestEngine::start().await;
        let (dispatcher, _sessions, _call) = native_dispatcher(&engine, OFFER).await;

        assert!(ring(&dispatcher.state, browser_and_desk_phone()).unwrap());

        let (browser_offer, plain_offer) = offers_by_flavour(&engine);
        assert_ne!(browser_offer.call_id, plain_offer.call_id);
        let browser_profile = browser_offer.profile.expect("the profile it carried");
        assert_eq!(browser_profile.ice.as_deref(), Some("force"));
        assert_eq!(browser_profile.rtcp_mux, vec!["require"]);
        assert_ne!(browser_profile.dtls.as_deref(), Some("off"));
        let plain_profile = plain_offer.profile.expect("the profile it carried");
        assert_eq!(plain_profile.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(plain_profile.ice.as_deref(), Some("remove"));
        assert_eq!(plain_profile.dtls.as_deref(), Some("off"));
        assert_eq!(plain_profile.rtcp_mux, vec!["demux"]);

        let invites = sent_invites(&dispatcher);
        assert!(
            media_line(&invites[&BROWSER.parse().unwrap()]).contains("UDP/TLS/RTP/SAVPF"),
            "the browser's INVITE carries the WebRTC offer"
        );
        let desk_line = media_line(&invites[&DESK_PHONE.parse().unwrap()]);
        assert!(desk_line.contains("RTP/AVP"), "{desk_line}");
        assert!(!desk_line.contains("SAVPF"), "{desk_line}");
    }

    /// The browser answering: its allocation becomes the call's media, the
    /// call is recorded under the resolved profile, and the desk phone's
    /// allocation is deleted from the engine.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_browser_answering_settles_on_its_allocation_and_frees_the_desk_phones() {
        let engine = NativeTestEngine::start().await;
        let (dispatcher, sessions, call_id) = native_dispatcher(&engine, OFFER).await;
        assert!(ring(&dispatcher.state, browser_and_desk_phone()).unwrap());
        let (browser_offer, plain_offer) = offers_by_flavour(&engine);
        let invites = sent_invites(&dispatcher);
        let browser = &invites[&BROWSER.parse().unwrap()];

        let mut answered = answer(browser, 200, "browser", BROWSER);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(browser),
            &mut answered,
            200,
            BROWSER.parse().unwrap(),
            &dispatcher.state
        ));

        let answers = engine.commands("answer");
        let last = answers.last().expect("the browser's answer");
        assert_eq!(last.call_id, browser_offer.call_id);
        let own = sessions.get(SIP_CALL_ID).expect("the call's session");
        assert_eq!(own.rtpengine_id(), browser_offer.call_id);
        assert_eq!(own.profile, "extension#webrtc-offer");
        assert_eq!(own.to_tag.as_deref(), Some("browser"));
        assert_eq!(sessions.dial_branch_calls(), 0);
        native_deleted(&engine, &plain_offer.call_id).await;
        assert!(
            !engine
                .commands("delete")
                .iter()
                .any(|command| command.call_id == browser_offer.call_id),
            "the winner's media stays up"
        );
    }

    /// The desk phone answering a ring the browser also got: the call settles
    /// on the plain allocation, as written, and the browser's is deleted.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_desk_phone_answering_settles_on_the_plain_profile_and_frees_the_browsers() {
        let engine = NativeTestEngine::start().await;
        let (dispatcher, sessions, call_id) = native_dispatcher(&engine, OFFER).await;
        assert!(ring(&dispatcher.state, browser_and_desk_phone()).unwrap());
        let (browser_offer, plain_offer) = offers_by_flavour(&engine);
        let invites = sent_invites(&dispatcher);
        let desk = &invites[&DESK_PHONE.parse().unwrap()];

        let mut answered = answer(desk, 200, "desk", DESK_PHONE);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(desk),
            &mut answered,
            200,
            DESK_PHONE.parse().unwrap(),
            &dispatcher.state
        ));

        let own = sessions.get(SIP_CALL_ID).expect("the call's session");
        assert_eq!(own.rtpengine_id(), plain_offer.call_id);
        assert_eq!(own.profile, "extension");
        assert_eq!(sessions.dial_branch_calls(), 0);
        native_deleted(&engine, &browser_offer.call_id).await;
    }

    /// A caller that offers WebRTC is answered WebRTC whichever branch wins:
    /// the `answer` half is decided by the caller's offer, and the desk phone's
    /// branch keeps its plain offer half.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_webrtc_caller_is_answered_with_the_webrtc_answer_half() {
        let engine = NativeTestEngine::start().await;
        let (dispatcher, _sessions, call_id) = native_dispatcher(&engine, BROWSER_OFFER).await;
        assert!(ring(
            &dispatcher.state,
            vec![bound(
                &format!("sip:201@{DESK_PHONE}"),
                Some(Transport::Udp)
            )]
        )
        .unwrap());
        let offers = engine.commands("offer");
        assert_eq!(offers.len(), 1);
        assert_eq!(
            offers[0]
                .profile
                .as_ref()
                .and_then(|profile| profile.transport_protocol.as_deref()),
            Some("RTP/AVP"),
            "the phone is offered plain RTP"
        );
        let invites = sent_invites(&dispatcher);
        let desk = &invites[&DESK_PHONE.parse().unwrap()];
        let mut answered = answer(desk, 200, "desk", DESK_PHONE);
        assert!(handle_b2bua_response(
            &call_id,
            &via_branch(desk),
            &mut answered,
            200,
            DESK_PHONE.parse().unwrap(),
            &dispatcher.state
        ));
        let answers = engine.commands("answer");
        let toward_caller = answers
            .last()
            .and_then(|command| command.profile.clone())
            .expect("the answer's profile");
        assert_eq!(
            toward_caller.transport_protocol.as_deref(),
            Some("UDP/TLS/RTP/SAVPF")
        );
        assert_eq!(toward_caller.ice.as_deref(), Some("force"));
        assert_eq!(toward_caller.rtcp_mux, vec!["require"]);
    }

    /// Per-module leak gate: a fork across both kinds that fails releases
    /// both allocations, every time, and the engine and the store drain.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_mixed_flavour_dials_drain_the_store_and_the_engine() {
        let engine = NativeTestEngine::start().await;
        let (dispatcher, sessions, parked) = native_dispatcher(&engine, OFFER).await;
        dispatcher.state.call_actors.remove_call(&parked);
        for _ in 0..20 {
            let call_id = park(&dispatcher.state);
            assert!(ring(&dispatcher.state, browser_and_desk_phone()).unwrap());
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
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while engine.held_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the engine holds nothing");
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
