//! Anchoring the media of a call siphon placed with an offerless INVITE:
//! answering the callee's 2xx offer on the media engine, and releasing the
//! session when the call fails before its ordinary teardown.
use crate::dispatcher::*;

/// Answer the callee's 2xx offer locally on the media backend and record the
/// media session under this leg's SIP Call-ID, so every media verb resolves
/// against it through [`b2bua_media_target`].
///
/// Returns the answer SDP for the ACK, or a short human reason on failure —
/// never a silent no-op, because an offerless INVITE with no answer is a
/// connected call with no audio.
pub fn originate_anchor_2xx(
    sip_call_id: &str,
    remote_tag: &str,
    response: &SipMessage,
    anchor: &crate::b2bua::actor::OriginateAnchor,
    state: &DispatcherState,
) -> Result<String, String> {
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or_else(|| "no media backend configured".to_string())?;
    let registry = state
        .rtpengine_profiles
        .as_ref()
        .ok_or_else(|| "no media profiles configured".to_string())?;
    let entry = registry
        .get(&anchor.profile)
        .ok_or_else(|| format!("unknown media profile '{}'", anchor.profile))?;
    let mut flags = entry.answer.clone();

    let offer_sdp = std::str::from_utf8(&response.body)
        .map_err(|_| "the callee's 2xx body is not valid UTF-8 SDP".to_string())?
        .to_string();
    if offer_sdp.trim().is_empty() {
        return Err("the callee answered with no SDP offer — nothing to anchor".to_string());
    }

    // ws_uri precedence: explicit per-call arg → the profile's own → none.
    let template = anchor.ws_uri.clone().or_else(|| flags.ws_uri.clone());
    if let Some(template) = template {
        let context = crate::script::api::rtpengine::WsUriContext {
            call_id: sip_call_id,
            from_tag: remote_tag,
            from_user: None,
            to_user: None,
        };
        flags.ws_uri = Some(
            crate::script::api::rtpengine::expand_ws_uri(&template, &context)
                .map_err(|error| format!("ws_uri templating failed: {error:?}"))?,
        );
    }
    let unsupported = backend.unsupported_flags(&flags);
    if !unsupported.is_empty() {
        return Err(format!(
            "media profile '{}' sets {} which the {} backend cannot honour",
            anchor.profile,
            unsupported.join(", "),
            backend.kind().as_str()
        ));
    }

    // The offerer here is the *callee* (it offered in its 2xx), so the engine's
    // monologue is keyed on the callee's tag — the same "key on the offerer's
    // tag" convention the inbound answer-first anchor uses.
    let answer = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer_local(
            sip_call_id,
            remote_tag,
            &offer_sdp,
            &flags,
        ))
    })
    .map_err(|error| format!("answer_local failed: {error}"))?;

    if let Some(sessions) = state.rtpengine_sessions.as_ref() {
        sessions.insert(crate::rtpengine::session::MediaSession {
            rtpengine_call_id: sip_call_id.to_string(),
            call_id: sip_call_id.to_string(),
            from_tag: remote_tag.to_string(),
            to_tag: None,
            profile: anchor.profile.clone(),
            ws_uri: flags.ws_uri.clone(),
            ws_tee: flags.ws_tee.clone(),
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });
    }
    Ok(answer)
}

/// Drop any media session anchored for an originated call that failed before it
/// could be torn down the ordinary way.
pub fn originate_delete_media(sip_call_id: &str, state: &DispatcherState) {
    if let (Some(backend), Some(sessions)) = (&state.rtpengine_set, &state.rtpengine_sessions) {
        if let Some(session) = sessions.remove(sip_call_id) {
            let backend = Arc::clone(backend);
            tokio::spawn(async move {
                if let Err(error) = backend
                    .delete(session.rtpengine_id(), &session.from_tag)
                    .await
                {
                    if !error.is_call_not_found() {
                        warn!(call_id = %session.call_id, "originate: media delete failed: {error}");
                    }
                }
            });
        }
    }
}
