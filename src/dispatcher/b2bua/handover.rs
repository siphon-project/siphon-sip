//! Handing a call to an external controller (the control plane).
//!
//! Answer-first anchoring and the Stasis-style payload, for a controller that
//! wants the call answered and media anchored before it decides anything.

use crate::dispatcher::*;

/// Parameters for [`control_handover`], grouped to keep the arity sane.
pub struct ControlHandoverParams<'a> {
    pub app: &'a str,
    pub on_lost: Option<&'a str>,
    pub deadline_ms: Option<u64>,
    pub vars: std::collections::HashMap<String, String>,
    /// Answer-first (AI-park): answer + anchor media before handing over.
    pub answer: bool,
    /// Answer-first only: media profile (default `voice_ai`).
    pub profile: Option<&'a str>,
    /// Answer-first only: per-call WS bridge URI (templated).
    pub ws_uri: Option<&'a str>,
}

/// Hand a call over to external control (`call.handover(...)`).
///
/// **Deferred mode** (`answer=false`): hold the INVITE transaction un-dialed
/// (kept alive by the automatic 100 Trying — no synthesized provisional),
/// register the call with the control plane, emit `StasisStart`, and arm the
/// handoff deadline. **Answer-first / AI-park** (`answer=true`): answer `200 OK`
/// with an `answer_local`-synthesized SDP that anchors the A-leg media to the
/// `voice_ai` WebSocket bridge, THEN register — the controller drives an already
/// -connected channel with the AI audio path open. If no controller is available
/// (or control is not configured) the handoff default fires immediately — never a
/// silent black-hole. Answer-first on a backend that cannot `answer_local`
/// (anything but siphon-rtp) is a hard, visible failure (503) — never a fake 200.
pub fn control_handover(
    call_id: &str,
    invite: &SipMessage,
    inbound: &InboundMessage,
    params: ControlHandoverParams<'_>,
    state: &DispatcherState,
) {
    let ControlHandoverParams {
        app,
        on_lost,
        deadline_ms,
        vars,
        answer,
        profile,
        ws_uri,
    } = params;

    let reject_and_drop = |code: u16, reason: &str| {
        let response = build_response(invite, code, reason, state.server_header.as_deref(), &[]);
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        state.call_actors.remove_call(call_id);
        state.call_event_receivers.remove(call_id);
    };

    let Some(bus) = crate::control::ControlBus::global() else {
        warn!(call_id = %call_id, %app, "handover requested but control plane is not configured — rejecting 503");
        reject_and_drop(503, "Service Unavailable");
        return;
    };
    if !bus.app_configured(app) {
        warn!(call_id = %call_id, %app, "handover to an unknown control app — rejecting 503");
        reject_and_drop(503, "Service Unavailable");
        return;
    }

    // Answer-first: synthesize the RFC 3264 answer + anchor media BEFORE handing
    // over. On any failure (no siphon-rtp backend, profile/flag/ws_uri error, or
    // engine error) reject visibly — a script asking for answer-first on a
    // backend that can't must fail, never fake a 200.
    if answer {
        match answer_first_anchor(
            call_id,
            invite,
            inbound.remote_addr.ip(),
            200,
            "OK",
            profile,
            ws_uri,
            state,
        ) {
            Ok(()) => {
                // b2bua_answer_call set the A-leg to Answered + stamped the CDR
                // answer time; the media now flows to the voice_ai bridge.
                info!(call_id = %call_id, %app, "B2BUA: answer-first handover — 200 OK sent, media anchored to voice_ai bridge");
            }
            Err(reason) => {
                warn!(call_id = %call_id, %app, %reason, "handover(answer=True) failed — rejecting 503 (no fake 200)");
                reject_and_drop(503, "AI Media Unavailable");
                return;
            }
        }
    }

    let sip_call_id = invite.headers.call_id().cloned().unwrap_or_default();
    let channel_id = format!("ch-{call_id}");
    let stasis_payload = build_stasis_payload(invite, inbound, &vars);

    // Record the control owner + mark awaiting the controller's first action. In
    // deferred mode send NO synthesized provisional — the caller's INVITE txn is
    // already kept alive by the automatic 100 Trying (a 180 would falsely signal
    // ringing before anything is dialed); the app sends its own via `progress`.
    // In answer-first mode the 200 already went out and the state is Answered.
    // Per-call value first, then the app's configured policy, then hangup.
    // `control.apps[].on_lost` parsed and was never read: only a per-call value
    // reached a channel, so an operator who set the policy once for the app got
    // the hardcoded default on every call and no indication of it.
    let app_on_lost = bus
        .app_config(app)
        .and_then(|config| config.on_lost.clone());
    let on_lost = on_lost
        .map(str::to_string)
        .or(app_on_lost)
        .unwrap_or_else(|| "hangup".to_string());

    state
        .call_actors
        .set_control_owner(call_id, app, Some(&on_lost));
    if !answer {
        state.call_actors.set_state(call_id, CallState::Ringing);
    }

    let outcome = bus.offer_channel(
        app,
        &channel_id,
        call_id,
        &sip_call_id,
        &on_lost,
        vars,
        stasis_payload,
    );

    match outcome {
        crate::control::OfferOutcome::Assigned | crate::control::OfferOutcome::Dialing => {
            // A handoff deadline only applies to a *parked, un-answered* call
            // (deferred mode) — the sweep degrades it if no controller acts. An
            // answer-first call is already answered + media-anchored (a real
            // call), so it is driven by the AI on its own timeline; control-loss
            // (owner disconnect) still applies via `on_lost`.
            if !answer {
                let deadline_ms = deadline_ms.unwrap_or_else(|| bus.handoff_deadline_ms());
                if deadline_ms > 0 {
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_millis(deadline_ms);
                    state.call_actors.set_answer_deadline(call_id, deadline);
                }
            }
            info!(call_id = %call_id, %app, channel = %channel_id, answer, "B2BUA: call handed over to control plane");
        }
        crate::control::OfferOutcome::NoController => {
            warn!(call_id = %call_id, %app, answer, "handover: no controller available — applying default");
            crate::metrics::try_metrics().inspect(|m| {
                m.control_handoff_timeouts_total
                    .with_label_values(&[app])
                    .inc()
            });
            if answer {
                // The call was already answered + media-anchored; there is no
                // controller to drive it, so tear it down cleanly (BYE + media
                // delete + StasisEnd) rather than leave an orphaned answered call.
                b2bua_terminate_call(&sip_call_id, Some("no control app connected"));
            } else {
                b2bua_reject_call(call_id, 503, "No Controller Available");
            }
        }
    }
}

/// Answer-first media anchor: resolve the profile (`voice_ai` by default),
/// template the per-call `ws_uri`, `answer_local` the A-leg offer to synthesize
/// the RFC 3264 answer with the media engine as the far side, record the media
/// session, and send the 2xx with that SDP. Returns `Err(reason)` (a short
/// human string) on any failure so the caller rejects visibly instead of faking
/// a 200. Reuses #131's `expand_ws_uri` + the profile registry — no duplicated
/// media logic.
///
/// `source_ip` rather than the `InboundMessage` it used to take: the only thing
/// read off it is the A-leg's source address (the `received_from` gate), and the
/// control plane's `answer` verb reaches this the same way but has no inbound
/// message in hand — the address lives on the stored leg by then. Everything
/// else comes off the INVITE, and the response leaves through
/// [`b2bua_answer_call`], which routes on the leg's own transport.
pub fn answer_first_anchor(
    call_id: &str,
    invite: &SipMessage,
    source_ip: std::net::IpAddr,
    code: u16,
    reason: &str,
    profile: Option<&str>,
    ws_uri: Option<&str>,
    state: &DispatcherState,
) -> Result<(), String> {
    // Anchored early media already put this leg on the engine and sent its SDP
    // answer in an 18x. The 2xx repeats that answer (RFC 3264 §4: the exchange
    // completed when the 18x carried it) and must not anchor a second time — a
    // second `answer_local` hands the caller a new media port under an answer
    // it has already accepted.
    let answer_sdp = match state.call_actors.early_media_anchor(call_id) {
        Some(anchor) => anchor.answer_sdp,
        None => anchor_a_leg(invite, source_ip, profile, ws_uri, state)?.answer_sdp,
    };

    // Send the 2xx with the synthesized answer SDP (marks the A-leg Answered +
    // stamps the CDR answer time).
    if !b2bua_answer_call(
        call_id,
        invite,
        code,
        reason,
        Some(answer_sdp.into_bytes()),
        Some("application/sdp"),
    ) {
        return Err(format!(
            "failed to send {code} {reason} (call gone / dispatcher down)"
        ));
    }
    Ok(())
}

/// Anchor the A-leg on the media engine and return the engine's SDP answer.
///
/// The media half shared by the answer-first 2xx and the early-media 18x:
/// resolve and validate the plan, `answer_local` the caller's offer, and record
/// the media session so a later delete or control-app media verb finds it.
/// Sends nothing — the caller decides which response carries the answer.
pub fn anchor_a_leg(
    invite: &SipMessage,
    source_ip: std::net::IpAddr,
    profile: Option<&str>,
    ws_uri: Option<&str>,
    state: &DispatcherState,
) -> Result<crate::b2bua::actor::EarlyMediaAnchor, String> {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return Err(
            "answer-first requires a media backend (media.backend), none configured".to_string(),
        );
    };
    let Some(registry) = state.rtpengine_profiles.as_ref() else {
        return Err("answer-first requires media profiles, none configured".to_string());
    };

    // Resolve + validate the media plan (backend gate, profile, ws_uri template,
    // capability check) — pure, unit-tested. No I/O here.
    let plan = answer_first_prepare(invite, source_ip, backend, registry, profile, ws_uri)?;

    // Media round-trip on the SIP-processing path (block_in_place is consistent
    // with the existing B2BUA answer paths — NOT the control-command path).
    let answer_sdp = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer_local(
            &plan.media_call_id,
            &plan.from_tag,
            &plan.offer_sdp,
            &plan.flags,
        ))
    })
    .map_err(|error| format!("answer_local failed: {error}"))?;

    // Record the media session (so a later delete / control-app media correlation
    // works), exactly as rtpengine.offer / answer_local do.
    if let Some(sessions) = state.rtpengine_sessions.as_ref() {
        sessions.insert(crate::rtpengine::session::MediaSession {
            rtpengine_call_id: plan.media_call_id.clone(),
            call_id: plan.media_call_id.clone(),
            from_tag: plan.from_tag.clone(),
            to_tag: None,
            profile: plan.profile_name.clone(),
            ws_uri: plan.flags.ws_uri.clone(),
            ws_tee: plan.flags.ws_tee.clone(),
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });
    }

    Ok(crate::b2bua::actor::EarlyMediaAnchor {
        answer_sdp,
        profile: plan.profile_name,
    })
}

/// Open early media through the engine: anchor the A-leg (or reuse the anchor
/// an earlier early response made) and send an 18x carrying the engine's SDP.
///
/// The answer is recorded on the call so the 2xx that follows repeats it rather
/// than anchoring again (see [`answer_first_anchor`]). On a media failure
/// nothing is sent and the call stays parked, like the answer path — never an
/// 18x with no media behind it.
#[allow(clippy::too_many_arguments)]
pub fn early_media_anchor_progress(
    call_id: &str,
    invite: &SipMessage,
    source_ip: std::net::IpAddr,
    code: u16,
    reason: &str,
    profile: Option<&str>,
    ws_uri: Option<&str>,
    state: &DispatcherState,
) -> Result<(), String> {
    let anchor = match state.call_actors.early_media_anchor(call_id) {
        Some(anchor) => anchor,
        None => {
            let anchor = anchor_a_leg(invite, source_ip, profile, ws_uri, state)?;
            state
                .call_actors
                .set_early_media_anchor(call_id, anchor.clone());
            anchor
        }
    };
    if !b2bua_progress_call(
        call_id,
        invite,
        code,
        reason,
        Some(anchor.answer_sdp.into_bytes()),
        Some("application/sdp"),
    ) {
        return Err(format!(
            "failed to send {code} {reason} (call gone / dispatcher down)"
        ));
    }
    Ok(())
}

/// The resolved, validated plan for an answer-first media anchor.
#[derive(Debug)]
pub struct AnswerFirstPlan {
    pub flags: crate::rtpengine::NgFlags,
    pub media_call_id: String,
    pub from_tag: String,
    pub offer_sdp: String,
    pub profile_name: String,
}

/// Pure decision for answer-first: gate the backend (siphon-rtp only), resolve
/// the profile (default `voice_ai`), template the per-call `ws_uri` with #131's
/// expander, apply the `received_from` gate, and run the backend-capability
/// check. Returns `Err(reason)` on any failure so the caller rejects the
/// handover visibly instead of faking a 200. No I/O — unit-testable.
pub fn answer_first_prepare(
    invite: &SipMessage,
    source_ip: std::net::IpAddr,
    backend: &crate::rtpengine::MediaBackend,
    registry: &crate::rtpengine::ProfileRegistry,
    profile: Option<&str>,
    ws_uri: Option<&str>,
) -> Result<AnswerFirstPlan, String> {
    // answer_local is siphon-rtp only — fail visibly on rtpengine/rtpproxy.
    if !matches!(backend.kind(), crate::config::MediaBackendKind::SiphonRtp) {
        return Err(format!(
            "answer-first (voice_ai) requires the siphon-rtp media backend; media.backend is {}",
            backend.kind().as_str()
        ));
    }
    let profile_name = profile.unwrap_or("voice_ai");
    let Some(entry) = registry.get(profile_name) else {
        return Err(format!(
            "unknown media profile '{profile_name}' for answer-first"
        ));
    };
    let mut flags = entry.answer.clone();

    // Identifiers off the A-leg INVITE (call_id / From-tag / From+To user parts).
    let media_call_id = invite.headers.call_id().cloned().unwrap_or_default();
    let from_tag = invite
        .headers
        .from()
        .and_then(|from| {
            from.split(';')
                .find_map(|part| part.trim().strip_prefix("tag=").map(|tag| tag.to_string()))
        })
        .unwrap_or_default();
    let user_of = |name: &str| -> Option<String> {
        invite
            .headers
            .get(name)
            .and_then(|value| crate::sip::headers::nameaddr::NameAddr::parse(value).ok())
            .and_then(|nameaddr| nameaddr.uri.user)
    };
    let from_user = user_of("From");
    let to_user = user_of("To");

    // ws_uri precedence: explicit arg → profile's own → none. Template it with
    // #131's expander (unknown/empty placeholder is an error, not a literal).
    let ws_uri_template = ws_uri.map(str::to_string).or_else(|| flags.ws_uri.clone());
    match ws_uri_template {
        Some(template) => {
            let context = crate::script::api::rtpengine::WsUriContext {
                call_id: &media_call_id,
                from_tag: &from_tag,
                from_user: from_user.as_deref(),
                to_user: to_user.as_deref(),
            };
            let expanded = crate::script::api::rtpengine::expand_ws_uri(&template, &context)
                .map_err(|error| format!("ws_uri templating failed: {error:?}"))?;
            flags.ws_uri = Some(expanded);
        }
        None => {
            // No bridge. The engine terminates the leg itself and siphon drives
            // it with `play`, DTMF and recording — which is the IVR menu, the
            // queue announcement, music on hold and the voicemail greeting, and
            // none of them involve a WebSocket.
            //
            // Refusing here meant a controller could only anchor a leg by also
            // opening an AI audio bridge it did not want, so most of what an
            // application does to a caller before a person picks up was not
            // reachable over the control rail at all.
            debug!(
                call_id = %media_call_id,
                profile = %profile_name,
                "answer-first: anchoring on the engine with no bridge"
            );
        }
    }

    // received_from gate: pin media ingress to the caller's real source IP.
    if flags.carry_received_from {
        flags.received_from = Some(source_ip);
    }

    // Final backend-capability guard (mirrors finalise_flags) — should pass on
    // siphon-rtp, but never answer a call whose flags the engine cannot honour.
    let unsupported = backend.unsupported_flags(&flags);
    if !unsupported.is_empty() {
        return Err(format!(
            "media profile '{profile_name}' sets {} which the {} backend cannot honour",
            unsupported.join(", "),
            backend.kind().as_str()
        ));
    }

    let offer_sdp = String::from_utf8_lossy(&invite.body).into_owned();
    if offer_sdp.trim().is_empty() {
        return Err("answer-first requires an SDP offer on the INVITE; none present".to_string());
    }

    Ok(AnswerFirstPlan {
        flags,
        media_call_id,
        from_tag,
        offer_sdp,
        profile_name: profile_name.to_string(),
    })
}

/// Build the `StasisStart` payload: the full SIP context (all headers, source,
/// R-URI shape, body) + the handover vars. Requirement #5 — the controller sees
/// the real headers, not a normalized summary.
pub fn build_stasis_payload(
    invite: &SipMessage,
    inbound: &InboundMessage,
    vars: &std::collections::HashMap<String, String>,
) -> serde_json::Value {
    let (method, ruri) = match &invite.start_line {
        StartLine::Request(request_line) => (
            request_line.method.as_str().to_string(),
            request_line.request_uri.to_string(),
        ),
        _ => (String::new(), String::new()),
    };
    let mut headers: Vec<[String; 2]> = Vec::new();
    for (name, values) in invite.headers.iter_original() {
        for value in values {
            headers.push([name.clone(), value.clone()]);
        }
    }
    let body = if invite.body.is_empty() {
        None
    } else {
        // SDP is text; surface it directly when valid UTF-8 (avoids a base64 dep
        // on the control rail). Non-text bodies report their length only.
        match std::str::from_utf8(&invite.body) {
            Ok(text) => Some(
                serde_json::json!({ "content_type": invite.headers.get("Content-Type").cloned(), "text": text }),
            ),
            Err(_) => Some(
                serde_json::json!({ "content_type": invite.headers.get("Content-Type").cloned(), "bytes": invite.body.len() }),
            ),
        }
    };
    serde_json::json!({
        "invite": {
            "method": method,
            "ruri": ruri,
            "headers": headers,
            "body": body,
        },
        "source_ip": inbound.remote_addr.ip().to_string(),
        "source_port": inbound.remote_addr.port(),
        "transport": format!("{}", inbound.transport).to_lowercase(),
        "vars": vars,
    })
}

/// Build the B-leg Contact header value.
///
/// Default is siphon's own userless address `<sip:host:port;transport=…>` — RFC
/// 3261 §8.1.1.8 puts no identity in the Contact userpart, and siphon's address
/// is all that's needed as the §12.2.1.1 in-dialog remote target. A script may
/// override it via `call.set_contact_user()` (inject a userpart, keep siphon's
/// host:port — in-dialog routing intact) or `call.set_contact_uri()` (replace
/// the whole URI — edge/GRUU deployments that front siphon). The full-URI
/// override wins over the userpart one; an empty userpart override collapses to
/// the userless default.
pub fn build_b_leg_contact(
    host: &str,
    port: u16,
    transport: Transport,
    contact_user_override: Option<&str>,
    contact_override: Option<&str>,
) -> String {
    if let Some(uri) = contact_override {
        format!("<{uri}>")
    } else if let Some(user) = contact_user_override.filter(|user| !user.is_empty()) {
        format!(
            "<sip:{}@{}:{};transport={}>",
            user,
            host,
            port,
            transport.to_string().to_lowercase(),
        )
    } else {
        format!(
            "<sip:{}:{};transport={}>",
            host,
            port,
            transport.to_string().to_lowercase(),
        )
    }
}

/// Advertise an option tag in `Supported` without repeating one already there.
///
/// `Supported` is a comma-separated list header, so the tag belongs *inside* the
/// existing value. Adding a second `Supported:` line is legal per RFC 3261
/// §7.3.1 and still wrong-looking on the wire — a peer sees
/// `Supported: histinfo,timer` followed by `Supported: timer`.
pub fn advertise_option_tag(headers: &mut crate::sip::headers::SipHeaders, tag: &str) {
    match headers.get("Supported") {
        Some(existing) => {
            if existing
                .split(',')
                .any(|option| option.trim().eq_ignore_ascii_case(tag))
            {
                return;
            }
            let merged = if existing.trim().is_empty() {
                tag.to_string()
            } else {
                format!("{},{tag}", existing.trim())
            };
            headers.set("Supported", merged);
        }
        None => headers.set("Supported", tag.to_string()),
    }
}
