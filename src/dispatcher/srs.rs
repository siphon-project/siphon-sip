//! The SRS role (RFC 7866): recording sessions siphon terminates, offered to
//! it by a remote SRC.
use super::*;

// ---------------------------------------------------------------------------
// SRS — Session Recording Server handlers
// ---------------------------------------------------------------------------

/// Check if an incoming INVITE is a SIPREC recording request.
///
/// Detection: Content-Type is `multipart/mixed` AND the body contains
/// `application/rs-metadata+xml`.
pub(super) fn is_siprec_invite(message: &SipMessage) -> bool {
    let content_type = match message.headers.get("Content-Type") {
        Some(content_type) => content_type,
        None => return false,
    };

    if !content_type
        .to_ascii_lowercase()
        .contains("multipart/mixed")
    {
        return false;
    }

    // Quick check: does the body contain the metadata content type?
    if message.body.is_empty() {
        return false;
    }
    let body_str = String::from_utf8_lossy(&message.body);
    body_str.contains("application/rs-metadata+xml")
}

/// Handle an inbound SIPREC INVITE (SRC → SRS).
///
/// Parses the multipart body, extracts SDP and recording metadata,
/// creates an SRS session, optionally sets up RTPEngine recording,
/// and sends 200 OK back to the SRC.
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. handle_srs_invite
pub(super) fn handle_srs_invite(
    inbound: InboundMessage,
    message: SipMessage,
    srs_manager: Arc<crate::srs::SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let call_id = message
            .headers
            .get("Call-ID")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let from_tag = message
            .headers
            .get("From")
            .and_then(|from| from.split("tag=").nth(1))
            .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string())
            .unwrap_or_default();

        info!(
            call_id = %call_id,
            remote = %inbound.remote_addr,
            "SRS: received SIPREC INVITE"
        );

        // Parse the multipart body.
        let content_type = match message.headers.get("Content-Type") {
            Some(content_type) => content_type.clone(),
            None => {
                warn!(call_id = %call_id, "SRS: SIPREC INVITE missing Content-Type");
                let response = build_response(
                    &message,
                    400,
                    "Bad Request",
                    state.server_header.as_deref(),
                    &[],
                );
                send_message_from(
                    response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    &state,
                );
                return;
            }
        };

        if message.body.is_empty() {
            warn!(call_id = %call_id, "SRS: SIPREC INVITE has no body");
            let response = build_response(
                &message,
                400,
                "Bad Request",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                &state,
            );
            return;
        }
        let body = message.body.clone();

        let parts = match crate::siprec::multipart::parse_multipart(&content_type, &body) {
            Ok(parts) => parts,
            Err(error) => {
                warn!(call_id = %call_id, error = %error, "SRS: failed to parse multipart body");
                let response = build_response(
                    &message,
                    400,
                    "Bad Request",
                    state.server_header.as_deref(),
                    &[],
                );
                send_message_from(
                    response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    &state,
                );
                return;
            }
        };

        // Extract SDP and metadata parts.
        let sdp_part = crate::siprec::multipart::find_part(&parts, "application/sdp");
        let metadata_part = crate::siprec::multipart::find_part(&parts, "application/rs-metadata");

        let metadata_xml = match metadata_part {
            Some(part) => String::from_utf8_lossy(&part.body).to_string(),
            None => {
                warn!(call_id = %call_id, "SRS: no rs-metadata+xml part in SIPREC INVITE");
                let response = build_response(
                    &message,
                    400,
                    "Bad Request",
                    state.server_header.as_deref(),
                    &[],
                );
                send_message_from(
                    response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    &state,
                );
                return;
            }
        };

        // Parse the recording metadata XML.
        let metadata = match crate::siprec::metadata::parse_recording_metadata(&metadata_xml) {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(call_id = %call_id, error = %error, "SRS: failed to parse recording metadata");
                let response = build_response(
                    &message,
                    400,
                    "Bad Request",
                    state.server_header.as_deref(),
                    &[],
                );
                send_message_from(
                    response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    &state,
                );
                return;
            }
        };

        info!(
            call_id = %call_id,
            session_id = %metadata.session_id,
            participants = metadata.participants.len(),
            streams = metadata.streams.len(),
            "SRS: parsed SIPREC metadata"
        );

        // Invoke Python @srs.on_invite handler if registered.
        let should_accept = {
            let engine_state = state.engine.state();
            let srs_handlers = engine_state.handlers_for(&HandlerKind::SrsOnInvite);
            if !srs_handlers.is_empty() {
                let py_metadata =
                    crate::script::api::srs::PyRecordingMetadata::from_metadata(&metadata);
                let result = pyo3::Python::attach(|python| {
                    let py_meta = match pyo3::Py::new(python, py_metadata) {
                        Ok(meta) => meta,
                        Err(error) => {
                            warn!(call_id = %call_id, error = %error, "SRS: failed to create PyRecordingMetadata");
                            return true; // Accept on error
                        }
                    };
                    for handler in &srs_handlers {
                        match handler.callable.call1(python, (py_meta.clone_ref(python),)) {
                            Ok(result) => {
                                if let Ok(accepted) = result.extract::<bool>(python) {
                                    if !accepted {
                                        return false;
                                    }
                                }
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, error = %error, "SRS: on_invite handler error");
                            }
                        }
                    }
                    true
                });
                drop(engine_state);
                result
            } else {
                drop(engine_state);
                true
            }
        };

        if !should_accept {
            info!(call_id = %call_id, "SRS: recording rejected by script");
            let response = build_response(
                &message,
                403,
                "Forbidden",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                &state,
            );
            return;
        }

        // Check if this is a re-INVITE for an existing session.
        let is_reinvite = srs_manager.is_srs_session(&call_id);

        let (session_id, to_tag) = if is_reinvite {
            // Re-INVITE: update existing session metadata, reuse to-tag.
            match srs_manager.update_session(&call_id, metadata) {
                Some(to_tag) => {
                    let session_id = srs_manager
                        .session_for_call_id(&call_id)
                        .unwrap_or_default();
                    (session_id, to_tag)
                }
                None => {
                    warn!(call_id = %call_id, "SRS: re-INVITE but session not found");
                    let response = build_response(
                        &message,
                        481,
                        "Call/Transaction Does Not Exist",
                        state.server_header.as_deref(),
                        &[],
                    );
                    send_message_from(
                        response,
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        Some(inbound.local_addr),
                        &state,
                    );
                    return;
                }
            }
        } else {
            // Initial INVITE: create a new session.
            match srs_manager.create_session(&call_id, &from_tag, metadata) {
                Some(result) => result,
                None => {
                    warn!(call_id = %call_id, "SRS: session creation failed (max sessions?)");
                    let response = build_response(
                        &message,
                        503,
                        "Service Unavailable",
                        state.server_header.as_deref(),
                        &[],
                    );
                    send_message_from(
                        response,
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        Some(inbound.local_addr),
                        &state,
                    );
                    return;
                }
            }
        };

        // Set up RTPEngine recording if available.
        let answer_sdp = if let (Some(ref rtpengine_set), Some(sdp_part)) =
            (&state.rtpengine_set, sdp_part)
        {
            let profile_name = srs_manager.rtpengine_profile();
            let profile_registry = crate::rtpengine::profile::ProfileRegistry::new();
            let profile = profile_registry.get(profile_name);

            if let Some(profile) = profile {
                // Create recording directory for RTPEngine.
                if let Some(recording_dir) = srs_manager.recording_dir(&session_id) {
                    let _ = tokio::fs::create_dir_all(&recording_dir).await;

                    let recording_dir_str = recording_dir.display().to_string();

                    // Split the dual-m= SDP into two single-m= SDPs (one per
                    // call direction).  RTPEngine needs a separate offer/answer
                    // pair to fully activate both media legs for recording.
                    let (sdp1, sdp2) = crate::siprec::split_dual_sdp(&sdp_part.body);

                    let mut offer_flags = profile.offer.clone();
                    offer_flags.record_call = true;
                    offer_flags.record_path = Some(recording_dir_str.clone());

                    let mut answer_flags = profile.answer.clone();
                    answer_flags.record_call = true;
                    answer_flags.record_path = Some(recording_dir_str);

                    // Step 1: offer() with first m= line (caller stream).
                    let offer_result = rtpengine_set
                        .offer(&call_id, &from_tag, &sdp1, &offer_flags)
                        .await;

                    match offer_result {
                        Ok(offer_response_sdp) => {
                            // Step 2: answer() with second m= line (callee stream).
                            let srs_to_tag = format!("srs-{}", uuid::Uuid::new_v4().as_simple());
                            let answer_result = rtpengine_set
                                .answer(&call_id, &from_tag, &srs_to_tag, &sdp2, &answer_flags)
                                .await;

                            match answer_result {
                                Ok(answer_response_sdp) => {
                                    // Combine both response SDPs into a single
                                    // recvonly SDP with 2 labeled m= lines.
                                    let combined = crate::siprec::combine_srs_answer_sdps(
                                        &offer_response_sdp,
                                        &answer_response_sdp,
                                    );
                                    srs_manager.activate_session(&session_id);
                                    Some(combined)
                                }
                                Err(error) => {
                                    warn!(
                                        call_id = %call_id,
                                        session_id = %session_id,
                                        error = %error,
                                        "SRS: RTPEngine answer failed"
                                    );
                                    srs_manager.fail_session(&session_id, &error.to_string());
                                    None
                                }
                            }
                        }
                        Err(error) => {
                            warn!(
                                call_id = %call_id,
                                session_id = %session_id,
                                error = %error,
                                "SRS: RTPEngine offer failed"
                            );
                            srs_manager.fail_session(&session_id, &error.to_string());
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                warn!(
                    call_id = %call_id,
                    profile = %profile_name,
                    "SRS: unknown RTPEngine profile"
                );
                None
            }
        } else {
            // No RTPEngine — accept without media anchoring.
            srs_manager.activate_session(&session_id);
            None
        };

        // Build 200 OK response.
        let mut response_builder = SipMessageBuilder::new().response(200, "OK".to_string());

        // Copy Via, From headers.
        if let Some(vias) = message.headers.get_all("Via") {
            for via in vias {
                response_builder = response_builder.via(via.clone());
            }
        }
        if let Some(from) = message.headers.from() {
            response_builder = response_builder.from(from.clone());
        }

        // Set To with our generated tag.
        if let Some(to) = message.headers.to() {
            let to_with_tag = if to.contains("tag=") {
                to.clone()
            } else {
                format!("{to};tag={to_tag}")
            };
            response_builder = response_builder.to(to_with_tag);
        }

        if let Some(call_id_header) = message.headers.get("Call-ID") {
            response_builder = response_builder.call_id(call_id_header.clone());
        }
        if let Some(cseq) = message.headers.get("CSeq") {
            response_builder = response_builder.cseq(cseq.clone());
        }

        // Add Contact header.
        response_builder =
            response_builder.header("Contact", format!("<sip:srs@{}>", state.local_addr));

        // Add SDP body (from RTPEngine or echo back original).
        // Sanitize o=/s= lines to hide the SRC's identity (e.g. "FreeSWITCH").
        // Flip SDP direction for the answer: the SRC offered sendonly (it sends
        // forked media), so the SRS answer must be recvonly (we receive it).
        // RTPEngine's offer response preserves the offer direction — we must flip
        // it since this SDP goes into the SIP 200 OK answer (RFC 3264 §5).
        let local_ip = state.local_addr.ip().to_string();
        if let Some(mut sdp) = answer_sdp {
            // combine_srs_answer_sdps already sets a=recvonly — no direction
            // flip needed.  Only sanitize the o=/s= identity lines.
            sanitize_sdp_identity(&mut sdp, "siphon", Some(&local_ip));
            response_builder = response_builder
                .header("Content-Type", "application/sdp".to_string())
                .body(sdp);
        } else if let Some(sdp_part) = sdp_part {
            let mut sdp = sdp_part.body.clone();
            fix_srs_answer_sdp_direction(&mut sdp);
            sanitize_sdp_identity(&mut sdp, "siphon", Some(&local_ip));
            response_builder = response_builder
                .header("Content-Type", "application/sdp".to_string())
                .body(sdp);
        } else {
            response_builder = response_builder.content_length(0);
        }

        if let Some(ref server) = state.server_header {
            response_builder = response_builder.header("Server", server.clone());
        }

        match response_builder.build() {
            Ok(response) => {
                info!(
                    call_id = %call_id,
                    session_id = %session_id,
                    "SRS: sending 200 OK to SRC"
                );
                send_message_from(
                    response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    &state,
                );
            }
            Err(error) => {
                error!(call_id = %call_id, error = %error, "SRS: failed to build 200 OK");
                srs_manager.fail_session(&session_id, &error.to_string());
            }
        }
    });
}

/// Handle a BYE for an active SRS recording session.
pub(super) fn handle_srs_bye(
    inbound: InboundMessage,
    message: SipMessage,
    call_id: &str,
    srs_manager: Arc<crate::srs::SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let call_id = call_id.to_string();
    let state = Arc::clone(state);
    tokio::spawn(async move {
        info!(call_id = %call_id, "SRS: received BYE from SRC");

        // Stop recording via RTPEngine.
        if let Some(ref rtpengine_set) = state.rtpengine_set {
            let from_tag = message
                .headers
                .get("From")
                .and_then(|from| from.split("tag=").nth(1))
                .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string())
                .unwrap_or_default();

            if let Err(error) = rtpengine_set.delete(&call_id, &from_tag).await {
                warn!(
                    call_id = %call_id,
                    error = %error,
                    "SRS: RTPEngine delete failed (session may have already ended)"
                );
            }
        }

        // Stop the SRS session and get the recording record.
        let record = srs_manager.stop_session(&call_id);

        // Send 200 OK for the BYE.
        let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            &state,
        );

        // Store recording metadata via configured backend.
        if let Some(record) = record {
            // Invoke @srs.on_session_end hook.
            {
                let engine_state = state.engine.state();
                let end_handlers = engine_state.handlers_for(&HandlerKind::SrsOnSessionEnd);
                if !end_handlers.is_empty() {
                    let py_session = crate::script::api::srs::PySrsSession::from_record(&record);
                    pyo3::Python::attach(|python| {
                        if let Ok(py_sess) = pyo3::Py::new(python, py_session) {
                            for handler in &end_handlers {
                                if let Err(error) =
                                    handler.callable.call1(python, (py_sess.clone_ref(python),))
                                {
                                    warn!(call_id = %call_id, error = %error, "SRS: on_session_end handler error");
                                }
                            }
                        }
                    });
                }
            }

            crate::srs::storage::store_recording(srs_manager.config(), &record).await;
        }
    });
}
