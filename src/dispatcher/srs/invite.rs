//! The initial SIPREC INVITE: from the SRC's offer to the 200 that starts the
//! recording, or the final response that refuses it.

use super::*;
use crate::siprec::metadata::{DataMode, RecordingMetadata};
use crate::siprec::srs_sdp::OfferedStream;
use crate::srs::{CreateSessionError, SrsDecision, SrsManager, SrsPeer};

/// What a request on a recording dialog carried: an SDP offer, recording
/// metadata, both, or neither.
pub(super) struct SrsBody {
    pub(super) offer: Option<Vec<OfferedStream>>,
    pub(super) metadata: Option<RecordingMetadata>,
}

/// A request refused for its body, with the status it is refused with.
pub(super) struct BodyRefusal {
    pub(super) code: u16,
    pub(super) reason: &'static str,
    pub(super) detail: String,
}

impl BodyRefusal {
    fn new(code: u16, reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            reason,
            detail: detail.into(),
        }
    }
}

/// Read a recording dialog request's body: a `multipart/mixed` with an SDP
/// part and a metadata part (RFC 7866 §6.1), or either alone (a re-INVITE or
/// UPDATE may carry only one, RFC 7866 §5.2), or nothing.
pub(super) fn parse_srs_body(message: &SipMessage) -> Result<SrsBody, BodyRefusal> {
    if message.body.is_empty() {
        return Ok(SrsBody {
            offer: None,
            metadata: None,
        });
    }
    let content_type = message
        .headers
        .get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .cloned()
        .unwrap_or_default();
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let (sdp, metadata_xml): (Option<Vec<u8>>, Option<String>) = match media_type.as_str() {
        "multipart/mixed" => {
            let parts = crate::siprec::multipart::parse_multipart(&content_type, &message.body)
                .map_err(|error| BodyRefusal::new(400, "Bad Request", error.to_string()))?;
            let sdp = crate::siprec::multipart::find_part(&parts, "application/sdp")
                .map(|part| part.body.clone());
            let metadata = crate::siprec::multipart::find_part(&parts, "application/rs-metadata")
                .map(|part| String::from_utf8_lossy(&part.body).into_owned());
            (sdp, metadata)
        }
        "application/sdp" => (Some(message.body.clone()), None),
        "application/rs-metadata+xml" => (
            None,
            Some(String::from_utf8_lossy(&message.body).into_owned()),
        ),
        other => {
            return Err(BodyRefusal::new(
                415,
                "Unsupported Media Type",
                format!("body of type {other:?}"),
            ))
        }
    };

    let offer = sdp
        .map(|sdp| crate::siprec::srs_sdp::split_offer(&sdp))
        .transpose()
        .map_err(|error| BodyRefusal::new(488, "Not Acceptable Here", error.to_string()))?;
    let metadata = metadata_xml
        .map(|xml| crate::siprec::metadata::parse_recording_metadata(&xml))
        .transpose()
        .map_err(|error| BodyRefusal::new(400, "Bad Request", error.to_string()))?;
    Ok(SrsBody { offer, metadata })
}

/// The SRC side of the dialog the INVITE opens, kept for a request siphon may
/// have to send in it.
fn peer_of(
    inbound: &InboundMessage,
    message: &SipMessage,
    to_tag: &str,
    contact: String,
    terminated: SipMessage,
) -> SrsPeer {
    let remote_contact = message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
        .map(|contact| crate::b2bua::actor::extract_contact_uri(contact));
    let local_to = message
        .headers
        .to()
        .map(|to| format!("{to};tag={to_tag}"))
        .unwrap_or_default();
    SrsPeer {
        remote_from: message.headers.from().cloned().unwrap_or_default(),
        local_to,
        remote_contact,
        local_contact: contact,
        route_set: message
            .headers
            .get_all("Record-Route")
            .map(|values| values.to_vec())
            .unwrap_or_default(),
        remote_addr: inbound.remote_addr,
        transport: inbound.transport,
        connection_id: inbound.connection_id,
        local_addr: Some(inbound.local_addr),
        terminated: Some(terminated),
    }
}

/// A new SIPREC INVITE. Everything that can be refused from the request alone
/// is refused here, on the dispatcher; the script and the media engine run on
/// a task, which answers it.
pub(super) fn handle_initial_invite(
    inbound: InboundMessage,
    message: SipMessage,
    srs_manager: Arc<SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let call_id = message.headers.call_id().cloned().unwrap_or_default();
    let from_tag = tag_of(message.headers.from()).unwrap_or_default();
    let branch = branch_of(&message).unwrap_or_default();
    info!(call_id = %call_id, remote = %inbound.remote_addr, "SRS: received SIPREC INVITE");

    // RFC 7866 §6.2: a SIPREC body alone is not a recording session. Refused
    // rather than recorded, or taken for a call.
    if !carries_recording_session_markers(&message) {
        warn!(call_id = %call_id, "SRS: SIPREC body without Require: siprec and +sip.src, refused");
        respond(
            &inbound,
            &message,
            400,
            "Not A Recording Session",
            None,
            &[],
            state,
        );
        return;
    }

    // The script and the media engine can take longer than T1: stop the SRC
    // retransmitting meanwhile (RFC 3261 §8.2.6.1, §17.2.1).
    respond(&inbound, &message, 100, "Trying", None, &[], state);

    let body = match parse_srs_body(&message) {
        Ok(body) => body,
        Err(refusal) => {
            warn!(call_id = %call_id, detail = %refusal.detail, "SRS: SIPREC INVITE refused for its body");
            respond(
                &inbound,
                &message,
                refusal.code,
                refusal.reason,
                None,
                &[],
                state,
            );
            return;
        }
    };
    let (Some(offer), Some(metadata)) = (body.offer, body.metadata) else {
        warn!(call_id = %call_id, "SRS: SIPREC INVITE without both an SDP offer and metadata");
        respond(&inbound, &message, 400, "Bad Request", None, &[], state);
        return;
    };
    // RFC 7866 §9.1: the first metadata of a session is the whole snapshot.
    if metadata.datamode == DataMode::Partial {
        respond(
            &inbound,
            &message,
            400,
            "Partial Metadata Without A Snapshot",
            None,
            &[],
            state,
        );
        return;
    }

    let to_tag = match srs_manager.create_session(&call_id, &from_tag, &branch, metadata.clone()) {
        Ok(to_tag) => to_tag,
        Err(CreateSessionError::AtCapacity) => {
            respond(
                &inbound,
                &message,
                503,
                "Service Unavailable",
                None,
                &[],
                state,
            );
            return;
        }
        Err(CreateSessionError::CallIdInUse) => {
            respond(&inbound, &message, 400, "Call-ID In Use", None, &[], state);
            return;
        }
    };
    let contact = srs_contact(&inbound, state);
    let terminated = build_srs_response(
        &message,
        487,
        "Request Terminated",
        Some(&to_tag),
        &[],
        state,
    );
    srs_manager.set_peer(
        &call_id,
        peer_of(&inbound, &message, &to_tag, contact, terminated),
    );

    let state = Arc::clone(state);
    tokio::spawn(async move {
        let invite = PendingInvite {
            inbound,
            message,
            call_id,
            from_tag,
            to_tag,
            srs_manager,
        };
        invite.complete(offer, metadata, &state).await;
    });
}

/// An accepted initial INVITE on its way to its final response.
struct PendingInvite {
    inbound: InboundMessage,
    message: SipMessage,
    call_id: String,
    from_tag: String,
    to_tag: String,
    srs_manager: Arc<SrsManager>,
}

impl PendingInvite {
    async fn complete(
        self,
        offer: Vec<OfferedStream>,
        metadata: RecordingMetadata,
        state: &Arc<DispatcherState>,
    ) {
        match self.decision(&offer, &metadata, state).await {
            SrsDecision::Accept(options) => self.srs_manager.set_recording(&self.call_id, options),
            SrsDecision::Reject { code, reason } => {
                info!(call_id = %self.call_id, code, "SRS: recording rejected");
                self.refuse(code, &reason, state);
                return;
            }
        }

        let recording = self.srs_manager.recording(&self.call_id);
        let recording_dir = self
            .srs_manager
            .recording_dir(&self.call_id)
            .unwrap_or_default();
        let owner = media::StreamOwner {
            recording_call_id: &self.call_id,
            from_tag: &self.from_tag,
            source_ip: self.inbound.remote_addr.ip(),
            recording_dir: &recording_dir,
            recording: &recording,
            left_label: media::left_label(&metadata),
        };
        let anchored = match media::anchor_streams(
            state,
            &owner,
            &offer,
            &[],
            self.srs_manager.rtpengine_profile(),
        )
        .await
        {
            Ok(anchored) => anchored,
            Err(error) => {
                warn!(call_id = %self.call_id, %error, "SRS: recording refused");
                let (code, reason) = error.status();
                self.refuse(code, reason, state);
                return;
            }
        };

        let response = self.answer(&anchored.answer, state);
        if !self
            .srs_manager
            .claim_final_response(&self.call_id, response.clone())
        {
            // A CANCEL got there first and the INVITE has its 487: nothing
            // that was started may stay up.
            info!(call_id = %self.call_id, "SRS: INVITE cancelled while its media was set up");
            media::release_streams(state, &anchored.streams, &self.from_tag).await;
            self.srs_manager.stop_session(&self.call_id);
            return;
        }
        self.srs_manager
            .set_streams(&self.call_id, anchored.streams, anchored.answer);
        self.srs_manager.activate_session(&self.call_id);

        // RFC 3261 §13.3.1.4: the 2xx is the UAS core's to retransmit until
        // the ACK, which `absorb_b2bua_ack` takes; the 64×T1 sweep ends a
        // session whose 2xx never was ACKed.
        let unacked = register_unacked_answer(&self.call_id, &response, state);
        info!(call_id = %self.call_id, "SRS: sending 200 OK to SRC");
        send_message_from(
            response.clone(),
            self.inbound.transport,
            self.inbound.remote_addr,
            self.inbound.connection_id,
            Some(self.inbound.local_addr),
            state,
        );
        start_2xx_retransmits(
            unacked,
            response,
            self.inbound.transport,
            self.inbound.remote_addr,
            self.inbound.connection_id,
            Some(self.inbound.local_addr),
            state,
        );
    }

    /// Whether to record, and how: the control application's decision when
    /// `srs.app` names one, otherwise the `@srs.on_invite` hooks'.
    async fn decision(
        &self,
        offer: &[OfferedStream],
        metadata: &RecordingMetadata,
        state: &Arc<DispatcherState>,
    ) -> SrsDecision {
        if let Some(app) = self.srs_manager.config().app.clone() {
            return control::offer_to_application(
                control::Offered {
                    app: &app,
                    inbound: &self.inbound,
                    message: &self.message,
                    call_id: &self.call_id,
                    metadata,
                    offer,
                },
                &self.srs_manager,
            )
            .await;
        }
        if script::invite_accepted(state, metadata, &self.call_id).await {
            SrsDecision::Accept(crate::srs::RecordingOptions::default())
        } else {
            SrsDecision::Reject {
                code: 403,
                reason: "Forbidden".to_string(),
            }
        }
    }

    /// The 200 carrying `sdp`.
    fn answer(&self, sdp: &[u8], state: &DispatcherState) -> SipMessage {
        let contact = self
            .srs_manager
            .peer(&self.call_id)
            .map(|peer| peer.local_contact)
            .unwrap_or_else(|| srs_contact(&self.inbound, state));
        let mut response = build_srs_response(
            &self.message,
            200,
            "OK",
            Some(&self.to_tag),
            &[("Contact", contact), ("Allow", ALLOW.to_string())],
            state,
        );
        let mut body = sdp.to_vec();
        let local_ip = state.local_addr.ip().to_string();
        sanitize_sdp_identity(&mut body, &state.sdp_name, Some(&local_ip));
        set_sdp_body(&mut response, body);
        response
    }

    /// Answer the INVITE `code` and end the session, unless a CANCEL already
    /// gave it its 487.
    fn refuse(self, code: u16, reason: &str, state: &DispatcherState) {
        let response =
            build_srs_response(&self.message, code, reason, Some(&self.to_tag), &[], state);
        if self
            .srs_manager
            .claim_final_response(&self.call_id, response.clone())
        {
            send_response(&self.inbound, &self.message, response, state);
            control_notify_terminated_with_cause(
                &self.call_id,
                "rejected",
                Some(code),
                Some(reason),
            );
        }
        self.srs_manager.stop_session(&self.call_id);
    }
}

/// Put `sdp` in `response` as its body.
pub(super) fn set_sdp_body(response: &mut SipMessage, sdp: Vec<u8>) {
    response
        .headers
        .set("Content-Type", "application/sdp".to_string());
    response
        .headers
        .set("Content-Length", sdp.len().to_string());
    response.body = sdp;
}

/// The initial INVITE again, while its session is held: its final response
/// again when it has one (the 2xx is also being retransmitted on its own
/// schedule), otherwise another 100 (RFC 3261 §17.2.1).
pub(super) fn answer_retransmission(
    inbound: &InboundMessage,
    message: &SipMessage,
    srs_manager: &SrsManager,
    state: &DispatcherState,
) {
    let call_id = message.headers.call_id().cloned().unwrap_or_default();
    match srs_manager.final_response(&call_id) {
        Some(response) => send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        ),
        None => respond(inbound, message, 100, "Trying", None, &[], state),
    }
}
