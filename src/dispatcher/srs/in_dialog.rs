//! Requests inside a recording dialog, and its ends: re-INVITE and UPDATE
//! (new SDP, new metadata or both, RFC 7866 §5.2), BYE, a CANCEL of the
//! initial INVITE, and a 2xx the SRC never ACKed.

use super::invite::{parse_srs_body, set_sdp_body};
use super::*;
use crate::srs::{CancelOutcome, SrsManager};

/// What a re-INVITE or UPDATE changed, and the answer to it.
enum Renegotiated {
    /// A new offer was answered with this SDP.
    Answered(Vec<u8>),
    /// No offer: the body is what siphon answers with (a re-INVITE without
    /// one is answered with siphon's current session as its offer, RFC 3261
    /// §14.2), or nothing for an UPDATE.
    NoOffer,
}

/// Fold an in-dialog request's metadata into the session and answer its offer.
async fn renegotiate(
    message: &SipMessage,
    srs_manager: &SrsManager,
    inbound: &InboundMessage,
    state: &DispatcherState,
) -> Result<Renegotiated, (u16, &'static str)> {
    let call_id = message.headers.call_id().cloned().unwrap_or_default();
    let body = parse_srs_body(message).map_err(|refusal| {
        warn!(call_id = %call_id, detail = %refusal.detail, "SRS: in-dialog request refused for its body");
        (refusal.code, refusal.reason)
    })?;
    if let Some(metadata) = body.metadata {
        let datamode = metadata.datamode;
        if let Some(merged) = srs_manager.update_session(&call_id, metadata) {
            events::metadata_updated(&call_id, datamode, &merged);
        }
    }
    let Some(offer) = body.offer else {
        return Ok(Renegotiated::NoOffer);
    };
    let existing = srs_manager.streams(&call_id).unwrap_or_default();
    // RFC 3264 §8: an offer keeps every m-line of the session, in place.
    if offer.len() < existing.len() {
        return Err((488, "Not Acceptable Here"));
    }
    let from_tag = tag_of(message.headers.from()).unwrap_or_default();
    let recording_dir = srs_manager.recording_dir(&call_id).unwrap_or_default();
    let recording = srs_manager.recording(&call_id);
    let owner = media::StreamOwner {
        recording_call_id: &call_id,
        from_tag: &from_tag,
        source_ip: inbound.remote_addr.ip(),
        recording_dir: &recording_dir,
        recording: &recording,
        left_label: srs_manager
            .metadata(&call_id)
            .and_then(|metadata| media::left_label(&metadata)),
    };
    match media::anchor_streams(
        state,
        &owner,
        &offer,
        &existing,
        srs_manager.rtpengine_profile(),
    )
    .await
    {
        Ok(anchored) => {
            srs_manager.set_streams(&call_id, anchored.streams, anchored.answer.clone());
            Ok(Renegotiated::Answered(anchored.answer))
        }
        Err(error) => {
            // RFC 3261 §14.1: refused, the session stays as it was.
            warn!(call_id = %call_id, %error, "SRS: in-dialog offer refused");
            Err(error.status())
        }
    }
}

/// A re-INVITE in a recording dialog: a stream added, removed, paused or
/// resumed, metadata updated, or a session refresh.
pub(super) fn handle_reinvite(
    inbound: InboundMessage,
    message: SipMessage,
    srs_manager: Arc<SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let call_id = message.headers.call_id().cloned().unwrap_or_default();
        let sdp = match renegotiate(&message, &srs_manager, &inbound, &state).await {
            Ok(Renegotiated::Answered(sdp)) => sdp,
            Ok(Renegotiated::NoOffer) => srs_manager
                .get_session(&call_id)
                .and_then(|session| session.answer_sdp.clone())
                .unwrap_or_default(),
            Err((code, reason)) => {
                respond(&inbound, &message, code, reason, None, &[], &state);
                return;
            }
        };
        let contact = srs_manager
            .peer(&call_id)
            .map(|peer| peer.local_contact)
            .unwrap_or_else(|| srs_contact(&inbound, &state));
        let mut response = build_srs_response(
            &message,
            200,
            "OK",
            None,
            &[("Contact", contact), ("Allow", ALLOW.to_string())],
            &state,
        );
        if !sdp.is_empty() {
            let mut body = sdp;
            let local_ip = state.local_addr.ip().to_string();
            sanitize_sdp_identity(&mut body, &state.sdp_name, Some(&local_ip));
            set_sdp_body(&mut response, body);
        }
        // A re-INVITE's 2xx is retransmitted until its ACK like the first one.
        let unacked = register_unacked_answer(&call_id, &response, &state);
        send_message_from(
            response.clone(),
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            &state,
        );
        start_2xx_retransmits(
            unacked,
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            &state,
        );
    });
}

/// An UPDATE in a recording dialog (RFC 3311): new metadata (RFC 7866 §5.2),
/// a new offer, or both.
pub(super) fn handle_update(
    inbound: InboundMessage,
    message: SipMessage,
    srs_manager: Arc<SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        match renegotiate(&message, &srs_manager, &inbound, &state).await {
            Ok(Renegotiated::Answered(sdp)) => {
                let mut response = build_srs_response(&message, 200, "OK", None, &[], &state);
                let mut body = sdp;
                let local_ip = state.local_addr.ip().to_string();
                sanitize_sdp_identity(&mut body, &state.sdp_name, Some(&local_ip));
                set_sdp_body(&mut response, body);
                send_response(&inbound, &message, response, &state);
            }
            Ok(Renegotiated::NoOffer) => {
                respond(&inbound, &message, 200, "OK", None, &[], &state);
            }
            Err((code, reason)) => respond(&inbound, &message, code, reason, None, &[], &state),
        }
    });
}

/// A session taken out of the store, its engine calls still to end.
pub(super) struct Ended {
    pub(super) record: crate::srs::RecordingRecord,
    pub(super) streams: Vec<crate::srs::SrsStream>,
    pub(super) from_tag: String,
    /// Notified once every recording of the session is closed.
    pub(super) done: Arc<tokio::sync::Notify>,
}

/// End a session for `reason` and hold it until its recordings close
/// ([`SrsManager::stop_into_closing`]), and stop the 2xx still waiting for an
/// ACK.
fn take_session(
    call_id: &str,
    reason: &str,
    srs_manager: &SrsManager,
    state: &DispatcherState,
) -> Option<Ended> {
    // Read before the session is removed; the guard ends with the statement.
    let from_tag = srs_manager
        .get_session(call_id)
        .map(|session| session.from_tag.clone())?;
    let (record, streams, done) = srs_manager.stop_into_closing(call_id, reason)?;
    if let Some((_, unacked)) = state.uas_2xx_retransmits.remove(call_id) {
        unacked.cancel.notify_one();
    }
    Some(Ended {
        record,
        streams,
        from_tag,
        done,
    })
}

/// A BYE from the SRC: the recording session is over.
pub(super) fn handle_bye(
    inbound: InboundMessage,
    message: SipMessage,
    call_id: String,
    srs_manager: Arc<SrsManager>,
    state: &Arc<DispatcherState>,
) {
    info!(call_id = %call_id, "SRS: received BYE from SRC");
    respond(&inbound, &message, 200, "OK", None, &[], state);
    let Some(ended) = take_session(&call_id, "bye", &srs_manager, state) else {
        return;
    };
    let state = Arc::clone(state);
    tokio::spawn(async move {
        script::session_ended(&state, &ended.record, &call_id).await;
        events::close_session(
            &call_id,
            "bye",
            ended,
            state.rtpengine_set.clone(),
            srs_manager,
        )
        .await;
    });
}

/// A CANCEL on a recording dialog's Call-ID. `false` when the Call-ID is no
/// recording dialog's, for the general CANCEL handling.
pub(in crate::dispatcher) fn handle_srs_cancel(
    inbound: &InboundMessage,
    message: &SipMessage,
    branch: &str,
    state: &DispatcherState,
) -> bool {
    let Some(srs_manager) = state.srs_manager.as_ref() else {
        return false;
    };
    let Some(call_id) = message.headers.call_id().cloned() else {
        return false;
    };
    if !srs_manager.is_srs_session(&call_id) {
        return false;
    }
    let from_tag = tag_of(message.headers.from()).unwrap_or_default();
    let Some(peer) = srs_manager.peer(&call_id) else {
        respond_481(inbound, message, state);
        return true;
    };
    let Some(terminated) = peer.terminated.clone() else {
        respond_481(inbound, message, state);
        return true;
    };
    match srs_manager.cancel_pending(&call_id, &from_tag, branch, terminated.clone()) {
        CancelOutcome::Cancelled => {
            info!(call_id = %call_id, "SRS: initial INVITE cancelled");
            // An application still deciding gets nothing more to decide.
            srs_manager.withdraw_decision(&call_id);
            control_notify_terminated_with_cause(
                &call_id,
                "cancelled",
                Some(487),
                Some("Request Terminated"),
            );
            respond(inbound, message, 200, "OK", None, &[], state);
            // The INVITE's 487, where the INVITE came from, and kept for its
            // retransmissions. The task answering it sees the CANCEL when it
            // claims the final response, and ends the session.
            let bytes = bytes::Bytes::from(terminated.to_bytes());
            state.completed_invites.remember(&call_id, branch, bytes);
            send_message_from(
                terminated,
                peer.transport,
                peer.remote_addr,
                peer.connection_id,
                peer.local_addr,
                state,
            );
        }
        // RFC 3261 §9.2: a CANCEL for an INVITE that already has its final
        // response changes nothing, and is still answered 200.
        CancelOutcome::TooLate => respond(inbound, message, 200, "OK", None, &[], state),
        CancelOutcome::NoMatch => respond_481(inbound, message, state),
    }
    true
}

/// The SRS dialog as a B2BUA leg, for the BYE builder every leg shares.
fn dialog_leg(call_id: &str, srs_manager: &SrsManager) -> Option<crate::b2bua::actor::Leg> {
    let session = srs_manager.get_session(call_id)?;
    let peer = session.peer.clone()?;
    let mut leg = crate::b2bua::actor::Leg::new_a_leg(
        call_id.to_string(),
        session.from_tag.clone(),
        TransactionKey::generate_branch(),
        crate::b2bua::actor::TransportInfo {
            remote_addr: peer.remote_addr,
            connection_id: peer.connection_id,
            transport: peer.transport,
            local_addr: peer.local_addr,
        },
    );
    leg.dialog.local_tag = session.to_tag.clone();
    leg.dialog.remote_contact = peer.remote_contact;
    leg.dialog.local_contact = Some(peer.local_contact);
    leg.dialog.route_set = peer.route_set;
    leg.dialog.local_from_uri = Some(peer.local_to);
    leg.dialog.remote_to_uri = Some(peer.remote_from);
    Some(leg)
}

/// RFC 3261 §13.3.1.4: the SRC never ACKed the 2xx within 64×T1. "The dialog
/// is confirmed, but the session SHOULD be terminated": siphon BYEs the SRC and
/// ends the recording. Called by the 64×T1 sweep, which has already taken the
/// 2xx out of the retransmission store.
/// BYE the SRC in the recording dialog (RFC 3261 §15), with the route set and
/// remote target the INVITE gave siphon.
fn send_bye_to_src(call_id: &str, srs_manager: &SrsManager, state: &DispatcherState) {
    let Some(leg) = dialog_leg(call_id, srs_manager) else {
        return;
    };
    let Some(bye) = crate::dispatcher::b2bua::build_b2bua_bye(&leg, state) else {
        return;
    };
    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    let connection_id =
        if destination == leg.transport.remote_addr && transport == leg.transport.transport {
            leg.transport.connection_id
        } else {
            ConnectionId::default()
        };
    send_message_from(
        bye,
        transport,
        destination,
        connection_id,
        leg.transport.local_addr,
        state,
    );
}

/// End a recording session from siphon's side: the application's `hangup`,
/// or its owner lost. The SRC is BYEd, the channel ends with `reason`, and the
/// recordings are closed and stored.
pub(super) fn end_from_siphon(call_id: &str, reason: &str, state: &Arc<DispatcherState>) {
    let Some(srs_manager) = state.srs_manager.clone() else {
        return;
    };
    info!(call_id = %call_id, reason, "SRS: ending the recording session");
    send_bye_to_src(call_id, &srs_manager, state);
    let Some(ended) = take_session(call_id, reason, &srs_manager, state) else {
        return;
    };
    let reason = reason.to_string();
    let call_id = call_id.to_string();
    let state = Arc::clone(state);
    tokio::spawn(async move {
        script::session_ended(&state, &ended.record, &call_id).await;
        events::close_session(
            &call_id,
            &reason,
            ended,
            state.rtpengine_set.clone(),
            srs_manager,
        )
        .await;
    });
}

/// RFC 3261 §13.3.1.4: the SRC never ACKed the 2xx within 64×T1. "The dialog
/// is confirmed, but the session SHOULD be terminated": siphon BYEs the SRC and
/// ends the recording. Called by the 64×T1 sweep, which has already taken the
/// 2xx out of the retransmission store.
pub(in crate::dispatcher) fn srs_unacked_answer_terminate(call_id: &str, state: &DispatcherState) {
    let Some(srs_manager) = state.srs_manager.clone() else {
        return;
    };
    warn!(call_id = %call_id, "RFC 3261 §13.3.1.4: the SRC never ACKed the 2xx within 64*T1, ending the recording");
    send_bye_to_src(call_id, &srs_manager, state);
    srs_manager.fail_session(call_id, "2xx never acknowledged");
    let Some(ended) = take_session(call_id, "unacknowledged", &srs_manager, state) else {
        return;
    };
    // The sweep runs on the script executor, where the hook can run in place.
    if !state
        .engine
        .state()
        .handlers_for(&HandlerKind::SrsOnSessionEnd)
        .is_empty()
    {
        script::run_srs_session_end_handlers(
            state,
            crate::script::api::srs::PySrsSession::from_record(&ended.record),
            call_id,
        );
    }
    let call_id = call_id.to_string();
    let backend = state.rtpengine_set.clone();
    tokio::spawn(async move {
        events::close_session(&call_id, "unacknowledged", ended, backend, srs_manager).await;
    });
}
