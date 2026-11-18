//! A recording session offered to a control application (`srs.app`).
//!
//! Before siphon answers a SIPREC INVITE or anchors any media, the session is
//! handed to the application as a channel: a `StasisStart` with `kind:
//! "siprec"` carrying the request as received, the SRC's own address and the
//! parsed recording metadata. The application answers `accept`, with how to
//! record, or `reject`, with the final response; no answer within the handoff
//! deadline is a rejection. That is what lets a multi-tenant controller file a
//! recording under the tenant its Request-URI names, and refuse one from a
//! source that tenant does not allow, with no script.

use super::*;
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::siprec::metadata::RecordingMetadata;
use crate::siprec::srs_sdp::OfferedStream;
use crate::srs::{RecordingOptions, SrsDecision, SrsManager};

/// The call-actor id an SRS channel carries in its frames: the recording
/// dialog's Call-ID behind a prefix no B2BUA call id has, so a verb on the
/// channel is told apart from a call's.
pub(crate) const SRS_ACTOR_PREFIX: &str = "srs:";

/// The status a session gets when its application never decided.
const NO_DECISION: (u16, &str) = (503, "No Controller Response");

/// The `StasisStart` payload of a recording session.
fn stasis_payload(
    inbound: &InboundMessage,
    message: &SipMessage,
    metadata: &RecordingMetadata,
    offer: &[OfferedStream],
) -> serde_json::Value {
    let ruri = match &message.start_line {
        crate::sip::message::StartLine::Request(line) => line.request_uri.to_string(),
        crate::sip::message::StartLine::Response(_) => String::new(),
    };
    // As received: original names, every value, in order.
    let headers: Vec<[String; 2]> = message
        .headers
        .iter_original()
        .flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| [name.to_string(), value.to_string()])
        })
        .collect();
    let media_of = |label: &str| {
        offer
            .iter()
            .find(|stream| stream.label.as_deref() == Some(label))
            .map(|stream| stream.media.clone())
    };
    serde_json::json!({
        "kind": "siprec",
        "invite": { "method": "INVITE", "ruri": ruri, "headers": headers },
        // The SRC's own address: on a listener behind a PROXY-protocol front
        // it is the one the PROXY header named, as it is for a call.
        "source_ip": inbound.remote_addr.ip().to_string(),
        "source_port": inbound.remote_addr.port(),
        "transport": inbound.transport.to_string().to_lowercase(),
        "recording_session": recording_session(metadata, media_of),
    })
}

/// The metadata as the control rail carries it: the same shape in the offer
/// and in every later event that reports it.
pub(super) fn recording_session(
    metadata: &RecordingMetadata,
    media_of: impl Fn(&str) -> Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "session_id": metadata.session_id,
        "sip_session_ids": metadata.sip_session_ids,
        "datamode": metadata.datamode.as_str(),
        "participants": metadata.participants.iter().map(|participant| serde_json::json!({
            "participant_id": participant.participant_id,
            "aor": participant.aor,
            "name": participant.name,
        })).collect::<Vec<_>>(),
        "streams": metadata.streams.iter().map(|stream| serde_json::json!({
            "stream_id": stream.stream_id,
            "label": stream.label,
            "media": media_of(&stream.label),
        })).collect::<Vec<_>>(),
        "participant_stream": metadata.participant_streams.iter().map(|association| serde_json::json!({
            "participant_id": association.participant_id,
            "send": association.send,
            "recv": association.recv,
        })).collect::<Vec<_>>(),
    })
}

/// What a recording session offered to `app` came to.
pub(super) struct Offered<'a> {
    pub(super) app: &'a str,
    pub(super) inbound: &'a InboundMessage,
    pub(super) message: &'a SipMessage,
    pub(super) call_id: &'a str,
    pub(super) metadata: &'a RecordingMetadata,
    pub(super) offer: &'a [OfferedStream],
}

/// Offer the session to its application and wait for the decision, at most
/// the handoff deadline. No application connected, or no decision in time, is
/// a rejection: a recording nobody claimed is never answered 200.
pub(super) async fn offer_to_application(
    offered: Offered<'_>,
    srs_manager: &SrsManager,
) -> SrsDecision {
    let reject = |(code, reason): (u16, &str)| SrsDecision::Reject {
        code,
        reason: reason.to_string(),
    };
    let Some(bus) = srs_manager.control_bus() else {
        warn!(call_id = %offered.call_id, "SRS: srs.app is set but the control plane is not running");
        return reject((503, "No Controller Available"));
    };
    let on_lost = bus.app_on_lost(offered.app);
    let decision = srs_manager.await_decision(offered.call_id);
    let channel_id = format!("srs-{}", uuid::Uuid::new_v4().simple());
    let outcome = bus.offer_channel(
        offered.app,
        &channel_id,
        &format!("{SRS_ACTOR_PREFIX}{}", offered.call_id),
        offered.call_id,
        &on_lost,
        std::collections::HashMap::new(),
        stasis_payload(
            offered.inbound,
            offered.message,
            offered.metadata,
            offered.offer,
        ),
    );
    if matches!(outcome, crate::control::OfferOutcome::NoController) {
        srs_manager.withdraw_decision(offered.call_id);
        info!(call_id = %offered.call_id, app = %offered.app, "SRS: no controller for the recording session");
        return reject((503, "No Controller Available"));
    }
    let deadline = std::time::Duration::from_millis(bus.handoff_deadline_ms());
    match tokio::time::timeout(deadline, decision).await {
        Ok(Ok(decision)) => decision,
        Ok(Err(_)) | Err(_) => {
            srs_manager.withdraw_decision(offered.call_id);
            warn!(call_id = %offered.call_id, app = %offered.app, "SRS: no decision within the handoff deadline");
            reject(NO_DECISION)
        }
    }
}

/// A verb on a recording channel, by the recording dialog's Call-ID. Through
/// the dispatcher published at start-up.
pub(crate) fn srs_control_verb(
    sip_call_id: &str,
    verb: &str,
    args: &serde_json::Value,
) -> ControlResult {
    let Some(control) = B2BUA_CONTROL.get() else {
        return ControlResult::error(ControlErrorCode::NotFound, "dispatcher not running");
    };
    let _enter = control.runtime.enter();
    srs_control_verb_in(&control.state, sip_call_id, verb, args)
}

/// [`srs_control_verb`] against an explicit dispatcher state.
pub(crate) fn srs_control_verb_in(
    state: &Arc<DispatcherState>,
    sip_call_id: &str,
    verb: &str,
    args: &serde_json::Value,
) -> ControlResult {
    let Some(srs_manager) = state.srs_manager.as_ref() else {
        return ControlResult::error(ControlErrorCode::NotFound, "the SRS is not enabled");
    };
    match verb {
        "accept" => match accept_options(args, state) {
            Ok(options) => decide(
                srs_manager,
                sip_call_id,
                SrsDecision::Accept(options),
                "accepted",
            ),
            Err(refusal) => refusal,
        },
        "reject" => {
            let code = args
                .get("code")
                .and_then(|code| code.as_u64())
                .unwrap_or(603);
            let Some(code) = u16::try_from(code)
                .ok()
                .filter(|code| (300..700).contains(code))
            else {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "reject requires a 3xx-6xx code",
                );
            };
            let reason = args
                .get("reason")
                .and_then(|reason| reason.as_str())
                .unwrap_or("Decline")
                .to_string();
            decide(
                srs_manager,
                sip_call_id,
                SrsDecision::Reject { code, reason },
                "rejected",
            )
        }
        "hangup" => {
            if srs_manager.is_awaiting_decision(sip_call_id) {
                return ControlResult::error(
                    ControlErrorCode::InvalidState,
                    "the recording session is not answered yet: accept or reject it",
                );
            }
            if srs_terminate_session_in(state, sip_call_id, "hangup") {
                ControlResult::Ok(serde_json::json!({ "state": "terminated" }))
            } else {
                ControlResult::error(ControlErrorCode::NotFound, "no such recording session")
            }
        }
        other => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!(
                "verb '{other}' does not apply to a recording session (accept, reject, hangup)"
            ),
        ),
    }
}

fn decide(
    srs_manager: &SrsManager,
    sip_call_id: &str,
    decision: SrsDecision,
    outcome: &str,
) -> ControlResult {
    match srs_manager.decide(sip_call_id, decision) {
        Ok(()) => ControlResult::Ok(serde_json::json!({ "state": outcome })),
        Err(_) => ControlResult::error(
            ControlErrorCode::InvalidState,
            "the recording session is not waiting for a decision",
        ),
    }
}

/// `accept`'s arguments, checked as `record_start` checks the same ones.
fn accept_options(
    args: &serde_json::Value,
    state: &DispatcherState,
) -> Result<RecordingOptions, ControlResult> {
    let bad = |message: String| ControlResult::error(ControlErrorCode::BadRequest, message);
    let mut options = RecordingOptions::default();
    if let Some(profile) = args.get("profile").and_then(|value| value.as_str()) {
        let known = state
            .rtpengine_profiles
            .as_ref()
            .is_some_and(|registry| registry.get(profile).is_some());
        if !known {
            return Err(bad(format!("unknown media profile {profile:?}")));
        }
        options.profile = Some(profile.to_string());
    }
    if let Some(format) = args.get("format").and_then(|value| value.as_str()) {
        options.format = crate::rtpengine::events::RecordingFormat::parse(format)
            .map_err(|error| bad(error.to_string()))?;
    }
    if let Some(bitrate) = args.get("bitrate_bps") {
        let bitrate = bitrate
            .as_u64()
            .and_then(|bitrate| u32::try_from(bitrate).ok())
            .ok_or_else(|| {
                bad("bitrate_bps must be a whole number of bits per second".to_string())
            })?;
        options.bitrate_bps = Some(bitrate);
    }
    crate::rtpengine::events::check_recording_bitrate(options.format, options.bitrate_bps)
        .map_err(bad)?;
    match args.get("channels").and_then(|value| value.as_str()) {
        None | Some("mono") => {}
        Some("stereo") => {
            return Err(ControlResult::error(
                ControlErrorCode::UnsupportedVerb,
                "channels: stereo is not available on a recording session yet: each stream \
                 is recorded to a file of its own",
            ))
        }
        Some(other) => {
            return Err(bad(format!(
                "channels must be mono or stereo, not {other:?}"
            )))
        }
    }
    if let Some(path) = args.get("path").and_then(|value| value.as_str()) {
        let directory = std::path::PathBuf::from(path);
        if !directory.is_absolute() {
            return Err(bad("path must be an absolute directory".to_string()));
        }
        options.directory = Some(directory);
    }
    Ok(options)
}

/// End a recording session from siphon's side (the application's `hangup`,
/// its owner lost): BYE the SRC and end the recording. `false` when the
/// Call-ID is no recording session's.
pub(crate) fn srs_terminate_session(sip_call_id: &str, reason: &str) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let _enter = control.runtime.enter();
    srs_terminate_session_in(&control.state, sip_call_id, reason)
}

/// [`srs_terminate_session`] against an explicit dispatcher state.
pub(crate) fn srs_terminate_session_in(
    state: &Arc<DispatcherState>,
    sip_call_id: &str,
    reason: &str,
) -> bool {
    let Some(srs_manager) = state.srs_manager.as_ref() else {
        return false;
    };
    if !srs_manager.is_srs_session(sip_call_id) {
        return false;
    }
    in_dialog::end_from_siphon(sip_call_id, reason, state);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_carries_the_request_the_source_and_the_metadata() {
        let raw = concat!(
            "INVITE sip:rec@tenant-a.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS 198.51.100.20:5061;branch=z9hG4bK-p\r\n",
            "From: <sip:src@example.com>;tag=src-1\r\n",
            "To: <sip:rec@tenant-a.example.com>\r\n",
            "Call-ID: payload@198.51.100.20\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let message = crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).unwrap();
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: crate::transport::Transport::Tls,
            local_addr: "192.0.2.1:5061".parse().unwrap(),
            remote_addr: "198.51.100.20:40123".parse().unwrap(),
            data: bytes::Bytes::from(raw),
        };
        let metadata = crate::siprec::metadata::parse_recording_metadata(concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">",
            "<datamode>complete</datamode>",
            "<session session_id=\"rs-1\"><sipSessionID>orig@example.com</sipSessionID></session>",
            "<participant participant_id=\"p-a\"><nameID aor=\"sip:alice@example.com\"/><name>Alice</name></participant>",
            "<stream stream_id=\"s-0\" session_id=\"rs-1\"><label>1</label></stream>",
            "<participantstreamassoc participant_id=\"p-a\"><send>s-0</send></participantstreamassoc>",
            "</recording>",
        ))
        .unwrap();
        let offer = crate::siprec::srs_sdp::split_offer(
            b"v=0\r\nc=IN IP4 198.51.100.20\r\nm=audio 4000 RTP/AVP 0\r\na=label:1\r\na=sendonly\r\n",
        )
        .unwrap();

        let payload = stasis_payload(&inbound, &message, &metadata, &offer);

        assert_eq!(payload["kind"], "siprec");
        assert_eq!(payload["invite"]["ruri"], "sip:rec@tenant-a.example.com");
        assert!(payload["invite"]["headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|header| header[0] == "To" && header[1] == "<sip:rec@tenant-a.example.com>"));
        assert_eq!(payload["source_ip"], "198.51.100.20");
        assert_eq!(payload["source_port"], 40123);
        assert_eq!(payload["transport"], "tls");
        let session = &payload["recording_session"];
        assert_eq!(session["session_id"], "rs-1");
        assert_eq!(session["sip_session_ids"][0], "orig@example.com");
        assert_eq!(session["datamode"], "complete");
        assert_eq!(session["participants"][0]["aor"], "sip:alice@example.com");
        assert_eq!(session["participants"][0]["name"], "Alice");
        assert_eq!(session["streams"][0]["label"], "1");
        assert_eq!(session["streams"][0]["media"], "audio");
        assert_eq!(session["participant_stream"][0]["send"][0], "s-0");
    }

    fn state_with_profiles() -> DispatcherState {
        let mut dispatcher = super::super::test_dispatcher::test_dispatcher();
        dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        dispatcher.state
    }

    #[test]
    fn accept_options_are_checked_like_record_start() {
        let state = state_with_profiles();
        let options = accept_options(
            &serde_json::json!({
                "profile": "srs_recording", "format": "ogg_opus",
                "bitrate_bps": 24000, "channels": "mono", "path": "/srv/tenant-a"
            }),
            &state,
        )
        .expect("valid");
        assert_eq!(options.profile.as_deref(), Some("srs_recording"));
        assert_eq!(
            options.format,
            crate::rtpengine::events::RecordingFormat::OggOpus
        );
        assert_eq!(options.bitrate_bps, Some(24000));
        assert_eq!(
            options.directory,
            Some(std::path::PathBuf::from("/srv/tenant-a"))
        );

        for refused in [
            serde_json::json!({ "profile": "nope" }),
            serde_json::json!({ "format": "mp3" }),
            serde_json::json!({ "format": "wav", "bitrate_bps": 24000 }),
            serde_json::json!({ "format": "ogg_opus", "bitrate_bps": 5 }),
            serde_json::json!({ "channels": "quad" }),
            serde_json::json!({ "path": "relative/dir" }),
        ] {
            assert!(
                matches!(
                    accept_options(&refused, &state),
                    Err(ControlResult::Error {
                        code: ControlErrorCode::BadRequest,
                        ..
                    })
                ),
                "{refused}"
            );
        }
        assert!(matches!(
            accept_options(&serde_json::json!({ "channels": "stereo" }), &state),
            Err(ControlResult::Error {
                code: ControlErrorCode::UnsupportedVerb,
                ..
            })
        ));
    }
}
