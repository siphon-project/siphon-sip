//! Terminating a recording session's streams on the media engine.
//!
//! Each offered m-line is answered on a single-leg engine call of its own
//! (`answer_local`), receive-only, and recorded there with `start_recording`.
//! The engine sends nothing toward a `sendonly` SRC (RFC 7866 §8.1.8: an SRS
//! does not normally send RTP), and a stream the SRC adds, removes, pauses or
//! resumes later is handled stream by stream.

use std::path::Path;

use super::*;
use crate::rtpengine::events::{
    RecordingChannels, RecordingDirection, RecordingFormat, RecordingRequest,
};
use crate::siprec::srs_sdp::{OfferedStream, StreamAnswer};
use crate::srs::SrsStream;

/// The streams an offer was answered with, and the answer.
pub(super) struct Anchored {
    pub(super) streams: Vec<SrsStream>,
    pub(super) answer: Vec<u8>,
}

/// Why an offer could not be answered. Each is a non-2xx: a recording server
/// never answers 200 for media it is not receiving.
#[derive(Debug)]
pub(super) enum AnchorError {
    /// No media engine to terminate the streams on.
    NoBackend,
    /// `srs.rtpengine_profile` names no configured media profile.
    UnknownProfile(String),
    /// The engine took none of the offered streams.
    NothingAnswered(String),
}

impl AnchorError {
    /// The final response this failure is answered with.
    pub(super) fn status(&self) -> (u16, &'static str) {
        match self {
            Self::NoBackend => (503, "Recording Unavailable"),
            Self::UnknownProfile(_) => (500, "Recording Profile Not Configured"),
            Self::NothingAnswered(_) => (488, "Not Acceptable Here"),
        }
    }
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBackend => write!(formatter, "no siphon-rtp media backend"),
            Self::UnknownProfile(name) => write!(formatter, "unknown media profile {name:?}"),
            Self::NothingAnswered(reason) => {
                write!(formatter, "the engine answered no stream: {reason}")
            }
        }
    }
}

/// A recording dialog's identifiers on the engine.
pub(super) struct StreamOwner<'a> {
    pub(super) recording_call_id: &'a str,
    pub(super) from_tag: &'a str,
    pub(super) source_ip: std::net::IpAddr,
    pub(super) recording_dir: &'a Path,
}

/// An offered m-section with its direction attribute left out: two offers of a
/// stream that differ only by pausing or resuming it are the same stream.
fn section_identity(stream: &OfferedStream) -> String {
    let section = match stream.sdp.find("m=") {
        Some(start) => &stream.sdp[start..],
        None => stream.sdp.as_str(),
    };
    section
        .lines()
        .filter(|line| {
            !matches!(
                *line,
                "a=sendonly" | "a=recvonly" | "a=sendrecv" | "a=inactive"
            )
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Answer `offered` on the engine, stream by stream, against the streams the
/// session already has (`existing`, empty for the initial INVITE).
///
/// - A stream that is the same as before, bar its direction, keeps its engine
///   call, its recording and its answer.
/// - A new or changed stream is answered on its engine call (an existing one is
///   replaced) and a recording is started on it.
/// - A port-0 stream is answered port 0, and an engine call it had is ended.
/// - A stream the engine refuses is answered port 0 (RFC 3264 §6).
///
/// Streams beyond the offer's count, which an SDP offer can never drop (RFC
/// 3264 §8), are left to the caller; there are none in a valid offer.
pub(super) async fn anchor_streams(
    state: &DispatcherState,
    owner: &StreamOwner<'_>,
    offered: &[OfferedStream],
    existing: &[SrsStream],
    profile_name: &str,
) -> Result<Anchored, AnchorError> {
    let backend = state
        .rtpengine_set
        .as_ref()
        .filter(|backend| backend.kind() == crate::config::MediaBackendKind::SiphonRtp)
        .ok_or(AnchorError::NoBackend)?;
    let profile = state
        .rtpengine_profiles
        .as_ref()
        .and_then(|registry| registry.get(profile_name))
        .ok_or_else(|| AnchorError::UnknownProfile(profile_name.to_string()))?;
    let mut flags = profile.answer.clone();
    // Recorded per stream with `start_recording`, so each file is closed and
    // reported on its own rather than written in one piece at teardown.
    flags.record_call = false;
    flags.record_path = None;
    flags.stamp_sip_call_id(owner.recording_call_id);
    flags.stamp_received_from(owner.source_ip);

    if let Err(error) = tokio::fs::create_dir_all(owner.recording_dir).await {
        warn!(
            recording_call_id = %owner.recording_call_id,
            directory = %owner.recording_dir.display(),
            %error,
            "SRS: recording directory could not be created"
        );
    }

    let mut streams = Vec::with_capacity(offered.len());
    let mut answers = Vec::with_capacity(offered.len());
    let mut last_refusal = String::from("no stream offered with a port");
    for stream in offered {
        let identity = section_identity(stream);
        let previous = existing.iter().find(|known| known.index == stream.index);

        if stream.disabled {
            if let Some(previous) = previous {
                release_stream(backend, previous, owner.from_tag).await;
            }
            streams.push(rejected(stream, identity));
            answers.push((stream.clone(), StreamAnswer::Rejected));
            continue;
        }

        if let Some(previous) = previous.filter(|previous| {
            previous.offered_section == identity && previous.engine_answer.is_some()
        }) {
            let answer = previous.engine_answer.clone().unwrap_or_default();
            streams.push(previous.clone());
            answers.push((stream.clone(), StreamAnswer::Engine(answer)));
            continue;
        }

        match answer_stream(backend, owner, stream, &flags).await {
            Ok((engine_call_id, engine_answer, recording_id)) => {
                streams.push(SrsStream {
                    index: stream.index,
                    label: stream.label.clone(),
                    engine_call_id: Some(engine_call_id),
                    recording_id: Some(recording_id),
                    offered_section: identity,
                    engine_answer: Some(engine_answer.clone()),
                });
                answers.push((stream.clone(), StreamAnswer::Engine(engine_answer)));
            }
            Err(reason) => {
                warn!(
                    recording_call_id = %owner.recording_call_id,
                    stream = stream.index,
                    %reason,
                    "SRS: stream refused, answered port 0"
                );
                last_refusal = reason;
                streams.push(rejected(stream, identity));
                answers.push((stream.clone(), StreamAnswer::Rejected));
            }
        }
    }

    match crate::siprec::srs_sdp::build_answer(&answers) {
        Some(answer) => Ok(Anchored { streams, answer }),
        None => {
            // Nothing was taken: whatever this offer started is ended again.
            release_streams(state, &streams, owner.from_tag).await;
            Err(AnchorError::NothingAnswered(last_refusal))
        }
    }
}

fn rejected(stream: &OfferedStream, identity: String) -> SrsStream {
    SrsStream {
        index: stream.index,
        label: stream.label.clone(),
        engine_call_id: None,
        recording_id: None,
        offered_section: identity,
        engine_answer: None,
    }
}

/// Answer one stream on its engine call and start recording it. On a refused
/// recording the engine call is ended again: a stream the SRS cannot record is
/// not answered.
async fn answer_stream(
    backend: &crate::rtpengine::MediaBackend,
    owner: &StreamOwner<'_>,
    stream: &OfferedStream,
    flags: &crate::rtpengine::NgFlags,
) -> Result<(String, String, String), String> {
    let engine_call_id = SrsStream::engine_call_id_for(owner.recording_call_id, stream.index);
    let engine_answer = backend
        .answer_local(&engine_call_id, owner.from_tag, &stream.sdp, flags)
        .await
        .map_err(|error| error.to_string())?;
    let file = owner.recording_dir.join(format!(
        "stream-{}-{}.wav",
        stream.index,
        &uuid::Uuid::new_v4().simple().to_string()[..8],
    ));
    let path = file.display().to_string();
    let request = RecordingRequest {
        format: RecordingFormat::Wav,
        bitrate_bps: None,
        direction: RecordingDirection::Ingress,
        channels: RecordingChannels::Mono,
        max_duration_ms: None,
        silence_ms: None,
        path: Some(&path),
    };
    match backend
        .start_recording(&engine_call_id, owner.from_tag, &request)
        .await
    {
        Ok(recording_id) => Ok((engine_call_id, engine_answer, recording_id)),
        Err(error) => {
            let _ = backend.delete(&engine_call_id, owner.from_tag).await;
            Err(format!("recording refused: {error}"))
        }
    }
}

async fn release_stream(
    backend: &crate::rtpengine::MediaBackend,
    stream: &SrsStream,
    from_tag: &str,
) {
    if let Some(engine_call_id) = &stream.engine_call_id {
        if let Err(error) = backend.delete(engine_call_id, from_tag).await {
            debug!(%engine_call_id, %error, "SRS: engine call already gone");
        }
    }
}

/// End every engine call of `streams`, which closes their recordings.
pub(super) async fn release_streams(
    state: &DispatcherState,
    streams: &[SrsStream],
    from_tag: &str,
) {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    for stream in streams {
        release_stream(backend, stream, from_tag).await;
    }
}
