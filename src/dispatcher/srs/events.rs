//! What a recording session reports on the control rail while it records
//! and once it ends (#889's events).
//!
//! - `RecordingFinished` for each file once the engine has closed it, with the
//!   SIPREC context a stored file needs: which streams and which participants
//!   it holds.
//! - `RecordingMetadataUpdated` when a re-INVITE or UPDATE changes the
//!   metadata, carrying the merged snapshot.
//! - `RecordingSessionEnded` once every file of an ended session is closed,
//!   then `StasisEnd`. The record is stored (or posted) only after that, so a
//!   backend never lists a directory whose files are still being written.

use super::in_dialog::Ended;
use super::*;
use crate::siprec::metadata::{DataMode, RecordingMetadata};
use crate::srs::{SrsManager, TrackedRecording};

/// How long an ended session waits for the engine to close its files before
/// it is reported and stored anyway. A file the engine writes at teardown is
/// closed well within it; one it never reports is missing from `recordings`.
const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The engine closed a recording. `true` when it was one of the SRS's: the
/// session's channel gets `RecordingFinished` with its SIPREC context.
pub(in crate::dispatcher) fn srs_recording_finished(
    state: &DispatcherState,
    recording: &crate::rtpengine::events::RecordingFinished,
) -> bool {
    let Some(srs_manager) = state.srs_manager.as_ref() else {
        return false;
    };
    // The channel hears of the file before the session can count it closed,
    // so its RecordingFinished always precedes RecordingSessionEnded.
    srs_manager
        .close_recording(&recording.recording_id, |tracked, metadata| {
            let report = recording_report(tracked, metadata, recording);
            crate::control::notify_channel_event(
                &tracked.recording_call_id,
                "RecordingFinished",
                report.clone(),
            );
            report
        })
        .is_some()
}

/// A closed recording as the control rail reports it: the file, and the
/// streams and participants it holds, from the metadata (RFC 7865 §8.4).
fn recording_report(
    tracked: &TrackedRecording,
    metadata: &RecordingMetadata,
    recording: &crate::rtpengine::events::RecordingFinished,
) -> serde_json::Value {
    let stream_ids: Vec<&str> = metadata
        .streams
        .iter()
        .filter(|stream| Some(stream.label.as_str()) == tracked.label.as_deref())
        .map(|stream| stream.stream_id.as_str())
        .collect();
    let participant_ids: Vec<&str> = metadata
        .participant_streams
        .iter()
        .filter(|association| {
            association
                .send
                .iter()
                .any(|stream_id| stream_ids.contains(&stream_id.as_str()))
        })
        .map(|association| association.participant_id.as_str())
        .collect();
    let format = match tracked.format {
        crate::rtpengine::events::RecordingFormat::Wav => "wav",
        crate::rtpengine::events::RecordingFormat::OggOpus => "ogg_opus",
    };
    serde_json::json!({
        "recording_id": recording.recording_id,
        "path": recording.path.clone().or_else(|| tracked.path.clone()),
        "format": format,
        "stream_ids": stream_ids,
        "label": tracked.label,
        "participant_ids": participant_ids,
        "duration_ms": recording.duration_ms,
        "reason": recording.reason,
    })
}

/// A re-INVITE or UPDATE changed the metadata: the merged snapshot, and the
/// mode the update came in.
pub(super) fn metadata_updated(call_id: &str, datamode: DataMode, merged: &RecordingMetadata) {
    crate::control::notify_channel_event(
        call_id,
        "RecordingMetadataUpdated",
        serde_json::json!({
            "session_id": merged.session_id,
            "datamode": datamode.as_str(),
            "metadata": control::recording_session(merged, |_| None),
        }),
    );
}

/// Close an ended session: end its engine calls, wait (at most
/// [`CLOSE_WAIT`]) for every file to be reported closed, report
/// `RecordingSessionEnded` and `StasisEnd`, then store the record.
pub(super) async fn close_session(
    call_id: &str,
    reason: &str,
    ended: Ended,
    backend: Option<Arc<crate::rtpengine::MediaBackend>>,
    srs_manager: Arc<SrsManager>,
) {
    let done = srs_manager.begin_closing(
        call_id,
        reason,
        ended.record.clone(),
        ended.metadata.clone(),
    );
    if let Some(backend) = backend {
        for stream in &ended.streams {
            if let Some(engine_call_id) = &stream.engine_call_id {
                if let Err(error) = backend.delete(engine_call_id, &ended.from_tag).await {
                    debug!(%engine_call_id, %error, "SRS: engine call already gone");
                }
            }
        }
    }
    if tokio::time::timeout(CLOSE_WAIT, done.notified())
        .await
        .is_err()
    {
        warn!(call_id = %call_id, "SRS: not every recording was reported closed; ending the session without them");
    }
    let Some(closing) = srs_manager.finish_closing(call_id) else {
        return;
    };
    crate::control::notify_channel_event(
        call_id,
        "RecordingSessionEnded",
        serde_json::json!({
            "session_id": closing.metadata.session_id,
            "sip_session_ids": closing.metadata.sip_session_ids,
            "reason": closing.reason,
            "metadata": control::recording_session(&closing.metadata, |_| None),
            "recordings": closing.finished,
        }),
    );
    control_notify_terminated(call_id, reason);
    crate::srs::storage::store_recording(srs_manager.config(), &closing.record).await;
}
