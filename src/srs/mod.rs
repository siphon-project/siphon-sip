//! SRS — Session Recording Server (RFC 7866).
//!
//! Receives SIPREC INVITEs from external SRCs, parses the recording
//! metadata XML, sets up RTPEngine recording sessions, and stores
//! recordings + metadata.

mod path;
pub mod storage;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use dashmap::DashMap;
use serde::Serialize;
use tracing::{error, info, warn};

use crate::config::SrsConfig;
use crate::sip::message::SipMessage;
use crate::siprec::metadata::RecordingMetadata;

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// State of an SRS recording session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrsSessionState {
    /// SIPREC INVITE received, RTPEngine being set up.
    Pending,
    /// RTPEngine recording active, media flowing.
    Recording,
    /// BYE received from SRC, tearing down.
    Stopping,
    /// Recording complete, metadata written.
    Completed,
    /// Recording failed.
    Failed(String),
}

impl fmt::Display for SrsSessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(formatter, "pending"),
            Self::Recording => write!(formatter, "recording"),
            Self::Stopping => write!(formatter, "stopping"),
            Self::Completed => write!(formatter, "completed"),
            Self::Failed(reason) => write!(formatter, "failed: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SRS session
// ---------------------------------------------------------------------------

/// One recorded stream: an m-line of the SRC's offer, terminated on its own
/// single-leg media engine call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsStream {
    /// Position of the m-line in the offer, from 0.
    pub index: usize,
    /// The m-line's `a=label`, which the metadata's `<stream>` refers to.
    pub label: Option<String>,
    /// The engine call terminating it; `None` for a stream answered port 0.
    pub engine_call_id: Option<String>,
    /// The recording the engine is writing for it.
    pub recording_id: Option<String>,
    /// The offered m-section it was last answered for, its direction left out,
    /// so a re-offer that only pauses or resumes it is recognised as the same
    /// stream.
    pub offered_section: String,
    /// The engine's answer for it, given again while the stream is unchanged
    /// (RFC 3264 §8).
    pub engine_answer: Option<String>,
}

impl SrsStream {
    /// The engine call-id for stream `index` of the recording dialog
    /// `recording_call_id`: one call per stream, so each is answered and
    /// recorded on its own.
    pub fn engine_call_id_for(recording_call_id: &str, index: usize) -> String {
        format!("{recording_call_id}~{index}")
    }
}

/// What siphon needs to send the SRC a request in the recording dialog (a BYE
/// for a 2xx it never ACKed): the dialog state RFC 3261 §12.1.1 has a UAS keep.
#[derive(Debug, Clone)]
pub struct SrsPeer {
    /// The SRC's From header, tag included: the To of a request siphon sends.
    pub remote_from: String,
    /// The To siphon answered with, its tag included: the From of a request
    /// siphon sends.
    pub local_to: String,
    /// The SRC's Contact URI: the remote target (RFC 3261 §12.1.1).
    pub remote_contact: Option<String>,
    /// The Contact siphon answered with.
    pub local_contact: String,
    /// The INVITE's Record-Route values, in order: the UAS route set.
    pub route_set: Vec<String>,
    /// Where the SRC's INVITE came from, and over what.
    pub remote_addr: std::net::SocketAddr,
    pub transport: crate::transport::Transport,
    pub connection_id: crate::transport::ConnectionId,
    pub local_addr: Option<std::net::SocketAddr>,
    /// The 487 the initial INVITE is answered with if a CANCEL ends it: built
    /// from the INVITE itself, whose Via stack the CANCEL does not carry when
    /// it came through a proxy (RFC 3261 §9.1).
    pub terminated: Option<SipMessage>,
}

/// What a CANCEL for a recording's initial INVITE found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The INVITE had no final response yet: it is cancelled, its 487 is the
    /// final response, and the session is to be torn down.
    Cancelled,
    /// The INVITE already has its final response: the CANCEL has no effect
    /// (RFC 3261 §9.2), but is answered 200.
    TooLate,
    /// No recording INVITE matches.
    NoMatch,
}

/// An active recording session managed by the SRS.
///
/// Keyed by siphon's own dialog with the SRC (RFC 3261 §12: the Call-ID, the
/// SRC's From-tag and siphon's To-tag), never by the metadata's `session_id`,
/// which the SRC chooses: two SRCs may send the same one, and it is carried as
/// data only.
#[derive(Debug)]
pub struct SrsSession {
    /// Recording session ID (from the SIPREC metadata). Data only.
    pub session_id: String,
    /// Siphon's own per-session key, and the name of the recording directory.
    /// Never the SRC's `session_id`: that is chosen by the peer, so a directory
    /// named from it could be shared by two sessions or escape the configured
    /// base (`../`).
    pub storage_key: String,
    /// SIP Call-ID of the SIPREC INVITE dialog (SRC → SRS).
    pub recording_call_id: String,
    /// Original call ID being recorded (from metadata, if available).
    pub original_call_id: Option<String>,
    /// From-tag of the SIPREC INVITE: the SRC's dialog tag.
    pub from_tag: String,
    /// To-tag generated by the SRS for the 200 OK: siphon's dialog tag.
    pub to_tag: String,
    /// Top Via branch of the initial INVITE: what a retransmission of it and a
    /// CANCEL for it carry (RFC 3261 §9.2, §17.2.3).
    pub invite_branch: String,
    /// The merged metadata snapshot (RFC 7865 §9.1: partial updates are folded
    /// into it).
    pub metadata: RecordingMetadata,
    /// Current session state.
    pub state: SrsSessionState,
    /// When the session was created.
    pub started_at: Instant,
    /// When the session ended (set on BYE).
    pub ended_at: Option<Instant>,
    /// Directory the recordings are written to.
    pub recording_dir: Option<PathBuf>,
    /// The offer's streams, in order.
    pub streams: Vec<SrsStream>,
    /// The SDP answer last sent, which an offer that changes nothing gets again
    /// (RFC 3264 §8).
    pub answer_sdp: Option<Vec<u8>>,
    /// The final response sent to the initial INVITE, which a retransmission of
    /// that INVITE is answered with again.
    pub final_response: Option<SipMessage>,
    /// A CANCEL arrived for the initial INVITE before its final response.
    pub cancelled: bool,
    /// The SRC side of the dialog, once the INVITE is accepted.
    pub peer: Option<SrsPeer>,
}

/// How an INVITE relates to the recording dialogs the SRS holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteMatch {
    /// A new recording dialog.
    New,
    /// The initial INVITE of a dialog already held, again (same From-tag and
    /// branch, no To-tag).
    Retransmission,
    /// The same Call-ID and From-tag on a different branch with no To-tag: a
    /// merged request (RFC 3261 §8.2.2.2), answered 482.
    Merged,
    /// The Call-ID is held by a recording dialog from another SRC (a different
    /// From-tag).
    CallIdInUse,
    /// A re-INVITE inside a dialog held (To-tag and From-tag match).
    InDialog,
    /// A To-tag naming no dialog the SRS holds (RFC 3261 §12.2.2: 481).
    UnknownDialog,
}

/// Why a recording session was not created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreateSessionError {
    /// `srs.max_sessions` sessions are already running.
    #[error("max sessions reached")]
    AtCapacity,
    /// A recording dialog with this Call-ID exists.
    #[error("Call-ID in use by another recording dialog")]
    CallIdInUse,
}

impl SrsSession {
    /// Duration in seconds (returns 0 if not yet ended).
    pub fn duration_secs(&self) -> u64 {
        self.ended_at
            .map(|end| end.duration_since(self.started_at).as_secs())
            .unwrap_or(0)
    }

    /// Build a serializable summary for storage.
    pub fn to_recording_record(&self) -> RecordingRecord {
        RecordingRecord {
            session_id: self.session_id.clone(),
            recording_call_id: self.recording_call_id.clone(),
            original_call_id: self.original_call_id.clone(),
            participants: self
                .metadata
                .participants
                .iter()
                .map(|participant| ParticipantRecord {
                    participant_id: participant.participant_id.clone(),
                    aor: participant.aor.clone(),
                    name: participant.name.clone(),
                })
                .collect(),
            streams: self
                .metadata
                .streams
                .iter()
                .map(|stream| StreamRecord {
                    stream_id: stream.stream_id.clone(),
                    label: stream.label.clone(),
                })
                .collect(),
            state: self.state.to_string(),
            duration_secs: self.duration_secs(),
            recording_dir: self
                .recording_dir
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Serializable recording record
// ---------------------------------------------------------------------------

/// JSON-serializable recording metadata for storage backends.
#[derive(Debug, Clone, Serialize)]
pub struct RecordingRecord {
    pub session_id: String,
    pub recording_call_id: String,
    pub original_call_id: Option<String>,
    pub participants: Vec<ParticipantRecord>,
    pub streams: Vec<StreamRecord>,
    pub state: String,
    pub duration_secs: u64,
    pub recording_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParticipantRecord {
    pub participant_id: String,
    pub aor: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamRecord {
    pub stream_id: String,
    pub label: String,
}

// ---------------------------------------------------------------------------
// SRS manager
// ---------------------------------------------------------------------------

/// Manages all active SRS recording sessions.
#[derive(Debug)]
pub struct SrsManager {
    /// The recording dialog's Call-ID → its session. The From-tag and To-tag
    /// are checked on every request that names one.
    sessions: DashMap<String, SrsSession>,
    /// Configuration.
    config: SrsConfig,
}

impl SrsManager {
    /// Create a new SRS manager from config.
    pub fn new(config: SrsConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            config,
        }
    }

    /// How an INVITE with these dialog identifiers relates to the sessions
    /// held.
    pub fn classify_invite(
        &self,
        recording_call_id: &str,
        from_tag: &str,
        to_tag: Option<&str>,
        branch: &str,
    ) -> InviteMatch {
        let Some(session) = self.sessions.get(recording_call_id) else {
            return match to_tag {
                Some(_) => InviteMatch::UnknownDialog,
                None => InviteMatch::New,
            };
        };
        match to_tag {
            Some(to_tag) if session.from_tag == from_tag && session.to_tag == to_tag => {
                InviteMatch::InDialog
            }
            Some(_) => InviteMatch::UnknownDialog,
            None if session.from_tag != from_tag => InviteMatch::CallIdInUse,
            None if session.invite_branch == branch => InviteMatch::Retransmission,
            None => InviteMatch::Merged,
        }
    }

    /// Whether a request with these identifiers is inside a recording dialog
    /// the SRS holds: the Call-ID, the SRC's From-tag and siphon's To-tag.
    pub fn in_dialog(&self, recording_call_id: &str, from_tag: &str, to_tag: &str) -> bool {
        self.sessions
            .get(recording_call_id)
            .is_some_and(|session| session.from_tag == from_tag && session.to_tag == to_tag)
    }

    /// Register a new recording session from an inbound SIPREC INVITE.
    ///
    /// Returns the To-tag siphon answers with.
    pub fn create_session(
        &self,
        recording_call_id: &str,
        from_tag: &str,
        invite_branch: &str,
        metadata: RecordingMetadata,
    ) -> Result<String, CreateSessionError> {
        if self.sessions.len() >= self.config.max_sessions {
            warn!(
                max = self.config.max_sessions,
                current = self.sessions.len(),
                "SRS: max sessions reached, rejecting recording"
            );
            return Err(CreateSessionError::AtCapacity);
        }

        let session_id = metadata.session_id.clone();
        let to_tag = format!("srs-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let storage_key = uuid::Uuid::new_v4().as_simple().to_string();
        // `path::recording_dir` is the only place a session directory is
        // built, and it keeps it directly inside the configured directory. The
        // key is siphon's own, so this cannot fail today; a failure leaves the
        // session without a directory, which is reported, rather than writing
        // somewhere unintended.
        let recording_dir = match path::recording_dir(
            Path::new(&self.config.recording_dir),
            &storage_key,
        ) {
            Ok(dir) => Some(dir),
            Err(error) => {
                error!(session_id = %session_id, %error, "SRS: cannot build a recording directory");
                None
            }
        };

        let session = SrsSession {
            session_id: session_id.clone(),
            recording_call_id: recording_call_id.to_string(),
            original_call_id: metadata.sip_session_ids.first().cloned(),
            from_tag: from_tag.to_string(),
            to_tag: to_tag.clone(),
            invite_branch: invite_branch.to_string(),
            storage_key,
            metadata,
            state: SrsSessionState::Pending,
            started_at: Instant::now(),
            ended_at: None,
            recording_dir,
            streams: Vec::new(),
            answer_sdp: None,
            final_response: None,
            cancelled: false,
            peer: None,
        };

        match self.sessions.entry(recording_call_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => Err(CreateSessionError::CallIdInUse),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                info!(
                    session_id = %session_id,
                    recording_call_id = %recording_call_id,
                    participants = session.metadata.participants.len(),
                    streams = session.metadata.streams.len(),
                    "SRS: new recording session"
                );
                vacant.insert(session);
                Ok(to_tag)
            }
        }
    }

    /// Fold metadata from a re-INVITE or UPDATE into the session's snapshot
    /// (RFC 7865 §9.1). Returns the merged snapshot, or `None` if the session
    /// doesn't exist.
    pub fn update_session(
        &self,
        recording_call_id: &str,
        metadata: RecordingMetadata,
    ) -> Option<RecordingMetadata> {
        let mut session = self.sessions.get_mut(recording_call_id)?;
        session.metadata.merge(metadata);
        info!(
            session_id = %session.session_id,
            recording_call_id = %recording_call_id,
            participants = session.metadata.participants.len(),
            streams = session.metadata.streams.len(),
            "SRS: updated recording metadata"
        );
        Some(session.metadata.clone())
    }

    /// Record the streams the session's offer was answered with, and the
    /// answer.
    pub fn set_streams(&self, recording_call_id: &str, streams: Vec<SrsStream>, answer: Vec<u8>) {
        if let Some(mut session) = self.sessions.get_mut(recording_call_id) {
            session.streams = streams;
            session.answer_sdp = Some(answer);
        }
    }

    /// The session's streams, `None` if the session doesn't exist.
    pub fn streams(&self, recording_call_id: &str) -> Option<Vec<SrsStream>> {
        self.sessions
            .get(recording_call_id)
            .map(|session| session.streams.clone())
    }

    /// Make `response` the initial INVITE's final response, unless a CANCEL
    /// got there first. `false` when the INVITE was cancelled: its 487 is the
    /// final response, and `response` must not be sent. The check and the claim
    /// are one step under the session's lock, so a CANCEL and the INVITE's own
    /// answer cannot both win.
    pub fn claim_final_response(&self, recording_call_id: &str, response: SipMessage) -> bool {
        match self.sessions.get_mut(recording_call_id) {
            Some(mut session) if !session.cancelled && session.final_response.is_none() => {
                session.final_response = Some(response);
                true
            }
            _ => false,
        }
    }

    /// The final response to the initial INVITE, once sent.
    pub fn final_response(&self, recording_call_id: &str) -> Option<SipMessage> {
        self.sessions
            .get(recording_call_id)
            .and_then(|session| session.final_response.clone())
    }

    /// A CANCEL for the initial INVITE on `branch` from the SRC tagged
    /// `from_tag` (RFC 3261 §9.2). An INVITE still without a final response is
    /// cancelled, and `terminated` (its 487) becomes that response.
    pub fn cancel_pending(
        &self,
        recording_call_id: &str,
        from_tag: &str,
        branch: &str,
        terminated: SipMessage,
    ) -> CancelOutcome {
        match self.sessions.get_mut(recording_call_id) {
            Some(mut session)
                if session.from_tag == from_tag && session.invite_branch == branch =>
            {
                if session.final_response.is_some() {
                    return CancelOutcome::TooLate;
                }
                session.cancelled = true;
                session.final_response = Some(terminated);
                CancelOutcome::Cancelled
            }
            _ => CancelOutcome::NoMatch,
        }
    }

    /// Keep the SRC side of the dialog, for a request siphon has to send in it.
    pub fn set_peer(&self, recording_call_id: &str, peer: SrsPeer) {
        if let Some(mut session) = self.sessions.get_mut(recording_call_id) {
            session.peer = Some(peer);
        }
    }

    /// The SRC side of the dialog.
    pub fn peer(&self, recording_call_id: &str) -> Option<SrsPeer> {
        self.sessions
            .get(recording_call_id)
            .and_then(|session| session.peer.clone())
    }

    /// Whether a CANCEL has arrived for the session's initial INVITE.
    pub fn is_cancelled(&self, recording_call_id: &str) -> bool {
        self.sessions
            .get(recording_call_id)
            .is_some_and(|session| session.cancelled)
    }

    /// Mark a session as actively recording (after media setup succeeds).
    pub fn activate_session(&self, recording_call_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(recording_call_id) {
            session.state = SrsSessionState::Recording;
            info!(session_id = %session.session_id, recording_call_id = %recording_call_id, "SRS: recording active");
        }
    }

    /// Mark a session as failed.
    pub fn fail_session(&self, recording_call_id: &str, reason: &str) {
        if let Some(mut session) = self.sessions.get_mut(recording_call_id) {
            session.state = SrsSessionState::Failed(reason.to_string());
            session.ended_at = Some(Instant::now());
            warn!(session_id = %session.session_id, recording_call_id = %recording_call_id, reason = %reason, "SRS: recording failed");
        }
    }

    /// End a session: on BYE, CANCEL, a refused offer, or a 2xx never ACKed.
    ///
    /// Returns the recording record for storage and the streams whose engine
    /// calls are to be deleted, or `None` if not found.
    pub fn stop_session(
        &self,
        recording_call_id: &str,
    ) -> Option<(RecordingRecord, Vec<SrsStream>)> {
        let (_, mut session) = self.sessions.remove(recording_call_id)?;
        if !matches!(session.state, SrsSessionState::Failed(_)) {
            session.state = SrsSessionState::Completed;
        }
        session.ended_at.get_or_insert_with(Instant::now);
        let record = session.to_recording_record();
        info!(
            session_id = %session.session_id,
            recording_call_id = %recording_call_id,
            duration = record.duration_secs,
            "SRS: recording session ended"
        );
        Some((record, session.streams))
    }

    /// Check if a Call-ID belongs to an active SRS session.
    pub fn is_srs_session(&self, call_id: &str) -> bool {
        self.sessions.contains_key(call_id)
    }

    /// Number of active recording sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the SRS config.
    pub fn config(&self) -> &SrsConfig {
        &self.config
    }

    /// Get session details by the recording dialog's Call-ID.
    pub fn get_session(
        &self,
        recording_call_id: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, SrsSession>> {
        self.sessions.get(recording_call_id)
    }

    /// Get the recording directory for a session.
    pub fn recording_dir(&self, recording_call_id: &str) -> Option<PathBuf> {
        self.sessions
            .get(recording_call_id)
            .and_then(|session| session.recording_dir.clone())
    }

    /// Get the media profile name to use for recording.
    pub fn rtpengine_profile(&self) -> &str {
        &self.config.rtpengine_profile
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::siprec::metadata::{Participant, StreamInfo};

    fn test_config() -> SrsConfig {
        SrsConfig {
            enabled: true,
            recording_dir: "/tmp/siphon-test-recordings".to_string(),
            max_sessions: 100,
            backend: "file".to_string(),
            file: None,
            http: None,
            rtpengine_profile: "srs_recording".to_string(),
        }
    }

    fn test_metadata() -> RecordingMetadata {
        RecordingMetadata {
            session_id: "test-session-001".to_string(),
            sip_session_ids: vec![],
            participants: vec![
                Participant {
                    participant_id: "p1".to_string(),
                    aor: "sip:alice@example.com".to_string(),
                    name: None,
                },
                Participant {
                    participant_id: "p2".to_string(),
                    aor: "sip:bob@example.com".to_string(),
                    name: None,
                },
            ],
            streams: vec![StreamInfo {
                stream_id: "s1".to_string(),
                session_id: "test-session-001".to_string(),
                label: "caller-audio".to_string(),
            }],
            ..Default::default()
        }
    }

    fn manager() -> SrsManager {
        SrsManager::new(test_config())
    }

    #[test]
    fn create_session_and_lookup() {
        let manager = manager();
        let to_tag = manager
            .create_session("call-1", "from-tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        assert!(to_tag.starts_with("srs-"));
        assert!(manager.is_srs_session("call-1"));
        assert!(manager.in_dialog("call-1", "from-tag-1", &to_tag));
        assert!(!manager.in_dialog("call-1", "other-tag", &to_tag));
        assert!(!manager.in_dialog("call-1", "from-tag-1", "srs-wrong"));
        let session = manager.get_session("call-1").unwrap();
        assert_eq!(session.session_id, "test-session-001", "kept as data");
        assert_eq!(session.state, SrsSessionState::Pending);
    }

    #[test]
    fn two_srcs_with_the_same_session_id_are_two_sessions() {
        // RFC 7866 lets the SRC pick the session_id: it is never a key.
        let manager = manager();
        let first = manager
            .create_session("call-a", "tag-a", "z9hG4bK-a", test_metadata())
            .unwrap();
        let second = manager
            .create_session("call-b", "tag-b", "z9hG4bK-b", test_metadata())
            .unwrap();
        assert_eq!(manager.session_count(), 2);

        let (_, _) = manager.stop_session("call-a").unwrap();
        assert!(manager.in_dialog("call-b", "tag-b", &second));
        assert!(!manager.in_dialog("call-a", "tag-a", &first));
    }

    #[test]
    fn a_held_call_id_is_not_created_twice() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        assert_eq!(
            manager.create_session("call-1", "tag-2", "z9hG4bK-2", test_metadata()),
            Err(CreateSessionError::CallIdInUse)
        );
    }

    #[test]
    fn invites_are_classified_by_dialog() {
        let manager = manager();
        assert_eq!(
            manager.classify_invite("call-1", "tag-1", None, "z9hG4bK-1"),
            InviteMatch::New
        );
        assert_eq!(
            manager.classify_invite("call-1", "tag-1", Some("srs-x"), "z9hG4bK-1"),
            InviteMatch::UnknownDialog
        );
        let to_tag = manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        assert_eq!(
            manager.classify_invite("call-1", "tag-1", None, "z9hG4bK-1"),
            InviteMatch::Retransmission
        );
        assert_eq!(
            manager.classify_invite("call-1", "tag-1", None, "z9hG4bK-2"),
            InviteMatch::Merged
        );
        assert_eq!(
            manager.classify_invite("call-1", "tag-9", None, "z9hG4bK-9"),
            InviteMatch::CallIdInUse
        );
        assert_eq!(
            manager.classify_invite("call-1", "tag-1", Some(&to_tag), "z9hG4bK-3"),
            InviteMatch::InDialog
        );
        assert_eq!(
            manager.classify_invite("call-1", "tag-1", Some("srs-wrong"), "z9hG4bK-3"),
            InviteMatch::UnknownDialog
        );
    }

    #[test]
    fn activate_session() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        manager.activate_session("call-1");
        assert_eq!(
            manager.get_session("call-1").unwrap().state,
            SrsSessionState::Recording
        );
    }

    #[test]
    fn stop_session_returns_record_and_streams() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        let streams = vec![SrsStream {
            index: 0,
            label: Some("1".to_string()),
            engine_call_id: Some(SrsStream::engine_call_id_for("call-1", 0)),
            recording_id: Some("rec-1".to_string()),
            offered_section: "m=audio 40000 RTP/AVP 0\r\n".to_string(),
            engine_answer: None,
        }];
        manager.set_streams("call-1", streams.clone(), b"v=0\r\n".to_vec());
        manager.activate_session("call-1");

        let (record, stopped) = manager.stop_session("call-1").unwrap();
        assert_eq!(record.session_id, "test-session-001");
        assert_eq!(record.recording_call_id, "call-1");
        assert_eq!(record.state, "completed");
        assert_eq!(stopped, streams);
        assert_eq!(manager.session_count(), 0, "the store drains");
        assert!(manager.stop_session("call-1").is_none());
    }

    #[test]
    fn a_failed_session_stops_as_failed() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        manager.fail_session("call-1", "engine refused");
        let (record, _) = manager.stop_session("call-1").unwrap();
        assert_eq!(record.state, "failed: engine refused");
    }

    #[test]
    fn max_sessions_enforced() {
        let mut config = test_config();
        config.max_sessions = 2;
        let manager = SrsManager::new(config);
        for index in 0..2 {
            manager
                .create_session(&format!("call-{index}"), "tag", "z9hG4bK", test_metadata())
                .unwrap();
        }
        assert_eq!(
            manager.create_session("call-2", "tag", "z9hG4bK", test_metadata()),
            Err(CreateSessionError::AtCapacity)
        );
        manager.stop_session("call-0");
        assert!(manager
            .create_session("call-2", "tag", "z9hG4bK", test_metadata())
            .is_ok());
    }

    #[test]
    fn a_cancel_matches_only_the_pending_initial_invite() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        assert_eq!(
            manager.cancel_pending("call-1", "tag-1", "z9hG4bK-other", response(487)),
            CancelOutcome::NoMatch
        );
        assert_eq!(
            manager.cancel_pending("call-1", "tag-other", "z9hG4bK-1", response(487)),
            CancelOutcome::NoMatch
        );
        assert!(!manager.is_cancelled("call-1"));
        assert_eq!(
            manager.cancel_pending("call-1", "tag-1", "z9hG4bK-1", response(487)),
            CancelOutcome::Cancelled
        );
        assert!(manager.is_cancelled("call-1"));
        assert_eq!(
            manager.final_response("call-1").unwrap().status_code(),
            Some(487),
            "a retransmitted INVITE gets the 487"
        );
        assert!(
            !manager.claim_final_response("call-1", response(200)),
            "the 200 lost to the CANCEL"
        );
    }

    fn response(code: u16) -> SipMessage {
        crate::sip::builder::SipMessageBuilder::new()
            .response(code, "Reason".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn a_cancel_after_the_final_response_matches_nothing() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        assert!(manager.claim_final_response("call-1", response(200)));
        assert!(
            !manager.claim_final_response("call-1", response(200)),
            "one final response per INVITE"
        );
        assert_eq!(
            manager.cancel_pending("call-1", "tag-1", "z9hG4bK-1", response(487)),
            CancelOutcome::TooLate
        );
        assert!(!manager.is_cancelled("call-1"));
    }

    #[test]
    fn stop_nonexistent_session_returns_none() {
        assert!(manager().stop_session("nope").is_none());
    }

    #[test]
    fn session_state_display() {
        assert_eq!(SrsSessionState::Pending.to_string(), "pending");
        assert_eq!(SrsSessionState::Recording.to_string(), "recording");
        assert_eq!(SrsSessionState::Stopping.to_string(), "stopping");
        assert_eq!(SrsSessionState::Completed.to_string(), "completed");
        assert_eq!(
            SrsSessionState::Failed("timeout".to_string()).to_string(),
            "failed: timeout"
        );
    }

    #[test]
    fn recording_record_serialization() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        let session = manager.get_session("call-1").unwrap();
        let json = serde_json::to_string(&session.to_recording_record()).unwrap();
        assert!(json.contains("test-session-001"));
        assert!(json.contains("alice@example.com"));
        assert!(json.contains("caller-audio"));
    }

    #[test]
    fn recording_dir_is_siphons_key_inside_the_configured_directory() {
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        let dir = manager.recording_dir("call-1").unwrap();
        let key = manager.get_session("call-1").unwrap().storage_key.clone();
        assert_eq!(dir, PathBuf::from("/tmp/siphon-test-recordings").join(&key));
        assert!(!dir.to_string_lossy().contains("test-session-001"));
    }

    /// The SRC chooses `session_id`: one built to climb out of the configured
    /// directory names nothing on disk, and two sessions sharing one get two
    /// directories.
    #[test]
    fn a_hostile_or_shared_session_id_never_names_a_directory() {
        let manager = manager();
        for (call_id, session_id) in [
            ("call-1", "../../etc"),
            ("call-2", "/absolute"),
            ("call-3", "same"),
            ("call-4", "same"),
        ] {
            let metadata = RecordingMetadata {
                session_id: session_id.to_string(),
                ..test_metadata()
            };
            manager
                .create_session(call_id, "tag", "z9hG4bK", metadata)
                .unwrap();
        }
        let dirs: Vec<PathBuf> = ["call-1", "call-2", "call-3", "call-4"]
            .iter()
            .map(|call_id| manager.recording_dir(call_id).unwrap())
            .collect();
        for dir in &dirs {
            assert_eq!(
                dir.parent(),
                Some(Path::new("/tmp/siphon-test-recordings")),
                "{dir:?}"
            );
        }
        assert_ne!(dirs[2], dirs[3], "a shared session_id is two directories");
    }

    #[test]
    fn an_update_merges_into_the_snapshot() {
        use crate::siprec::metadata::DataMode;
        let manager = manager();
        manager
            .create_session("call-1", "tag-1", "z9hG4bK-1", test_metadata())
            .unwrap();
        let partial = RecordingMetadata {
            datamode: DataMode::Partial,
            participants: vec![Participant {
                participant_id: "p3".to_string(),
                aor: "sip:carol@example.com".to_string(),
                name: None,
            }],
            ..Default::default()
        };
        let merged = manager.update_session("call-1", partial).unwrap();
        assert_eq!(merged.participants.len(), 3);
        assert_eq!(merged.session_id, "test-session-001");
        assert_eq!(
            manager
                .get_session("call-1")
                .unwrap()
                .metadata
                .participants
                .len(),
            3
        );
        assert!(manager
            .update_session("nope", RecordingMetadata::default())
            .is_none());
    }

    #[test]
    fn engine_call_ids_are_one_per_stream() {
        assert_eq!(SrsStream::engine_call_id_for("call-1@h", 0), "call-1@h~0");
        assert_ne!(
            SrsStream::engine_call_id_for("call-1@h", 0),
            SrsStream::engine_call_id_for("call-1@h", 1)
        );
    }

    #[test]
    fn concurrent_sessions_drain_to_zero() {
        let manager = std::sync::Arc::new(manager());
        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let manager = std::sync::Arc::clone(&manager);
                std::thread::spawn(move || {
                    for index in 0..10 {
                        let call_id = format!("call-{worker}-{index}");
                        manager
                            .create_session(&call_id, "tag", "z9hG4bK", test_metadata())
                            .unwrap();
                        manager.stop_session(&call_id).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(manager.session_count(), 0);
    }
}
