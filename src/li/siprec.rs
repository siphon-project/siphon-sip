//! SIPREC — RFC 7866 SIP-based media recording.
//!
//! SIPREC works by forking the call's media to a Session Recording Server (SRS)
//! via a separate SIP INVITE containing recording metadata XML (RFC 7865).
//!
//! Integrated under lawful_intercept: as an alternative X3 content delivery
//! mechanism. While ETSI X3 uses raw RTP encapsulation, SIPREC uses standard
//! SIP signaling to establish the recording session.
//!
//! # Flow
//!
//! 1. Intercepted call is answered (or script triggers `li.intercept(call)`)
//! 2. SIPhon sends INVITE to the SRS with:
//!    - SDP containing the media streams to record
//!    - Recording metadata XML body (RFC 7865)
//! 3. SRS answers, RTPEngine bridges media to the SRS
//! 4. On call teardown, SIPhon sends BYE to the SRS

use crate::config::LiSiprecConfig;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::info;

/// An active SIPREC recording session.
#[derive(Debug, Clone)]
pub struct RecordingSession {
    /// Call-ID of the original call being recorded.
    pub original_call_id: String,
    /// Call-ID of the SIPREC session to the SRS.
    pub recording_call_id: String,
    /// LIID (if triggered by lawful intercept).
    pub liid: Option<String>,
    /// SRS URI.
    pub srs_uri: String,
    /// State of the recording session.
    pub state: RecordingState,
}

/// State of a SIPREC recording session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    /// INVITE sent to SRS, waiting for answer.
    Initiating,
    /// SRS answered, recording is active.
    Active,
    /// BYE sent, recording is stopping.
    Stopping,
    /// Recording session terminated.
    Terminated,
}

/// SIPREC session manager.
#[derive(Clone)]
pub struct SiprecManager {
    /// Active recording sessions keyed by original Call-ID.
    sessions: Arc<DashMap<String, RecordingSession>>,
    /// SRS URI from config.
    srs_uri: String,
    /// Number of parallel session copies per call.
    session_copies: u32,
    /// Transport for SRS INVITE (reserved for future use).
    _transport: String,
}

impl SiprecManager {
    /// Create a new SIPREC manager from configuration.
    pub fn new(config: &LiSiprecConfig) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            srs_uri: config.srs_uri.clone(),
            session_copies: config.session_copies,
            _transport: config.transport.clone(),
        }
    }

    /// Start a recording session for a call.
    ///
    /// In a full implementation, this would:
    /// 1. Build recording metadata XML (RFC 7865)
    /// 2. Send INVITE to the SRS via the UAC module
    /// 3. Handle the SRS response
    ///
    /// For now, registers the session in the store.
    pub fn start_recording(&self, original_call_id: &str, liid: Option<&str>) -> RecordingSession {
        let recording_call_id = format!("siprec-{}", uuid::Uuid::new_v4());

        let session = RecordingSession {
            original_call_id: original_call_id.to_string(),
            recording_call_id: recording_call_id.clone(),
            liid: liid.map(String::from),
            srs_uri: self.srs_uri.clone(),
            state: RecordingState::Initiating,
        };

        info!(
            original_call_id = %original_call_id,
            recording_call_id = %recording_call_id,
            srs_uri = %self.srs_uri,
            liid = ?liid,
            "SIPREC: recording session initiated"
        );

        self.sessions
            .insert(original_call_id.to_string(), session.clone());
        session
    }

    /// Mark a recording session as active (SRS answered).
    pub fn mark_active(&self, original_call_id: &str) -> bool {
        if let Some(mut session) = self.sessions.get_mut(original_call_id) {
            session.state = RecordingState::Active;
            true
        } else {
            false
        }
    }

    /// Stop recording for a call.
    ///
    /// In a full implementation, this would send BYE to the SRS.
    pub fn stop_recording(&self, original_call_id: &str) -> Option<RecordingSession> {
        if let Some(mut session) = self.sessions.get_mut(original_call_id) {
            session.state = RecordingState::Stopping;
            info!(
                original_call_id = %original_call_id,
                recording_call_id = %session.recording_call_id,
                "SIPREC: recording session stopping"
            );
        }

        self.sessions
            .remove(original_call_id)
            .map(|(_, session)| session)
    }

    /// Check if a call is being recorded.
    pub fn is_recording(&self, original_call_id: &str) -> bool {
        self.sessions.contains_key(original_call_id)
    }

    /// Get session info for a call.
    pub fn get_session(&self, original_call_id: &str) -> Option<RecordingSession> {
        self.sessions
            .get(original_call_id)
            .map(|entry| entry.clone())
    }

    /// Number of active recording sessions.
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// SRS URI.
    pub fn srs_uri(&self) -> &str {
        &self.srs_uri
    }

    /// Build RFC 7865 recording metadata XML for a session.
    ///
    /// This is a simplified version containing the essential elements.
    pub fn build_metadata_xml(
        &self,
        original_call_id: &str,
        from_uri: &str,
        to_uri: &str,
        direction: &str,
    ) -> String {
        format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
                "  <datamode>complete</datamode>\n",
                "  <session session_id=\"{original_call_id}\">\n",
                "    <sipSessionID>{original_call_id}</sipSessionID>\n",
                "  </session>\n",
                "  <participant participant_id=\"from\">\n",
                "    <nameID aor=\"{from_uri}\"/>\n",
                "  </participant>\n",
                "  <participant participant_id=\"to\">\n",
                "    <nameID aor=\"{to_uri}\"/>\n",
                "  </participant>\n",
                "  <stream stream_id=\"audio\" session_id=\"{original_call_id}\">\n",
                "    <label>audio</label>\n",
                "    <mode>{direction}</mode>\n",
                "  </stream>\n",
                "</recording>\n",
            ),
            original_call_id = original_call_id,
            from_uri = from_uri,
            to_uri = to_uri,
            direction = direction,
        )
    }
}

impl std::fmt::Debug for SiprecManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiprecManager")
            .field("srs_uri", &self.srs_uri)
            .field("session_copies", &self.session_copies)
            .field("active_sessions", &self.sessions.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LiSiprecConfig {
        LiSiprecConfig {
            srs_uri: "sip:srs@recorder.example.com".to_string(),
            session_copies: 1,
            transport: "tcp".to_string(),
            rtpengine_profile: "siprec_src".to_string(),
        }
    }

    #[test]
    fn create_siprec_manager() {
        let manager = SiprecManager::new(&test_config());
        assert_eq!(manager.srs_uri(), "sip:srs@recorder.example.com");
        assert_eq!(manager.active_sessions(), 0);
    }

    #[test]
    fn start_and_stop_recording() {
        let manager = SiprecManager::new(&test_config());

        let session = manager.start_recording("call-123@example.com", Some("LI-001"));
        assert_eq!(session.state, RecordingState::Initiating);
        assert!(session.recording_call_id.starts_with("siprec-"));
        assert_eq!(session.liid.as_deref(), Some("LI-001"));
        assert!(manager.is_recording("call-123@example.com"));
        assert_eq!(manager.active_sessions(), 1);

        let stopped = manager.stop_recording("call-123@example.com").unwrap();
        assert_eq!(stopped.original_call_id, "call-123@example.com");
        assert!(!manager.is_recording("call-123@example.com"));
    }

    #[test]
    fn mark_active() {
        let manager = SiprecManager::new(&test_config());
        manager.start_recording("call-123", None);

        assert!(manager.mark_active("call-123"));
        let session = manager.get_session("call-123").unwrap();
        assert_eq!(session.state, RecordingState::Active);

        // Non-existent call
        assert!(!manager.mark_active("call-nonexistent"));
    }

    #[test]
    fn stop_nonexistent_returns_none() {
        let manager = SiprecManager::new(&test_config());
        assert!(manager.stop_recording("nonexistent").is_none());
    }

    #[test]
    fn build_metadata_xml_contains_required_elements() {
        let manager = SiprecManager::new(&test_config());
        let xml = manager.build_metadata_xml(
            "call-123@example.com",
            "sip:alice@example.com",
            "sip:bob@example.com",
            "sendrecv",
        );

        assert!(xml.contains("urn:ietf:params:xml:ns:recording:1"));
        assert!(xml.contains("call-123@example.com"));
        assert!(xml.contains("sip:alice@example.com"));
        assert!(xml.contains("sip:bob@example.com"));
        assert!(xml.contains("sendrecv"));
        assert!(xml.contains("<datamode>complete</datamode>"));
    }

    #[test]
    fn multiple_concurrent_recordings() {
        let manager = SiprecManager::new(&test_config());

        manager.start_recording("call-1", Some("LI-001"));
        manager.start_recording("call-2", None);
        manager.start_recording("call-3", Some("LI-002"));

        assert_eq!(manager.active_sessions(), 3);

        manager.stop_recording("call-2");
        assert_eq!(manager.active_sessions(), 2);
        assert!(manager.is_recording("call-1"));
        assert!(!manager.is_recording("call-2"));
        assert!(manager.is_recording("call-3"));
    }

    #[test]
    fn recording_without_liid() {
        let manager = SiprecManager::new(&test_config());

        // SIPREC can be used without LI (regular call recording)
        let session = manager.start_recording("call-123", None);
        assert!(session.liid.is_none());
    }
}
