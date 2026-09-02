//! Media session tracking — maps SIP Call-IDs to active RTPEngine sessions.

use std::time::Instant;

use dashmap::DashMap;

/// An active RTPEngine media session associated with a SIP dialog.
#[derive(Debug, Clone)]
pub struct MediaSession {
    /// SIP Call-ID header value. This is the **store key** — the dispatcher
    /// looks sessions up by the A-leg's SIP Call-ID.
    pub call_id: String,
    /// The opaque call-id used in rtpengine NG commands (`offer`/`answer`/
    /// `delete`). Normally equal to [`MediaSession::call_id`], but decoupled so
    /// a siphon-terminated transfer can re-anchor the surviving pair on a
    /// **fresh** rtpengine call-id while the store key stays the (post-promotion)
    /// SIP Call-ID that later re-INVITEs/teardown look up. Use
    /// [`MediaSession::rtpengine_id`] rather than reading this directly.
    pub rtpengine_call_id: String,
    /// SIP From-tag (A leg).
    pub from_tag: String,
    /// SIP To-tag (B leg) — set after the answer.
    pub to_tag: Option<String>,
    /// The media profile name used for this session.
    pub profile: String,
    /// The fully-expanded WebSocket bridge URI this session's media is attached
    /// to, when one was requested (`siphon-rtp` voice-AI bridge).
    ///
    /// Recorded at `offer` so a later `answer` on the same Call-ID reuses the
    /// same bridge without the script re-passing `ws_uri=` — the same reason
    /// [`MediaSession::profile`] is recorded.
    pub ws_uri: Option<String>,
    /// The WebSocket **tee** URI streaming a copy of this session's audio, when
    /// one is attached.
    ///
    /// Deliberately separate from [`MediaSession::ws_uri`]: a tee is additive
    /// (the call relays on and a copy goes out) while `ws_uri` is a takeover
    /// (the server *is* the far side). Conflating them makes a leg with a
    /// takeover look like a leg with a tee, which sends the wrong detach at
    /// bridge time — the wrong verb succeeds harmlessly and the media path the
    /// bridge was about to renegotiate is still owned by the WebSocket server.
    pub ws_tee: Option<String>,
    /// Whether a WebSocket **takeover bridge** was attached to this session
    /// *mid-call* (`attach_ws_bridge`) rather than negotiated through the
    /// profile's `ws_uri`.
    ///
    /// Only a mid-call attach can be detached — it took over a live relay, so
    /// there is a relay to give back. A `ws_uri`-negotiated bridge is the
    /// call's whole media path and the engine refuses to detach it, which is
    /// why the two are tracked apart rather than as one "has a bridge" flag.
    pub ws_bridge_attached: bool,
    /// When this session was created.
    pub created_at: Instant,
}

impl MediaSession {
    /// The call-id to address rtpengine with. Falls back to the SIP `call_id`
    /// when `rtpengine_call_id` was left empty (back-compat for sessions created
    /// before the decoupling), so all existing anchored calls talk to rtpengine
    /// on their SIP Call-ID exactly as before.
    pub fn rtpengine_id(&self) -> &str {
        if self.rtpengine_call_id.is_empty() {
            &self.call_id
        } else {
            &self.rtpengine_call_id
        }
    }
}

/// Thread-safe store of active media sessions, keyed by SIP Call-ID.
pub struct MediaSessionStore {
    sessions: DashMap<String, MediaSession>,
}

impl MediaSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Insert or update a media session.
    pub fn insert(&self, session: MediaSession) {
        self.sessions.insert(session.call_id.clone(), session);
    }

    /// Look up a session by Call-ID.
    pub fn get(&self, call_id: &str) -> Option<MediaSession> {
        self.sessions.get(call_id).map(|entry| entry.clone())
    }

    /// Remove a session by Call-ID. Returns the removed session, if any.
    pub fn remove(&self, call_id: &str) -> Option<MediaSession> {
        self.sessions.remove(call_id).map(|(_, session)| session)
    }

    /// Update the to_tag for an existing session.
    pub fn set_to_tag(&self, call_id: &str, to_tag: String) {
        if let Some(mut entry) = self.sessions.get_mut(call_id) {
            entry.to_tag = Some(to_tag);
        }
    }

    /// Record the WebSocket **tee** attached to a session, or clear it on
    /// detach.
    ///
    /// Kept apart from the takeover bridge below: a bridge plan has to send
    /// `detach_ws_tee` for one and `detach_ws_bridge` for the other, and the
    /// wrong verb succeeds harmlessly rather than failing loudly — so a
    /// conflated flag leaves the media path still owned by the WebSocket
    /// server while the plan believes it was handed back.
    pub fn set_ws_tee(&self, call_id: &str, ws_tee: Option<String>) {
        if let Some(mut entry) = self.sessions.get_mut(call_id) {
            entry.ws_tee = ws_tee;
        }
    }

    /// Record that a WebSocket **takeover bridge** was attached to a session
    /// mid-call, or that it was detached.
    ///
    /// Only mid-call attaches are tracked here. A bridge negotiated through the
    /// profile's `ws_uri` is not detachable, so flagging it would make a bridge
    /// plan emit a detach the engine refuses.
    pub fn set_ws_bridge_attached(&self, call_id: &str, attached: bool) {
        if let Some(mut entry) = self.sessions.get_mut(call_id) {
            entry.ws_bridge_attached = attached;
        }
    }

    /// Remove sessions older than `max_age`.
    pub fn sweep_stale(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.sessions
            .retain(|_, session| session.created_at > cutoff);
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for MediaSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn make_session(call_id: &str) -> MediaSession {
        MediaSession {
            call_id: call_id.to_string(),
            rtpengine_call_id: call_id.to_string(),
            from_tag: "tag-a".to_string(),
            to_tag: None,
            profile: "srtp_to_rtp".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn insert_and_get() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        let session = store.get("call-1").unwrap();
        assert_eq!(session.call_id, "call-1");
        assert_eq!(session.from_tag, "tag-a");
        assert!(session.to_tag.is_none());
    }

    #[test]
    fn get_missing_returns_none() {
        let store = MediaSessionStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn remove_session() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        assert_eq!(store.len(), 1);
        let removed = store.remove("call-1").unwrap();
        assert_eq!(removed.call_id, "call-1");
        assert!(store.is_empty());
    }

    #[test]
    fn remove_missing_returns_none() {
        let store = MediaSessionStore::new();
        assert!(store.remove("nonexistent").is_none());
    }

    #[test]
    fn set_to_tag() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        store.set_to_tag("call-1", "tag-b".to_string());
        let session = store.get("call-1").unwrap();
        assert_eq!(session.to_tag.as_deref(), Some("tag-b"));
    }

    #[test]
    fn set_to_tag_missing_is_noop() {
        let store = MediaSessionStore::new();
        store.set_to_tag("nonexistent", "tag-b".to_string());
        assert!(store.is_empty());
    }

    #[test]
    fn sweep_stale_removes_old() {
        let store = MediaSessionStore::new();

        // Insert a session with a past created_at.
        let mut old_session = make_session("old-call");
        old_session.created_at = Instant::now() - std::time::Duration::from_secs(120);
        store.insert(old_session);

        // Insert a fresh session.
        store.insert(make_session("new-call"));

        assert_eq!(store.len(), 2);
        store.sweep_stale(std::time::Duration::from_secs(60));
        assert_eq!(store.len(), 1);
        assert!(store.get("old-call").is_none());
        assert!(store.get("new-call").is_some());
    }

    #[test]
    fn concurrent_access() {
        let store = Arc::new(MediaSessionStore::new());
        let mut handles = vec![];

        for index in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let call_id = format!("call-{index}");
                store.insert(make_session(&call_id));
                assert!(store.get(&call_id).is_some());
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.len(), 10);
    }

    #[test]
    fn insert_overwrites_existing() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        let mut updated = make_session("call-1");
        updated.from_tag = "tag-updated".to_string();
        store.insert(updated);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("call-1").unwrap().from_tag, "tag-updated");
    }

    #[test]
    fn default_trait() {
        let store = MediaSessionStore::default();
        assert!(store.is_empty());
    }

    #[test]
    fn rtpengine_id_uses_field_then_falls_back_to_call_id() {
        // Normal session: rtpengine_call_id == call_id → both agree.
        let mut session = make_session("sip-cid");
        assert_eq!(session.rtpengine_id(), "sip-cid");

        // Decoupled (transfer re-anchor): store key stays the SIP Call-ID, but
        // rtpengine is addressed on the fresh id.
        session.rtpengine_call_id = "b2b-fresh-anchor".to_string();
        assert_eq!(session.call_id, "sip-cid");
        assert_eq!(session.rtpengine_id(), "b2b-fresh-anchor");

        // Back-compat: an empty rtpengine_call_id falls back to the SIP Call-ID.
        session.rtpengine_call_id = String::new();
        assert_eq!(session.rtpengine_id(), "sip-cid");
    }

    /// The takeover URI and the tee URI are independent state. Conflating them
    /// is what made a leg holding a `ws_uri` takeover look like a leg holding a
    /// tee, so the bridge plan sent the tee detach — which succeeds, being
    /// idempotent — and then renegotiated a path the WebSocket server owned.
    #[test]
    fn a_takeover_uri_and_a_tee_uri_are_tracked_apart() {
        let store = MediaSessionStore::new();
        store.insert(MediaSession {
            ws_uri: Some("wss://ai.invalid/takeover".to_string()),
            ..make_session("call-1")
        });

        // A leg with only a takeover has no tee.
        let session = store.get("call-1").expect("session");
        assert!(session.ws_uri.is_some());
        assert!(session.ws_tee.is_none(), "a takeover is not a tee");
        assert!(
            !session.ws_bridge_attached,
            "a profile takeover is not a mid-call attach"
        );

        // Attaching a tee leaves the takeover alone, and vice versa.
        store.set_ws_tee("call-1", Some("wss://asr.invalid/tee".to_string()));
        let session = store.get("call-1").expect("session");
        assert_eq!(session.ws_tee.as_deref(), Some("wss://asr.invalid/tee"));
        assert_eq!(session.ws_uri.as_deref(), Some("wss://ai.invalid/takeover"));

        store.set_ws_tee("call-1", None);
        assert!(store.get("call-1").expect("session").ws_tee.is_none());
        assert!(
            store.get("call-1").expect("session").ws_uri.is_some(),
            "detaching a tee must not disturb the takeover"
        );
    }

    /// Only a mid-call attach is detachable, so it is tracked separately from
    /// the profile-negotiated `ws_uri`.
    #[test]
    fn a_mid_call_takeover_is_flagged_detachable_and_clears_on_detach() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        assert!(!store.get("call-1").expect("session").ws_bridge_attached);

        store.set_ws_bridge_attached("call-1", true);
        assert!(store.get("call-1").expect("session").ws_bridge_attached);

        // A re-point stays attached; only a detach clears it.
        store.set_ws_bridge_attached("call-1", true);
        assert!(store.get("call-1").expect("session").ws_bridge_attached);

        store.set_ws_bridge_attached("call-1", false);
        assert!(!store.get("call-1").expect("session").ws_bridge_attached);
    }
}
