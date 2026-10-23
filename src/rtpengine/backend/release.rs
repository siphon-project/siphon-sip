//! Releasing a call's media by its SIP Call-ID alone.
//!
//! Every other delete is driven by a SIP message that carries the tags. A
//! script that learns a call is gone outside any SIP transaction (an Rx
//! Abort-Session, an N5 termination notify, a periodic sweep) has only the
//! Call-ID, and without this the media stays anchored until the engine's own
//! timeout reaps it.

use super::MediaBackend;
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::session::MediaSessionStore;

impl MediaBackend {
    /// Tear down the media of the call `call_id` names, and forget its session.
    ///
    /// The session this process tracks for the call supplies the engine call-id
    /// (a re-anchored call is held under one of its own) and the From-tag, so a
    /// tracked call is deleted exactly as the dispatcher's own teardown deletes
    /// it. `from_tag` overrides the tracked tag. With neither, the whole call is
    /// deleted by id: rtpengine takes a tagless `delete` as the whole call, and
    /// siphon-rtp scopes it to the calls this control identity created. rtpproxy
    /// cannot address a call without a tag, so that case is an error there.
    ///
    /// The session is forgotten whatever the engine answers: the call is over
    /// either way, and an entry kept for a failed delete would never be removed.
    ///
    /// Returns `true` when the engine released the call, `false` when it no
    /// longer held it (already reaped, or never anchored).
    pub async fn release_call(
        &self,
        sessions: &MediaSessionStore,
        call_id: &str,
        from_tag: Option<&str>,
    ) -> Result<bool, RtpEngineError> {
        let session = sessions.get(call_id);
        let engine_call_id = session
            .as_ref()
            .map_or(call_id, |session| session.rtpengine_id());
        let tag = from_tag.or(session.as_ref().map(|session| session.from_tag.as_str()));
        let outcome = match tag {
            Some(tag) => self.delete(engine_call_id, tag).await,
            None => self.delete_call(engine_call_id).await,
        };
        sessions.remove(call_id);
        match outcome {
            Ok(()) => Ok(true),
            Err(error) if error.is_call_not_found() => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::MediaBackend;
    use crate::rtpengine::client::RtpEngineSet;
    use crate::rtpengine::profile::NgFlags;
    use crate::rtpengine::session::{MediaSession, MediaSessionStore};
    use crate::rtpengine::test_engine::TestEngine;
    use crate::rtpengine::test_native_engine::NativeTestEngine;

    const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

    fn session(call_id: &str, engine_call_id: &str, from_tag: &str) -> MediaSession {
        MediaSession {
            call_id: call_id.to_string(),
            rtpengine_call_id: engine_call_id.to_string(),
            from_tag: from_tag.to_string(),
            to_tag: Some("callee-tag".to_string()),
            profile: "default".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: std::time::Instant::now(),
        }
    }

    /// A tracked call is deleted on its engine call-id with its own From-tag,
    /// as the dispatcher's teardown would, and its session is forgotten.
    #[tokio::test]
    async fn a_tracked_call_is_deleted_with_its_own_engine_id_and_tag() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();
        sessions.insert(session("sip-call", "reanchored-media", "caller-tag"));

        assert!(backend
            .release_call(&sessions, "sip-call", None)
            .await
            .unwrap());

        let deletes = engine.commands("delete");
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].call_id.as_deref(), Some("reanchored-media"));
        assert_eq!(deletes[0].from_tag.as_deref(), Some("caller-tag"));
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn a_given_from_tag_overrides_the_tracked_one() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();
        sessions.insert(session("sip-call", "", "caller-tag"));

        backend
            .release_call(&sessions, "sip-call", Some("callee-tag"))
            .await
            .unwrap();

        let deletes = engine.commands("delete");
        assert_eq!(deletes[0].call_id.as_deref(), Some("sip-call"));
        assert_eq!(deletes[0].from_tag.as_deref(), Some("callee-tag"));
    }

    /// An untracked call with no tag is deleted whole: rtpengine takes a
    /// `delete` without `from-tag` as the entire call.
    #[tokio::test]
    async fn an_untracked_call_without_a_tag_is_deleted_whole() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;

        assert!(backend
            .release_call(&MediaSessionStore::new(), "other-node-call", None)
            .await
            .unwrap());

        let deletes = engine.commands("delete");
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].call_id.as_deref(), Some("other-node-call"));
        assert_eq!(deletes[0].from_tag, None);
    }

    /// siphon-rtp: an anchored call is released by Call-ID alone, and a call
    /// the engine no longer holds reads as nothing to release, not a failure.
    #[tokio::test]
    async fn native_engine_releases_by_call_id_and_reports_an_unknown_call() {
        let engine = NativeTestEngine::start().await;
        let backend = engine.backend();
        let sessions = MediaSessionStore::new();
        backend
            .offer("anchored", "caller-tag", OFFER, &NgFlags::default())
            .await
            .unwrap();
        assert!(engine.holds("anchored"));

        assert!(backend
            .release_call(&sessions, "anchored", None)
            .await
            .unwrap());
        assert!(!engine.holds("anchored"));

        assert!(!backend
            .release_call(&sessions, "anchored", None)
            .await
            .unwrap());
    }

    /// An engine that cannot be reached is an error the script sees, and the
    /// session still goes: nothing else would ever remove it.
    #[tokio::test]
    async fn an_unreachable_engine_is_an_error_and_the_session_is_forgotten() {
        // The discard port: nothing answers there.
        let set = RtpEngineSet::new(vec![("127.0.0.1:9".parse().unwrap(), 200, 1)])
            .await
            .unwrap();
        let backend = MediaBackend::RtpEngine(Arc::new(set));
        let sessions = MediaSessionStore::new();
        sessions.insert(session("sip-call", "", "caller-tag"));

        let outcome = backend.release_call(&sessions, "sip-call", None).await;

        assert!(outcome.is_err());
        assert!(sessions.is_empty());
    }

    /// Leak gate: a batch of anchored calls released by Call-ID leaves neither
    /// a tracked session nor an engine call behind.
    #[tokio::test]
    async fn released_calls_leave_no_session_or_engine_call() {
        let engine = NativeTestEngine::start().await;
        let backend = engine.backend();
        let sessions = MediaSessionStore::new();
        for index in 0..64 {
            let call_id = format!("leak-release-{index}");
            backend
                .offer(&call_id, "caller-tag", OFFER, &NgFlags::default())
                .await
                .unwrap();
            sessions.insert(session(&call_id, "", "caller-tag"));
        }
        assert_eq!(sessions.len(), 64);

        for index in 0..64 {
            let call_id = format!("leak-release-{index}");
            assert!(backend
                .release_call(&sessions, &call_id, None)
                .await
                .unwrap());
        }

        assert!(sessions.is_empty());
        assert_eq!(engine.held_count(), 0);
    }
}
