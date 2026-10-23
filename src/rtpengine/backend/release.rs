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
use crate::rtpengine::CallScope;

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
    /// `scope` releases only the leg anchored under that per-call scope
    /// (`rtpengine.offer(..., scope=)`). Without one, the call's own media goes
    /// and so does every leg any per-call scope anchored under `call_id`, each
    /// under the scope it was offered under: one release ends the call. Every
    /// leg is attempted before the first refusal is returned.
    ///
    /// Returns `true` when the engine released the call (any leg of it),
    /// `false` when it no longer held any (already reaped, or never anchored).
    pub async fn release_call(
        &self,
        sessions: &MediaSessionStore,
        call_id: &str,
        from_tag: Option<&str>,
        scope: Option<&CallScope>,
    ) -> Result<bool, RtpEngineError> {
        let outcomes = match scope {
            Some(scope) => {
                let session = sessions
                    .scoped_existing(scope)
                    .and_then(|store| store.remove(call_id));
                let tag = from_tag.or(session.as_ref().map(|session| session.from_tag.as_str()));
                vec![self.release_leg(Some(scope), call_id, tag).await]
            }
            None => {
                let session = sessions.get(call_id);
                let engine_call_id = session
                    .as_ref()
                    .map_or(call_id, |session| session.rtpengine_id());
                let tag = from_tag.or(session.as_ref().map(|session| session.from_tag.as_str()));
                let mut outcomes = vec![self.release_leg(None, engine_call_id, tag).await];
                sessions.remove(call_id);
                for (scope, session) in sessions.take_scoped(call_id) {
                    let tag = from_tag.unwrap_or(session.from_tag.as_str());
                    outcomes.push(self.release_leg(Some(&scope), call_id, Some(tag)).await);
                }
                outcomes
            }
        };
        let mut released = false;
        for outcome in outcomes {
            match outcome {
                Ok(()) => released = true,
                Err(error) if error.is_call_not_found() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(released)
    }

    /// Delete one engine call under `scope`, naming `tag`, or the whole call by
    /// id without one.
    async fn release_leg(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        match tag {
            Some(tag) => self.delete_in(scope, call_id, tag).await,
            None => self.delete_call_in(scope, call_id).await,
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
            .release_call(&sessions, "sip-call", None, None)
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
            .release_call(&sessions, "sip-call", Some("callee-tag"), None)
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
            .release_call(&MediaSessionStore::new(), "other-node-call", None, None)
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
            .release_call(&sessions, "anchored", None, None)
            .await
            .unwrap());
        assert!(!engine.holds("anchored"));

        assert!(!backend
            .release_call(&sessions, "anchored", None, None)
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

        let outcome = backend
            .release_call(&sessions, "sip-call", None, None)
            .await;

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
                .release_call(&sessions, &call_id, None, None)
                .await
                .unwrap());
        }

        assert!(sessions.is_empty());
        assert_eq!(engine.held_count(), 0);
    }

    fn scope(name: &str) -> crate::rtpengine::CallScope {
        crate::rtpengine::CallScope::per_call(name).unwrap()
    }

    /// Without a scope, a release ends every leg a per-call scope anchored
    /// under the Call-ID, each under its own scope, and frees their sessions.
    #[tokio::test]
    async fn an_unscoped_release_ends_every_scoped_leg() {
        let engine = NativeTestEngine::start().await;
        let backend = engine.backend();
        let sessions = MediaSessionStore::new();
        for leg in ["orig", "term"] {
            let leg_scope = scope(leg);
            backend
                .offer_in(
                    Some(&leg_scope),
                    "two-legs",
                    "caller-tag",
                    OFFER,
                    &NgFlags::default(),
                )
                .await
                .unwrap();
            sessions.scoped(&leg_scope).unwrap().insert(session(
                "two-legs",
                "two-legs",
                "caller-tag",
            ));
        }

        assert!(backend
            .release_call(&sessions, "two-legs", None, None)
            .await
            .unwrap());

        assert_eq!(engine.held_count(), 0);
        assert_eq!(sessions.scoped_len(), 0);
    }

    /// With a scope, only that leg goes, on both backends' keying.
    #[tokio::test]
    async fn a_scoped_release_ends_only_its_leg() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();
        let orig = scope("orig");
        sessions
            .scoped(&orig)
            .unwrap()
            .insert(session("two-legs", "two-legs", "caller-tag"));
        sessions.scoped(&scope("term")).unwrap().insert(session(
            "two-legs",
            "two-legs",
            "caller-tag",
        ));

        assert!(backend
            .release_call(&sessions, "two-legs", None, Some(&orig))
            .await
            .unwrap());

        let deletes = engine.commands("delete");
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].call_id.as_deref(), Some("two-legs;orig"));
        assert_eq!(deletes[0].from_tag.as_deref(), Some("caller-tag"));
        assert_eq!(sessions.scoped_len(), 1, "the term leg stays");
    }
}
