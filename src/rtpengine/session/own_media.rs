//! What a bridge shaped and pinned a party with, kept for the party's own
//! call once that call has no media session of its own left to say it.
//!
//! When a bridge forms, the `with` leg's own session is retired: its party
//! relays through the pair's session, which is stored under the anchor. From
//! then on nothing stored under the leg's own SIP Call-ID says which profile
//! it was anchored with or whose `received_from` policy pins its media
//! ingress. The pair's session records both, but only for that pair: bridged
//! to a different anchor afterwards, the leg would be shaped and pinned by
//! that anchor's profile.
//!
//! So the store keeps a small record per such call, by its SIP Call-ID, beside
//! the sessions. It is written when a bridge retires the call's own session
//! and rewritten by each bridge the call forms after that. It goes when the
//! call does: every teardown removes the call's session entry by SIP Call-ID
//! whether or not it finds one ([`MediaSessionStore::remove`]), and that
//! removal takes the record with it.

use std::time::Instant;

use super::{MediaSession, MediaSessionStore, SideFlags};

/// What a bridge shaped and pinned a party with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnMedia {
    /// The profile whose `offer` half shapes the SDP the party is offered.
    pub profile: String,
    /// Whose `received_from` policy pins the party's media ingress.
    pub ingress: SideFlags,
}

/// A record and when it was written, for the stale sweep.
#[derive(Debug)]
pub(super) struct Recorded {
    own: OwnMedia,
    recorded_at: Instant,
}

impl MediaSessionStore {
    /// Retire the media session stored under `sip_call_id`, a leg whose party
    /// relays through a bridged pair's session from here on, and keep `own`,
    /// what the bridge shaped and pinned that party with, for the leg's call.
    /// Returns the retired session.
    ///
    /// A leg whose session an earlier bridge retired has its record replaced.
    /// A leg that never had a session and has no record gets none: it has no
    /// profile of its own, and whichever anchor it is bridged to next decides
    /// for it.
    pub fn retire_for_bridge(
        &self,
        sip_call_id: &str,
        own: Option<OwnMedia>,
    ) -> Option<MediaSession> {
        let retired = self.take_session(sip_call_id);
        if let Some(own) = own {
            if retired.is_some() || self.own_media.contains_key(sip_call_id) {
                self.own_media.insert(
                    sip_call_id.to_string(),
                    Recorded {
                        own,
                        recorded_at: Instant::now(),
                    },
                );
            }
        }
        retired
    }

    /// What a bridge shaped and pinned the party of call `sip_call_id` with,
    /// when a bridge retired that call's own session. `None` for a call that
    /// still has its session, or never had one.
    pub fn own_media(&self, sip_call_id: &str) -> Option<OwnMedia> {
        self.own_media
            .get(sip_call_id)
            .map(|recorded| recorded.own.clone())
    }

    /// Calls with a record. Drains with the calls: the leak gate.
    #[cfg(test)]
    pub fn own_media_len(&self) -> usize {
        self.own_media.len()
    }

    /// Drop the record of call `sip_call_id`, which is ending.
    pub(super) fn forget_own_media(&self, sip_call_id: &str) {
        self.own_media.remove(sip_call_id);
    }

    /// Drop every record written before `cutoff`, with the sessions that old.
    pub(super) fn sweep_own_media(&self, cutoff: Instant) {
        self.own_media
            .retain(|_, recorded| recorded.recorded_at > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtpengine::session::ProfileHalf;

    fn session(call_id: &str) -> MediaSession {
        MediaSession {
            call_id: call_id.to_string(),
            rtpengine_call_id: call_id.to_string(),
            from_tag: "tag-a".to_string(),
            to_tag: None,
            profile: "own_profile".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: Instant::now(),
        }
    }

    fn own(profile: &str) -> OwnMedia {
        OwnMedia {
            profile: profile.to_string(),
            ingress: SideFlags {
                profile: profile.to_string(),
                half: ProfileHalf::Answer,
            },
        }
    }

    #[test]
    fn a_retired_session_leaves_a_record_that_goes_with_the_call() {
        let store = MediaSessionStore::new();
        store.insert(session("leg@192.0.2.10"));
        let retired = store.retire_for_bridge("leg@192.0.2.10", Some(own("own_profile")));
        assert!(retired.is_some());
        assert!(store.is_empty(), "the session is gone");
        assert_eq!(store.own_media("leg@192.0.2.10"), Some(own("own_profile")));
        assert_eq!(store.own_media_len(), 1);

        // A later bridge retires nothing, and rewrites what it used.
        assert!(store
            .retire_for_bridge("leg@192.0.2.10", Some(own("pair_profile")))
            .is_none());
        assert_eq!(store.own_media("leg@192.0.2.10"), Some(own("pair_profile")));
        assert_eq!(store.own_media_len(), 1);

        // The call ends: its teardown removes a session it no longer has.
        assert!(store.remove("leg@192.0.2.10").is_none());
        assert_eq!(store.own_media("leg@192.0.2.10"), None);
        assert_eq!(store.own_media_len(), 0);
    }

    #[test]
    fn a_leg_that_never_had_a_session_gets_no_record() {
        let store = MediaSessionStore::new();
        assert!(store
            .retire_for_bridge("bare@192.0.2.11", Some(own("anchor_profile")))
            .is_none());
        assert_eq!(store.own_media("bare@192.0.2.11"), None);
        // Nor does a retirement that names nothing to keep.
        store.insert(session("raw@192.0.2.12"));
        assert!(store.retire_for_bridge("raw@192.0.2.12", None).is_some());
        assert_eq!(store.own_media_len(), 0);
    }

    #[test]
    fn the_stale_sweep_takes_old_records_with_old_sessions() {
        let store = MediaSessionStore::new();
        store.insert(session("old@192.0.2.13"));
        store.retire_for_bridge("old@192.0.2.13", Some(own("own_profile")));
        store.sweep_stale(std::time::Duration::from_secs(60));
        assert_eq!(store.own_media_len(), 1, "a fresh record is kept");
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.sweep_stale(std::time::Duration::ZERO);
        assert_eq!(store.own_media_len(), 0);
    }
}
