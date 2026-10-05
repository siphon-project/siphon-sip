//! The media profile a call was first anchored with, kept for the call once a
//! bridge has put its party on a session that no longer says it.
//!
//! A bridge changes what is stored under each of its legs. The `with` leg's
//! own session is retired: its party relays through the pair's session, which
//! is stored under the anchor. The anchor's session becomes the pair's, and
//! takes the profile the pair was shaped with, which a pair `profile` named
//! for that bridge makes somebody else's. From then on nothing stored under
//! either leg's SIP Call-ID says which profile that call was anchored with or
//! whose `received_from` policy pins its party's media ingress. The pair's
//! session records what the pair used, but only for that pair: parted and
//! bridged to another leg, a party would be shaped and pinned by a profile
//! chosen for a pairing it is no longer in.
//!
//! So the store keeps a small record per such call, by its SIP Call-ID, beside
//! the sessions: the profile and the policy the call had on the session of its
//! own, read off that session the first time a bridge retires or takes it
//! over. It is written once and never rewritten. What a later bridge shaped
//! the party with is that pair's business, and a pair profile least of all
//! says what the call is. It goes when the call does: every teardown removes
//! the call's session entry by SIP Call-ID whether or not it finds one
//! ([`MediaSessionStore::remove`]), and that removal takes the record with it.

use std::time::Instant;

use super::{MediaSession, MediaSessionStore, SideFlags};

/// The profile a call was first anchored with, and its party's own policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnMedia {
    /// The profile the call's own session was anchored with: its `offer` half
    /// shapes the SDP the party is offered as a bridge's `with` leg, its
    /// `answer` half what it is re-INVITEd with as a bridge's anchor.
    pub profile: String,
    /// Whose `received_from` policy pins the party's media ingress.
    pub ingress: SideFlags,
}

impl OwnMedia {
    /// What `session`, a call's own, says of its party: the one on its
    /// `from_tag`.
    fn of(session: &MediaSession) -> Self {
        OwnMedia {
            profile: session.profile.clone(),
            ingress: session.party_ingress(true),
        }
    }
}

/// A record and when it was written, for the stale sweep.
#[derive(Debug)]
pub(super) struct Recorded {
    own: OwnMedia,
    recorded_at: Instant,
}

impl MediaSessionStore {
    /// Retire the media session stored under `sip_call_id`, a leg whose party
    /// relays through a bridged pair's session from here on, and keep what
    /// that session said of the party for the leg's call. Returns the retired
    /// session.
    ///
    /// A leg an earlier bridge retired the session of has nothing to retire
    /// and keeps the record it has. A leg that never had a session gets none:
    /// it has no profile of its own, and whichever anchor it is bridged to
    /// decides for it.
    pub fn retire_for_bridge(&self, sip_call_id: &str) -> Option<MediaSession> {
        let retired = self.take_session(sip_call_id);
        if let Some(session) = &retired {
            self.keep_own_media(sip_call_id, session);
        }
        retired
    }

    /// Keep what `session`, the one stored under `sip_call_id` until now, says
    /// of its party, before a bridge makes that session a pair's. Only the
    /// first time: what is kept is what the call was anchored with, and a
    /// session a bridge has already shaped no longer says that.
    pub fn keep_own_media(&self, sip_call_id: &str, session: &MediaSession) {
        self.own_media
            .entry(sip_call_id.to_string())
            .or_insert_with(|| Recorded {
                own: OwnMedia::of(session),
                recorded_at: Instant::now(),
            });
    }

    /// The profile and policy call `sip_call_id` was first anchored with, once
    /// a bridge has retired or taken over its own session. `None` for a call
    /// no bridge has formed on, whose session still says it, and for one that
    /// never had a session.
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
        let retired = store.retire_for_bridge("leg@192.0.2.10");
        assert!(retired.is_some());
        assert!(store.is_empty(), "the session is gone");
        assert_eq!(store.own_media("leg@192.0.2.10"), Some(own("own_profile")));
        assert_eq!(store.own_media_len(), 1);

        // A later bridge retires nothing, and the record stays the call's own:
        // neither a session that bridge shaped under a pair profile nor a
        // second retirement rewrites it.
        assert!(store.retire_for_bridge("leg@192.0.2.10").is_none());
        let mut under_a_pair = session("leg@192.0.2.10");
        under_a_pair.profile = "pair_profile".to_string();
        store.keep_own_media("leg@192.0.2.10", &under_a_pair);
        assert_eq!(store.own_media("leg@192.0.2.10"), Some(own("own_profile")));
        assert_eq!(store.own_media_len(), 1);

        // The call ends: its teardown removes a session it no longer has.
        assert!(store.remove("leg@192.0.2.10").is_none());
        assert_eq!(store.own_media("leg@192.0.2.10"), None);
        assert_eq!(store.own_media_len(), 0);
    }

    #[test]
    fn a_leg_that_never_had_a_session_gets_no_record() {
        let store = MediaSessionStore::new();
        assert!(store.retire_for_bridge("bare@192.0.2.11").is_none());
        assert_eq!(store.own_media("bare@192.0.2.11"), None);
        assert_eq!(store.own_media_len(), 0);
    }

    /// An anchor keeps its session through a bridge, so its record is taken
    /// from the session as it stood before the bridge made it the pair's: the
    /// party of a relay is pinned by the half its SDP was offered under.
    #[test]
    fn an_anchors_record_is_what_its_session_said_before_the_bridge() {
        let store = MediaSessionStore::new();
        let mut relaying = session("anchor@192.0.2.14");
        relaying.to_tag = Some("tag-b".to_string());
        store.keep_own_media("anchor@192.0.2.14", &relaying);
        assert_eq!(
            store.own_media("anchor@192.0.2.14"),
            Some(OwnMedia {
                profile: "own_profile".to_string(),
                ingress: SideFlags {
                    profile: "own_profile".to_string(),
                    half: ProfileHalf::Offer,
                },
            })
        );
        store.insert(relaying);
        assert!(store.remove("anchor@192.0.2.14").is_some());
        assert_eq!(store.own_media_len(), 0, "it goes with the call");
    }

    #[test]
    fn the_stale_sweep_takes_old_records_with_old_sessions() {
        let store = MediaSessionStore::new();
        store.insert(session("old@192.0.2.13"));
        store.retire_for_bridge("old@192.0.2.13");
        store.sweep_stale(std::time::Duration::from_secs(60));
        assert_eq!(store.own_media_len(), 1, "a fresh record is kept");
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.sweep_stale(std::time::Duration::ZERO);
        assert_eq!(store.own_media_len(), 0);
    }
}
