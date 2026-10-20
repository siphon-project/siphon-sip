//! The media allocations a controller `dial` holds for the profiles its
//! branches name beyond the call's own.
//!
//! One allocation serves every branch that names the same profile, exactly as
//! one serves a whole fork when the dial names a single profile. A branch that
//! names another profile needs its own: the engine's side towards the branches
//! is shaped by the profile's offer flags (plain RTP for a desk phone, SDES-SRTP
//! for a trunk), and one allocation has one such side. The first profile of
//! the dial is the call's own session, stored under the SIP Call-ID like any
//! other; the rest are held here, by the same SIP Call-ID, until a branch
//! answers.
//!
//! The branch that answers settles it ([`MediaSessionStore::promote_dial_branch`]):
//! an allocation held here becomes the call's own session and every other is
//! handed back for the engine to delete. A dial that fails, and every
//! teardown, takes them all ([`MediaSessionStore::take_dial_branches`]) for the
//! same delete. They count as live to the orphan reap while held, so a reap
//! running during a ring cannot delete a branch's media from under it.

use std::time::Instant;

use super::{MediaSession, MediaSessionStore};

/// What settling a dial on its winning branch's allocation hands back for the
/// engine to delete.
#[derive(Debug, Default)]
pub struct SettledDialMedia {
    /// The call's own session, when the winner's allocation replaced it.
    pub replaced: Option<MediaSession>,
    /// Every other allocation the dial held.
    pub released: Vec<MediaSession>,
}

impl MediaSessionStore {
    /// Hold `session` as one of the call's dial-branch allocations, keyed by
    /// its SIP Call-ID. One with the same profile replaces the one held.
    pub fn insert_dial_branch(&self, session: MediaSession) {
        let mut held = self
            .dial_branches
            .entry(session.call_id.clone())
            .or_default();
        held.retain(|existing| existing.profile != session.profile);
        held.push(session);
    }

    /// The allocation the call's dial holds for `profile`, if it holds one.
    pub fn dial_branch(&self, call_id: &str, profile: &str) -> Option<MediaSession> {
        self.dial_branches
            .get(call_id)?
            .iter()
            .find(|session| session.profile == profile)
            .cloned()
    }

    /// Record the tag of the party that answered the allocation for `profile`,
    /// as [`MediaSessionStore::set_to_tag`] does for the call's own session.
    pub fn set_dial_branch_to_tag(&self, call_id: &str, profile: &str, to_tag: String) {
        if let Some(mut held) = self.dial_branches.get_mut(call_id) {
            if let Some(session) = held
                .iter_mut()
                .find(|session| session.profile == profile && session.from_tag != to_tag)
            {
                session.to_tag = Some(to_tag);
            }
        }
    }

    /// Take every allocation the call's dial holds, for the engine to delete.
    pub fn take_dial_branches(&self, call_id: &str) -> Vec<MediaSession> {
        self.dial_branches
            .remove(call_id)
            .map(|(_, held)| held)
            .unwrap_or_default()
    }

    /// Settle the call's dial on the allocation for `profile`: when the dial
    /// holds one, it becomes the call's own session and the session it replaces
    /// is handed back; every other allocation is handed back either way.
    ///
    /// `profile` naming the call's own session's (or none held) keeps that
    /// session and releases the rest.
    pub fn promote_dial_branch(&self, call_id: &str, profile: Option<&str>) -> SettledDialMedia {
        let mut held = self.take_dial_branches(call_id);
        let winner = profile.and_then(|profile| {
            held.iter()
                .position(|session| session.profile == profile)
                .map(|index| held.swap_remove(index))
        });
        let replaced = winner.map(|winner| {
            let replaced = self.get(call_id);
            self.insert(winner);
            replaced
        });
        SettledDialMedia {
            replaced: replaced.flatten(),
            released: held,
        }
    }

    /// How many calls hold dial-branch allocations.
    pub fn dial_branch_calls(&self) -> usize {
        self.dial_branches.len()
    }

    /// The engine call-ids of every dial-branch allocation held.
    pub(super) fn dial_branch_engine_call_ids(&self) -> Vec<String> {
        self.dial_branches
            .iter()
            .flat_map(|entry| {
                entry
                    .value()
                    .iter()
                    .map(|session| session.rtpengine_id().to_string())
                    .collect::<Vec<String>>()
            })
            .collect()
    }

    /// Drop what a removed call still held. A teardown takes and deletes them
    /// first; this is only the store's own hygiene for a path that did not.
    pub(super) fn forget_dial_branches(&self, call_id: &str) {
        if let Some((_, held)) = self.dial_branches.remove(call_id) {
            tracing::debug!(
                %call_id,
                allocations = held.len(),
                "media session store: dropped dial-branch allocations with the call's session"
            );
        }
    }

    /// Drop the allocations of every dial older than `cutoff`, as
    /// [`MediaSessionStore::sweep_stale`] drops stale sessions.
    pub(super) fn sweep_dial_branches(&self, cutoff: Instant) {
        self.dial_branches.retain(|_, held| {
            held.retain(|session| session.created_at > cutoff);
            !held.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(profile: &str, engine_call_id: &str) -> MediaSession {
        MediaSession {
            call_id: "caller@192.0.2.10".to_string(),
            rtpengine_call_id: engine_call_id.to_string(),
            from_tag: "caller-tag".to_string(),
            to_tag: None,
            profile: profile.to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn a_held_allocation_is_found_by_its_profile_and_counts_as_live() {
        let store = MediaSessionStore::new();
        store.insert(allocation("latching", "engine-own"));
        store.insert_dial_branch(allocation("sdes_srtp", "engine-srtp"));

        let held = store
            .dial_branch("caller@192.0.2.10", "sdes_srtp")
            .expect("held");
        assert_eq!(held.rtpengine_id(), "engine-srtp");
        assert!(store.dial_branch("caller@192.0.2.10", "latching").is_none());
        let live = store.live_engine_call_ids();
        assert!(live.contains("engine-own") && live.contains("engine-srtp"));
        assert_eq!(store.len(), 1, "the call has one session of its own");
    }

    #[test]
    fn the_same_profile_held_twice_keeps_the_later_allocation() {
        let store = MediaSessionStore::new();
        store.insert_dial_branch(allocation("sdes_srtp", "first"));
        store.insert_dial_branch(allocation("sdes_srtp", "second"));
        let taken = store.take_dial_branches("caller@192.0.2.10");
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].rtpengine_id(), "second");
    }

    #[test]
    fn a_winner_on_a_held_allocation_takes_over_the_calls_session() {
        let store = MediaSessionStore::new();
        store.insert(allocation("latching", "engine-own"));
        store.insert_dial_branch(allocation("sdes_srtp", "engine-srtp"));
        store.insert_dial_branch(allocation("other", "engine-other"));
        store.set_dial_branch_to_tag("caller@192.0.2.10", "sdes_srtp", "trunk".to_string());

        let settled = store.promote_dial_branch("caller@192.0.2.10", Some("sdes_srtp"));

        assert_eq!(
            settled.replaced.map(|session| session.rtpengine_call_id),
            Some("engine-own".to_string())
        );
        assert_eq!(
            settled
                .released
                .iter()
                .map(|session| session.rtpengine_id().to_string())
                .collect::<Vec<String>>(),
            vec!["engine-other".to_string()]
        );
        let own = store.get("caller@192.0.2.10").expect("promoted");
        assert_eq!(own.rtpengine_id(), "engine-srtp");
        assert_eq!(own.profile, "sdes_srtp");
        assert_eq!(own.to_tag.as_deref(), Some("trunk"));
        assert_eq!(store.dial_branch_calls(), 0);
    }

    #[test]
    fn a_winner_on_the_calls_own_session_releases_every_held_allocation() {
        let store = MediaSessionStore::new();
        store.insert(allocation("latching", "engine-own"));
        store.insert_dial_branch(allocation("sdes_srtp", "engine-srtp"));

        let settled = store.promote_dial_branch("caller@192.0.2.10", Some("latching"));

        assert!(settled.replaced.is_none());
        assert_eq!(settled.released.len(), 1);
        assert_eq!(
            store
                .get("caller@192.0.2.10")
                .map(|own| own.rtpengine_call_id),
            Some("engine-own".to_string())
        );
        assert_eq!(store.dial_branch_calls(), 0);
    }

    #[test]
    fn removing_the_call_and_sweeping_both_drain_the_held_allocations() {
        let store = MediaSessionStore::new();
        store.insert(allocation("latching", "engine-own"));
        store.insert_dial_branch(allocation("sdes_srtp", "engine-srtp"));
        store.remove("caller@192.0.2.10");
        assert_eq!(store.dial_branch_calls(), 0);

        store.insert_dial_branch(allocation("sdes_srtp", "engine-srtp"));
        store.sweep_stale(std::time::Duration::ZERO);
        assert_eq!(store.dial_branch_calls(), 0);
    }

    /// Per-module leak gate: a batch of complete dials, each settled on one of
    /// its branches or failed, leaves nothing held.
    #[test]
    fn complete_dials_drain_the_held_allocations_to_baseline() {
        let store = MediaSessionStore::new();
        let baseline = store.dial_branch_calls();
        for index in 0..500 {
            let call_id = format!("call-{index}@192.0.2.10");
            let mut own = allocation("latching", &format!("own-{index}"));
            own.call_id.clone_from(&call_id);
            store.insert(own);
            for profile in ["sdes_srtp", "other"] {
                let mut held = allocation(profile, &format!("{profile}-{index}"));
                held.call_id.clone_from(&call_id);
                store.insert_dial_branch(held);
            }
            match index % 3 {
                0 => drop(store.promote_dial_branch(&call_id, Some("sdes_srtp"))),
                1 => drop(store.promote_dial_branch(&call_id, Some("latching"))),
                _ => drop(store.take_dial_branches(&call_id)),
            }
            store.remove(&call_id);
        }
        assert_eq!(store.dial_branch_calls(), baseline);
        assert_eq!(store.len(), 0);
    }
}
