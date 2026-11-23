//! The dialogs a node has seen open, kept so a warrant activated while one is
//! up can find it.
//!
//! A session decision ([`super::session`]) exists only for a call a warrant
//! covers or that a message has been matched on since one was provisioned, and
//! on a node with nothing provisioned no message is matched at all. A warrant
//! that arrives in the middle of a call therefore has nothing to look at: it
//! took effect at the call's next SIP message, which for a call in the middle
//! of a conversation can be minutes away, and for a call with no further
//! message before its BYE was never. Audio that went by in between was not
//! delivered.
//!
//! This index is what is looked at instead. It holds, for each dialog-forming
//! INVITE seen while lawful intercept is enabled, the identities that INVITE
//! carried, which is all a warrant is matched on. It costs one insert per
//! initial INVITE, nothing per message after it, and it is released as the
//! dialog ends, by the sweep when the call is gone, by an age bound and by a
//! cap, so it cannot outgrow the calls that are up.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::error;

use super::session::header_tag;
use super::LiManager;

/// How many dialogs the index holds.
///
/// A bound rather than a hope: the Call-ID is chosen by whoever sent the
/// INVITE, and an INVITE that is never answered or ended would otherwise stay
/// until the sweep. Past the cap a new dialog is not remembered, which costs
/// that call the old behaviour (a warrant activated while it is up takes
/// effect at its next message) and is counted and logged, never silent.
pub const MAX_LIVE_DIALOGS: usize = 100_000;

/// How long a dialog is kept before the sweep asks whether its call is still
/// there: long enough for the script to decide and for the call to exist, and
/// short enough that an INVITE siphon refused, which no later message from
/// the caller ends, does not sit in the index.
pub const LIVE_DIALOG_GRACE: Duration = Duration::from_secs(32);

/// The longest a dialog is kept. A call that lasts longer is intercepted from
/// its next message after a warrant, as it was before this index.
pub const MAX_LIVE_DIALOG_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Log one overflow in this many, and the first. A flood of INVITEs at the
/// cap would otherwise write a line each.
const OVERFLOW_LOG_INTERVAL: u64 = 1_000;

/// What a dialog-forming INVITE carried: the identities a warrant is matched
/// on, and when it was seen.
#[derive(Debug, Clone)]
pub struct LiveDialog {
    /// The INVITE's Call-ID, which names the dialog (and, for a B2BUA call,
    /// its caller leg).
    pub call_id: Box<str>,
    /// The Request-URI.
    pub request_uri: Box<str>,
    /// The From header, tag included.
    pub from: Box<str>,
    /// The To header: no tag on the INVITE that forms a dialog.
    pub to: Box<str>,
    /// Where the INVITE came from.
    pub source_ip: Option<IpAddr>,
    /// Whether a 2xx to the INVITE has been seen on this Call-ID. A B2BUA
    /// call's answer arrives on another leg and is not seen here; the call
    /// itself says whether it is answered.
    pub answered: bool,
    /// When the INVITE was seen.
    pub opened: Instant,
}

impl LiveDialog {
    /// The tag of the party that opened the dialog: the `From` tag.
    pub fn caller_tag(&self) -> Option<&str> {
        header_tag(&self.from)
    }
}

/// The index. Keyed by Call-ID.
#[derive(Debug, Default)]
pub(super) struct LiveDialogs {
    dialogs: DashMap<Box<str>, LiveDialog>,
    /// How many are held, so a hot path can ask without taking every shard.
    count: AtomicUsize,
    overflowed: AtomicU64,
}

impl LiveDialogs {
    /// Remember a dialog, building the owned record only when it is new.
    fn remember(
        &self,
        call_id: &str,
        request_uri: &impl std::fmt::Display,
        from: &str,
        to: &str,
        source_ip: Option<IpAddr>,
    ) {
        // A retransmitted INVITE is the same dialog.
        if self.dialogs.contains_key(call_id) {
            return;
        }
        if self.count.load(Ordering::Acquire) >= MAX_LIVE_DIALOGS {
            crate::metrics::li::live_dialog_overflowed();
            let seen = self.overflowed.fetch_add(1, Ordering::Relaxed);
            if seen.is_multiple_of(OVERFLOW_LOG_INTERVAL) {
                error!(
                    held = MAX_LIVE_DIALOGS,
                    overflowed = seen + 1,
                    "the lawful-intercept live-dialog index is full; a warrant activated \
                     while this call is up takes effect at its next message"
                );
            }
            return;
        }
        let dialog = LiveDialog {
            call_id: Box::from(call_id),
            request_uri: request_uri.to_string().into_boxed_str(),
            from: Box::from(from),
            to: Box::from(to),
            source_ip,
            answered: false,
            opened: Instant::now(),
        };
        if self.dialogs.insert(Box::from(call_id), dialog).is_none() {
            self.count.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn forget(&self, call_id: &str) {
        if self.dialogs.remove(call_id).is_some() {
            self.count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Forget the dialog unless a 2xx has answered it.
    fn forget_unanswered(&self, call_id: &str) {
        if self
            .dialogs
            .remove_if(call_id, |_, dialog| !dialog.answered)
            .is_some()
        {
            self.count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn mark_answered(&self, call_id: &str) {
        if let Some(mut dialog) = self.dialogs.get_mut(call_id) {
            dialog.answered = true;
        }
    }

    fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// A copy of every dialog held, with no guard on the map: the caller
    /// calls into other stores for each, which must not happen under one.
    fn snapshot(&self) -> Vec<LiveDialog> {
        self.dialogs
            .iter()
            .map(|dialog| dialog.value().clone())
            .collect()
    }

    /// Whether this very dialog (the Call-ID, opened at `opened`) is still
    /// held: a Call-ID used again for a new call is not it.
    fn is_held(&self, call_id: &str, opened: Instant) -> bool {
        self.dialogs
            .get(call_id)
            .is_some_and(|dialog| dialog.opened == opened)
    }

    /// Release what is over: past the age bound, or past the grace with
    /// `is_live` saying nothing holds the call.
    fn sweep(&self, now: Instant, is_live: impl Fn(&LiveDialog) -> bool) {
        let candidates: Vec<LiveDialog> = self
            .dialogs
            .iter()
            .filter(|dialog| now.saturating_duration_since(dialog.opened) >= LIVE_DIALOG_GRACE)
            .map(|dialog| dialog.value().clone())
            .collect();
        for dialog in candidates {
            let over_age = now.saturating_duration_since(dialog.opened) >= MAX_LIVE_DIALOG_AGE;
            // Asked with no guard held, then removed only if it is still the
            // dialog that was asked about: the Call-ID may have been used
            // again in between.
            if over_age || !is_live(&dialog) {
                let removed = self
                    .dialogs
                    .remove_if(&*dialog.call_id, |_, held| held.opened == dialog.opened);
                if removed.is_some() {
                    self.count.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
    }
}

impl LiManager {
    /// A dialog-forming INVITE has arrived: remember what a warrant would be
    /// matched on, so one activated while the call is up can find it.
    ///
    /// Borrowed values: the owned record, and the Request-URI's text, are
    /// built only for a dialog that is new. Nothing when lawful intercept is
    /// disabled.
    pub fn live_dialog_opened(
        &self,
        call_id: &str,
        request_uri: &impl std::fmt::Display,
        from: &str,
        to: &str,
        source_ip: Option<IpAddr>,
    ) {
        if self.config.enabled {
            self.live_dialogs
                .remember(call_id, request_uri, from, to, source_ip);
        }
    }

    /// A 2xx answered the INVITE of `call_id`.
    pub fn live_dialog_answered(&self, call_id: &str) {
        self.live_dialogs.mark_answered(call_id);
    }

    /// The dialog `call_id` is over (a BYE and its answer).
    pub fn live_dialog_ended(&self, call_id: &str) {
        self.live_dialogs.forget(call_id);
    }

    /// The INVITE of `call_id` has been cancelled or refused: over unless a
    /// 2xx already made it a dialog.
    pub fn live_dialog_failed(&self, call_id: &str) {
        self.live_dialogs.forget_unanswered(call_id);
    }

    /// Whether any dialog is held. One load; for the response path, which
    /// has nothing to do on a node that holds none.
    pub fn holds_live_dialogs(&self) -> bool {
        self.live_dialogs.len() > 0
    }

    /// How many dialogs are held. For the leak tests and the sweep.
    pub fn live_dialog_count(&self) -> usize {
        self.live_dialogs.len()
    }

    /// Every dialog held, copied. See [`LiveDialogs::snapshot`].
    pub fn live_dialogs(&self) -> Vec<LiveDialog> {
        self.live_dialogs.snapshot()
    }

    /// Whether `dialog` is still the one held under its Call-ID.
    pub fn live_dialog_held(&self, dialog: &LiveDialog) -> bool {
        self.live_dialogs.is_held(&dialog.call_id, dialog.opened)
    }

    /// Release the dialogs that are over. `is_live` says whether anything
    /// still holds the call of a dialog (a B2BUA call, media, a seat).
    pub fn sweep_live_dialogs(&self, now: Instant, is_live: impl Fn(&LiveDialog) -> bool) {
        self.live_dialogs.sweep(now, is_live);
    }

    /// A receiver woken whenever the warrants change. See
    /// [`TaskStore::subscribe`](super::x1::store::TaskStore::subscribe).
    pub fn subscribe_tasks(&self) -> tokio::sync::watch::Receiver<u64> {
        self.tasks.subscribe()
    }

    /// A receiver woken whenever a destination is modified or removed.
    pub fn subscribe_destinations(&self) -> tokio::sync::watch::Receiver<u64> {
        self.destinations.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::tests::manager;

    fn open(manager: &LiManager, call_id: &str) {
        manager.live_dialog_opened(
            call_id,
            &"sip:bob@example.com",
            "<sip:alice@example.com>;tag=a",
            "<sip:bob@example.com>",
            None,
        );
    }

    #[test]
    fn a_dialog_is_remembered_with_no_warrant_provisioned() {
        let (manager, _iri, _audit) = manager();
        assert!(manager.tasks().is_empty());
        open(&manager, "call-1@example.com");
        assert_eq!(manager.live_dialog_count(), 1);
        let held = manager.live_dialogs();
        assert_eq!(held.len(), 1);
        assert_eq!(&*held[0].call_id, "call-1@example.com");
        assert_eq!(&*held[0].request_uri, "sip:bob@example.com");
        assert_eq!(held[0].caller_tag(), Some("a"));
        assert!(!held[0].answered);
    }

    #[test]
    fn a_retransmitted_invite_is_one_dialog() {
        let (manager, _iri, _audit) = manager();
        open(&manager, "call-1@example.com");
        open(&manager, "call-1@example.com");
        assert_eq!(manager.live_dialog_count(), 1);
    }

    #[test]
    fn nothing_is_remembered_when_lawful_intercept_is_disabled() {
        let (manager, _iri, _audit) = crate::li::tests::manager_disabled();
        open(&manager, "call-1@example.com");
        assert_eq!(manager.live_dialog_count(), 0);
    }

    #[test]
    fn a_bye_ends_the_dialog() {
        let (manager, _iri, _audit) = manager();
        open(&manager, "call-1@example.com");
        manager.live_dialog_ended("call-1@example.com");
        assert_eq!(manager.live_dialog_count(), 0);
        manager.live_dialog_ended("call-1@example.com");
        assert_eq!(manager.live_dialog_count(), 0, "ending twice counts once");
    }

    #[test]
    fn a_refused_or_cancelled_invite_ends_an_unanswered_dialog_only() {
        let (manager, _iri, _audit) = manager();
        open(&manager, "unanswered@example.com");
        manager.live_dialog_failed("unanswered@example.com");
        assert_eq!(manager.live_dialog_count(), 0);

        open(&manager, "answered@example.com");
        manager.live_dialog_answered("answered@example.com");
        // The failure of a re-INVITE, or a CANCEL of one, ends nothing.
        manager.live_dialog_failed("answered@example.com");
        assert_eq!(manager.live_dialog_count(), 1);
        assert!(manager.live_dialogs()[0].answered);
    }

    #[test]
    fn the_sweep_keeps_a_young_dialog_whatever_it_is_told() {
        let (manager, _iri, _audit) = manager();
        open(&manager, "young@example.com");
        manager.sweep_live_dialogs(Instant::now(), |_| false);
        assert_eq!(manager.live_dialog_count(), 1);
    }

    #[test]
    fn the_sweep_releases_a_dialog_nothing_holds_after_the_grace() {
        let (manager, _iri, _audit) = manager();
        open(&manager, "gone@example.com");
        open(&manager, "held@example.com");
        let later = Instant::now() + LIVE_DIALOG_GRACE + Duration::from_secs(1);
        manager.sweep_live_dialogs(later, |dialog| &*dialog.call_id == "held@example.com");
        let held: Vec<_> = manager.live_dialogs();
        assert_eq!(held.len(), 1);
        assert_eq!(&*held[0].call_id, "held@example.com");
        assert_eq!(manager.live_dialog_count(), 1);
    }

    #[test]
    fn the_age_bound_releases_a_dialog_something_still_holds() {
        let (manager, _iri, _audit) = manager();
        open(&manager, "ancient@example.com");
        let much_later = Instant::now() + MAX_LIVE_DIALOG_AGE + Duration::from_secs(1);
        manager.sweep_live_dialogs(much_later, |_| true);
        assert_eq!(manager.live_dialog_count(), 0);
    }

    #[test]
    fn a_full_index_remembers_no_more_and_says_so() {
        crate::metrics::init().expect("metrics");
        let before = crate::metrics::li::live_dialogs_overflowed().expect("registered");
        let (manager, _iri, _audit) = manager();
        for number in 0..MAX_LIVE_DIALOGS {
            open(&manager, &format!("fill-{number}@example.com"));
        }
        assert_eq!(manager.live_dialog_count(), MAX_LIVE_DIALOGS);
        open(&manager, "one-too-many@example.com");
        assert_eq!(manager.live_dialog_count(), MAX_LIVE_DIALOGS);
        assert!(
            manager
                .live_dialogs()
                .iter()
                .all(|dialog| &*dialog.call_id != "one-too-many@example.com"),
            "the dialog that did not fit is not held"
        );
        assert!(
            crate::metrics::li::live_dialogs_overflowed().expect("registered") > before,
            "and it is counted"
        );
        manager.live_dialog_ended("fill-0@example.com");
        open(&manager, "now-it-fits@example.com");
        assert_eq!(manager.live_dialog_count(), MAX_LIVE_DIALOGS);
    }

    #[test]
    fn a_node_that_holds_none_says_so() {
        let (manager, _iri, _audit) = manager();
        assert!(!manager.holds_live_dialogs());
        open(&manager, "call-1@example.com");
        assert!(manager.holds_live_dialogs());
    }
}
