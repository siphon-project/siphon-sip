//! Draining the registrar's and the registrant's state-change broadcasts into
//! their consumers, and recovering when a consumer falls behind.
//!
//! Both publish on a bounded `tokio::sync::broadcast` channel. A receiver that
//! falls more than the channel's capacity behind gets `RecvError::Lagged(n)`:
//! `n` events are gone, and it resumes from the oldest one still held. Treating
//! that as the end of the stream (`while let Ok(..) = recv().await`) stops every
//! consumer for the life of the process with nothing logged, which is what a
//! registration storm after a restart, against a slow `@registrar.on_change`
//! handler, does.
//!
//! So a lag is counted (`siphon_event_consumer_lagged_total`), logged, and
//! answered with a **snapshot**: one delivery per AoR, tagged `snapshot` rather
//! than a change, each reading the AoR's current state the way every live event
//! already does. A consumer that keeps its own copy is whole again for every
//! AoR.
//!
//! The snapshot is not a walk that blocks the channel. Re-reporting thousands
//! of AoRs one handler call at a time takes longer than a channel of a few
//! thousand events absorbs a live stream, so a loop that finished the walk
//! before it read the channel again lagged again, started another walk, and
//! never recovered, losing every live event meanwhile. Instead a lag turns the
//! snapshot into a *pending set*, and the loop interleaves: it delivers every
//! live event that is ready first, delivers one pending AoR only when none is,
//! and waits on the channel when nothing is pending. A live event for a pending
//! AoR drops it from the set (it was just reported with current state). A lag
//! while a snapshot is pending **replaces** the pending set with a fresh one; a
//! second full snapshot is never queued behind the first.
//!
//! The loop remembers which AoRs it last reported as present (registered or
//! refreshed, or a snapshot of one with bindings; dropped on deregistered or
//! expired). The pending set is the AoRs held now plus those remembered AoRs
//! that are held no longer, so a deregistration or expiry lost inside the lag
//! window is re-reported too, as a `snapshot` of an AoR with no bindings, which
//! the handler reads exactly as it reads a live removal. The remembered set only
//! ever holds present AoRs, so it is bounded by what the source holds.
//!
//! Only the end of the channel (`RecvError::Closed`, the source dropped) ends
//! a loop.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::metrics::event_lag::{
    record_lag, record_snapshot_aor, record_snapshot_started, LaggedConsumer,
};
use crate::registrant::{RegistrantEvent, RegistrantManager};
use crate::registrar::{RegisterExchange, Registrar, RegistrationEvent};

/// The `event` a delivery carries when it re-reports held state after a lag
/// instead of reporting a change.
pub(crate) const SNAPSHOT: &str = "snapshot";

/// One registrar delivery: which AoR, and what happened to it (`registered`,
/// `refreshed`, `deregistered`, `expired`, or [`SNAPSHOT`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistrarChange {
    pub aor: String,
    pub event: &'static str,
    /// The REGISTER behind the change and its 200 OK, when this node received
    /// and answered one. `None` for an expiry, a network or admin removal and
    /// a snapshot.
    pub exchange: Option<Arc<RegisterExchange>>,
}

impl RegistrarChange {
    fn from_event(event: RegistrationEvent) -> Self {
        let (aor, event, exchange) = match event {
            RegistrationEvent::Registered { aor, exchange } => (aor, "registered", exchange),
            RegistrationEvent::Refreshed { aor, exchange } => (aor, "refreshed", exchange),
            RegistrationEvent::Deregistered { aor, exchange } => (aor, "deregistered", exchange),
            RegistrationEvent::Expired { aor } => (aor, "expired", None),
        };
        Self {
            aor,
            event,
            exchange,
        }
    }

    /// Whether this re-reports held state rather than a change.
    pub fn is_snapshot(&self) -> bool {
        self.event == SNAPSHOT
    }
}

/// One registrant (outbound REGISTER) delivery: which AoR, what happened
/// (`registered`, `refreshed`, `failed`, `deregistered`, `awaiting_address`,
/// or [`SNAPSHOT`]), and
/// the status a `failed` carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistrantChange {
    pub aor: String,
    pub event: &'static str,
    pub status_code: Option<u16>,
}

impl RegistrantChange {
    fn from_event(event: RegistrantEvent) -> Self {
        let (aor, event, status_code) = match event {
            RegistrantEvent::Registered { aor } => (aor, "registered", None),
            RegistrantEvent::Refreshed { aor } => (aor, "refreshed", None),
            RegistrantEvent::Failed { aor, status_code } => (aor, "failed", Some(status_code)),
            RegistrantEvent::Deregistered { aor } => (aor, "deregistered", None),
            RegistrantEvent::AwaitingAddress { aor } => (aor, "awaiting_address", None),
        };
        Self {
            aor,
            event,
            status_code,
        }
    }
}

/// What a delivered change says about whether its AoR is still held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence {
    Present,
    Absent,
}

/// What differs between the registrar and the registrant consumer; the drain
/// loop is the same.
trait EventSource {
    type Event: Clone;
    type Change;
    const CONSUMER: LaggedConsumer;

    fn change(&self, event: Self::Event) -> Self::Change;
    fn aor<'a>(&self, change: &'a Self::Change) -> &'a str;
    fn presence(&self, change: &Self::Change) -> Presence;
    fn snapshot(&self, aor: String) -> Self::Change;
    /// Every AoR the source holds now.
    fn held(&self) -> HashSet<String>;
    /// Number the lost events, so a controller sees the gap in `seq`.
    fn skip(&self, skipped: u64);
    fn log_lag(&self, skipped: u64, pending: usize);
}

/// The AoRs the loop last reported as present, and the snapshot still to be
/// delivered.
#[derive(Default)]
struct Recovery {
    known: HashSet<String>,
    /// AoRs to re-report, with whether each was held when the lag was seen.
    queue: VecDeque<(String, bool)>,
    /// The members of `queue` not yet delivered or superseded by a live event.
    pending: HashSet<String>,
}

impl Recovery {
    /// Note what a delivered change says about its AoR. A live event for a
    /// pending AoR takes it out of the snapshot.
    fn track(&mut self, aor: &str, presence: Presence) {
        match presence {
            Presence::Present => {
                if !self.known.contains(aor) {
                    self.known.insert(aor.to_string());
                }
            }
            Presence::Absent => {
                self.known.remove(aor);
            }
        }
        if !self.pending.is_empty() {
            self.pending.remove(aor);
        }
    }

    /// Start a snapshot of `held` plus every remembered AoR that is not held
    /// now, dropping whatever an earlier one still had pending.
    fn begin_snapshot(&mut self, held: HashSet<String>) -> usize {
        self.queue.clear();
        self.pending.clear();
        let gone: Vec<String> = self
            .known
            .iter()
            .filter(|aor| !held.contains(*aor))
            .cloned()
            .collect();
        for aor in held {
            self.pending.insert(aor.clone());
            self.queue.push_back((aor, true));
        }
        for aor in gone {
            self.pending.insert(aor.clone());
            self.queue.push_back((aor, false));
        }
        self.pending.len()
    }

    /// The next AoR to re-report, skipping those a live event has covered.
    /// Reporting it settles what is remembered about it.
    fn next_pending(&mut self) -> Option<String> {
        while let Some((aor, held)) = self.queue.pop_front() {
            if !self.pending.remove(&aor) {
                continue;
            }
            if held {
                if !self.known.contains(&aor) {
                    self.known.insert(aor.clone());
                }
            } else {
                self.known.remove(&aor);
            }
            return Some(aor);
        }
        None
    }
}

/// Feed every event to `deliver`, one at a time, until the channel closes.
/// Live events go first; a lag starts a snapshot that is delivered one AoR at a
/// time while no live event is waiting.
async fn drain_events<S, D, F>(
    mut receiver: broadcast::Receiver<S::Event>,
    source: S,
    mut deliver: D,
) where
    S: EventSource,
    D: FnMut(S::Change) -> F,
    F: Future<Output = ()>,
{
    use broadcast::error::{RecvError, TryRecvError};

    let mut recovery = Recovery::default();
    loop {
        let received = match receiver.try_recv() {
            Ok(event) => Ok(event),
            Err(TryRecvError::Lagged(skipped)) => Err(RecvError::Lagged(skipped)),
            Err(TryRecvError::Closed) => Err(RecvError::Closed),
            Err(TryRecvError::Empty) => {
                if let Some(aor) = recovery.next_pending() {
                    record_snapshot_aor(S::CONSUMER);
                    deliver(source.snapshot(aor)).await;
                    continue;
                }
                receiver.recv().await
            }
        };
        match received {
            Ok(event) => {
                let change = source.change(event);
                recovery.track(source.aor(&change), source.presence(&change));
                deliver(change).await;
            }
            Err(RecvError::Lagged(skipped)) => {
                record_lag(S::CONSUMER, skipped);
                source.skip(skipped);
                record_snapshot_started(S::CONSUMER);
                let pending = recovery.begin_snapshot(source.held());
                source.log_lag(skipped, pending);
            }
            Err(RecvError::Closed) => {
                info!(
                    consumer = S::CONSUMER.as_str(),
                    "state-change events: the event channel closed, the event task ends"
                );
                break;
            }
        }
    }
}

struct RegistrarSource {
    registrar: Arc<Registrar>,
}

impl EventSource for RegistrarSource {
    type Event = RegistrationEvent;
    type Change = RegistrarChange;
    const CONSUMER: LaggedConsumer = LaggedConsumer::Registrar;

    fn change(&self, event: RegistrationEvent) -> RegistrarChange {
        RegistrarChange::from_event(event)
    }

    fn aor<'a>(&self, change: &'a RegistrarChange) -> &'a str {
        &change.aor
    }

    fn presence(&self, change: &RegistrarChange) -> Presence {
        match change.event {
            "deregistered" | "expired" => Presence::Absent,
            _ => Presence::Present,
        }
    }

    fn snapshot(&self, aor: String) -> RegistrarChange {
        RegistrarChange {
            aor,
            event: SNAPSHOT,
            exchange: None,
        }
    }

    fn held(&self) -> HashSet<String> {
        self.registrar.registered_aors().into_iter().collect()
    }

    fn skip(&self, skipped: u64) {
        crate::control::registration::skip_registration_events(skipped);
    }

    fn log_lag(&self, skipped: u64, pending: usize) {
        warn!(
            skipped,
            pending,
            "registrar events: @registrar.on_change and RegistrationChanged fell behind the \
             registrar and lost events; re-reporting the current state of every registered AoR, \
             and of every AoR last reported present that is gone, as a snapshot between live \
             events. Counted in siphon_event_consumer_lagged_total{{consumer=\"registrar\"}}; \
             raise registrar.event_capacity if it repeats"
        );
    }
}

struct RegistrantSource {
    registrant: Arc<RegistrantManager>,
}

impl EventSource for RegistrantSource {
    type Event = RegistrantEvent;
    type Change = RegistrantChange;
    const CONSUMER: LaggedConsumer = LaggedConsumer::Registrant;

    fn change(&self, event: RegistrantEvent) -> RegistrantChange {
        RegistrantChange::from_event(event)
    }

    fn aor<'a>(&self, change: &'a RegistrantChange) -> &'a str {
        &change.aor
    }

    fn presence(&self, change: &RegistrantChange) -> Presence {
        match change.event {
            "deregistered" => Presence::Absent,
            _ => Presence::Present,
        }
    }

    fn snapshot(&self, aor: String) -> RegistrantChange {
        RegistrantChange {
            aor,
            event: SNAPSHOT,
            status_code: None,
        }
    }

    fn held(&self) -> HashSet<String> {
        self.registrant
            .list()
            .into_iter()
            .map(|(aor, _, _)| aor)
            .collect()
    }

    fn skip(&self, skipped: u64) {
        crate::control::registration::skip_registrant_events(skipped);
    }

    fn log_lag(&self, skipped: u64, pending: usize) {
        warn!(
            skipped,
            pending,
            "registrant events: @registration.on_change fell behind the outbound registrations \
             and lost events; re-reporting the current state of every outbound registration, \
             and of every one last reported present that is gone, as a snapshot between live \
             events. Counted in siphon_event_consumer_lagged_total{{consumer=\"registrant\"}}"
        );
    }
}

/// Feed every registrar event to `deliver`, one at a time, until the channel
/// closes. A lag is counted and answered with a [`SNAPSHOT`] delivery per AoR,
/// interleaved with the live events (see the module documentation).
pub(crate) async fn drain_registrar_events<D, F>(
    receiver: broadcast::Receiver<RegistrationEvent>,
    registrar: Arc<Registrar>,
    deliver: D,
) where
    D: FnMut(RegistrarChange) -> F,
    F: Future<Output = ()>,
{
    drain_events(receiver, RegistrarSource { registrar }, deliver).await;
}

/// Feed every registrant event to `deliver`, one at a time, until the channel
/// closes. A lag is counted and answered with a [`SNAPSHOT`] delivery per
/// outbound registration, interleaved with the live events.
pub(crate) async fn drain_registrant_events<D, F>(
    receiver: broadcast::Receiver<RegistrantEvent>,
    registrant: Arc<RegistrantManager>,
    deliver: D,
) where
    D: FnMut(RegistrantChange) -> F,
    F: Future<Output = ()>,
{
    drain_events(receiver, RegistrantSource { registrant }, deliver).await;
}

#[cfg(test)]
#[path = "registration_events_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "registration_events_recovery_tests.rs"]
mod recovery_tests;
