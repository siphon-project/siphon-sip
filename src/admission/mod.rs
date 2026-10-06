//! Inbound call admission control for the B2BUA.
//!
//! A ceiling on what an instance accepts: how many calls it holds at once and
//! how fast new ones may arrive. Checked on the inbound initial INVITE before a
//! call or a script exists, so a refused call costs a response and nothing else.
//!
//! Only inbound calls are ever refused. A call siphon places itself, an INVITE
//! taking over a dialog (RFC 3891) and an emergency call (RFC 5031) each take a
//! slot, so the total stays the number of calls the instance is carrying, but
//! none of them is turned away by it.
//!
//! The slot is an [`AdmissionPermit`] owned by the call. Dropping the call gives
//! it back, which is what makes every teardown path release it without any of
//! them having to remember to.

pub mod refused;

use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// The limits one scope enforces, as resolved from configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundLimits {
    /// Calls held at once. `0` is unlimited.
    pub max_concurrent_calls: u32,
    /// New calls per second, with a burst of one second's worth. `0` is
    /// unlimited.
    pub max_calls_per_second: u32,
    /// Status code a refused INVITE is answered with.
    pub reject_code: u16,
    /// `Retry-After` on the refusal, in seconds. `0` omits the header.
    pub retry_after_secs: u32,
}

impl InboundLimits {
    /// RFC 3261 §21.5.4: the server is temporarily unable to process the
    /// request due to overloading.
    pub const DEFAULT_REJECT_CODE: u16 = 503;
    /// Long enough for a peer to try elsewhere, short enough not to black a
    /// trunk out over one refused call.
    pub const DEFAULT_RETRY_AFTER_SECS: u32 = 1;

    /// No ceiling of either kind.
    pub const UNLIMITED: Self = Self {
        max_concurrent_calls: 0,
        max_calls_per_second: 0,
        reject_code: Self::DEFAULT_REJECT_CODE,
        retry_after_secs: Self::DEFAULT_RETRY_AFTER_SECS,
    };

    /// Whether either ceiling is set.
    pub fn is_limited(&self) -> bool {
        self.max_concurrent_calls > 0 || self.max_calls_per_second > 0
    }
}

/// The live counters behind one set of [`InboundLimits`].
///
/// The limits are atomics rather than plain fields so they can be replaced
/// while calls hold slots against the same counters.
#[derive(Debug)]
pub struct LimitState {
    active: AtomicU32,
    max_concurrent_calls: AtomicU32,
    max_calls_per_second: AtomicU32,
    reject_code: AtomicU16,
    retry_after_secs: AtomicU32,
    /// What `theoretical_arrival_nanos` is measured from.
    epoch: Instant,
    /// GCRA theoretical arrival time of the next conforming call, in
    /// nanoseconds since `epoch`.
    theoretical_arrival_nanos: AtomicU64,
}

impl LimitState {
    pub fn new(limits: InboundLimits) -> Self {
        Self {
            active: AtomicU32::new(0),
            max_concurrent_calls: AtomicU32::new(limits.max_concurrent_calls),
            max_calls_per_second: AtomicU32::new(limits.max_calls_per_second),
            reject_code: AtomicU16::new(limits.reject_code),
            retry_after_secs: AtomicU32::new(limits.retry_after_secs),
            epoch: Instant::now(),
            theoretical_arrival_nanos: AtomicU64::new(0),
        }
    }

    /// Replace the limits, keeping the slots already held.
    pub fn set_limits(&self, limits: InboundLimits) {
        self.max_concurrent_calls
            .store(limits.max_concurrent_calls, Ordering::Relaxed);
        self.max_calls_per_second
            .store(limits.max_calls_per_second, Ordering::Relaxed);
        self.reject_code
            .store(limits.reject_code, Ordering::Relaxed);
        self.retry_after_secs
            .store(limits.retry_after_secs, Ordering::Relaxed);
    }

    pub fn limits(&self) -> InboundLimits {
        InboundLimits {
            max_concurrent_calls: self.max_concurrent_calls.load(Ordering::Relaxed),
            max_calls_per_second: self.max_calls_per_second.load(Ordering::Relaxed),
            reject_code: self.reject_code.load(Ordering::Relaxed),
            retry_after_secs: self.retry_after_secs.load(Ordering::Relaxed),
        }
    }

    /// Slots currently held.
    pub fn active(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }

    /// Take a slot if one is free. An unlimited state still counts, since the
    /// total is what the gauge reports.
    fn try_take_slot(&self) -> bool {
        let limit = self.max_concurrent_calls.load(Ordering::Relaxed);
        if limit == 0 {
            self.active.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        update_u32(&self.active, |current| {
            (current < limit).then_some(current + 1)
        })
    }

    /// Take a slot whatever the ceiling says.
    fn take_slot_unrefused(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    fn release_slot(&self) {
        update_u32(&self.active, |current| Some(current.saturating_sub(1)));
    }

    /// Whether a call arriving at `now` conforms to the rate, consuming its
    /// place in the schedule if it does.
    ///
    /// The generic cell rate algorithm: one atomic holds the time the next
    /// conforming call is due, each admitted call pushes it out by the emission
    /// interval, and a call is admitted while that time is no further ahead
    /// than the burst tolerance. The tolerance is one second's worth less one
    /// interval, so an idle limiter admits `max_calls_per_second` calls at once
    /// and then one per interval.
    ///
    /// `now` is asked for only when a rate is set, so an instance with no rate
    /// ceiling does not read the clock for every call.
    fn try_take_rate(&self, now: impl FnOnce() -> Instant) -> bool {
        let rate = u64::from(self.max_calls_per_second.load(Ordering::Relaxed));
        if rate == 0 {
            return true;
        }
        let interval = (NANOS_PER_SECOND / rate).max(1);
        let tolerance = interval.saturating_mul(rate - 1);
        let now_nanos = u64::try_from(now().saturating_duration_since(self.epoch).as_nanos())
            .unwrap_or(u64::MAX);
        update_u64(&self.theoretical_arrival_nanos, |arrival| {
            (arrival <= now_nanos.saturating_add(tolerance))
                .then(|| arrival.max(now_nanos).saturating_add(interval))
        })
    }
}

/// Replace the value with `next(current)` unless that is `None`, retrying
/// while another thread gets in between. Returns whether it was replaced.
///
/// Written out as a compare-and-swap loop because the standard library renamed
/// its own form of this between the toolchain the crate's `rust-version` names
/// and current stable, and deprecated the old name: either spelling warns, or
/// does not exist, on one of the two.
fn update_u32(atomic: &AtomicU32, mut next: impl FnMut(u32) -> Option<u32>) -> bool {
    let mut current = atomic.load(Ordering::Relaxed);
    loop {
        let Some(replacement) = next(current) else {
            return false;
        };
        match atomic.compare_exchange_weak(
            current,
            replacement,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// [`update_u32`] for a 64-bit value.
fn update_u64(atomic: &AtomicU64, mut next: impl FnMut(u64) -> Option<u64>) -> bool {
    let mut current = atomic.load(Ordering::Relaxed);
    loop {
        let Some(replacement) = next(current) else {
            return false;
        };
        match atomic.compare_exchange_weak(
            current,
            replacement,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Which ceiling refused a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalScope {
    /// The instance-wide `b2bua.inbound_limit`.
    Global,
    /// The `inbound_limit` of the named gateway group, which admits the
    /// caller's source address.
    Gateway(Arc<str>),
}

impl RefusalScope {
    /// The value written to a refused call's CDR.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Gateway(_) => "gateway",
        }
    }

    /// The gateway group whose limit refused the call, when one did.
    pub fn gateway_group(&self) -> Option<&str> {
        match self {
            Self::Global => None,
            Self::Gateway(name) => Some(name),
        }
    }
}

/// One gateway group's inbound limit, as the admission check takes it: the
/// group's name and the counters calls from it are held against.
#[derive(Debug, Clone)]
pub struct GroupLimit {
    pub name: Arc<str>,
    pub state: Arc<LimitState>,
}

impl GroupLimit {
    fn refusal(&self, reason: RefusalReason) -> Refusal {
        let limits = self.state.limits();
        Refusal {
            scope: RefusalScope::Gateway(Arc::clone(&self.name)),
            reason,
            reject_code: limits.reject_code,
            retry_after_secs: limits.retry_after_secs,
        }
    }
}

/// Which of a scope's two ceilings refused a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// `max_concurrent_calls` was reached.
    Concurrent,
    /// `max_calls_per_second` was exceeded.
    Rate,
}

impl RefusalReason {
    /// The metric label and CDR value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Concurrent => "concurrent",
            Self::Rate => "rate",
        }
    }
}

/// Why an inbound call was not admitted, and how to answer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub scope: RefusalScope,
    pub reason: RefusalReason,
    pub reject_code: u16,
    pub retry_after_secs: u32,
}

/// A call's hold on the capacity it was admitted against.
///
/// Owned by the call. Dropping it releases the slot, so no teardown path can
/// leak one by returning early.
#[derive(Debug)]
pub struct AdmissionPermit {
    /// The instance-wide slot, once taken. `None` only while the permit is
    /// being put together, so that dropping a half-built one gives back
    /// exactly what it holds.
    global: Option<Arc<LimitState>>,
    /// A slot in each gateway group that admits the caller and has a limit.
    /// Empty for most calls, and an empty `Vec` allocates nothing.
    groups: Vec<Arc<LimitState>>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if let Some(global) = &self.global {
            global.release_slot();
        }
        for group in &self.groups {
            group.release_slot();
        }
    }
}

/// The admission decision for inbound calls.
#[derive(Debug)]
pub struct AdmissionController {
    global: Arc<LimitState>,
}

impl AdmissionController {
    pub fn new(global: InboundLimits) -> Self {
        Self {
            global: Arc::new(LimitState::new(global)),
        }
    }

    /// A controller that counts calls and refuses none.
    pub fn unlimited() -> Self {
        Self::new(InboundLimits::UNLIMITED)
    }

    /// Admit an inbound call arriving now, or say why not.
    pub fn admit(&self) -> Result<AdmissionPermit, Refusal> {
        self.admit_with(&[], Instant::now)
    }

    /// [`admit`](Self::admit) at a stated time.
    pub fn admit_at(&self, now: Instant) -> Result<AdmissionPermit, Refusal> {
        self.admit_with(&[], || now)
    }

    /// Admit an inbound call from a source the gateway groups in `groups`
    /// admit, against each of their limits and then the instance's own.
    pub fn admit_from(&self, groups: &[GroupLimit]) -> Result<AdmissionPermit, Refusal> {
        self.admit_with(groups, Instant::now)
    }

    /// [`admit_from`](Self::admit_from) at a stated time.
    pub fn admit_from_at(
        &self,
        groups: &[GroupLimit],
        now: Instant,
    ) -> Result<AdmissionPermit, Refusal> {
        self.admit_with(groups, || now)
    }

    /// Every slot is taken before any rate is consulted: a slot is given back
    /// by dropping the permit, while a place in a rate schedule cannot be
    /// returned, so a call refused for want of a slot must not have spent one.
    ///
    /// Groups come before the instance in both passes. A carrier over its own
    /// limit is then refused in its own name and with its own response code,
    /// and has cost the instance nothing. The one thing that is not undone is
    /// a group's rate, spent on a call the instance's rate then refuses.
    fn admit_with(
        &self,
        groups: &[GroupLimit],
        now: impl FnOnce() -> Instant,
    ) -> Result<AdmissionPermit, Refusal> {
        let mut permit = AdmissionPermit {
            global: None,
            groups: Vec::with_capacity(groups.len()),
        };
        for group in groups {
            if !group.state.try_take_slot() {
                return Err(group.refusal(RefusalReason::Concurrent));
            }
            permit.groups.push(Arc::clone(&group.state));
        }
        if !self.global.try_take_slot() {
            return Err(self.refusal(RefusalReason::Concurrent));
        }
        permit.global = Some(Arc::clone(&self.global));

        // One reading of the clock for every rate, taken only if one is set.
        let mut now = Some(now);
        let mut read: Option<Instant> = None;
        let mut clock = || match read {
            Some(instant) => instant,
            None => {
                let instant = now.take().map_or_else(Instant::now, |now| now());
                read = Some(instant);
                instant
            }
        };
        for group in groups {
            if !group.state.try_take_rate(&mut clock) {
                return Err(group.refusal(RefusalReason::Rate));
            }
        }
        if !self.global.try_take_rate(&mut clock) {
            return Err(self.refusal(RefusalReason::Rate));
        }
        Ok(permit)
    }

    /// Count a call that is never refused: one siphon originated, a dialog
    /// takeover, an emergency call. It holds a slot and spends no rate.
    pub fn admit_unrefused(&self) -> AdmissionPermit {
        self.admit_unrefused_from(&[])
    }

    /// [`admit_unrefused`](Self::admit_unrefused) for a call from a source the
    /// gateway groups in `groups` admit. It holds a slot in each, so a group's
    /// count stays the number of calls it has up.
    pub fn admit_unrefused_from(&self, groups: &[GroupLimit]) -> AdmissionPermit {
        self.global.take_slot_unrefused();
        AdmissionPermit {
            global: Some(Arc::clone(&self.global)),
            groups: groups
                .iter()
                .map(|group| {
                    group.state.take_slot_unrefused();
                    Arc::clone(&group.state)
                })
                .collect(),
        }
    }

    /// Calls currently holding a slot.
    pub fn active(&self) -> u32 {
        self.global.active()
    }

    /// The instance-wide limits in force.
    pub fn limits(&self) -> InboundLimits {
        self.global.limits()
    }

    fn refusal(&self, reason: RefusalReason) -> Refusal {
        let limits = self.global.limits();
        Refusal {
            scope: RefusalScope::Global,
            reason,
            reject_code: limits.reject_code,
            retry_after_secs: limits.retry_after_secs,
        }
    }
}

/// Whether a request URI names an emergency service: `urn:service:sos` or one
/// of its sub-services such as `urn:service:sos.fire` (RFC 5031 §4.1). Takes the
/// URI's scheme and the rest of it apart, which is how the SIP parser holds a
/// URN. Service labels compare case-insensitively (RFC 5031 §3).
pub fn is_emergency_service_urn(scheme: &str, rest: &str) -> bool {
    const SOS: &str = "service:sos";
    if !scheme.eq_ignore_ascii_case("urn") {
        return false;
    }
    let Some(head) = rest.get(..SOS.len()) else {
        return false;
    };
    head.eq_ignore_ascii_case(SOS) && matches!(rest.as_bytes().get(SOS.len()), None | Some(b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limits(max_concurrent_calls: u32, max_calls_per_second: u32) -> InboundLimits {
        InboundLimits {
            max_concurrent_calls,
            max_calls_per_second,
            ..InboundLimits::UNLIMITED
        }
    }

    #[test]
    fn an_unlimited_controller_admits_and_counts() {
        let controller = AdmissionController::unlimited();
        let permits: Vec<_> = (0..1000)
            .map(|_| controller.admit().expect("nothing to refuse it"))
            .collect();
        assert_eq!(controller.active(), 1000);
        drop(permits);
        assert_eq!(controller.active(), 0);
    }

    #[test]
    fn the_call_past_the_concurrent_ceiling_is_refused() {
        let controller = AdmissionController::new(limits(2, 0));
        let first = controller.admit().expect("first slot");
        let _second = controller.admit().expect("second slot");
        let refusal = controller.admit().expect_err("no third slot");
        assert_eq!(
            refusal,
            Refusal {
                scope: RefusalScope::Global,
                reason: RefusalReason::Concurrent,
                reject_code: 503,
                retry_after_secs: 1,
            }
        );
        assert_eq!(controller.active(), 2, "a refusal holds nothing");
        drop(first);
        controller.admit().expect("the freed slot");
    }

    #[test]
    fn a_refusal_carries_the_configured_code_and_retry_after() {
        let controller = AdmissionController::new(InboundLimits {
            max_concurrent_calls: 1,
            max_calls_per_second: 0,
            reject_code: 486,
            retry_after_secs: 0,
        });
        let _held = controller.admit().expect("the one slot");
        let refusal = controller.admit().expect_err("no second slot");
        assert_eq!(refusal.reject_code, 486);
        assert_eq!(refusal.retry_after_secs, 0);
    }

    /// Hand-computed for 4 calls per second: interval 250 ms, tolerance 750 ms.
    /// An idle limiter admits four at once, then one each 250 ms.
    #[test]
    fn the_rate_follows_the_gcra_schedule() {
        let state = LimitState::new(limits(0, 4));
        let start = state.epoch;
        let at = |millis: u64| start + Duration::from_millis(millis);

        let burst: Vec<bool> = (0..5).map(|_| state.try_take_rate(|| at(0))).collect();
        assert_eq!(burst, [true, true, true, true, false]);

        assert!(
            !state.try_take_rate(|| at(249)),
            "one interval has not passed"
        );
        assert!(state.try_take_rate(|| at(250)));
        assert!(!state.try_take_rate(|| at(250)));
        assert!(state.try_take_rate(|| at(500)));
        assert!(state.try_take_rate(|| at(750)));
        assert!(!state.try_take_rate(|| at(999)));

        // A full idle second refills the burst and no more than the burst.
        let refilled: Vec<bool> = (0..5).map(|_| state.try_take_rate(|| at(3000))).collect();
        assert_eq!(refilled, [true, true, true, true, false]);
    }

    #[test]
    fn a_rate_of_one_admits_one_call_each_second() {
        let state = LimitState::new(limits(0, 1));
        let start = state.epoch;
        assert!(state.try_take_rate(|| start));
        assert!(!state.try_take_rate(|| start + Duration::from_millis(999)));
        assert!(state.try_take_rate(|| start + Duration::from_secs(1)));
    }

    #[test]
    fn a_call_refused_on_rate_gives_its_slot_back() {
        let controller = AdmissionController::new(limits(10, 1));
        let now = Instant::now();
        let _held = controller
            .admit_at(now)
            .expect("the first call of the second");
        let refusal = controller.admit_at(now).expect_err("over the rate");
        assert_eq!(refusal.reason, RefusalReason::Rate);
        assert_eq!(controller.active(), 1);
    }

    #[test]
    fn a_call_refused_for_a_slot_spends_no_rate() {
        let controller = AdmissionController::new(limits(1, 2));
        let now = Instant::now();
        let held = controller.admit_at(now).expect("the one slot");
        for _ in 0..50 {
            let refusal = controller.admit_at(now).expect_err("no slot");
            assert_eq!(refusal.reason, RefusalReason::Concurrent);
        }
        drop(held);
        controller
            .admit_at(now)
            .expect("the second call of the second is still in the schedule");
    }

    #[test]
    fn an_unrefused_call_takes_a_slot_past_the_ceiling_and_no_rate() {
        let controller = AdmissionController::new(limits(1, 1));
        let now = Instant::now();
        let unrefused: Vec<_> = (0..5).map(|_| controller.admit_unrefused()).collect();
        assert_eq!(controller.active(), 5);
        assert_eq!(
            controller
                .admit_at(now)
                .expect_err("the ceiling is passed")
                .reason,
            RefusalReason::Concurrent
        );
        drop(unrefused);
        controller
            .admit_at(now)
            .expect("the unrefused calls left the rate schedule alone");
    }

    #[test]
    fn limits_change_in_place_and_keep_the_held_slots() {
        let state = Arc::new(LimitState::new(limits(1, 0)));
        let controller = AdmissionController {
            global: Arc::clone(&state),
        };
        let _held = controller.admit().expect("the one slot");
        controller.admit().expect_err("no second slot");

        state.set_limits(limits(2, 0));
        assert_eq!(controller.active(), 1);
        let _second = controller.admit().expect("the raised ceiling");
        controller.admit().expect_err("no third slot");
        assert_eq!(controller.limits().max_concurrent_calls, 2);
    }

    #[test]
    fn the_concurrent_ceiling_is_exact_under_contention() {
        const CEILING: u32 = 64;
        let controller = Arc::new(AdmissionController::new(limits(CEILING, 0)));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let controller = Arc::clone(&controller);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..1000)
                        .filter_map(|_| controller.admit().ok())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let permits: Vec<AdmissionPermit> = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("an admitting thread"))
            .collect();
        assert_eq!(permits.len() as u32, CEILING);
        assert_eq!(controller.active(), CEILING);
        drop(permits);
        assert_eq!(controller.active(), 0);
    }

    /// The per-module leak gate: complete admit-and-release cycles, refused
    /// calls among them, leave nothing held.
    #[test]
    fn slots_drain_to_baseline_after_complete_cycles() {
        let controller = AdmissionController::new(limits(8, 0));
        for round in 0..10_000u32 {
            let mut held = Vec::new();
            for _ in 0..12 {
                if let Ok(permit) = controller.admit() {
                    held.push(permit);
                }
            }
            held.push(controller.admit_unrefused());
            assert_eq!(controller.active(), 9, "round {round}");
            drop(held);
            assert_eq!(controller.active(), 0, "round {round}");
        }
    }

    fn group(name: &str, limits: InboundLimits) -> GroupLimit {
        GroupLimit {
            name: Arc::from(name),
            state: Arc::new(LimitState::new(limits)),
        }
    }

    #[test]
    fn a_call_past_its_groups_ceiling_is_refused_in_the_groups_name() {
        let controller = AdmissionController::unlimited();
        let carrier = group(
            "carrier-a",
            InboundLimits {
                max_concurrent_calls: 1,
                max_calls_per_second: 0,
                reject_code: 486,
                retry_after_secs: 0,
            },
        );
        let groups = [carrier.clone()];
        let held = controller
            .admit_from(&groups)
            .expect("the group's one slot");
        assert_eq!(carrier.state.active(), 1);
        assert_eq!(controller.active(), 1);

        let refusal = controller.admit_from(&groups).expect_err("no second slot");
        assert_eq!(
            refusal,
            Refusal {
                scope: RefusalScope::Gateway(Arc::from("carrier-a")),
                reason: RefusalReason::Concurrent,
                reject_code: 486,
                retry_after_secs: 0,
            }
        );
        assert_eq!(refusal.scope.gateway_group(), Some("carrier-a"));
        assert_eq!(
            controller.active(),
            1,
            "the refusal cost the instance nothing"
        );

        // A caller from no limited group is not held to that group's ceiling.
        controller.admit().expect("another source");
        drop(held);
        assert_eq!(carrier.state.active(), 0);
        controller.admit_from(&groups).expect("the freed slot");
    }

    #[test]
    fn a_source_in_two_limited_groups_is_counted_against_both() {
        let controller = AdmissionController::unlimited();
        let wide = group("wide", limits(2, 0));
        let narrow = group("narrow", limits(1, 0));
        let both = [wide.clone(), narrow.clone()];

        let held = controller.admit_from(&both).expect("a slot in each");
        assert_eq!((wide.state.active(), narrow.state.active()), (1, 1));

        let refusal = controller.admit_from(&both).expect_err("narrow is full");
        assert_eq!(refusal.scope.gateway_group(), Some("narrow"));
        assert_eq!(
            wide.state.active(),
            1,
            "the slot taken in the first group was given back"
        );
        assert_eq!(controller.active(), 1);

        drop(held);
        assert_eq!((wide.state.active(), narrow.state.active()), (0, 0));
        assert_eq!(controller.active(), 0);
    }

    #[test]
    fn the_instance_ceiling_refuses_a_group_caller_and_returns_the_groups_slot() {
        let controller = AdmissionController::new(limits(1, 0));
        let carrier = group("carrier-a", limits(10, 0));
        let groups = [carrier.clone()];
        let _held = controller.admit().expect("the instance's one slot");

        let refusal = controller
            .admit_from(&groups)
            .expect_err("the instance is full");
        assert_eq!(refusal.scope, RefusalScope::Global);
        assert_eq!(carrier.state.active(), 0);
    }

    #[test]
    fn a_groups_rate_refuses_in_its_name_and_holds_no_slot() {
        let controller = AdmissionController::unlimited();
        let carrier = group("carrier-a", limits(0, 1));
        let groups = [carrier.clone()];
        let now = Instant::now();
        let _held = controller
            .admit_from_at(&groups, now)
            .expect("the first call");
        let refusal = controller
            .admit_from_at(&groups, now)
            .expect_err("over the group's rate");
        assert_eq!(refusal.scope.gateway_group(), Some("carrier-a"));
        assert_eq!(refusal.reason, RefusalReason::Rate);
        assert_eq!(carrier.state.active(), 1);
        assert_eq!(controller.active(), 1);
        controller
            .admit_at(now)
            .expect("the instance has no rate and another source is not held to the group's");
    }

    #[test]
    fn an_unrefused_call_from_a_group_is_counted_in_it() {
        let controller = AdmissionController::new(limits(1, 0));
        let carrier = group("carrier-a", limits(1, 0));
        let groups = [carrier.clone()];
        let permits: Vec<_> = (0..3)
            .map(|_| controller.admit_unrefused_from(&groups))
            .collect();
        assert_eq!(carrier.state.active(), 3);
        assert_eq!(controller.active(), 3);
        drop(permits);
        assert_eq!(carrier.state.active(), 0);
        assert_eq!(controller.active(), 0);
    }

    /// The per-module leak gate for the group half: admitted, refused by the
    /// group, refused by the instance and unrefused calls all leave both
    /// counts where they started.
    #[test]
    fn group_slots_drain_to_baseline_after_complete_cycles() {
        let controller = AdmissionController::new(limits(6, 0));
        let first = group("first", limits(4, 0));
        let second = group("second", limits(3, 0));
        let both = [first.clone(), second.clone()];
        let only_first = [first.clone()];
        for round in 0..5_000u32 {
            let mut held = Vec::new();
            for _ in 0..5 {
                held.extend(controller.admit_from(&both).ok());
                held.extend(controller.admit_from(&only_first).ok());
                held.extend(controller.admit().ok());
            }
            held.push(controller.admit_unrefused_from(&both));
            drop(held);
            assert_eq!(controller.active(), 0, "round {round}");
            assert_eq!(first.state.active(), 0, "round {round}");
            assert_eq!(second.state.active(), 0, "round {round}");
        }
    }

    #[test]
    fn a_release_never_wraps_below_zero() {
        let state = LimitState::new(InboundLimits::UNLIMITED);
        state.release_slot();
        assert_eq!(state.active(), 0);
    }

    #[test]
    fn unlimited_limits_are_not_limited() {
        assert!(!InboundLimits::UNLIMITED.is_limited());
        assert!(limits(1, 0).is_limited());
        assert!(limits(0, 1).is_limited());
    }

    #[test]
    fn emergency_service_urns_are_recognised() {
        for (scheme, rest) in [
            ("urn", "service:sos"),
            ("URN", "SERVICE:SOS"),
            ("urn", "service:sos.fire"),
            ("urn", "service:sos.police.municipal"),
        ] {
            assert!(is_emergency_service_urn(scheme, rest), "{scheme}:{rest}");
        }
        for (scheme, rest) in [
            ("urn", "service:sosx"),
            ("urn", "service:counseling"),
            ("urn", "service:so"),
            ("urn", ""),
            ("sip", "service:sos"),
            ("tel", "112"),
        ] {
            assert!(!is_emergency_service_urn(scheme, rest), "{scheme}:{rest}");
        }
    }

    #[test]
    fn refusal_labels_are_stable() {
        assert_eq!(RefusalScope::Global.as_str(), "global");
        assert_eq!(RefusalScope::Gateway(Arc::from("x")).as_str(), "gateway");
        assert_eq!(RefusalScope::Global.gateway_group(), None);
        assert_eq!(RefusalReason::Concurrent.as_str(), "concurrent");
        assert_eq!(RefusalReason::Rate.as_str(), "rate");
    }
}
