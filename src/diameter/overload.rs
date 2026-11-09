//! Diameter Overload Indication Conveyance (RFC 7683), loss algorithm.
//!
//! * The AVPs: OC-Supported-Features (621), OC-Feature-Vector (622), OC-OLR
//!   (623), OC-Sequence-Number (624), OC-Validity-Duration (625),
//!   OC-Report-Type (626) and OC-Reduction-Percentage (627), all without the
//!   M bit so a node that does not know them ignores them.
//! * The reacting node ([`ReactingTable`]): applies the OC-OLR of an answer by
//!   abating that share of the requests it sends towards the reporting node,
//!   until the validity runs out or a newer report says otherwise.
//! * The reporting node ([`ReportingState`]): turns a load into the OC-OLR
//!   that goes in answers to requests whose sender advertised DOIC.
//! * A relay (RFC 7683 section 5.2.3) leaves every OC-* AVP alone: it passes
//!   them through unchanged, so the reacting node and the reporting node
//!   behind it talk to each other. Nothing in the relay path reads or writes
//!   them.

use super::codec::{Avp, AvpData, DiameterMsg};
use super::dictionary::avp;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

/// OC-Feature-Vector bit of the default loss algorithm (RFC 7683 section 7.3,
/// OLR_DEFAULT_ALGO).
pub const FEATURE_LOSS: u64 = 0x0000_0000_0000_0001;
/// OC-Validity-Duration when the report gives none (section 7.4: 30 s).
pub const DEFAULT_VALIDITY_SECS: u32 = 30;
/// The longest OC-Validity-Duration (section 7.4: 86400 s).
pub const MAX_VALIDITY_SECS: u32 = 86_400;

/// OC-Report-Type (section 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportType {
    /// The report concerns the reporting host.
    Host = 0,
    /// The report concerns the realm the reporting host serves.
    Realm = 1,
}

impl ReportType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Host),
            1 => Some(Self::Realm),
            _ => None,
        }
    }
}

/// An OC-OLR: what a reporting node asks of those that send it requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Olr {
    pub sequence: u64,
    pub report_type: ReportType,
    pub validity_secs: u32,
    pub reduction_percentage: u32,
}

fn grouped(code: u32, children: Vec<Avp>) -> Avp {
    Avp {
        code,
        vendor: 0,
        flags: 0,
        value: AvpData::Grouped(children),
    }
}

/// OC-Supported-Features carrying OC-Feature-Vector `vector`.
pub fn supported_features_avp(vector: u64) -> Avp {
    grouped(
        avp::OC_SUPPORTED_FEATURES,
        vec![Avp::raw(
            avp::OC_FEATURE_VECTOR,
            0,
            vector.to_be_bytes().to_vec(),
        )],
    )
}

/// The OC-OLR AVP of `olr`.
pub fn olr_avp(olr: &Olr) -> Avp {
    grouped(
        avp::OC_OLR,
        vec![
            Avp::raw(avp::OC_SEQUENCE_NUMBER, 0, olr.sequence.to_be_bytes().to_vec()),
            Avp::u32(avp::OC_REPORT_TYPE, 0, olr.report_type as u32),
            Avp::u32(avp::OC_REDUCTION_PERCENTAGE, 0, olr.reduction_percentage),
            Avp::u32(avp::OC_VALIDITY_DURATION, 0, olr.validity_secs),
        ],
    )
}

fn child<'a>(children: &'a [Avp], code: u32) -> Option<&'a Avp> {
    children.iter().find(|avp| avp.code == code && avp.vendor == 0)
}

fn as_u64(avp: &Avp) -> Option<u64> {
    let bytes = avp.raw_bytes()?;
    Some(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).ok()?))
}

/// The OC-Feature-Vector the sender of `message` advertised, 0 when it did
/// not advertise DOIC.
pub fn advertised_features(message: &DiameterMsg) -> u64 {
    let Some(Avp {
        value: AvpData::Grouped(children),
        ..
    }) = message.find(avp::OC_SUPPORTED_FEATURES, 0)
    else {
        return 0;
    };
    child(children, avp::OC_FEATURE_VECTOR)
        .and_then(as_u64)
        .unwrap_or(0)
}

/// Whether the sender of `message` supports the loss algorithm.
pub fn supports_loss(message: &DiameterMsg) -> bool {
    advertised_features(message) & FEATURE_LOSS != 0
}

/// The OC-OLR of `message`, None when there is none or it is not usable: no
/// sequence number, an unknown report type, a reduction above 100 %.
/// A missing reduction is 0 %, a missing validity 30 s, and a validity above
/// the maximum is the maximum.
pub fn parse_olr(message: &DiameterMsg) -> Option<Olr> {
    let Some(Avp {
        value: AvpData::Grouped(children),
        ..
    }) = message.find(avp::OC_OLR, 0)
    else {
        return None;
    };
    let sequence = as_u64(child(children, avp::OC_SEQUENCE_NUMBER)?)?;
    let report_type = ReportType::from_u32(child(children, avp::OC_REPORT_TYPE)?.as_u32()?)?;
    let reduction_percentage = match child(children, avp::OC_REDUCTION_PERCENTAGE) {
        Some(avp) => avp.as_u32()?,
        None => 0,
    };
    if reduction_percentage > 100 {
        return None;
    }
    let validity_secs = match child(children, avp::OC_VALIDITY_DURATION) {
        Some(avp) => avp.as_u32()?.min(MAX_VALIDITY_SECS),
        None => DEFAULT_VALIDITY_SECS,
    };
    Some(Olr {
        sequence,
        report_type,
        validity_secs,
        reduction_percentage,
    })
}

/// A uniform draw in `[0, 1)` from a per-thread generator seeded from the
/// system source. Abatement is a statistical choice, not a secret.
pub fn random_unit() -> f64 {
    thread_local! {
        static STATE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            let mut seed = [0u8; 8];
            let _ = getrandom::fill(&mut seed);
            x = u64::from_le_bytes(seed) | 1;
        }
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state.set(x);
        let value = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        (value >> 11) as f64 / (1u64 << 53) as f64
    })
}

// ── Reacting node ───────────────────────────────────────────────────────────

/// What a report is about, as the reacting node keys it: a host or a realm,
/// for one application (RFC 7683 section 5.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportKey {
    pub report_type: ReportType,
    /// The reporting host or realm, lower case.
    pub identity: String,
    pub application_id: u32,
}

impl ReportKey {
    pub fn new(report_type: ReportType, identity: &str, application_id: u32) -> Self {
        Self {
            report_type,
            identity: identity.to_ascii_lowercase(),
            application_id,
        }
    }
}

#[derive(Debug, Clone)]
struct Report {
    sequence: u64,
    expires: Instant,
    reduction: u32,
}

/// What [`ReactingTable::update`] did with a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// The report is in force.
    Applied,
    /// An older or repeated sequence number: the report in force stands.
    Ignored,
    /// The report ends abatement (no reduction, or no validity left).
    Ended,
}

/// The reports in force at a reacting node.
#[derive(Debug, Default)]
pub struct ReactingTable {
    reports: Mutex<HashMap<ReportKey, Report>>,
    /// Reports in force, so the common case (none) costs a load.
    count: AtomicUsize,
}

impl ReactingTable {
    /// Whether any report may be in force.
    pub fn is_idle(&self) -> bool {
        self.count.load(Ordering::Relaxed) == 0
    }

    /// Apply `olr` from the reporting node `key` names. A sequence number
    /// that is not higher than the one in force is ignored (section 5.2.2);
    /// a higher one replaces it, and ends abatement when it asks for no
    /// reduction or no validity.
    pub fn update(&self, key: ReportKey, olr: &Olr, now: Instant) -> Update {
        let Ok(mut reports) = self.reports.lock() else {
            return Update::Ignored;
        };
        if let Some(held) = reports.get(&key) {
            if held.expires > now && olr.sequence <= held.sequence {
                return Update::Ignored;
            }
        }
        if olr.reduction_percentage == 0 || olr.validity_secs == 0 {
            reports.remove(&key);
            self.count.store(reports.len(), Ordering::Relaxed);
            return Update::Ended;
        }
        reports.insert(
            key,
            Report {
                sequence: olr.sequence,
                expires: now + Duration::from_secs(u64::from(olr.validity_secs)),
                reduction: olr.reduction_percentage,
            },
        );
        self.count.store(reports.len(), Ordering::Relaxed);
        Update::Applied
    }

    /// The reduction in force for the first of `keys` that has one, as
    /// (percentage, the key it came from), dropping reports that expired.
    pub fn reduction_for(&self, keys: &[ReportKey], now: Instant) -> Option<(u32, ReportKey)> {
        if self.is_idle() {
            return None;
        }
        let mut reports = self.reports.lock().ok()?;
        let mut strongest: Option<(u32, ReportKey)> = None;
        for key in keys {
            let Some(report) = reports.get(key) else {
                continue;
            };
            if report.expires <= now {
                reports.remove(key);
                self.count.store(reports.len(), Ordering::Relaxed);
                continue;
            }
            if strongest
                .as_ref()
                .is_none_or(|(reduction, _)| report.reduction > *reduction)
            {
                strongest = Some((report.reduction, key.clone()));
            }
        }
        strongest
    }

    /// Whether a request towards the nodes `keys` names is abated, drawing
    /// with `unit` in `[0, 1)`: the share of requests abated is the reduction
    /// percentage. Returns the key that abated it.
    pub fn abate(&self, keys: &[ReportKey], now: Instant, unit: f64) -> Option<ReportKey> {
        let (reduction, key) = self.reduction_for(keys, now)?;
        (unit * 100.0 < f64::from(reduction)).then_some(key)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

// ── Reporting node ──────────────────────────────────────────────────────────

/// How the reporting node derives a reduction from its pending-request depth:
/// nothing up to `start`, rising linearly to `max_reduction` at `full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepthScale {
    pub start: usize,
    pub full: usize,
    pub max_reduction: u32,
}

impl DepthScale {
    /// The reduction for `depth` requests pending.
    pub fn reduction(&self, depth: usize) -> u32 {
        if depth <= self.start || self.full <= self.start {
            return if depth >= self.full && depth > self.start {
                self.max_reduction.min(100)
            } else {
                0
            };
        }
        if depth >= self.full {
            return self.max_reduction.min(100);
        }
        let span = (self.full - self.start) as f64;
        let share = (depth - self.start) as f64 / span;
        (share * f64::from(self.max_reduction.min(100))).round() as u32
    }
}

#[derive(Debug, Clone)]
struct Standing {
    reduction: u32,
    sequence: u64,
    expires: Instant,
}

/// The overload this node reports. The load comes from the application (a
/// reduction it sets) and from the pending-request depth; the larger counts.
#[derive(Debug)]
pub struct ReportingState {
    validity_secs: u32,
    depth_scale: Option<DepthScale>,
    set_by_application: AtomicU64,
    set_until: Mutex<Option<Instant>>,
    sequence: AtomicU64,
    standing: Mutex<Option<Standing>>,
}

impl ReportingState {
    pub fn new(validity_secs: u32, depth_scale: Option<DepthScale>) -> Self {
        Self {
            validity_secs: validity_secs.clamp(1, MAX_VALIDITY_SECS),
            depth_scale,
            set_by_application: AtomicU64::new(0),
            set_until: Mutex::new(None),
            // Seeded from the clock so a restart does not reuse numbers a
            // reacting node still holds (section 5.2.1: the sequence number
            // survives restarts or is a timestamp).
            sequence: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_millis() as u64)
                    .unwrap_or(1),
            ),
            standing: Mutex::new(None),
        }
    }

    /// The application reports `reduction` percent (0 clears it), for
    /// `lasts` or, without it, until it is set again.
    pub fn set(&self, reduction: u32, lasts: Option<Duration>, now: Instant) {
        self.set_by_application
            .store(u64::from(reduction.min(100)), Ordering::Relaxed);
        if let Ok(mut until) = self.set_until.lock() {
            *until = lasts.map(|lasts| now + lasts);
        }
    }

    fn application_reduction(&self, now: Instant) -> u32 {
        let set = self.set_by_application.load(Ordering::Relaxed) as u32;
        if set == 0 {
            return 0;
        }
        match self.set_until.lock() {
            Ok(until) if until.is_some_and(|until| until <= now) => 0,
            _ => set,
        }
    }

    /// The reduction this node reports now, given `pending` requests.
    pub fn reduction(&self, pending: usize, now: Instant) -> u32 {
        let by_depth = self
            .depth_scale
            .map_or(0, |scale| scale.reduction(pending));
        self.application_reduction(now).max(by_depth)
    }

    /// The OC-OLR to put in an answer now, None when there is nothing to
    /// report. A change of reduction takes a new sequence number; the same
    /// report is repeated within its validity and renewed (new sequence
    /// number) when half of it is gone. When the overload ends, one report
    /// with no reduction tells the reacting nodes.
    pub fn olr(&self, pending: usize, now: Instant) -> Option<Olr> {
        let reduction = self.reduction(pending, now);
        let mut standing = self.standing.lock().ok()?;
        let validity = Duration::from_secs(u64::from(self.validity_secs));
        let renew = |sequence: &AtomicU64| sequence.fetch_add(1, Ordering::Relaxed) + 1;
        match (standing.as_ref(), reduction) {
            (None, 0) => None,
            (Some(held), 0) => {
                let ended = held.reduction == 0;
                if ended {
                    *standing = None;
                    return None;
                }
                let sequence = renew(&self.sequence);
                *standing = Some(Standing {
                    reduction: 0,
                    sequence,
                    expires: now + validity,
                });
                Some(self.report(sequence, 0))
            }
            (Some(held), _)
                if held.reduction == reduction && held.expires > now + validity / 2 =>
            {
                Some(self.report(held.sequence, reduction))
            }
            (_, _) => {
                let sequence = renew(&self.sequence);
                *standing = Some(Standing {
                    reduction,
                    sequence,
                    expires: now + validity,
                });
                Some(self.report(sequence, reduction))
            }
        }
    }

    fn report(&self, sequence: u64, reduction: u32) -> Olr {
        Olr {
            sequence,
            report_type: ReportType::Host,
            validity_secs: self.validity_secs,
            reduction_percentage: reduction,
        }
    }

    /// Add what the reporting node says to `answer` for a request that
    /// advertised `request_features`: its own OC-Supported-Features always,
    /// the OC-OLR while there is overload to report. An answer that already
    /// carries OC-* AVPs (one relayed from a node behind this one) is left as
    /// it is. Returns whether an OC-OLR was added.
    pub fn annotate(
        &self,
        answer: &mut DiameterMsg,
        request_features: u64,
        pending: usize,
        now: Instant,
    ) -> bool {
        if request_features & FEATURE_LOSS == 0 {
            return false;
        }
        if answer.find(avp::OC_SUPPORTED_FEATURES, 0).is_some()
            || answer.find(avp::OC_OLR, 0).is_some()
        {
            return false;
        }
        answer.avps.push(supported_features_avp(FEATURE_LOSS));
        match self.olr(pending, now) {
            Some(olr) => {
                answer.avps.push(olr_avp(&olr));
                true
            }
            None => false,
        }
    }
}

// ── Process-wide state ──────────────────────────────────────────────────────

/// What a reacting node does with a request it abates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AbatementAction {
    /// Fail it here with DIAMETER_TOO_BUSY (3004).
    #[default]
    Reject,
    /// Send it to another peer of its route where one exists, and fail it
    /// as above where none does.
    Divert,
}

/// The installed overload behaviour of this node.
#[derive(Debug)]
pub struct Overload {
    pub reacting: Option<AbatementAction>,
    pub reporting: Option<ReportingState>,
    pub table: ReactingTable,
}

impl Overload {
    pub fn new(reacting: Option<AbatementAction>, reporting: Option<ReportingState>) -> Self {
        Self {
            reacting,
            reporting,
            table: ReactingTable::default(),
        }
    }
}

static CURRENT: LazyLock<RwLock<std::sync::Arc<Overload>>> =
    LazyLock::new(|| RwLock::new(std::sync::Arc::new(Overload::new(None, None))));

/// The overload behaviour in force. Disabled (every field None) until
/// [`install`] is called.
pub fn current() -> std::sync::Arc<Overload> {
    CURRENT
        .read()
        .map(|current| std::sync::Arc::clone(&current))
        .unwrap_or_else(|poisoned| std::sync::Arc::clone(&poisoned.into_inner()))
}

/// Put `overload` in force.
pub fn install(overload: Overload) {
    let mut current = CURRENT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *current = std::sync::Arc::new(overload);
}
