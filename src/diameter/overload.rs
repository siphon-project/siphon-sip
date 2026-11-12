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
//!   them, unless `diameter.overload.agent` makes it a DOIC agent (section
//!   5.3, see [`super::overload_agent`]).

use super::codec::{Avp, AvpData, DiameterMsg};
use super::dictionary::avp;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
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
            Avp::raw(
                avp::OC_SEQUENCE_NUMBER,
                0,
                olr.sequence.to_be_bytes().to_vec(),
            ),
            Avp::u32(avp::OC_REPORT_TYPE, 0, olr.report_type as u32),
            Avp::u32(avp::OC_REDUCTION_PERCENTAGE, 0, olr.reduction_percentage),
            Avp::u32(avp::OC_VALIDITY_DURATION, 0, olr.validity_secs),
        ],
    )
}

fn child(children: &[Avp], code: u32) -> Option<&Avp> {
    children
        .iter()
        .find(|avp| avp.code == code && avp.vendor == 0)
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

/// The reduction moves in multiples of this when the admission limit sheds.
const SHED_STEP: u32 = 10;
/// How long shedding must stay away before the reduction it caused drops by
/// a step, and how long a reduction that did not stop the shedding holds
/// before it is raised by one.
const SHED_HOLD: Duration = Duration::from_secs(2);

/// What the admission limit asks of the requesters.
#[derive(Debug, Default)]
struct Shed {
    level: u32,
    last_shed: Option<Instant>,
    last_raised: Option<Instant>,
}

impl Shed {
    /// The level at `now`: it leaves one step per `SHED_HOLD` without a shed.
    fn at(&self, now: Instant) -> u32 {
        let Some(last) = self.last_shed else {
            return 0;
        };
        let quiet = now.saturating_duration_since(last).as_millis() / SHED_HOLD.as_millis();
        self.level
            .saturating_sub((quiet as u32).saturating_mul(SHED_STEP))
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
    report_type: ReportType,
    validity_secs: u32,
    depth_scale: Option<DepthScale>,
    set_by_application: AtomicU64,
    set_until: Mutex<Option<Instant>>,
    shed: Mutex<Shed>,
    sequence: AtomicU64,
    standing: Mutex<Option<Standing>>,
}

impl ReportingState {
    pub fn new(validity_secs: u32, depth_scale: Option<DepthScale>) -> Self {
        Self::of_type(ReportType::Host, validity_secs, depth_scale)
    }

    /// A node that reports about `report_type`: the host itself, or the
    /// realm it serves (an agent speaking for the nodes behind it).
    pub fn of_type(
        report_type: ReportType,
        validity_secs: u32,
        depth_scale: Option<DepthScale>,
    ) -> Self {
        Self {
            report_type,
            validity_secs: validity_secs.clamp(1, MAX_VALIDITY_SECS),
            depth_scale,
            set_by_application: AtomicU64::new(0),
            set_until: Mutex::new(None),
            shed: Mutex::new(Shed::default()),
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

    /// A request was shed with `pending` in service and `limit` allowed: ask
    /// for at least the share that brings the load back under the limit,
    /// rounded up to a step, at once; if the reduction in force did not stop
    /// the shedding, raise it one step, at most once per `SHED_HOLD`. It
    /// leaves a step at a time once the shedding stops.
    pub fn note_shed(&self, pending: usize, limit: usize, now: Instant) {
        let excess = pending.saturating_sub(limit).max(1) as u128;
        let share = (excess * 100).div_ceil(pending.max(1) as u128) as u32;
        let wanted = share.div_ceil(SHED_STEP).max(1) * SHED_STEP;
        let Ok(mut shed) = self.shed.lock() else {
            return;
        };
        let current = shed.at(now);
        let raise_due = shed
            .last_raised
            .is_none_or(|raised| now.saturating_duration_since(raised) >= SHED_HOLD);
        let level = if wanted > current {
            wanted
        } else if raise_due {
            current + SHED_STEP
        } else {
            current
        };
        if level != current || shed.last_raised.is_none() {
            shed.last_raised = Some(now);
        }
        shed.level = level.min(100);
        shed.last_shed = Some(now);
    }

    fn shed_reduction(&self, now: Instant) -> u32 {
        self.shed.lock().map_or(0, |shed| shed.at(now))
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
        let by_depth = self.depth_scale.map_or(0, |scale| scale.reduction(pending));
        self.application_reduction(now)
            .max(by_depth)
            .max(self.shed_reduction(now))
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
            (Some(held), _) if held.reduction == reduction && held.expires > now + validity / 2 => {
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
            report_type: self.report_type,
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

/// The installed overload behaviour of this node.
#[derive(Debug)]
pub struct Overload {
    /// Whether this node is a reacting node.
    pub reacting: bool,
    pub reporting: Option<ReportingState>,
    pub table: ReactingTable,
    /// Requests in service above which one is answered 3004 without the
    /// script (`reporting.admission_limit`).
    pub admission_limit: Option<usize>,
    /// The DOIC agent behaviour of a relay (`diameter.overload.agent`).
    pub agent: Option<super::overload_agent::Agent>,
}

impl Overload {
    /// From `diameter.overload`.
    pub fn from_config(config: Option<&crate::config::DiameterOverloadConfig>) -> Self {
        let Some(config) = config else {
            return Self::new(false, None);
        };
        let reacting = config.reacting.is_some();
        let reporting = config.reporting.as_ref().map(|reporting| {
            ReportingState::new(
                reporting.validity,
                reporting.pending_requests.as_ref().map(|scale| DepthScale {
                    start: scale.start,
                    full: scale.full,
                    max_reduction: scale.max_reduction,
                }),
            )
        });
        let mut overload = Self::new(reacting, reporting);
        overload.admission_limit = config
            .reporting
            .as_ref()
            .and_then(|reporting| reporting.admission_limit);
        if config.agent {
            overload.agent = Some(super::overload_agent::Agent::new(
                config
                    .reporting
                    .as_ref()
                    .map_or(DEFAULT_VALIDITY_SECS, |reporting| reporting.validity),
            ));
        }
        overload
    }

    pub fn new(reacting: bool, reporting: Option<ReportingState>) -> Self {
        Self {
            reacting,
            reporting,
            table: ReactingTable::default(),
            admission_limit: None,
            agent: None,
        }
    }
}

static CURRENT: LazyLock<RwLock<std::sync::Arc<Overload>>> =
    LazyLock::new(|| RwLock::new(std::sync::Arc::new(Overload::new(false, None))));

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

// ── The node's own use of the above ─────────────────────────────────────────

/// The error of a request abated at this node, for
/// [`super::peer::DiameterPeer::send_request_timeout`] and what routes on it.
pub const ABATED: &str = "overload abated";

/// Whether `error` is [`ABATED`].
pub fn is_abated(error: &str) -> bool {
    error == ABATED
}

/// Where a request this node sends comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Made by this node: it advertises DOIC in it and abates it.
    Local,
    /// Received from another node and relayed: left exactly as it is
    /// (RFC 7683 section 5.2.3), abatement is the originator's business.
    Relayed,
}

/// Requests this node is serving now: the pending-request depth the
/// reporting node derives its load from.
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Counts a request being served until dropped.
pub struct InflightGuard;

impl Drop for InflightGuard {
    fn drop(&mut self) {
        INFLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A request is being served.
pub fn track_inflight() -> InflightGuard {
    INFLIGHT.fetch_add(1, Ordering::Relaxed);
    InflightGuard
}

/// The peer of `candidates` an agent should send a relayed request to: the
/// one whose host report asks for the least. Without an agent, or without any
/// report in force, the first. Candidates are in configured order.
pub fn least_reduced<'a>(
    candidates: impl Iterator<Item = &'a Arc<super::DiameterClient>>,
    application: u32,
    origin: Origin,
) -> Option<&'a Arc<super::DiameterClient>> {
    let overload = current();
    if origin != Origin::Relayed || overload.agent.is_none() || overload.table.is_idle() {
        return candidates.into_iter().next();
    }
    let now = Instant::now();
    candidates.min_by_key(|client| {
        client
            .peer()
            .remote_origin_host()
            .and_then(|host| {
                overload
                    .table
                    .reduction_for(&[ReportKey::new(ReportType::Host, host, application)], now)
            })
            .map_or(0, |found| found.0)
    })
}

/// Requests being served now.
pub fn inflight() -> usize {
    INFLIGHT.load(Ordering::Relaxed)
}

/// Whether more requests are in service than `reporting.admission_limit`
/// allows, which makes the receive path answer 3004 itself. Counts the
/// request being admitted, so a limit of N serves N at once.
pub fn over_admission_limit() -> bool {
    current()
        .admission_limit
        .is_some_and(|limit| inflight() > limit)
}

/// Count a request shed at `node` (`admission_limit`, `dispatch_queue`).
pub fn count_shed(node: &str) {
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics
            .diameter_overload_abated_total
            .with_label_values(&[node])
            .inc();
    }
    // A shed request is never left without a report: the reduction goes up
    // now, and the answer that follows carries it. Without an admission
    // limit the load in service is the limit the shed request exceeded.
    let overload = current();
    if let Some(reporting) = overload.reporting.as_ref() {
        let (pending, limit) = match overload.admission_limit {
            Some(limit) => (inflight(), limit),
            None => (inflight() + 1, inflight()),
        };
        reporting.note_shed(pending, limit, Instant::now());
    }
}

/// The DIAMETER_TOO_BUSY (3004) answer to the request `raw`, counted as shed
/// at `node`, with the overload this node reports (RFC 7683) for a requester
/// that advertised DOIC. None when `raw` does not parse.
pub fn too_busy_answer(raw: &[u8], origin: (&str, &str), node: &str) -> Option<Vec<u8>> {
    count_shed(node);
    let request = DiameterMsg::from_wire(raw).ok()?;
    let answer = super::forward::build_answer(
        &request,
        origin.0,
        origin.1,
        super::dictionary::DIAMETER_TOO_BUSY,
        Some("overloaded"),
    );
    Some(annotate_answer(request_features(raw), answer.to_wire()))
}

/// The DOIC features the sender of the request in `raw` advertised; 0 when
/// this node reports no overload (nothing is read then) or it advertised none.
pub fn request_features(raw: &[u8]) -> u64 {
    if current().reporting.is_none() {
        return 0;
    }
    DiameterMsg::from_wire(raw)
        .map(|message| advertised_features(&message))
        .unwrap_or(0)
}

/// The answer `wire` with this node's overload report added for a request
/// that advertised `request_features`. Unchanged when the node reports no
/// overload or the requester did not advertise the loss algorithm.
pub fn annotate_answer(request_features: u64, wire: Vec<u8>) -> Vec<u8> {
    let overload = current();
    let Some(reporting) = overload.reporting.as_ref() else {
        return wire;
    };
    if request_features & FEATURE_LOSS == 0 {
        return wire;
    }
    let Ok(mut answer) = DiameterMsg::from_wire(&wire) else {
        return wire;
    };
    let now = Instant::now();
    let pending = inflight();
    let before = answer.avps.len();
    let reported = reporting.annotate(&mut answer, request_features, pending, now);
    if answer.avps.len() == before {
        return wire;
    }
    if reported {
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .diameter_overload_olr_total
                .with_label_values(&["sent"])
                .inc();
            metrics
                .diameter_overload_reduction_percent
                .with_label_values(&["reporting", "local"])
                .set(i64::from(reporting.reduction(pending, now)));
        }
    }
    answer.to_wire()
}

/// The request `wire` as it leaves this node for the peer that gave
/// `peer_host` and `peer_realm`: a locally made request advertises DOIC, and
/// is abated when a report in force says so. `Err` carries the report that
/// abated it.
pub fn prepare_outbound(
    wire: Vec<u8>,
    origin: Origin,
    peer_host: Option<&str>,
    peer_realm: Option<&str>,
) -> Result<Vec<u8>, ReportKey> {
    let overload = current();
    match origin {
        // A relay abates only as an agent, and only once a report is in
        // force: the common case parses nothing.
        Origin::Relayed if overload.agent.is_none() || overload.table.is_idle() => return Ok(wire),
        Origin::Local if !overload.reacting => return Ok(wire),
        _ => {}
    }
    let Ok(mut request) = DiameterMsg::from_wire(&wire) else {
        return Ok(wire);
    };
    // The base protocol (capabilities, watchdog, disconnect) has no
    // application, and overload is reported per application.
    if request.application_id == 0 || !request.is_request() {
        return Ok(wire);
    }
    let application = request.application_id;
    let mut keys = Vec::with_capacity(4);
    let mut push = |report_type, identity: Option<String>| {
        if let Some(identity) = identity.filter(|identity| !identity.is_empty()) {
            keys.push(ReportKey::new(report_type, &identity, application));
        }
    };
    push(ReportType::Host, peer_host.map(str::to_owned));
    push(ReportType::Host, request.get_str(avp::DESTINATION_HOST));
    push(ReportType::Realm, request.get_str(avp::DESTINATION_REALM));
    push(ReportType::Realm, peer_realm.map(str::to_owned));
    if let Some(key) = overload.table.abate(&keys, Instant::now(), random_unit()) {
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .diameter_overload_abated_total
                .with_label_values(&[&key.identity])
                .inc();
        }
        return Err(key);
    }
    // A relayed request carries what its originator and, for an agent,
    // `overload_agent::prepare_request` put in it.
    if origin == Origin::Relayed || request.find(avp::OC_SUPPORTED_FEATURES, 0).is_some() {
        return Ok(wire);
    }
    request.avps.push(supported_features_avp(FEATURE_LOSS));
    Ok(request.to_wire())
}

/// Take in the OC-OLR of an answer received from the node that gave
/// `origin_host` and `origin_realm`: it starts, replaces or ends the
/// abatement towards it.
pub fn note_answer(wire: &[u8]) {
    let overload = current();
    if !overload.reacting && overload.agent.is_none() {
        return;
    }
    let Ok(answer) = DiameterMsg::from_wire(wire) else {
        return;
    };
    let Some(report) = parse_olr(&answer) else {
        return;
    };
    let identity = match report.report_type {
        ReportType::Host => answer.get_str(avp::ORIGIN_HOST),
        ReportType::Realm => answer.get_str(avp::ORIGIN_REALM),
    };
    let Some(identity) = identity.filter(|identity| !identity.is_empty()) else {
        return;
    };
    let key = ReportKey::new(report.report_type, &identity, answer.application_id);
    let outcome = overload.table.update(key, &report, Instant::now());
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics
            .diameter_overload_olr_total
            .with_label_values(&["received"])
            .inc();
        if outcome != Update::Ignored {
            metrics
                .diameter_overload_reduction_percent
                .with_label_values(&["reacting", &identity.to_ascii_lowercase()])
                .set(i64::from(if outcome == Update::Ended {
                    0
                } else {
                    report.reduction_percentage
                }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::{encode_avps, FLAG_PROXIABLE, FLAG_REQUEST};
    use crate::diameter::forward;

    fn request(avps: Vec<Avp>) -> DiameterMsg {
        DiameterMsg {
            flags: FLAG_REQUEST | FLAG_PROXIABLE,
            command_code: 318,
            application_id: 16_777_251,
            hop_by_hop: 1,
            end_to_end: 2,
            avps,
        }
    }

    fn olr(sequence: u64, reduction: u32, validity: u32) -> Olr {
        Olr {
            sequence,
            report_type: ReportType::Host,
            validity_secs: validity,
            reduction_percentage: reduction,
        }
    }

    fn key(host: &str) -> ReportKey {
        ReportKey::new(ReportType::Host, host, 16_777_251)
    }

    // Hand-assembled from RFC 7683 section 7 (AVP codes 621 to 627, no M or V
    // bit, every length a multiple of four), not produced by the encoder.
    const SUPPORTED_FEATURES_LOSS: [u8; 24] = [
        0x00, 0x00, 0x02, 0x6d, 0x00, 0x00, 0x00, 0x18, // OC-Supported-Features, 24
        0x00, 0x00, 0x02, 0x6e, 0x00, 0x00, 0x00, 0x10, // OC-Feature-Vector, 16
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // OLR_DEFAULT_ALGO
    ];
    const OLR_30_PERCENT: [u8; 60] = [
        0x00, 0x00, 0x02, 0x6f, 0x00, 0x00, 0x00, 0x3c, // OC-OLR, 60
        0x00, 0x00, 0x02, 0x70, 0x00, 0x00, 0x00, 0x10, // OC-Sequence-Number
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
        0x00, 0x00, 0x02, 0x72, 0x00, 0x00, 0x00, 0x0c, // OC-Report-Type
        0x00, 0x00, 0x00, 0x00, // HOST_REPORT
        0x00, 0x00, 0x02, 0x73, 0x00, 0x00, 0x00, 0x0c, // OC-Reduction-Percentage
        0x00, 0x00, 0x00, 0x1e, // 30
        0x00, 0x00, 0x02, 0x71, 0x00, 0x00, 0x00, 0x0c, // OC-Validity-Duration
        0x00, 0x00, 0x00, 0x1e, // 30 s
    ];

    #[test]
    fn oc_supported_features_encodes_to_the_rfc_7683_bytes() {
        assert_eq!(
            encode_avps(&[supported_features_avp(FEATURE_LOSS)]),
            SUPPORTED_FEATURES_LOSS
        );
    }

    #[test]
    fn oc_olr_encodes_to_the_rfc_7683_bytes() {
        assert_eq!(encode_avps(&[olr_avp(&olr(1, 30, 30))]), OLR_30_PERCENT);
    }

    #[test]
    fn the_hand_assembled_bytes_decode_to_the_values() {
        let mut wire = request(vec![]).to_wire();
        let mut body = SUPPORTED_FEATURES_LOSS.to_vec();
        body.extend_from_slice(&OLR_30_PERCENT);
        let length = (wire.len() + body.len()) as u32;
        wire.extend_from_slice(&body);
        wire[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
        let message = DiameterMsg::from_wire(&wire).unwrap();
        assert!(supports_loss(&message));
        assert_eq!(parse_olr(&message), Some(olr(1, 30, 30)));
    }

    #[test]
    fn a_message_without_doic_advertises_nothing() {
        let message = request(vec![]);
        assert_eq!(advertised_features(&message), 0);
        assert!(!supports_loss(&message));
        assert_eq!(parse_olr(&message), None);
    }

    #[test]
    fn an_unknown_algorithm_bit_alone_is_not_loss_support() {
        let message = request(vec![supported_features_avp(0x8)]);
        assert!(!supports_loss(&message));
    }

    #[test]
    fn a_report_missing_its_sequence_or_type_or_above_100_percent_is_not_usable() {
        let mut no_sequence = olr_avp(&olr(1, 30, 30));
        if let AvpData::Grouped(children) = &mut no_sequence.value {
            children.retain(|child| child.code != avp::OC_SEQUENCE_NUMBER);
        }
        assert_eq!(parse_olr(&request(vec![no_sequence])), None);
        let mut no_type = olr_avp(&olr(1, 30, 30));
        if let AvpData::Grouped(children) = &mut no_type.value {
            children.retain(|child| child.code != avp::OC_REPORT_TYPE);
        }
        assert_eq!(parse_olr(&request(vec![no_type])), None);
        assert_eq!(parse_olr(&request(vec![olr_avp(&olr(1, 101, 30))])), None);
    }

    #[test]
    fn a_missing_reduction_is_zero_a_missing_validity_thirty_and_a_long_one_is_capped() {
        let mut sparse = olr_avp(&olr(7, 50, 30));
        if let AvpData::Grouped(children) = &mut sparse.value {
            children.retain(|child| {
                child.code != avp::OC_REDUCTION_PERCENTAGE
                    && child.code != avp::OC_VALIDITY_DURATION
            });
        }
        assert_eq!(parse_olr(&request(vec![sparse])), Some(olr(7, 0, 30)));
        let long = olr_avp(&olr(7, 50, 1_000_000));
        assert_eq!(
            parse_olr(&request(vec![long])).map(|olr| olr.validity_secs),
            Some(MAX_VALIDITY_SECS)
        );
    }

    #[test]
    fn a_relay_passes_the_oc_avps_through_unchanged() {
        // Both directions: a request carrying OC-Supported-Features and an
        // answer carrying OC-OLR go through the relay primitives intact, the
        // identity rewrite included.
        let mut forwarded = request(vec![
            Avp::utf8(avp::ORIGIN_HOST, 0, "client.example.org"),
            supported_features_avp(FEATURE_LOSS),
        ]);
        forward::prepare_forward(&mut forwarded, &["relay.example.org"], "client.example.org")
            .unwrap();
        forward::rewrite_origin(&mut forwarded, "relay.example.org", "example.org");
        let received = DiameterMsg::from_wire(&forwarded.to_wire()).unwrap();
        assert_eq!(
            received.find(avp::OC_SUPPORTED_FEATURES, 0),
            Some(&supported_features_avp(FEATURE_LOSS))
        );

        let mut answer =
            forward::build_answer(&forwarded, "server.example.org", "example.org", 2001, None);
        answer.avps.push(olr_avp(&olr(9, 40, 60)));
        let mut relayed = DiameterMsg::from_wire(&answer.to_wire()).unwrap();
        relayed.hop_by_hop = 77;
        relayed.end_to_end = 88;
        let delivered = DiameterMsg::from_wire(&relayed.to_wire()).unwrap();
        assert_eq!(parse_olr(&delivered), Some(olr(9, 40, 60)));
    }

    // ── reacting node ───────────────────────────────────────────────────

    #[test]
    fn a_report_abates_its_percentage_of_requests_within_tolerance() {
        let table = ReactingTable::default();
        let now = Instant::now();
        assert_eq!(
            table.update(key("hss.example.org"), &olr(1, 30, 30), now),
            Update::Applied
        );
        let keys = [key("hss.example.org")];
        let total = 20_000;
        let abated = (0..total)
            .filter(|_| table.abate(&keys, now, random_unit()).is_some())
            .count();
        let share = abated as f64 / total as f64 * 100.0;
        assert!(
            (share - 30.0).abs() < 1.5,
            "abated {share:.2} % instead of 30 %"
        );
    }

    #[test]
    fn nothing_is_abated_without_a_report_or_for_another_node() {
        let table = ReactingTable::default();
        let now = Instant::now();
        assert!(table.is_idle());
        assert!(table.abate(&[key("hss.example.org")], now, 0.0).is_none());
        table.update(key("hss.example.org"), &olr(1, 100, 30), now);
        assert!(table.abate(&[key("other.example.org")], now, 0.0).is_none());
        assert!(table.abate(&[key("HSS.example.org")], now, 0.0).is_some());
        let other_application = ReportKey::new(ReportType::Host, "hss.example.org", 4);
        assert!(table.abate(&[other_application], now, 0.0).is_none());
    }

    #[test]
    fn abatement_stops_when_the_validity_runs_out() {
        let table = ReactingTable::default();
        let start = Instant::now();
        table.update(key("hss.example.org"), &olr(1, 100, 30), start);
        let keys = [key("hss.example.org")];
        assert!(table
            .abate(&keys, start + Duration::from_secs(29), 0.0)
            .is_some());
        assert!(table
            .abate(&keys, start + Duration::from_secs(30), 0.0)
            .is_none());
        assert!(table.is_idle(), "the expired report is dropped");
    }

    #[test]
    fn a_newer_sequence_replaces_a_report_and_zero_ends_it() {
        let table = ReactingTable::default();
        let now = Instant::now();
        table.update(key("hss.example.org"), &olr(5, 80, 30), now);
        // Older and repeated numbers are ignored.
        assert_eq!(
            table.update(key("hss.example.org"), &olr(4, 10, 30), now),
            Update::Ignored
        );
        assert_eq!(
            table.update(key("hss.example.org"), &olr(5, 10, 30), now),
            Update::Ignored
        );
        assert_eq!(
            table
                .reduction_for(&[key("hss.example.org")], now)
                .map(|found| found.0),
            Some(80)
        );
        // A newer one replaces it.
        assert_eq!(
            table.update(key("hss.example.org"), &olr(6, 20, 30), now),
            Update::Applied
        );
        assert_eq!(
            table
                .reduction_for(&[key("hss.example.org")], now)
                .map(|found| found.0),
            Some(20)
        );
        // A newer one asking for nothing ends it.
        assert_eq!(
            table.update(key("hss.example.org"), &olr(7, 0, 30), now),
            Update::Ended
        );
        assert!(table.abate(&[key("hss.example.org")], now, 0.0).is_none());
        assert!(table.is_idle());
    }

    #[test]
    fn a_zero_validity_ends_a_report() {
        let table = ReactingTable::default();
        let now = Instant::now();
        table.update(key("a.example.org"), &olr(1, 50, 30), now);
        assert_eq!(
            table.update(key("a.example.org"), &olr(2, 50, 0), now),
            Update::Ended
        );
        assert!(table.is_idle());
    }

    #[test]
    fn a_report_after_expiry_is_taken_whatever_its_sequence() {
        let table = ReactingTable::default();
        let start = Instant::now();
        table.update(key("a.example.org"), &olr(100, 50, 10), start);
        let later = start + Duration::from_secs(20);
        assert_eq!(
            table.update(key("a.example.org"), &olr(1, 60, 10), later),
            Update::Applied
        );
    }

    #[test]
    fn the_strongest_of_the_reports_that_apply_wins() {
        let table = ReactingTable::default();
        let now = Instant::now();
        table.update(key("hss.example.org"), &olr(1, 20, 30), now);
        table.update(
            ReportKey::new(ReportType::Realm, "example.org", 16_777_251),
            &olr(1, 60, 30),
            now,
        );
        let keys = [
            key("hss.example.org"),
            ReportKey::new(ReportType::Realm, "example.org", 16_777_251),
        ];
        assert_eq!(
            table.reduction_for(&keys, now).map(|found| found.0),
            Some(60)
        );
        assert_eq!(table.len(), 2);
    }

    // ── reporting node ──────────────────────────────────────────────────

    #[test]
    fn the_depth_scale_rises_linearly_between_its_marks() {
        let scale = DepthScale {
            start: 100,
            full: 200,
            max_reduction: 80,
        };
        assert_eq!(scale.reduction(0), 0);
        assert_eq!(scale.reduction(100), 0);
        assert_eq!(scale.reduction(150), 40);
        assert_eq!(scale.reduction(200), 80);
        assert_eq!(scale.reduction(10_000), 80);
    }

    #[test]
    fn the_application_sets_the_reported_reduction_and_it_lapses() {
        let reporting = ReportingState::new(30, None);
        let now = Instant::now();
        assert_eq!(reporting.reduction(0, now), 0);
        reporting.set(40, Some(Duration::from_secs(10)), now);
        assert_eq!(reporting.reduction(0, now), 40);
        assert_eq!(reporting.reduction(0, now + Duration::from_secs(11)), 0);
        reporting.set(70, None, now);
        assert_eq!(reporting.reduction(0, now + Duration::from_secs(3600)), 70);
        reporting.set(0, None, now);
        assert_eq!(reporting.reduction(0, now), 0);
    }

    #[test]
    fn the_larger_of_the_application_and_the_pending_depth_is_reported() {
        let reporting = ReportingState::new(
            30,
            Some(DepthScale {
                start: 0,
                full: 100,
                max_reduction: 100,
            }),
        );
        let now = Instant::now();
        reporting.set(30, None, now);
        assert_eq!(reporting.reduction(10, now), 30);
        assert_eq!(reporting.reduction(60, now), 60);
    }

    #[test]
    fn a_report_keeps_its_sequence_within_its_validity_and_a_change_raises_it() {
        let reporting = ReportingState::new(30, None);
        let now = Instant::now();
        assert!(reporting.olr(0, now).is_none(), "nothing to report");
        reporting.set(50, None, now);
        let first = reporting.olr(0, now).unwrap();
        assert_eq!(first.reduction_percentage, 50);
        let repeat = reporting.olr(0, now + Duration::from_secs(5)).unwrap();
        assert_eq!(repeat.sequence, first.sequence, "same report, same number");
        reporting.set(60, None, now);
        let changed = reporting.olr(0, now + Duration::from_secs(6)).unwrap();
        assert!(changed.sequence > first.sequence);
        assert_eq!(changed.reduction_percentage, 60);
        // Past half its validity it is renewed under a new number.
        let renewed = reporting.olr(0, now + Duration::from_secs(6 + 20)).unwrap();
        assert!(renewed.sequence > changed.sequence);
        assert_eq!(renewed.validity_secs, 30);
    }

    #[test]
    fn the_end_of_an_overload_is_reported_once_with_no_reduction() {
        let reporting = ReportingState::new(30, None);
        let now = Instant::now();
        reporting.set(50, None, now);
        let during = reporting.olr(0, now).unwrap();
        reporting.set(0, None, now);
        let end = reporting.olr(0, now + Duration::from_secs(1)).unwrap();
        assert_eq!(end.reduction_percentage, 0);
        assert!(end.sequence > during.sequence);
        assert!(reporting.olr(0, now + Duration::from_secs(2)).is_none());
    }

    #[test]
    fn an_answer_to_a_doic_capable_request_carries_the_report_and_others_do_not() {
        let reporting = ReportingState::new(30, None);
        let now = Instant::now();
        reporting.set(50, None, now);

        let mut capable = request(vec![]);
        capable.flags = 0;
        assert!(reporting.annotate(&mut capable, FEATURE_LOSS, 0, now));
        assert!(supports_loss(&capable), "the answer says it supports DOIC");
        assert_eq!(
            parse_olr(&capable).map(|found| found.reduction_percentage),
            Some(50)
        );

        let mut legacy = request(vec![]);
        assert!(!reporting.annotate(&mut legacy, 0, 0, now));
        assert!(
            legacy.avps.is_empty(),
            "a requester without DOIC gets nothing"
        );
        let mut other_algorithm = request(vec![]);
        assert!(!reporting.annotate(&mut other_algorithm, 0x8, 0, now));
        assert!(other_algorithm.avps.is_empty());
    }

    #[test]
    fn a_capable_requester_is_told_of_support_even_when_there_is_nothing_to_report() {
        let reporting = ReportingState::new(30, None);
        let mut answer = request(vec![]);
        assert!(!reporting.annotate(&mut answer, FEATURE_LOSS, 0, Instant::now()));
        assert!(supports_loss(&answer));
        assert_eq!(parse_olr(&answer), None);
    }

    #[test]
    fn an_answer_that_already_carries_doic_from_a_node_behind_is_not_touched() {
        let reporting = ReportingState::new(30, None);
        let now = Instant::now();
        reporting.set(90, None, now);
        let mut relayed = request(vec![olr_avp(&olr(3, 10, 30))]);
        let before = relayed.clone();
        assert!(!reporting.annotate(&mut relayed, FEATURE_LOSS, 0, now));
        assert_eq!(relayed, before);
    }

    #[test]
    fn the_configuration_turns_the_two_roles_on_independently() {
        let none = Overload::from_config(None);
        assert!(!none.reacting && none.reporting.is_none());
        let config: crate::config::DiameterConfig = serde_saphyr::from_str(
            "overload:\n  reporting:\n    validity: 45\n    pending_requests: {start: 10, full: 20}\n",
        )
        .unwrap();
        let reporting_only = Overload::from_config(config.overload.as_ref());
        assert!(!reporting_only.reacting);
        let reporting = reporting_only.reporting.expect("reporting configured");
        // Full scale from `full` on, at the default max_reduction of 100.
        assert_eq!(reporting.reduction(20, Instant::now()), 100);
        assert_eq!(reporting.reduction(15, Instant::now()), 50);
        let config: crate::config::DiameterConfig =
            serde_saphyr::from_str("overload:\n  reacting: {}\n").unwrap();
        let reacting_only = Overload::from_config(config.overload.as_ref());
        assert!(reacting_only.reacting && reacting_only.reporting.is_none());
    }

    #[test]
    fn shedding_raises_the_report_at_once_and_it_leaves_a_step_at_a_time() {
        let reporting = ReportingState::new(30, None);
        let start = Instant::now();
        assert_eq!(reporting.reduction(0, start), 0);
        // 105 in service of 100 allowed: 5 percent over, one step.
        reporting.note_shed(105, 100, start);
        assert_eq!(reporting.reduction(0, start), 10);
        let first = reporting.olr(0, start).unwrap();
        assert_eq!(first.reduction_percentage, 10);
        // 150 of 100: a third over, 40 at once.
        reporting.note_shed(150, 100, start);
        assert_eq!(reporting.reduction(0, start), 40);
        reporting.note_shed(150, 100, start + Duration::from_secs(1));
        assert_eq!(reporting.reduction(0, start + Duration::from_secs(1)), 40);
        // Shedding goes on although 40 is in force: one step, once per hold.
        let later = start + SHED_HOLD;
        reporting.note_shed(150, 100, later);
        assert_eq!(reporting.reduction(0, later), 50);
        reporting.note_shed(150, 100, later);
        assert_eq!(reporting.reduction(0, later), 50, "not twice in a hold");
        // It leaves a step per hold without a shed, then ends once.
        assert_eq!(reporting.reduction(0, later + SHED_HOLD), 40);
        assert_eq!(reporting.reduction(0, later + SHED_HOLD * 3), 20);
        let end = later + SHED_HOLD * 5;
        assert_eq!(reporting.reduction(0, end), 0);
        let held = reporting.olr(0, later).unwrap();
        let ended = reporting.olr(0, end).unwrap();
        assert_eq!(ended.reduction_percentage, 0);
        assert!(ended.sequence > held.sequence);
        assert!(reporting.olr(0, end + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn a_limit_of_zero_asks_for_everything_and_never_overflows() {
        let reporting = ReportingState::new(30, None);
        let now = Instant::now();
        reporting.note_shed(1, 0, now);
        assert_eq!(reporting.reduction(0, now), 100);
        reporting.note_shed(usize::MAX, 0, now);
        assert_eq!(reporting.reduction(0, now + SHED_HOLD), 100 - SHED_STEP);
    }

    #[test]
    fn the_agent_and_the_admission_limit_are_configured() {
        let none = Overload::from_config(None);
        assert!(none.agent.is_none() && none.admission_limit.is_none());
        let config: crate::config::DiameterConfig = serde_saphyr::from_str(
            "overload:\n  agent: true\n  reporting: {validity: 45, admission_limit: 500}\n",
        )
        .unwrap();
        let configured = Overload::from_config(config.overload.as_ref());
        assert!(configured.agent.is_some());
        assert_eq!(configured.admission_limit, Some(500));
        assert!(!configured.reacting);
        let bare: crate::config::DiameterConfig =
            serde_saphyr::from_str("overload:\n  agent: true\n").unwrap();
        assert!(Overload::from_config(bare.overload.as_ref())
            .agent
            .is_some());
    }

    #[test]
    fn an_agent_gives_every_relayed_request_somewhere_to_be_diverted_to() {
        let config: crate::config::DiameterConfig =
            serde_saphyr::from_str("overload:\n  agent: true\n").unwrap();
        let policy = crate::diameter::retry::RetryPolicy::from_config(&config);
        assert!(policy.divert_abated);
    }

    /// Emit the DOIC AVPs for `scripts/validate_diameter_overload.sh`, which
    /// has Wireshark's dissector read them back.
    #[test]
    fn emit_doic_messages_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_DIAMETER_OVERLOAD_HEX_OUT") else {
            return;
        };
        let mut capable_request = request(vec![
            Avp::utf8(avp::SESSION_ID, 0, "client.example.org;1;1"),
            Avp::utf8(avp::ORIGIN_HOST, 0, "client.example.org"),
            Avp::utf8(avp::ORIGIN_REALM, 0, "example.org"),
            supported_features_avp(FEATURE_LOSS),
        ]);
        capable_request.command_code = 280;
        capable_request.application_id = 0;
        let reporting = ReportingState::new(30, None);
        reporting.set(30, None, Instant::now());
        let mut answer = forward::build_answer(
            &capable_request,
            "server.example.org",
            "example.org",
            2001,
            None,
        );
        reporting.annotate(&mut answer, FEATURE_LOSS, 0, Instant::now());
        let mut realm_report = forward::build_answer(
            &capable_request,
            "server.example.org",
            "example.org",
            2001,
            None,
        );
        realm_report.avps.push(olr_avp(&Olr {
            sequence: 0x0102_0304_0506_0708,
            report_type: ReportType::Realm,
            validity_secs: 86_400,
            reduction_percentage: 100,
        }));
        // What a DOIC agent says: one backend of two reports 100 percent.
        let table = ReactingTable::default();
        let backend = |name: &str| super::super::overload_agent::Backend {
            host: Some(name.to_string()),
            realm: Some("example.org".to_string()),
        };
        table.update(
            ReportKey::new(ReportType::Host, "a.example.org", 0),
            &olr(1, 100, 30),
            Instant::now(),
        );
        let mut agent_answer = forward::build_answer(
            &capable_request,
            "server.example.org",
            "example.org",
            2001,
            None,
        );
        super::super::overload_agent::Agent::new(30).rewrite_answer(
            &table,
            &mut agent_answer,
            "example.org",
            true,
            &[backend("a.example.org"), backend("b.example.org")],
            2,
            Instant::now(),
        );
        let mut dump = String::new();
        for wire in [
            capable_request.to_wire(),
            answer.to_wire(),
            realm_report.to_wire(),
            agent_answer.to_wire(),
        ] {
            for (offset, chunk) in wire.chunks(16).enumerate() {
                dump.push_str(&format!("{:06x}", offset * 16));
                for byte in chunk {
                    dump.push_str(&format!(" {byte:02x}"));
                }
                dump.push('\n');
            }
            dump.push('\n');
        }
        std::fs::write(path, dump).unwrap();
    }
}
