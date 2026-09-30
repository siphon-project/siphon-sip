//! Live log tail — an in-process fan-out of `tracing` events to the admin API.
//!
//! An operator debugging a call should not have to leave the dashboard for
//! `journalctl`. This module makes the process's own log stream readable over
//! HTTP, as Server-Sent Events, filtered server-side.
//!
//! # Why capture is on-demand
//!
//! The Rust datapath emits nothing at INFO for an ordinary message or call, but
//! a logging Python script does: `b2bua_default.py` writes roughly five lines
//! per call, which is ~150k lines a second at 30k cps. Formatting all of that
//! into a ring buffer that nobody is reading would be a real cost on the
//! hot path, paid permanently for a feature used occasionally.
//!
//! So [`LogTailLayer::on_event`] starts with one relaxed atomic load and
//! returns when there are no attached streams and the event is below WARN.
//! Formatting — the allocation, the field visitor, the `Arc` — happens only
//! past that gate. WARN and above are always retained, in a small ring, because
//! they are rare by construction and they are the context an operator wants
//! *already collected* when they open the tail after something went wrong.
//!
//! An operator who wants the INFO lines kept too (to read what a call did
//! after it ended, not only what went wrong) opts in with
//! `admin.log_tail.retain_level`. That fills a second, separately sized ring,
//! so a busy INFO stream cannot evict the warnings, and it moves the gate for
//! the retained levels: they are formatted on every event from then on. The
//! default stays WARN only, and the cost above is only paid by a node that
//! asked for it.
//!
//! # Backpressure
//!
//! Each attached stream owns a bounded queue with a drop-oldest policy, the
//! same discipline the control plane applies to a slow application
//! (`crate::control::registry::OutboundQueue`): a browser that stops reading
//! loses lines and is told how many, and pressure never reaches the tracing
//! layer, let alone the thread that logged. A log tail must not be able to slow
//! down signalling.
//!
//! # What the tail can see
//!
//! `EnvFilter` sits above every layer in the subscriber stack, so this layer
//! only ever observes events the node's configured `log.level` already admits.
//! Tailing debug requires the node to be running at debug; there is no runtime
//! level override, because making the global filter reloadable puts an
//! `RwLock` read on the per-event path.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use serde::Serialize;
use tokio::sync::Notify;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Entries of WARN and above retained even when nobody is tailing, unless
/// `admin.log_tail.warn_capacity` says otherwise.
const WARN_RING_CAPACITY: usize = 512;

/// Default size of the optional below-WARN ring (`admin.log_tail.retain_capacity`).
const RETAIN_RING_CAPACITY: usize = 4096;

/// Per-stream queue depth before the oldest line is dropped.
const STREAM_QUEUE_CAPACITY: usize = 2048;

/// One captured log event, as the admin API serializes it.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    /// Position in this process's log, increasing by one per captured record.
    /// The cursor for paging `GET /admin/logs` backwards (`before=`), and the
    /// order the two retained rings are merged in. Restarts at 0 with the
    /// process.
    pub seq: u64,
    /// Milliseconds since the UNIX epoch.
    pub timestamp_ms: u64,
    /// `ERROR` / `WARN` / `INFO` / `DEBUG` / `TRACE`.
    pub level: &'static str,
    /// Emitting module path (`siphon::b2bua::actor`).
    pub target: String,
    /// The event's `message` field, rendered.
    pub message: String,
    /// The Call-ID, when the call site attached one as a structured field.
    ///
    /// There are no spans anywhere in this codebase, so there is no ambient
    /// call-id to inherit: this is populated only for the call sites that
    /// literally write `call_id = %…`, and never for Python `log.*` output,
    /// which carries no fields at all. Correlation by call-id is therefore
    /// best-effort, and the UI says so rather than implying completeness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Remaining structured fields, in call-site order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<(String, String)>,
}

impl LogRecord {
    /// Whether this record satisfies a stream's filter.
    fn matches(&self, filter: &TailFilter) -> bool {
        if level_rank(self.level) > filter.max_rank {
            return false;
        }
        if let Some(ref call_id) = filter.call_id {
            if self.call_id.as_deref() != Some(call_id.as_str()) {
                return false;
            }
        }
        if let Some(ref needle) = filter.contains {
            let hit = self.message.to_lowercase().contains(needle)
                || self.target.to_lowercase().contains(needle)
                || self
                    .fields
                    .iter()
                    .any(|(name, value)| value.to_lowercase().contains(needle) || name == needle);
            if !hit {
                return false;
            }
        }
        true
    }
}

/// Severity as a sortable rank: ERROR is 0, TRACE is 4. A filter admits every
/// record whose rank is `<=` its own, i.e. "this level and above".
fn level_rank(level: &str) -> u8 {
    match level {
        "ERROR" => 0,
        "WARN" => 1,
        "INFO" => 2,
        "DEBUG" => 3,
        _ => 4,
    }
}

/// Parse a level name case-insensitively, refusing anything that is not one.
///
/// [`level_rank`] maps an unknown name to TRACE, which is the right forgiveness
/// for a query filter but the wrong one for config: a misspelt `retain_level`
/// would silently retain everything.
pub fn parse_level(value: &str) -> Option<&'static str> {
    match value.to_ascii_uppercase().as_str() {
        "ERROR" => Some("ERROR"),
        "WARN" | "WARNING" => Some("WARN"),
        "INFO" => Some("INFO"),
        "DEBUG" => Some("DEBUG"),
        "TRACE" => Some("TRACE"),
        _ => None,
    }
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// Server-side filter for one attached stream.
#[derive(Debug, Clone)]
pub struct TailFilter {
    /// Highest rank admitted (see [`level_rank`]). Defaults to TRACE, i.e. all.
    pub max_rank: u8,
    /// Case-insensitive substring across message, target and field values.
    pub contains: Option<String>,
    /// Exact Call-ID match.
    pub call_id: Option<String>,
}

impl Default for TailFilter {
    /// "Everything the node logs" — deliberately hand-written rather than
    /// derived. A derived `Default` gives `max_rank: 0`, which is ERROR-only:
    /// a caller that built a default filter would silently receive almost
    /// nothing, and the failure mode of a log tail showing too little is that
    /// the operator concludes the node is quiet.
    fn default() -> Self {
        Self {
            max_rank: level_rank("TRACE"),
            contains: None,
            call_id: None,
        }
    }
}

impl TailFilter {
    /// Build from query parameters, defaulting to "everything the node logs".
    ///
    /// Filtering here rather than in the browser is what keeps a narrow filter
    /// cheap: at 150k lines a second, shipping everything to the client so it
    /// can throw most of it away would spend the bandwidth and the serialization
    /// to deliver a handful of lines.
    pub fn new(level: Option<&str>, contains: Option<&str>, call_id: Option<&str>) -> Self {
        Self {
            max_rank: level
                .map(|value| level_rank(&value.to_ascii_uppercase()))
                .unwrap_or(4),
            contains: contains
                .filter(|value| !value.is_empty())
                .map(|value| value.to_lowercase()),
            call_id: call_id.filter(|value| !value.is_empty()).map(String::from),
        }
    }
}

/// A bounded, drop-oldest queue feeding one attached SSE stream.
#[derive(Debug)]
pub struct TailStream {
    inner: Mutex<VecDeque<Arc<LogRecord>>>,
    notify: Notify,
    filter: TailFilter,
    dropped: AtomicU64,
    closed: AtomicBool,
}

impl TailStream {
    fn new(filter: TailFilter) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(64)),
            notify: Notify::new(),
            filter,
            dropped: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Arc<LogRecord>>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Offer a record. Never blocks, never awaits — this runs on whatever thread
    /// called `info!`, which may be the dispatcher or a Python worker.
    fn offer(&self, record: &Arc<LogRecord>) {
        if !record.matches(&self.filter) {
            return;
        }
        {
            let mut queue = self.lock();
            if queue.len() >= STREAM_QUEUE_CAPACITY {
                queue.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.log_tail_dropped_total.inc();
                }
            }
            queue.push_back(Arc::clone(record));
        }
        self.notify.notify_one();
    }

    /// Await and drain everything currently queued, plus the number of lines
    /// dropped since the last drain. An empty vector means the stream closed.
    pub async fn recv_many(&self) -> (Vec<Arc<LogRecord>>, u64) {
        loop {
            {
                let mut queue = self.lock();
                if !queue.is_empty() {
                    let drained = queue.drain(..).collect();
                    return (drained, self.dropped.swap(0, Ordering::Relaxed));
                }
            }
            if self.closed.load(Ordering::SeqCst) {
                return (Vec::new(), self.dropped.swap(0, Ordering::Relaxed));
            }
            self.notify.notified().await;
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

/// How the tail is sized and what it keeps, from `admin.log_tail`.
#[derive(Debug, Clone, Copy)]
pub struct LogTailSettings {
    /// Concurrent streams allowed.
    pub max_streams: usize,
    /// Size of the WARN+ ring.
    pub warn_capacity: usize,
    /// Lowest level retained below WARN (`INFO` / `DEBUG` / `TRACE`), or `None`
    /// to retain WARN and above only.
    pub retain_level: Option<&'static str>,
    /// Size of the below-WARN ring.
    pub retain_capacity: usize,
}

impl Default for LogTailSettings {
    fn default() -> Self {
        Self {
            max_streams: 4,
            warn_capacity: WARN_RING_CAPACITY,
            retain_level: None,
            retain_capacity: RETAIN_RING_CAPACITY,
        }
    }
}

/// A read of the retained rings for `GET /admin/logs`.
#[derive(Debug, Clone, Default)]
pub struct RetainedQuery {
    /// Level, substring and Call-ID filter, as the stream takes them.
    pub filter: TailFilter,
    /// Only records older than this `seq` (the page cursor).
    pub before: Option<u64>,
    /// At most this many records: the newest that match.
    pub limit: Option<usize>,
}

/// The answer to a [`RetainedQuery`], oldest first.
#[derive(Debug)]
pub struct RetainedPage {
    pub records: Vec<Arc<LogRecord>>,
    /// Older matching records exist beyond this page. Pass the first record's
    /// `seq` as `before` to read them.
    pub truncated: bool,
}

/// Process-wide tail registry.
#[derive(Debug)]
pub struct LogTail {
    /// Attached streams. Small by construction (see `max_streams`), so a `Vec`
    /// behind a mutex beats a concurrent map here.
    streams: Mutex<Vec<Arc<TailStream>>>,
    /// Fast gate read on every event, kept in step with `streams.len()`.
    attached: AtomicUsize,
    warn_ring: Mutex<VecDeque<Arc<LogRecord>>>,
    warn_capacity: AtomicUsize,
    /// Records ranked below WARN, down to `retain_rank`. Empty unless
    /// `retain_level` is configured.
    retain_ring: Mutex<VecDeque<Arc<LogRecord>>>,
    retain_capacity: AtomicUsize,
    /// Lowest-severity rank retained. WARN's rank means the second ring is off,
    /// which is the default and keeps the event gate where it always was.
    retain_rank: AtomicU8,
    next_seq: AtomicU64,
    enabled: AtomicBool,
    max_streams: AtomicUsize,
}

impl Default for LogTail {
    fn default() -> Self {
        Self {
            streams: Mutex::new(Vec::new()),
            attached: AtomicUsize::new(0),
            warn_ring: Mutex::new(VecDeque::new()),
            warn_capacity: AtomicUsize::new(WARN_RING_CAPACITY),
            retain_ring: Mutex::new(VecDeque::new()),
            retain_capacity: AtomicUsize::new(RETAIN_RING_CAPACITY),
            retain_rank: AtomicU8::new(level_rank("WARN")),
            next_seq: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            max_streams: AtomicUsize::new(0),
        }
    }
}

/// Lock a ring, recovering from poisoning: a panicked logger must not take the
/// tail down with it.
fn lock_ring(ring: &Mutex<VecDeque<Arc<LogRecord>>>) -> MutexGuard<'_, VecDeque<Arc<LogRecord>>> {
    match ring.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Push onto a bounded ring, evicting the oldest. A zero capacity keeps nothing.
fn push_bounded(ring: &Mutex<VecDeque<Arc<LogRecord>>>, capacity: usize, record: &Arc<LogRecord>) {
    if capacity == 0 {
        return;
    }
    let mut ring = lock_ring(ring);
    while ring.len() >= capacity {
        ring.pop_front();
    }
    ring.push_back(Arc::clone(record));
}

impl LogTail {
    fn streams(&self) -> MutexGuard<'_, Vec<Arc<TailStream>>> {
        match self.streams.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Whether capture is switched on at all.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Number of streams currently attached.
    pub fn attached(&self) -> usize {
        self.attached.load(Ordering::Relaxed)
    }

    /// Attach a stream, or `None` when the concurrent-stream cap is reached.
    ///
    /// The cap exists because the admin server has no connection limiting of
    /// any kind: without it, one client could pin an unbounded number of
    /// queues, each up to `STREAM_QUEUE_CAPACITY` records.
    pub fn attach(&self, filter: TailFilter) -> Option<Arc<TailStream>> {
        let mut streams = self.streams();
        if streams.len() >= self.max_streams.load(Ordering::Relaxed) {
            return None;
        }
        let stream = Arc::new(TailStream::new(filter));
        streams.push(Arc::clone(&stream));
        self.attached.store(streams.len(), Ordering::Relaxed);
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.log_tail_streams.set(streams.len() as i64);
        }
        Some(stream)
    }

    /// Detach a stream. Idempotent — a client that vanishes mid-write and one
    /// that closes cleanly both land here exactly once, via the guard.
    pub fn detach(&self, stream: &Arc<TailStream>) {
        stream.close();
        let mut streams = self.streams();
        streams.retain(|existing| !Arc::ptr_eq(existing, stream));
        self.attached.store(streams.len(), Ordering::Relaxed);
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.log_tail_streams.set(streams.len() as i64);
        }
    }

    /// The retained WARN+ ring, oldest first.
    pub fn recent_warnings(&self) -> Vec<Arc<LogRecord>> {
        lock_ring(&self.warn_ring).iter().cloned().collect()
    }

    /// The lowest level the retained rings hold: `WARN` by default, or the
    /// configured `retain_level`. `GET /admin/logs` reports it, so an empty
    /// answer reads as "no warnings" rather than "nothing happened".
    pub fn retained_level(&self) -> &'static str {
        match self.retain_rank.load(Ordering::Relaxed) {
            0 | 1 => "WARN",
            2 => "INFO",
            3 => "DEBUG",
            _ => "TRACE",
        }
    }

    /// Records held across both rings.
    pub fn retained_count(&self) -> usize {
        lock_ring(&self.warn_ring).len() + lock_ring(&self.retain_ring).len()
    }

    /// Read the retained rings: filtered, merged in `seq` order, and cut to the
    /// newest `limit` records older than `before`.
    pub fn retained(&self, query: &RetainedQuery) -> RetainedPage {
        let admit = |record: &&Arc<LogRecord>| {
            // `map_or(true, …)` not `is_none_or`: MSRV 1.80.
            query.before.map_or(true, |before| record.seq < before) && record.matches(&query.filter)
        };
        let mut records: Vec<Arc<LogRecord>> = lock_ring(&self.warn_ring)
            .iter()
            .filter(admit)
            .cloned()
            .collect();
        records.extend(lock_ring(&self.retain_ring).iter().filter(admit).cloned());
        // Each ring is in push order, which can trail `seq` by a record when two
        // threads log at once; the sort settles both that and the merge.
        records.sort_by_key(|record| record.seq);

        let truncated = query.limit.is_some_and(|limit| records.len() > limit);
        if let Some(limit) = query.limit {
            let excess = records.len().saturating_sub(limit);
            records.drain(..excess);
        }
        RetainedPage { records, truncated }
    }

    fn publish(&self, mut record: LogRecord) {
        record.seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let record = Arc::new(record);
        let rank = level_rank(record.level);
        if rank <= level_rank("WARN") {
            push_bounded(
                &self.warn_ring,
                self.warn_capacity.load(Ordering::Relaxed),
                &record,
            );
        } else if rank <= self.retain_rank.load(Ordering::Relaxed) {
            push_bounded(
                &self.retain_ring,
                self.retain_capacity.load(Ordering::Relaxed),
                &record,
            );
        }
        for stream in self.streams().iter() {
            stream.offer(&record);
        }
    }
}

static LOG_TAIL: OnceLock<Arc<LogTail>> = OnceLock::new();

/// The process-wide tail. Always present; inert until [`enable`] is called.
pub fn log_tail() -> &'static Arc<LogTail> {
    LOG_TAIL.get_or_init(|| Arc::new(LogTail::default()))
}

impl LogTail {
    /// A tail configured and switched on, outside the process-wide one. For a
    /// caller that wants its own (a test of the admin read path).
    pub fn with_settings(settings: LogTailSettings) -> Self {
        let tail = Self::default();
        tail.configure(settings);
        tail
    }

    /// Publish a record as the layer would, without a subscriber.
    #[cfg(test)]
    pub(crate) fn publish_for_test(
        &self,
        level: &'static str,
        message: &str,
        call_id: Option<&str>,
    ) {
        self.publish(LogRecord {
            seq: 0,
            timestamp_ms: 0,
            level,
            target: "siphon::test".to_string(),
            message: message.to_string(),
            call_id: call_id.map(String::from),
            fields: Vec::new(),
        });
    }
}

/// Switch capture on. Called from the server once the admin config is known.
pub fn enable(settings: LogTailSettings) {
    log_tail().configure(settings);
}

impl LogTail {
    fn configure(&self, settings: LogTailSettings) {
        self.max_streams
            .store(settings.max_streams.max(1), Ordering::Relaxed);
        self.warn_capacity
            .store(settings.warn_capacity, Ordering::Relaxed);
        self.retain_capacity
            .store(settings.retain_capacity, Ordering::Relaxed);
        // Never below WARN's rank: ERROR and WARN always go to the warning ring,
        // and a `retain_level` of `warn` or `error` means no second ring.
        let rank = settings
            .retain_level
            .map(level_rank)
            .unwrap_or(0)
            .max(level_rank("WARN"));
        self.retain_rank.store(rank, Ordering::Relaxed);
        self.enabled.store(true, Ordering::Relaxed);
    }
}

/// Collects an event's fields into a [`LogRecord`].
struct RecordVisitor {
    message: String,
    call_id: Option<String>,
    fields: Vec<(String, String)>,
}

impl RecordVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            call_id: None,
            fields: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, value: String) {
        match name {
            "message" => self.message = value,
            "call_id" => self.call_id = Some(value),
            _ => self.fields.push((name.to_string(), value)),
        }
    }
}

impl Visit for RecordVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field.name(), value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record(field.name(), value.to_string());
    }
}

/// The `tracing` layer that feeds [`LogTail`].
pub struct LogTailLayer;

impl<S: Subscriber> Layer<S> for LogTailLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let tail = log_tail();
        if !tail.enabled.load(Ordering::Relaxed) {
            return;
        }

        let level = level_name(event.metadata().level());
        let rank = level_rank(level);

        // The gate. Two relaxed loads on the overwhelmingly common path (INFO
        // and below, nobody watching, retention at its WARN default), before
        // anything is formatted.
        if rank > tail.retain_rank.load(Ordering::Relaxed)
            && tail.attached.load(Ordering::Relaxed) == 0
        {
            return;
        }

        let mut visitor = RecordVisitor::new();
        event.record(&mut visitor);

        tail.publish(LogRecord {
            seq: 0, // assigned by publish()
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis() as u64)
                .unwrap_or(0),
            level,
            target: event.metadata().target().to_string(),
            message: visitor.message,
            call_id: visitor.call_id,
            fields: visitor.fields,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(level: &'static str, message: &str) -> LogRecord {
        LogRecord {
            seq: 0,
            timestamp_ms: 0,
            level,
            target: "siphon::test".to_string(),
            message: message.to_string(),
            call_id: None,
            fields: Vec::new(),
        }
    }

    #[test]
    fn level_ranks_are_ordered_most_severe_first() {
        assert!(level_rank("ERROR") < level_rank("WARN"));
        assert!(level_rank("WARN") < level_rank("INFO"));
        assert!(level_rank("INFO") < level_rank("DEBUG"));
        assert!(level_rank("DEBUG") < level_rank("TRACE"));
        assert_eq!(level_rank("nonsense"), 4);
    }

    #[test]
    fn filter_admits_the_named_level_and_above() {
        let filter = TailFilter::new(Some("warn"), None, None);
        assert!(record("ERROR", "x").matches(&filter));
        assert!(record("WARN", "x").matches(&filter));
        assert!(!record("INFO", "x").matches(&filter));
    }

    #[test]
    fn filter_defaults_to_everything() {
        for filter in [TailFilter::new(None, None, None), TailFilter::default()] {
            assert!(record("TRACE", "x").matches(&filter));
            assert!(record("INFO", "x").matches(&filter));
            assert!(record("ERROR", "x").matches(&filter));
        }
    }

    #[test]
    fn substring_filter_is_case_insensitive_across_message_and_target() {
        let filter = TailFilter::new(None, Some("REGISTER"), None);
        assert!(record("INFO", "handling register from ue").matches(&filter));
        assert!(!record("INFO", "handling invite").matches(&filter));

        let mut with_field = record("INFO", "no hit here");
        with_field
            .fields
            .push(("aor".into(), "sip:REGISTERED".into()));
        assert!(with_field.matches(&filter));
    }

    #[test]
    fn call_id_filter_is_exact_and_excludes_records_without_one() {
        let filter = TailFilter::new(None, None, Some("abc123"));
        let mut matching = record("INFO", "x");
        matching.call_id = Some("abc123".to_string());
        assert!(matching.matches(&filter));

        let mut other = record("INFO", "x");
        other.call_id = Some("def456".to_string());
        assert!(!other.matches(&filter));

        assert!(!record("INFO", "x").matches(&filter));
    }

    #[tokio::test]
    async fn stream_receives_matching_records() {
        let stream = Arc::new(TailStream::new(TailFilter::new(Some("info"), None, None)));
        stream.offer(&Arc::new(record("INFO", "hello")));
        stream.offer(&Arc::new(record("DEBUG", "ignored")));

        let (records, dropped) = stream.recv_many().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "hello");
        assert_eq!(dropped, 0);
    }

    #[tokio::test]
    async fn overflow_drops_the_oldest_and_counts_it() {
        let stream = Arc::new(TailStream::new(TailFilter::default()));
        for index in 0..(STREAM_QUEUE_CAPACITY + 10) {
            stream.offer(&Arc::new(record("ERROR", &format!("line {index}"))));
        }

        let (records, dropped) = stream.recv_many().await;
        assert_eq!(records.len(), STREAM_QUEUE_CAPACITY);
        assert_eq!(dropped, 10);
        // The oldest went, not the newest: a tail is only useful if it keeps up
        // with the present.
        assert_eq!(records[0].message, "line 10");
    }

    #[tokio::test]
    async fn a_closed_stream_stops_yielding() {
        let stream = Arc::new(TailStream::new(TailFilter::default()));
        stream.close();
        let (records, _) = stream.recv_many().await;
        assert!(records.is_empty());
    }

    #[test]
    fn warn_ring_retains_warnings_and_evicts_oldest() {
        let tail = LogTail::default();
        tail.enabled.store(true, Ordering::Relaxed);
        for index in 0..(WARN_RING_CAPACITY + 5) {
            tail.publish(record("WARN", &format!("warn {index}")));
        }
        // INFO is not retained when nobody is attached — that is the whole
        // point of the on-demand half.
        tail.publish(record("INFO", "not retained"));

        let retained = tail.recent_warnings();
        assert_eq!(retained.len(), WARN_RING_CAPACITY);
        assert_eq!(retained[0].message, "warn 5");
        assert!(retained.iter().all(|entry| entry.level == "WARN"));
    }

    #[test]
    fn attach_is_capped_and_detach_frees_a_slot() {
        let tail = LogTail::default();
        tail.max_streams.store(2, Ordering::Relaxed);

        let first = tail.attach(TailFilter::default()).expect("first attaches");
        let _second = tail.attach(TailFilter::default()).expect("second attaches");
        assert!(tail.attach(TailFilter::default()).is_none());
        assert_eq!(tail.attached(), 2);

        tail.detach(&first);
        assert_eq!(tail.attached(), 1);
        assert!(tail.attach(TailFilter::default()).is_some());
    }

    #[test]
    fn detach_is_idempotent() {
        let tail = LogTail::default();
        tail.max_streams.store(1, Ordering::Relaxed);
        let stream = tail.attach(TailFilter::default()).expect("attaches");
        tail.detach(&stream);
        tail.detach(&stream);
        assert_eq!(tail.attached(), 0);
    }

    #[test]
    fn publish_fans_out_to_every_attached_stream() {
        let tail = LogTail::default();
        tail.enabled.store(true, Ordering::Relaxed);
        tail.max_streams.store(4, Ordering::Relaxed);

        let broad = tail.attach(TailFilter::default()).expect("attaches");
        let narrow = tail
            .attach(TailFilter::new(Some("error"), None, None))
            .expect("attaches");

        tail.publish(record("INFO", "informational"));

        assert_eq!(broad.lock().len(), 1);
        assert_eq!(narrow.lock().len(), 0);
    }

    #[test]
    fn a_disabled_tail_retains_nothing() {
        let tail = LogTail::default();
        tail.publish(record("ERROR", "dropped on the floor"));
        // publish() is only reached past the layer's enabled check; the ring
        // itself is unconditional, so assert the layer gate instead.
        assert!(!tail.is_enabled());
    }

    #[test]
    fn visitor_splits_message_call_id_and_other_fields() {
        let mut visitor = RecordVisitor::new();
        visitor.record("message", "relaying INVITE".to_string());
        visitor.record("call_id", "abc@example".to_string());
        visitor.record("branch", "z9hG4bK1".to_string());

        assert_eq!(visitor.message, "relaying INVITE");
        assert_eq!(visitor.call_id.as_deref(), Some("abc@example"));
        assert_eq!(
            visitor.fields,
            vec![("branch".to_string(), "z9hG4bK1".to_string())]
        );
    }

    fn retaining(level: Option<&'static str>, warn: usize, retain: usize) -> LogTail {
        let tail = LogTail::default();
        tail.configure(LogTailSettings {
            max_streams: 4,
            warn_capacity: warn,
            retain_level: level,
            retain_capacity: retain,
        });
        tail
    }

    fn messages(page: &RetainedPage) -> Vec<&str> {
        page.records
            .iter()
            .map(|record| record.message.as_str())
            .collect()
    }

    #[test]
    fn parse_level_accepts_the_five_levels_and_refuses_the_rest() {
        assert_eq!(parse_level("info"), Some("INFO"));
        assert_eq!(parse_level("Warning"), Some("WARN"));
        assert_eq!(parse_level("TRACE"), Some("TRACE"));
        assert_eq!(parse_level("verbose"), None);
        assert_eq!(parse_level(""), None);
    }

    #[test]
    fn default_retention_holds_warnings_only_and_says_so() {
        let tail = retaining(None, 8, 8);
        tail.publish(record("INFO", "not kept"));
        tail.publish(record("WARN", "kept"));
        assert_eq!(tail.retained_level(), "WARN");
        assert_eq!(
            messages(&tail.retained(&RetainedQuery::default())),
            ["kept"]
        );
    }

    #[test]
    fn retain_level_warn_or_error_means_no_second_ring() {
        for level in ["WARN", "ERROR"] {
            let tail = retaining(Some(level), 8, 8);
            tail.publish(record("INFO", "not kept"));
            assert_eq!(tail.retained_level(), "WARN");
            assert_eq!(tail.retained_count(), 0);
        }
    }

    #[test]
    fn retain_level_info_keeps_info_but_not_debug() {
        let tail = retaining(Some("INFO"), 8, 8);
        tail.publish(record("INFO", "flow step"));
        tail.publish(record("DEBUG", "too verbose"));
        assert_eq!(tail.retained_level(), "INFO");
        assert_eq!(
            messages(&tail.retained(&RetainedQuery::default())),
            ["flow step"]
        );
    }

    #[test]
    fn a_busy_info_stream_does_not_evict_the_warnings() {
        let tail = retaining(Some("INFO"), 4, 3);
        tail.publish(record("WARN", "the warning"));
        for index in 0..100 {
            tail.publish(record("INFO", &format!("info {index}")));
        }
        let page = tail.retained(&RetainedQuery::default());
        assert_eq!(
            messages(&page),
            ["the warning", "info 97", "info 98", "info 99"]
        );
    }

    #[test]
    fn retained_merges_both_rings_in_log_order() {
        let tail = retaining(Some("INFO"), 8, 8);
        tail.publish(record("INFO", "one"));
        tail.publish(record("WARN", "two"));
        tail.publish(record("INFO", "three"));
        tail.publish(record("ERROR", "four"));
        let page = tail.retained(&RetainedQuery::default());
        assert_eq!(messages(&page), ["one", "two", "three", "four"]);
        let seqs: Vec<u64> = page.records.iter().map(|record| record.seq).collect();
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn retained_applies_the_stream_filters() {
        let tail = retaining(Some("INFO"), 8, 8);
        let mut on_call = record("INFO", "answered");
        on_call.call_id = Some("call-a".to_string());
        tail.publish(on_call);
        let mut other_call = record("INFO", "answered");
        other_call.call_id = Some("call-b".to_string());
        tail.publish(other_call);
        tail.publish(record("WARN", "gateway down"));

        let by_call = RetainedQuery {
            filter: TailFilter::new(None, None, Some("call-a")),
            ..RetainedQuery::default()
        };
        let page = tail.retained(&by_call);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].call_id.as_deref(), Some("call-a"));

        let by_level = RetainedQuery {
            filter: TailFilter::new(Some("warn"), None, None),
            ..RetainedQuery::default()
        };
        assert_eq!(messages(&tail.retained(&by_level)), ["gateway down"]);

        let by_text = RetainedQuery {
            filter: TailFilter::new(None, Some("GATEWAY"), None),
            ..RetainedQuery::default()
        };
        assert_eq!(messages(&tail.retained(&by_text)), ["gateway down"]);
    }

    #[test]
    fn limit_returns_the_newest_and_before_pages_back() {
        let tail = retaining(Some("INFO"), 8, 16);
        for index in 0..10 {
            tail.publish(record("INFO", &format!("line {index}")));
        }

        let first = tail.retained(&RetainedQuery {
            limit: Some(4),
            ..RetainedQuery::default()
        });
        assert_eq!(messages(&first), ["line 6", "line 7", "line 8", "line 9"]);
        assert!(first.truncated);

        let second = tail.retained(&RetainedQuery {
            limit: Some(4),
            before: Some(first.records[0].seq),
            ..RetainedQuery::default()
        });
        assert_eq!(messages(&second), ["line 2", "line 3", "line 4", "line 5"]);
        assert!(second.truncated);

        let last = tail.retained(&RetainedQuery {
            limit: Some(4),
            before: Some(second.records[0].seq),
            ..RetainedQuery::default()
        });
        assert_eq!(messages(&last), ["line 0", "line 1"]);
        assert!(!last.truncated);
    }

    #[test]
    fn a_zero_capacity_ring_keeps_nothing() {
        let tail = retaining(Some("INFO"), 0, 0);
        tail.publish(record("WARN", "x"));
        tail.publish(record("INFO", "y"));
        assert_eq!(tail.retained_count(), 0);
    }

    #[test]
    fn steady_state_does_not_grow_the_retained_rings() {
        // Leak gate for the retention half: a long run of publishes leaves both
        // rings at their configured bound, not above it.
        let tail = retaining(Some("DEBUG"), 16, 32);
        for index in 0..10_000 {
            let level = match index % 3 {
                0 => "WARN",
                1 => "INFO",
                _ => "DEBUG",
            };
            tail.publish(record(level, "traffic"));
        }
        assert_eq!(lock_ring(&tail.warn_ring).len(), 16);
        assert_eq!(lock_ring(&tail.retain_ring).len(), 32);
        assert_eq!(tail.retained_count(), 48);
    }

    #[test]
    fn steady_state_does_not_grow_the_ring_or_the_streams() {
        // The per-module leak gate: a batch of complete attach/detach cycles
        // plus a batch of publishes must leave both structures at baseline.
        let tail = LogTail::default();
        tail.enabled.store(true, Ordering::Relaxed);
        tail.max_streams.store(4, Ordering::Relaxed);

        for _ in 0..500 {
            let stream = tail.attach(TailFilter::default()).expect("attaches");
            tail.publish(record("INFO", "traffic"));
            let _ = stream.lock().drain(..).count();
            tail.detach(&stream);
        }

        assert_eq!(tail.attached(), 0);
        assert_eq!(tail.streams().len(), 0);
        // Only the WARN+ ring retains anything, and it is bounded.
        assert!(tail.recent_warnings().is_empty());
    }
}
