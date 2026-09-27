//! What the dispatcher does with inbound bytes that are not a SIP message.
//!
//! Two jobs, both about a peer that keeps sending something the parser cannot
//! use. [`classify_non_sip`] names the payloads that *cannot* be SIP under any
//! reading, so they are dropped without costing a warning. [`ParseErrorLimiter`]
//! rate-limits the warning for everything else, so one noisy source costs one
//! line plus a periodic summary rather than one line per datagram.
//!
//! Both exist for the same reason: a parse-error WARN an operator learns to
//! scroll past is worse than no WARN at all, because the next one is real.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::warn;

/// The fewest bytes that can still hold a complete SIP start line.
///
/// Derived from the grammar (RFC 3261 §25.1), taking the shorter of the two
/// start lines:
///
/// ```text
/// Status-Line  = SIP-Version SP Status-Code SP Reason-Phrase CRLF
///              = "SIP/2.0" (7) + SP (1) + 3DIGIT (3) + SP (1)
///                + empty Reason-Phrase (0) + CRLF (2)                  = 14
/// Request-Line = Method SP Request-URI SP SIP-Version CRLF
///              = one-character extension-method token (1) + SP (1)
///                + shortest absoluteURI, "a:b" (3) + SP (1)
///                + "SIP/2.0" (7) + CRLF (2)                            = 15
/// ```
///
/// So 14, and deliberately the *grammar* floor rather than anything a real peer
/// would emit: `Reason-Phrase` may be empty (§25.1 makes it `*(…)`), and a
/// method may be a one-character extension token (§27.4 reserves no minimum),
/// so a tighter bound — a three-letter method, a `sip:` URI, a non-empty reason
/// phrase — would encode a guess about the peer instead of a fact about SIP, and
/// a guess here silently discards the malformed message an operator most wants
/// to see.
///
/// Below 14 bytes there is no start line to complete, so the parser can only
/// ever reject the payload, and it rejects it with the same context-free
/// complaint about a missing header/body boundary that names nothing actionable.
/// Dropping instead at TRACE with a counter is strictly more than that WARN
/// carried: the volume stays visible on the metric and the bytes come back with
/// one log-level change.
pub(super) const MIN_SIP_START_LINE_BYTES: usize = 14;

/// Why an inbound payload was dropped before the parser saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NonSipPayload {
    /// Stray CR / LF / SP only. RFC 3261 §7.5 says to ignore it, and RFC 5626
    /// §4.4.1 makes a double CRLF a keepalive on connection-oriented
    /// transports; some UDP peers send it anyway.
    Whitespace,
    /// An all-NUL payload. No RFC defines this as a keepalive — RFC 5626
    /// §4.4.1 is CRLF or STUN — but it is a common vendor NAT keepalive: four
    /// NUL bytes poked at a registered contact every 15 s, for as long as the
    /// registration lives. A SIP start line begins with a method token or
    /// `SIP`, so there is nothing here to diagnose.
    AllNul,
    /// Too short to hold a SIP start line — see [`MIN_SIP_START_LINE_BYTES`].
    TooShort,
}

impl NonSipPayload {
    /// The `reason` label on `siphon_non_sip_datagrams_dropped_total`.
    pub(super) fn label(self) -> &'static str {
        match self {
            NonSipPayload::Whitespace => "whitespace",
            NonSipPayload::AllNul => "all_nul",
            NonSipPayload::TooShort => "too_short",
        }
    }
}

/// Classify an inbound payload that cannot be a SIP message.
///
/// `None` means "hand it to the parser": either it is SIP, or it is malformed in
/// a way worth a log line.
///
/// Only UDP gets the all-NUL and too-short verdicts, and the asymmetry is the
/// point. A stream transport's read task already has its own non-SIP classifier
/// and scores what it rejects toward the auto-ban, so a short or NUL frame that
/// made it past framing there is a signal worth a warning. UDP has no
/// connection to score, is trivially spoofable, and — in the all-NUL case — is
/// carrying a keepalive a well-behaved peer sends on purpose. The whitespace
/// verdict stays transport-agnostic because that is where it has always been;
/// stream read tasks drain CRLF keepalives before the dispatcher ever sees them,
/// so in practice it too only fires for UDP.
pub(super) fn classify_non_sip(
    data: &[u8],
    transport: crate::transport::Transport,
) -> Option<NonSipPayload> {
    let udp = matches!(transport, crate::transport::Transport::Udp);

    let Some(first) = data.first() else {
        // An empty UDP datagram is legal on the wire and carries no start line.
        return udp.then_some(NonSipPayload::TooShort);
    };

    // Fast-path gates on the first byte: a real SIP message starts with a
    // method token or `SIP`, so the all-bytes scans only run once that is
    // already ruled out. The two scans are disjoint, so their order is
    // immaterial.
    if matches!(first, b'\r' | b'\n' | b' ')
        && data.iter().all(|byte| matches!(byte, b'\r' | b'\n' | b' '))
    {
        return Some(NonSipPayload::Whitespace);
    }

    if !udp {
        return None;
    }

    if *first == 0 && data.iter().all(|byte| *byte == 0) {
        return Some(NonSipPayload::AllNul);
    }

    (data.len() < MIN_SIP_START_LINE_BYTES).then_some(NonSipPayload::TooShort)
}

/// How long one source's parse-error warning stands for before the next logs.
///
/// A peer sending something unparseable every few seconds then costs one line a
/// minute instead of one line a datagram, which is short enough that an
/// operator watching a live log still sees the problem as it starts.
pub(super) const PARSE_ERROR_SUMMARY_WINDOW: Duration = Duration::from_secs(60);

/// Ceiling on the sources the suppression table tracks at once.
///
/// Bounds the table against the one shape that could otherwise grow it without
/// limit: a flood from many spoofed UDP sources. Past the ceiling nothing is
/// inserted and every parse error logs, which is deliberate — unparseable
/// traffic from more than this many distinct sources is itself the thing worth
/// seeing, and the alternative (evicting a tracked source to admit a new one)
/// turns the table into a cache that suppresses nothing.
///
/// This ceiling, not [`prune`](ParseErrorLimiter::prune), is what bounds the
/// memory: the backing map's *capacity* never shrinks once grown, so pruning
/// returns the entry count to zero but not the allocation. 4,096 entries of an
/// `IpAddr` plus two `Instant`s and a counter is tens of kilobytes at the
/// high-water mark, which is the number worth bounding.
pub(super) const PARSE_ERROR_MAX_SOURCES: usize = 4096;

/// What the caller should do with a parse error it just caught.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ParseErrorAction {
    /// Log it. `suppressed` is how many errors from this source went unlogged
    /// since the last line: 0 on the first, non-zero on a window summary.
    Log { suppressed: u64 },
    /// A line for this source is already standing in this window. The error is
    /// counted and reported by the next summary, not dropped.
    Suppress,
}

/// One tracked source's suppression state.
#[derive(Clone, Copy, Debug)]
struct SourceState {
    /// When the standing line for this source was logged.
    logged_at: Instant,
    /// Errors seen from this source since that line.
    suppressed: u64,
    /// When the most recent error arrived, for eviction.
    last_seen: Instant,
}

/// Per-source rate limiter for the inbound parse-error warning.
///
/// Keyed on the source IP rather than the full socket address: a peer retrying
/// from a fresh ephemeral port every few seconds is one peer, and keying on the
/// port would make the table grow as fast as the noise it exists to suppress.
///
/// [`prune`](Self::prune) is what keeps the table bounded over time — the
/// dispatcher's periodic sweep calls it, and it flushes any count a source left
/// behind before forgetting the source, so no suppressed error goes unreported.
pub(super) struct ParseErrorLimiter {
    sources: DashMap<IpAddr, SourceState>,
    window: Duration,
    max_sources: usize,
}

impl Default for ParseErrorLimiter {
    fn default() -> Self {
        Self::new(PARSE_ERROR_SUMMARY_WINDOW, PARSE_ERROR_MAX_SOURCES)
    }
}

impl ParseErrorLimiter {
    pub(super) fn new(window: Duration, max_sources: usize) -> Self {
        Self {
            sources: DashMap::new(),
            window,
            max_sources,
        }
    }

    /// Record one parse error from `source` and say whether to log it.
    pub(super) fn record(&self, source: IpAddr, now: Instant) -> ParseErrorAction {
        if let Some(mut state) = self.sources.get_mut(&source) {
            state.last_seen = now;
            if now.duration_since(state.logged_at) >= self.window {
                let suppressed = std::mem::take(&mut state.suppressed);
                state.logged_at = now;
                return ParseErrorAction::Log { suppressed };
            }
            state.suppressed += 1;
            return ParseErrorAction::Suppress;
        }

        // A new source. The shard guard above is released by every path that
        // reaches here, so the length check and insert cannot self-deadlock.
        // Two threads admitting the same new source race to insert the same
        // value, and two admitting different ones can overshoot the ceiling by
        // the number of racing threads — both harmless, and cheaper than
        // holding a lock across the whole path.
        if self.sources.len() >= self.max_sources {
            return ParseErrorAction::Log { suppressed: 0 };
        }
        self.sources.insert(
            source,
            SourceState {
                logged_at: now,
                suppressed: 0,
                last_seen: now,
            },
        );
        ParseErrorAction::Log { suppressed: 0 }
    }

    /// Forget every source quiet for a full window, reporting any count it left
    /// behind first.
    ///
    /// Returns how many sources were forgotten.
    pub(super) fn prune(&self, now: Instant) -> usize {
        let mut forgotten = 0usize;
        let mut flushed: Vec<(IpAddr, u64)> = Vec::new();
        self.sources.retain(|source, state| {
            if now.duration_since(state.last_seen) < self.window {
                return true;
            }
            if state.suppressed > 0 {
                flushed.push((*source, state.suppressed));
            }
            forgotten += 1;
            false
        });

        // Logged after `retain` returns, so no shard lock is held across a
        // formatting call.
        for (source, suppressed) in &flushed {
            warn!(
                remote = %source,
                suppressed,
                "SIP parse errors suppressed for this source (it has since gone quiet)"
            );
        }
        forgotten
    }

    /// How many sources the table is tracking. The leak gate asserts this
    /// returns to its baseline once sources go quiet; nothing in production
    /// reads it, so it is test-only rather than a published gauge.
    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.sources.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;
    use std::net::Ipv4Addr;

    fn source(host: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, host))
    }

    // --- classify_non_sip ---------------------------------------------------

    #[test]
    fn all_nul_udp_datagram_is_dropped() {
        assert_eq!(
            classify_non_sip(&[0, 0, 0, 0], Transport::Udp),
            Some(NonSipPayload::AllNul)
        );
    }

    #[test]
    fn long_all_nul_udp_datagram_is_dropped_as_nul_not_short() {
        let payload = [0u8; 64];
        assert_eq!(
            classify_non_sip(&payload, Transport::Udp),
            Some(NonSipPayload::AllNul)
        );
    }

    #[test]
    fn udp_datagram_shorter_than_a_start_line_is_dropped() {
        // One byte short of the 14-byte floor, and not whitespace or NUL, so
        // only the length bound can catch it.
        let payload = b"SIP/2.0 200\r\n";
        assert_eq!(payload.len(), MIN_SIP_START_LINE_BYTES - 1);
        assert_eq!(
            classify_non_sip(payload, Transport::Udp),
            Some(NonSipPayload::TooShort)
        );
    }

    #[test]
    fn shortest_possible_status_line_reaches_the_parser() {
        // The grammar floor itself: "SIP/2.0", SP, 3DIGIT, SP, empty
        // Reason-Phrase, CRLF. Malformed as a message (no header/body
        // boundary), which is exactly why it must still be logged.
        let payload = b"SIP/2.0 200 \r\n";
        assert_eq!(payload.len(), MIN_SIP_START_LINE_BYTES);
        assert_eq!(classify_non_sip(payload, Transport::Udp), None);
    }

    #[test]
    fn empty_udp_datagram_is_dropped() {
        assert_eq!(
            classify_non_sip(&[], Transport::Udp),
            Some(NonSipPayload::TooShort)
        );
    }

    #[test]
    fn crlf_keepalive_still_drops() {
        for keepalive in [&b"\r\n\r\n"[..], &b"\r\n"[..], &b"   "[..], &b"\n"[..]] {
            assert_eq!(
                classify_non_sip(keepalive, Transport::Udp),
                Some(NonSipPayload::Whitespace),
                "keepalive {keepalive:?} must drop"
            );
        }
    }

    #[test]
    fn crlf_keepalive_drops_on_every_transport() {
        for transport in [
            Transport::Udp,
            Transport::Tcp,
            Transport::Tls,
            Transport::WebSocket,
            Transport::WebSocketSecure,
        ] {
            assert_eq!(
                classify_non_sip(b"\r\n\r\n", transport),
                Some(NonSipPayload::Whitespace),
                "{transport:?} must keep dropping a CRLF keepalive"
            );
        }
    }

    #[test]
    fn stream_transports_keep_warning_on_short_and_nul_frames() {
        // The stream read tasks have their own non-SIP classifier and score
        // what they reject toward the auto-ban, so anything that got past
        // framing there is worth the warning.
        for transport in [Transport::Tcp, Transport::Tls, Transport::WebSocket] {
            assert_eq!(classify_non_sip(&[0, 0, 0, 0], transport), None);
            assert_eq!(classify_non_sip(b"junk", transport), None);
        }
    }

    #[test]
    fn a_malformed_but_plausible_request_reaches_the_parser() {
        // A real INVITE with its header/body boundary chopped off: the parser
        // rejects it, and an operator wants to know.
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=1928301774\r\n",
        );
        assert_eq!(classify_non_sip(raw.as_bytes(), Transport::Udp), None);
    }

    #[test]
    fn a_well_formed_request_reaches_the_parser() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=1928301774\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: a84b4c76e66710@192.0.2.10\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        assert_eq!(classify_non_sip(raw.as_bytes(), Transport::Udp), None);
    }

    #[test]
    fn a_payload_that_merely_starts_with_a_nul_reaches_the_parser() {
        // Not all-NUL: a binary probe with structure is a security signal, and
        // long enough to carry a start line, so it keeps its warning.
        let payload = b"\0INVITE sip:bob@example.com SIP/2.0\r\n";
        assert_eq!(classify_non_sip(payload, Transport::Udp), None);
    }

    #[test]
    fn reason_labels_are_distinct() {
        let labels = [
            NonSipPayload::Whitespace.label(),
            NonSipPayload::AllNul.label(),
            NonSipPayload::TooShort.label(),
        ];
        assert_eq!(labels, ["whitespace", "all_nul", "too_short"]);
    }

    // --- ParseErrorLimiter -------------------------------------------------

    #[test]
    fn first_error_from_a_source_logs() {
        let limiter = ParseErrorLimiter::default();
        assert_eq!(
            limiter.record(source(10), Instant::now()),
            ParseErrorAction::Log { suppressed: 0 }
        );
    }

    #[test]
    fn repeats_inside_the_window_are_suppressed_then_summarised() {
        let limiter = ParseErrorLimiter::default();
        let peer = source(10);
        let start = Instant::now();

        assert_eq!(
            limiter.record(peer, start),
            ParseErrorAction::Log { suppressed: 0 }
        );
        // A keepalive every 15 s for a minute: suppressed, not logged.
        for step in 1..4 {
            assert_eq!(
                limiter.record(peer, start + Duration::from_secs(15 * step)),
                ParseErrorAction::Suppress
            );
        }
        // The first error past the window carries the count of the ones that
        // did not log.
        assert_eq!(
            limiter.record(peer, start + PARSE_ERROR_SUMMARY_WINDOW),
            ParseErrorAction::Log { suppressed: 3 }
        );
        // …and the counter starts over.
        assert_eq!(
            limiter.record(peer, start + PARSE_ERROR_SUMMARY_WINDOW),
            ParseErrorAction::Suppress
        );
        assert_eq!(
            limiter.record(peer, start + PARSE_ERROR_SUMMARY_WINDOW * 2),
            ParseErrorAction::Log { suppressed: 1 }
        );
    }

    #[test]
    fn sources_are_limited_independently() {
        let limiter = ParseErrorLimiter::default();
        let now = Instant::now();
        assert_eq!(
            limiter.record(source(10), now),
            ParseErrorAction::Log { suppressed: 0 }
        );
        assert_eq!(
            limiter.record(source(11), now),
            ParseErrorAction::Log { suppressed: 0 }
        );
        assert_eq!(limiter.record(source(10), now), ParseErrorAction::Suppress);
        assert_eq!(limiter.record(source(11), now), ParseErrorAction::Suppress);
        assert_eq!(limiter.tracked_sources(), 2);
    }

    #[test]
    fn a_source_flood_past_the_ceiling_logs_instead_of_growing() {
        let limiter = ParseErrorLimiter::new(PARSE_ERROR_SUMMARY_WINDOW, 2);
        let now = Instant::now();
        assert_eq!(
            limiter.record(source(10), now),
            ParseErrorAction::Log { suppressed: 0 }
        );
        assert_eq!(
            limiter.record(source(11), now),
            ParseErrorAction::Log { suppressed: 0 }
        );
        // Table full: the third source is never tracked, and every one of its
        // errors keeps logging rather than being swallowed.
        for _ in 0..4 {
            assert_eq!(
                limiter.record(source(12), now),
                ParseErrorAction::Log { suppressed: 0 }
            );
        }
        assert_eq!(limiter.tracked_sources(), 2);
    }

    #[test]
    fn prune_keeps_a_source_that_is_still_noisy() {
        let limiter = ParseErrorLimiter::default();
        let peer = source(10);
        let start = Instant::now();
        limiter.record(peer, start);
        limiter.record(peer, start + Duration::from_secs(30));
        assert_eq!(limiter.prune(start + Duration::from_secs(45)), 0);
        assert_eq!(limiter.tracked_sources(), 1);
    }

    #[test]
    fn prune_reports_a_quiet_sources_outstanding_count() {
        let limiter = ParseErrorLimiter::default();
        let peer = source(10);
        let start = Instant::now();
        limiter.record(peer, start);
        limiter.record(peer, start);
        limiter.record(peer, start);
        // Two errors suppressed behind the standing line; the source then goes
        // quiet, so `prune` is the only thing left to report them.
        assert_eq!(
            limiter.prune(start + PARSE_ERROR_SUMMARY_WINDOW * 2),
            1,
            "the quiet source with an outstanding count is reported"
        );
        assert_eq!(limiter.tracked_sources(), 0);
    }

    /// Steady-state leak gate: the suppression table returns to its starting
    /// `len()` after every batch of sources goes quiet, so a flood of one-off
    /// noisy peers cannot pin an entry per peer for the life of the process.
    #[test]
    fn suppression_table_returns_to_baseline_after_sources_go_quiet() {
        let limiter = ParseErrorLimiter::default();
        let baseline = limiter.tracked_sources();
        let start = Instant::now();

        const SOURCES: u8 = 64;
        for cycle in 0..8u64 {
            let cycle_start = start + Duration::from_secs(cycle * 600);
            for host in 0..SOURCES {
                for repeat in 0..16u64 {
                    limiter.record(
                        source(host),
                        cycle_start + Duration::from_millis(repeat * 10),
                    );
                }
            }
            assert_eq!(
                limiter.tracked_sources(),
                baseline + usize::from(SOURCES),
                "cycle {cycle} should have filled the table before the prune"
            );

            limiter.prune(cycle_start + PARSE_ERROR_SUMMARY_WINDOW * 2);
            assert_eq!(
                limiter.tracked_sources(),
                baseline,
                "cycle {cycle} left entries behind"
            );
        }
    }

    #[test]
    fn concurrent_sources_are_tracked_without_losing_the_ceiling() {
        use std::sync::Arc;

        let limiter = Arc::new(ParseErrorLimiter::new(PARSE_ERROR_SUMMARY_WINDOW, 16));
        let now = Instant::now();
        let mut handles = Vec::new();
        for thread in 0..8u8 {
            let limiter = Arc::clone(&limiter);
            handles.push(std::thread::spawn(move || {
                for host in 0..32u8 {
                    limiter.record(source(thread.wrapping_mul(32).wrapping_add(host)), now);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("the worker thread completes");
        }
        // Racing admissions may overshoot by at most one per thread.
        assert!(
            limiter.tracked_sources() <= 16 + 8,
            "table grew to {}",
            limiter.tracked_sources()
        );
        limiter.prune(now + PARSE_ERROR_SUMMARY_WINDOW * 2);
        assert_eq!(limiter.tracked_sources(), 0);
    }
}
