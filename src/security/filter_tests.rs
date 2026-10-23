//! What an operator sees of a rate-limit ban: one WARN when it goes in, one
//! INFO when it ends, the banned sources while it lasts, and nothing per
//! dropped request.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::*;
use crate::config::SecurityConfig;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a literal address")
}

fn filter(max_requests: u32, ban_duration_secs: u32) -> Arc<SecurityFilter> {
    let config: SecurityConfig = crate::config::yaml::from_str(&format!(
        "rate_limit: {{ window_secs: 10, max_requests: {max_requests}, ban_duration_secs: {ban_duration_secs} }}\n"
    ))
    .expect("a security section");
    SecurityFilter::from_config(&config).expect("rate_limit installs the filter")
}

/// Run `body` with every log line it emits captured, and return them.
fn captured(body: impl FnOnce()) -> String {
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(log.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    log.rendered()
}

fn lines_with<'log>(log: &'log str, needle: &str) -> Vec<&'log str> {
    log.lines().filter(|line| line.contains(needle)).collect()
}

/// In its own process: tracing's per-callsite interest is process-wide, and a
/// test elsewhere registering a quieter subscriber at the same moment can
/// leave these lines unrecorded.
#[test]
fn a_ban_is_logged_once_when_it_goes_in_and_once_when_it_ends() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_ban_is_logged_once_when_it_goes_in_and_once_when_it_ends"
        ),
        || {
            let filter = filter(3, 300);
            let source = ip("203.0.113.40");
            let t0 = Instant::now();
            let log = captured(|| {
                for _ in 0..3 {
                    assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
                }
                // The fourth trips the limit; the rest land inside the ban.
                for offset in 0..50 {
                    assert_eq!(
                        filter.evaluate_at(source, None, t0 + Duration::from_millis(offset)),
                        SecurityVerdict::RateLimited
                    );
                }
                // Past the ban: the next request lifts it and is counted afresh.
                assert_eq!(
                    filter.evaluate_at(source, None, t0 + Duration::from_secs(301)),
                    SecurityVerdict::Allow
                );
            });

            let installed = lines_with(&log, "rate_limit: source banned");
            assert_eq!(installed.len(), 1, "one WARN per ban, not per drop:\n{log}");
            let line = installed[0];
            for field in [
                "WARN",
                "source=203.0.113.40",
                "requests=4",
                "max_requests=3",
                "window_secs=10",
                "ban_secs=300",
            ] {
                assert!(line.contains(field), "{field} missing from {line}");
            }
            let lifted = lines_with(&log, "rate_limit: ban lifted");
            assert_eq!(lifted.len(), 1, "one INFO at the end:\n{log}");
            assert!(lifted[0].contains("INFO") && lifted[0].contains("source=203.0.113.40"));
        },
    );
}

#[test]
fn a_ban_that_runs_out_quietly_is_lifted_at_the_prune() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_ban_that_runs_out_quietly_is_lifted_at_the_prune"
        ),
        || {
            let filter = filter(1, 60);
            let source = ip("203.0.113.41");
            let t0 = Instant::now();
            let log = captured(|| {
                filter.evaluate_at(source, None, t0);
                assert_eq!(
                    filter.evaluate_at(source, None, t0),
                    SecurityVerdict::RateLimited
                );
                filter.prune_at(t0 + Duration::from_secs(30));
                assert_eq!(filter.rate_limit_bans(), 1, "still banned at 30 s");
                filter.prune_at(t0 + Duration::from_secs(61));
            });
            assert_eq!(filter.rate_limit_bans(), 0);
            let lifted = lines_with(&log, "rate_limit: ban lifted");
            assert_eq!(lifted.len(), 1, "{log}");
            assert!(lifted[0].contains("source=203.0.113.41"));
        },
    );
}

/// A scanner fleet tripping the limit from many addresses at once must not
/// flood the log: past the budget the lines are counted, and the count is
/// said when the window rolls.
#[test]
fn a_ban_wave_is_logged_within_a_budget_and_the_rest_counted() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_ban_wave_is_logged_within_a_budget_and_the_rest_counted"
        ),
        || {
            let filter = filter(1, 600);
            let t0 = Instant::now();
            let sources = 200u32;
            let log = captured(|| {
                for index in 0..sources {
                    // 198.51.100.0 + index, all inside the /24.
                    let source = IpAddr::from((0xC633_6400u32 + index).to_be_bytes());
                    filter.evaluate_at(source, None, t0);
                    assert_eq!(
                        filter.evaluate_at(source, None, t0),
                        SecurityVerdict::RateLimited
                    );
                }
                // The window rolls at the next prune: the unlogged rest is said.
                filter.prune_at(t0 + BAN_LOG_WINDOW + Duration::from_secs(1));
            });
            assert_eq!(filter.rate_limit_bans(), sources as usize);
            let installed = lines_with(&log, "rate_limit: source banned");
            assert_eq!(installed.len(), BAN_LOG_BUDGET as usize, "{log}");
            let summary = lines_with(&log, "further rate-limit bans went unlogged");
            assert_eq!(summary.len(), 1, "{log}");
            let unlogged = sources - BAN_LOG_BUDGET;
            assert!(
                summary[0].contains(&format!("unlogged={unlogged}")),
                "{}",
                summary[0]
            );
        },
    );
}

#[test]
fn banned_sources_lists_each_ban_with_its_remaining_time() {
    let filter = filter(1, 300);
    let banned = ip("203.0.113.42");
    let within = ip("203.0.113.43");
    let t0 = Instant::now();
    filter.evaluate_at(banned, None, t0);
    filter.evaluate_at(banned, None, t0);
    filter.evaluate_at(within, None, t0);

    assert_eq!(
        filter.rate_limit_banned_sources_at(t0 + Duration::from_secs(100)),
        vec![(banned, 200)]
    );
    assert!(
        filter
            .rate_limit_banned_sources_at(t0 + Duration::from_secs(301))
            .is_empty(),
        "a ban past its expiry is not listed, pruned or not"
    );
}

#[test]
fn the_banned_sources_gauge_follows_the_bans() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::the_banned_sources_gauge_follows_the_bans"
        ),
        || {
            crate::metrics::init().expect("the metrics registry builds");
            let filter = filter(1, 60);
            let t0 = Instant::now();
            for source in [ip("203.0.113.44"), ip("203.0.113.45")] {
                filter.evaluate_at(source, None, t0);
                filter.evaluate_at(source, None, t0);
            }
            let exposition = crate::metrics::encode_metrics();
            assert!(
                exposition.contains("siphon_rate_limit_banned_sources 2"),
                "{exposition}"
            );
            assert!(
                exposition.contains("siphon_rate_limit_bans_total 2"),
                "{exposition}"
            );
            filter.prune_at(t0 + Duration::from_secs(61));
            assert!(crate::metrics::encode_metrics().contains("siphon_rate_limit_banned_sources 0"));
        },
    );
}
