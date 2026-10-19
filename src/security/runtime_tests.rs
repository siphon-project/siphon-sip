//! The reloadable abuse controls, on runtimes with slots of their own so no
//! test touches the process-wide controls.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::*;
use crate::apiban::ApiBanStore;
use crate::firewall::{Command, KernelFirewall};
use crate::security::SecurityVerdict;

const SOURCE: &str = "203.0.113.9";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a literal address")
}

fn security(yaml: &str) -> SecurityConfig {
    crate::config::yaml::from_str(yaml).expect("a security section")
}

fn rate_limit(max_requests: u32) -> SecurityConfig {
    security(&format!(
        "rate_limit: {{ window_secs: 60, max_requests: {max_requests}, ban_duration_secs: 600 }}\n"
    ))
}

fn ban_policy(threshold: u32) -> BanPolicy {
    BanPolicy::new(threshold, 600, 3600, 1, 0, 86_400)
}

fn no_blocklist() -> Option<&'static InstalledBlocklist> {
    None
}

fn unbans(receiver: &mut tokio::sync::mpsc::Receiver<Command>) -> Vec<IpAddr> {
    let mut unbanned = Vec::new();
    while let Ok(command) = receiver.try_recv() {
        if let Command::Unban { ip } = command {
            unbanned.push(ip);
        }
    }
    unbanned
}

/// The one test that needs a blocklist owns these.
static BLOCKLIST: OnceLock<InstalledBlocklist> = OnceLock::new();
static BLOCKLIST_FIREWALL: Mutex<Option<tokio::sync::mpsc::Receiver<Command>>> = Mutex::new(None);

fn blocklist() -> Option<&'static InstalledBlocklist> {
    BLOCKLIST.get()
}

fn listed_blocklist() -> Arc<ApiBanStore> {
    let store = Arc::new(ApiBanStore::new());
    let (firewall, receiver) = KernelFirewall::capturing();
    *BLOCKLIST_FIREWALL.lock().expect("lock") = Some(receiver);
    store.insert(ip(SOURCE), Some(Duration::from_secs(7200)));
    store.insert(ip("198.51.100.77"), Some(Duration::from_secs(7200)));
    let installed = InstalledBlocklist::for_test(
        Arc::clone(&store),
        SourceTrust::from_cidrs(&[]),
        Some(firewall),
    );
    assert!(BLOCKLIST.set(installed).is_ok(), "set once");
    store
}

/// A source trusted at run time — by a bare address, which userspace parsing
/// used to drop while the kernel allow set took it — loses every ban held
/// against it: auto-ban (kernel element too), rate limit and APIBAN (kernel
/// element too). Nothing else is touched.
#[tokio::test]
async fn a_newly_trusted_source_has_every_ban_lifted() {
    let (firewall, mut kernel) = KernelFirewall::capturing();
    let runtime = SecurityRuntime::detached(&[], None, Some(firewall), blocklist);
    let listed = listed_blocklist();
    runtime.apply_auto_ban(Some(ban_policy(1)));
    runtime.apply_filter(Some(&rate_limit(1)));
    let store = runtime.auto_ban().expect("installed");
    let filter = runtime.security_filter().expect("installed");

    assert!(store.record_failure(ip(SOURCE)));
    assert!(store.record_failure(ip("198.51.100.77")));
    assert_eq!(filter.evaluate(ip(SOURCE), None), SecurityVerdict::Allow);
    assert_eq!(
        filter.evaluate(ip(SOURCE), None),
        SecurityVerdict::RateLimited
    );
    unbans(&mut kernel);

    runtime.apply_trusted(TrustedCidrs::parse(&[SOURCE.to_string()]).0);

    assert!(!store.is_banned(ip(SOURCE)));
    assert!(
        store.is_banned(ip("198.51.100.77")),
        "an untrusted ban stays"
    );
    assert_eq!(filter.evaluate(ip(SOURCE), None), SecurityVerdict::Allow);
    assert_eq!(filter.rate_limit_bans(), 0);
    assert_eq!(unbans(&mut kernel), [ip(SOURCE)]);
    assert_eq!(listed.len(), 1, "the APIBAN entry is evicted");
    let mut blocklist_kernel = BLOCKLIST_FIREWALL
        .lock()
        .expect("lock")
        .take()
        .expect("receiver");
    assert_eq!(unbans(&mut blocklist_kernel), [ip(SOURCE)]);
}

#[tokio::test]
async fn a_newly_trusted_cidr_lifts_the_bans_inside_it() {
    let (firewall, mut kernel) = KernelFirewall::capturing();
    let runtime = SecurityRuntime::detached(&[], None, Some(firewall), no_blocklist);
    runtime.apply_auto_ban(Some(ban_policy(1)));
    let store = runtime.auto_ban().expect("installed");
    assert!(store.record_failure(ip(SOURCE)));
    unbans(&mut kernel);

    runtime.apply_trusted(TrustedCidrs::parse(&["203.0.113.9/32".to_string()]).0);
    assert!(!store.is_banned(ip(SOURCE)));
    assert_eq!(unbans(&mut kernel), [ip(SOURCE)]);
    assert_eq!(store.tracked_sources(), (0, 0));
}

/// Taken off the list, a source is counted again — from zero, never for what
/// it sent while trusted.
#[tokio::test]
async fn a_source_no_longer_trusted_is_counted_from_zero() {
    let runtime = SecurityRuntime::detached(&[SOURCE.to_string()], None, None, no_blocklist);
    runtime.apply_auto_ban(Some(ban_policy(2)));
    let store = runtime.auto_ban().expect("installed");
    for _ in 0..10 {
        assert!(!store.record_failure(ip(SOURCE)));
    }
    runtime.apply_trusted(Vec::new());
    assert!(!store.record_failure(ip(SOURCE)), "1 of 2");
    assert!(store.record_failure(ip(SOURCE)), "2 of 2 bans");
}

/// A new threshold is judged against the count already held.
#[tokio::test]
async fn a_threshold_change_keeps_the_failure_count() {
    let runtime = SecurityRuntime::detached(&[], None, None, no_blocklist);
    runtime.apply_auto_ban(Some(ban_policy(3)));
    let store = Arc::clone(runtime.auto_ban().expect("installed"));
    assert!(!store.record_failure(ip(SOURCE)));
    assert!(!store.record_failure(ip(SOURCE)));
    runtime.apply_auto_ban(Some(ban_policy(2)));
    assert!(
        Arc::ptr_eq(&store, runtime.auto_ban().expect("installed")),
        "the same store"
    );
    assert!(
        store.record_failure(ip(SOURCE)),
        "the third signal bans at 2"
    );
}

/// A rate-limit ban keeps its expiry across a policy change; the new limit
/// applies from the next request.
#[tokio::test]
async fn a_rate_limit_change_keeps_a_ban_in_force() {
    let runtime = SecurityRuntime::detached(&[], None, None, no_blocklist);
    runtime.apply_filter(Some(&rate_limit(1)));
    let filter = runtime.security_filter().expect("installed");
    filter.evaluate(ip(SOURCE), None);
    assert_eq!(
        filter.evaluate(ip(SOURCE), None),
        SecurityVerdict::RateLimited
    );
    runtime.apply_filter(Some(&rate_limit(100)));
    assert_eq!(
        filter.evaluate(ip(SOURCE), None),
        SecurityVerdict::RateLimited
    );
    let other = ip("203.0.113.10");
    for _ in 0..100 {
        assert_eq!(filter.evaluate(other, None), SecurityVerdict::Allow);
    }
    assert_eq!(filter.evaluate(other, None), SecurityVerdict::RateLimited);
}

#[tokio::test]
async fn failed_auth_ban_turns_on_off_and_on_again() {
    let (firewall, mut kernel) = KernelFirewall::capturing();
    let runtime = SecurityRuntime::detached(&[], None, Some(firewall), no_blocklist);
    runtime.apply_auto_ban(None);
    assert!(runtime.auto_ban().is_none(), "absent stays absent");

    runtime.apply_auto_ban(Some(ban_policy(1)));
    let store = Arc::clone(runtime.auto_ban().expect("installed late"));
    assert!(store.is_enabled());
    assert!(store.record_failure(ip(SOURCE)));
    unbans(&mut kernel);

    runtime.apply_auto_ban(None);
    assert!(!store.is_enabled());
    assert!(!store.is_banned(ip(SOURCE)));
    assert_eq!(unbans(&mut kernel), [ip(SOURCE)]);
    assert!(!store.record_failure(ip(SOURCE)), "nothing is counted");
    assert_eq!(store.tracked_sources(), (0, 0));

    runtime.apply_auto_ban(Some(ban_policy(1)));
    assert!(Arc::ptr_eq(&store, runtime.auto_ban().expect("installed")));
    assert!(store.record_failure(ip(SOURCE)));
}

#[tokio::test]
async fn rate_limit_turns_on_off_and_on_again() {
    let runtime = SecurityRuntime::detached(&[], None, None, no_blocklist);
    runtime.apply_filter(Some(&security("trusted_cidrs: []\n")));
    assert!(runtime.security_filter().is_none(), "nothing to enforce");

    runtime.apply_filter(Some(&rate_limit(1)));
    let filter = Arc::clone(runtime.security_filter().expect("installed late"));
    filter.evaluate(ip(SOURCE), None);
    assert_eq!(
        filter.evaluate(ip(SOURCE), None),
        SecurityVerdict::RateLimited
    );

    runtime.apply_filter(Some(&security("trusted_cidrs: []\n")));
    assert!(!filter.is_enabled());
    assert_eq!(filter.rate_limit_bans(), 0, "removing it clears its tables");
    assert_eq!(filter.evaluate(ip(SOURCE), None), SecurityVerdict::Allow);
    assert_eq!(filter.rate.tracked_sources(), (0, 0, 0));

    runtime.apply_filter(Some(&rate_limit(1)));
    assert!(Arc::ptr_eq(
        &filter,
        runtime.security_filter().expect("installed")
    ));
    filter.evaluate(ip(SOURCE), None);
    assert_eq!(
        filter.evaluate(ip(SOURCE), None),
        SecurityVerdict::RateLimited
    );
}

#[tokio::test]
async fn scanner_block_turns_on_off_and_on_again() {
    let scanner = security("scanner_block: { user_agents: [\"friendly-scanner\"] }\n");
    let runtime = SecurityRuntime::detached(&[], None, None, no_blocklist);
    runtime.apply_filter(None);
    assert!(runtime.security_filter().is_none());

    runtime.apply_filter(Some(&scanner));
    let filter = Arc::clone(runtime.security_filter().expect("installed late"));
    assert_eq!(
        filter.evaluate(ip(SOURCE), Some("friendly-scanner")),
        SecurityVerdict::Scanner
    );
    // No `security:` section at all is both off.
    runtime.apply_filter(None);
    assert_eq!(
        filter.evaluate(ip(SOURCE), Some("friendly-scanner")),
        SecurityVerdict::Allow
    );
    runtime.apply_filter(Some(&scanner));
    assert_eq!(
        filter.evaluate(ip(SOURCE), Some("friendly-scanner")),
        SecurityVerdict::Scanner
    );
}

/// A bare address is a host route in userspace too, the parser the kernel
/// allow set already used.
#[test]
fn a_bare_address_is_trusted() {
    let trust = SourceTrust::from_cidrs(&[SOURCE.to_string(), "2001:db8::7".to_string()]);
    assert!(trust.is_trusted(ip(SOURCE)));
    assert!(!trust.is_trusted(ip("203.0.113.10")));
    assert!(trust.is_trusted(ip("2001:db8::7")));
}

/// Start-up keeps going past an entry it cannot read, and says so.
#[test]
fn start_up_warns_about_an_invalid_trusted_entry() {
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(log.clone())
        .finish();
    let runtime = tracing::subscriber::with_default(subscriber, || {
        SecurityRuntime::new(
            &["198.51.100.0/24".to_string(), "not-an-address".to_string()],
            None,
            None,
        )
    });
    assert_eq!(runtime.trusted().load().len(), 1);
    let rendered = log.rendered();
    assert!(
        rendered.contains("not-an-address") && rendered.contains("trusted_cidrs"),
        "{rendered}"
    );
}

#[cfg(target_os = "linux")]
fn read_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
}

#[cfg(not(target_os = "linux"))]
fn read_rss_kb() -> Option<u64> {
    None
}

/// Leak gate for reloading the security section: 1,000 reloads cycling every
/// hot field through on, changed and off. The live-task count settles after
/// the first enable (each prune task is spawned once), no reload subscribes
/// another gateway-view listener, every replaced policy and trusted list is
/// freed, the tables drain to nothing after a prune, and RSS plateaus.
///
/// Runs in its own process: RSS and the task count belong to the whole binary.
#[test]
fn security_reload_cycles_do_not_leak() {
    crate::own_process::run(
        concat!(module_path!(), "::security_reload_cycles_do_not_leak"),
        measure_security_reload_cycles,
    );
}

fn measure_security_reload_cycles() {
    use crate::server::config_reload::{ConfigReloader, ReloadTargets};

    const CYCLES: usize = 1_000;
    const PER_RELOAD_BUDGET_BYTES: u64 = 2_048;

    let documents = [
        concat!(
            "security:\n",
            "  trusted_cidrs: [\"198.51.100.0/24\"]\n",
            "  rate_limit: { window_secs: 60, max_requests: 5, ban_duration_secs: 600 }\n",
            "  scanner_block: { user_agents: [\"friendly-scanner\"] }\n",
            "  failed_auth_ban: { threshold: 3, window_secs: 600, ban_duration_secs: 3600 }\n",
        ),
        concat!(
            "security:\n",
            "  trusted_cidrs: [\"198.51.100.0/24\", \"203.0.113.9\", \"bogus\"]\n",
            "  rate_limit: { window_secs: 30, max_requests: 9, ban_duration_secs: 60 }\n",
            "  failed_auth_ban: { threshold: 5, window_secs: 60, ban_duration_secs: 600 }\n",
        ),
        "security:\n  trusted_cidrs: []\n",
    ];
    let config = |security: &str| {
        format!(
            "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\n{security}"
        )
    };

    let runtime_handle = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime_handle.block_on(async {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("siphon.yaml");
        std::fs::write(&path, config(documents[2])).expect("write");
        let (_, baseline) = crate::config::Config::load_with_document(&path).expect("loads");
        let view = Arc::new(GatewayView::new());
        let security = Arc::new(SecurityRuntime::detached(
            &[],
            Some(Arc::clone(&view)),
            None,
            no_blocklist,
        ));
        let reloader = ConfigReloader::new(
            path.clone(),
            baseline,
            ReloadTargets::new(
                crate::config::IdentityHeaders::default().shared(),
                "SIPhon",
                "9.9.9",
            )
            .with_security(Arc::clone(&security)),
        );
        let reload = |index: usize| {
            std::fs::write(&path, config(documents[index % documents.len()])).expect("write");
            let reloader = &reloader;
            async move { reloader.reload().await.expect("validates") }
        };
        // Some traffic through each control, so the tables hold rows.
        let traffic = |security: &SecurityRuntime| {
            let now = Instant::now();
            for host in 1..=50u8 {
                let source = IpAddr::from([192, 0, 2, host]);
                if let Some(filter) = security.security_filter() {
                    filter.evaluate_at(source, Some("friendly-scanner"), now);
                    filter.evaluate_at(source, None, now);
                }
                if let Some(store) = security.auto_ban() {
                    store.record_failure(source);
                }
            }
        };

        // The first enable installs both controls and spawns their prune tasks.
        let report = reload(0).await;
        assert!(report.warnings.is_empty());
        let report = reload(1).await;
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        let store = Arc::clone(security.auto_ban().expect("installed"));
        let filter = Arc::clone(security.security_filter().expect("installed"));
        let listeners = view.listener_count();
        let tasks = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let replaced_policy = Arc::downgrade(&store.policy.load_full().expect("enabled"));
        let replaced_filter_policy = Arc::downgrade(&filter.policy.load_full());
        let replaced_trusted = Arc::downgrade(&*security.trusted().load());

        let cycle = |count: usize| {
            let security = &security;
            let reload = &reload;
            async move {
                for index in 0..count {
                    reload(index).await;
                    traffic(security);
                }
            }
        };
        cycle(CYCLES).await;
        let rss_baseline = read_rss_kb();
        cycle(CYCLES).await;
        let rss_after = read_rss_kb();

        assert_eq!(view.listener_count(), listeners, "a reload subscribed");
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            tasks,
            "a reload left a task behind"
        );
        assert!(
            replaced_policy.upgrade().is_none(),
            "a replaced ban policy lives"
        );
        assert!(
            replaced_filter_policy.upgrade().is_none(),
            "a replaced filter policy lives"
        );
        assert!(
            replaced_trusted.upgrade().is_none(),
            "a replaced list lives"
        );

        // Still on, a prune past every window and ban empties the tables;
        // turned off, they are empty at once.
        reload(0).await;
        traffic(&security);
        assert_ne!(store.tracked_sources(), (0, 0), "the traffic was counted");
        let later = Instant::now() + Duration::from_secs(3 * 3600);
        store.prune_at(later);
        filter.prune_at(later);
        assert_eq!(store.tracked_sources(), (0, 0));
        assert_eq!(filter.rate.tracked_sources(), (0, 0, 0));
        traffic(&security);
        reload(2).await;
        assert_eq!(store.tracked_sources(), (0, 0));
        assert_eq!(filter.rate.tracked_sources(), (0, 0, 0));

        if let (Some(baseline), Some(after)) = (rss_baseline, rss_after) {
            let delta_kb = after.saturating_sub(baseline);
            let budget_kb = (CYCLES as u64 * PER_RELOAD_BUDGET_BYTES) / 1024;
            assert!(
                delta_kb < budget_kb,
                "RSS grew {delta_kb} KB across {CYCLES} steady-state reloads \
                 (budget {budget_kb} KB) — likely a leak",
            );
        }
    });
}

/// The connection ceilings read the same list: a source trusted by a reload
/// is unmetered on its next connection.
#[test]
fn the_connection_ceilings_follow_the_shared_list() {
    let runtime = SecurityRuntime::detached(&[], None, None, no_blocklist);
    let limiter = Arc::new(
        crate::security::ConnectionLimiter::new(
            crate::security::ConnectionLimits {
                max_handshakes_per_source: 1,
                max_handshakes: 0,
                max_connections_per_source: 1,
                max_connections: 0,
            },
            &[],
        )
        .with_trusted(runtime.trusted()),
    );
    let _held = limiter.try_accept(ip(SOURCE)).expect("the first slot");
    assert!(limiter.try_accept(ip(SOURCE)).is_err(), "over the ceiling");
    runtime.apply_trusted(TrustedCidrs::parse(&[SOURCE.to_string()]).0);
    assert!(limiter.try_accept(ip(SOURCE)).is_ok(), "trusted, unmetered");
}
