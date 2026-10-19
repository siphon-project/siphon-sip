//! A config reload of the `security` section, seen on the wire: a source the
//! request filter drops is answered once a reload trusts it, and what the
//! controls held against it is lifted, the kernel element included.
//!
//! These install the process-wide request filter and auto-ban store, so each
//! runs alone in a child process of the test binary.

use std::net::IpAddr;

use super::originate_test_harness::{drain, socket};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::config::{Config, IdentityHeaders};
use crate::firewall::{Command, KernelFirewall};
use crate::security::runtime::SecurityRuntime;
use crate::server::config_reload::{ConfigReloader, ReloadTargets, SectionStatus};

const SOURCE: &str = "203.0.113.9";

fn config_file(trusted: &str) -> String {
    format!(
        concat!(
            "listen:\n",
            "  udp: [\"0.0.0.0:5060\"]\n",
            "domain:\n",
            "  local: [\"siphon.example.com\"]\n",
            "security:\n",
            "  trusted_cidrs: [{trusted}]\n",
            "  rate_limit: {{ window_secs: 60, max_requests: 1, ban_duration_secs: 600 }}\n",
            "  failed_auth_ban: {{ threshold: 1, window_secs: 600, ban_duration_secs: 3600 }}\n",
        ),
        trusted = trusted,
    )
}

/// Send an OPTIONS no script claims from `SOURCE` and return every frame
/// siphon sent for it.
fn probe(
    state: &Arc<DispatcherState>,
    udp: &flume::Receiver<OutboundMessage>,
    branch: &str,
) -> usize {
    let peer = format!("{SOURCE}:5060");
    let raw = format!(
        concat!(
            "OPTIONS sip:siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {peer};branch=z9hG4bK-trust-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:probe@example.com>;tag=probe-{branch}\r\n",
            "To: <sip:siphon.example.com>\r\n",
            "Call-ID: trust-{branch}@203.0.113.9\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        peer = peer,
        branch = branch,
    );
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: crate::transport::ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket("192.0.2.1:5060"),
        remote_addr: socket(&peer),
        data: Bytes::from(raw),
    };
    tokio::task::block_in_place(|| super::inbound::handle_inbound(inbound, state));
    drain(udp)
        .iter()
        .filter(|frame| frame.message.status_code() == Some(200))
        .count()
}

fn trusting_the_source_lifts_its_bans(entry: &str) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("siphon.yaml");
        std::fs::write(&path, config_file("")).expect("write the config");
        let (config, baseline) = Config::load_with_document(&path).expect("the config loads");

        // Start-up, as the server does it, with the kernel captured.
        let (firewall, mut kernel) = KernelFirewall::capturing();
        let security = Arc::new(SecurityRuntime::new(&[], None, Some(firewall)));
        security.apply_filter(config.security.as_ref());
        security.apply_auto_ban(
            config
                .security
                .as_ref()
                .and_then(|section| section.failed_auth_ban.as_ref())
                .map(crate::security::BanPolicy::from_config),
        );
        let TestDispatcher { state, udp } = test_dispatcher();
        let state = Arc::new(state);
        let reloader = ConfigReloader::new(
            path.clone(),
            baseline,
            ReloadTargets::new(IdentityHeaders::default().shared(), "SIPhon", "9.9.9")
                .with_security(Arc::clone(&security)),
        );
        let source: IpAddr = SOURCE.parse().expect("an address");

        assert_eq!(probe(&state, &udp, "1"), 1, "the first is answered");
        assert_eq!(probe(&state, &udp, "2"), 0, "the second is rate limited");
        let auto_ban = crate::security::auto_ban().expect("installed");
        assert!(auto_ban.record_failure(source));
        while kernel.try_recv().is_ok() {}

        std::fs::write(&path, config_file(&format!("\"{entry}\""))).expect("rewrite");
        let report = reloader.reload().await.expect("the reload validates");
        assert_eq!(report.sections["security"].status, SectionStatus::Applied);
        assert_eq!(report.applied, ["security.trusted_cidrs"]);

        assert_eq!(probe(&state, &udp, "3"), 1, "answered once trusted");
        assert_eq!(probe(&state, &udp, "4"), 1, "and not counted");
        let filter = crate::security::security_filter().expect("installed");
        assert_eq!(filter.rate_limit_bans(), 0);
        assert!(!auto_ban.is_banned(source));
        let mut unbanned = Vec::new();
        while let Ok(command) = kernel.try_recv() {
            if let Command::Unban { ip } = command {
                unbanned.push(ip);
            }
        }
        assert_eq!(unbanned, [source], "the kernel element is lifted too");
    });
}

#[test]
fn a_reload_trusting_a_host_route_lets_a_rate_limited_source_through() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_reload_trusting_a_host_route_lets_a_rate_limited_source_through"
        ),
        || trusting_the_source_lifts_its_bans("203.0.113.9/32"),
    );
}

/// A bare address is trusted in userspace too, as the kernel allow set
/// always took it.
#[test]
fn a_reload_trusting_a_bare_address_lets_a_rate_limited_source_through() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_reload_trusting_a_bare_address_lets_a_rate_limited_source_through"
        ),
        || trusting_the_source_lifts_its_bans(SOURCE),
    );
}

/// An entry that is neither a CIDR nor an address is skipped with a warning
/// in the report; the valid ones still apply.
#[test]
fn an_invalid_trusted_entry_is_reported_and_the_rest_applied() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::an_invalid_trusted_entry_is_reported_and_the_rest_applied"
        ),
        || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a runtime");
            runtime.block_on(async {
                let directory = tempfile::tempdir().expect("a temporary directory");
                let path = directory.path().join("siphon.yaml");
                std::fs::write(&path, config_file("")).expect("write the config");
                let (config, baseline) =
                    Config::load_with_document(&path).expect("the config loads");
                let security = Arc::new(SecurityRuntime::new(&[], None, None));
                security.apply_filter(config.security.as_ref());
                let TestDispatcher { state, udp } = test_dispatcher();
                let state = Arc::new(state);
                let reloader = ConfigReloader::new(
                    path.clone(),
                    baseline,
                    ReloadTargets::new(IdentityHeaders::default().shared(), "SIPhon", "9.9.9")
                        .with_security(Arc::clone(&security)),
                );
                std::fs::write(
                    &path,
                    config_file(&format!("\"{SOURCE}\", \"not-an-address\"")),
                )
                .expect("rewrite");
                let report = reloader.reload().await.expect("the reload validates");
                assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
                assert!(report.warnings[0].contains("not-an-address"));
                assert_eq!(security.trusted().load().len(), 1);
                for branch in ["1", "2", "3"] {
                    assert_eq!(probe(&state, &udp, branch), 1, "trusted, never limited");
                }
            });
        },
    );
}
