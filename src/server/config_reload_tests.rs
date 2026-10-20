//! Tests for the config reloader: the diff, the all-or-nothing apply, the
//! baseline that moves only for applied fields, serialisation, and the
//! steady-state leak gate.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager};
use crate::security::runtime::SecurityRuntime;
use crate::sip::uri::SipUri;
use crate::transport::{OutboundRouter, Transport};

const PRODUCT_NAME: &str = "SIPhon";
const PRODUCT_VERSION: &str = "9.9.9";

/// A config file with `server:` set to `server_block` (indented two spaces,
/// one key per line) and `extra` appended at the top level.
fn document(server_block: &str, extra: &str) -> String {
    format!(
        concat!(
            "# a node config\n",
            "listen:\n",
            "  udp: [\"0.0.0.0:5060\"]\n",
            "domain:\n",
            "  local: [\"example.com\"]\n",
            "server:\n",
            "{server}",
            "{extra}",
        ),
        server = server_block,
        extra = extra,
    )
}

const SERVER_A: &str = concat!(
    "  server_header: \"edge-a\"\n",
    "  user_agent_header: \"edge-a-agent\"\n",
    "  drain_secs: 10\n",
);

const SERVER_B: &str = concat!(
    "  server_header: \"edge-b\"\n",
    "  user_agent_header: \"edge-b-agent\"\n",
    "  drain_secs: 10\n",
);

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    identity: SharedIdentityHeaders,
    reloader: Arc<ConfigReloader>,
}

impl Fixture {
    /// A reloader over a file holding `text`, its baseline and identity taken
    /// from that file the way startup takes them.
    fn new(text: &str) -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("siphon.yaml");
        std::fs::write(&path, text).expect("write the config");
        let (config, baseline) = Config::load_with_document(&path).expect("the config loads");
        let identity =
            IdentityHeaders::resolve(config.server.as_ref(), PRODUCT_NAME, PRODUCT_VERSION)
                .shared();
        let reloader = Arc::new(ConfigReloader::new(
            path.clone(),
            baseline,
            ReloadTargets::new(Arc::clone(&identity), PRODUCT_NAME, PRODUCT_VERSION),
        ));
        Self {
            _directory: directory,
            path,
            identity,
            reloader,
        }
    }

    fn rewrite(&self, text: &str) {
        std::fs::write(&self.path, text).expect("rewrite the config");
    }

    fn server(&self) -> Option<String> {
        self.identity.load().server.clone()
    }

    fn user_agent(&self) -> Option<String> {
        self.identity.load().user_agent.clone()
    }
}

fn status(report: &ReloadReport, section: &str) -> SectionStatus {
    report
        .sections
        .get(section)
        .unwrap_or_else(|| panic!("no {section} in {report:?}"))
        .status
}

#[tokio::test]
async fn an_untouched_file_reports_every_section_unchanged() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    let names: Vec<&str> = report.sections.keys().map(String::as_str).collect();
    assert_eq!(names, ["domain", "listen", "server"]);
    assert!(report
        .sections
        .values()
        .all(|section| section.status == SectionStatus::Unchanged));
    assert!(report.applied.is_empty());
    assert!(report.restart_required.is_empty());
}

/// A comment, whitespace, key order and flow-vs-block style are not changes.
#[tokio::test]
async fn comment_whitespace_and_reorder_edits_change_nothing() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(concat!(
        "# rewritten by hand\n",
        "server:\n",
        "  drain_secs: 10      # seconds\n",
        "  user_agent_header: \"edge-a-agent\"\n",
        "\n",
        "  server_header: edge-a\n",
        "domain: { local: [ \"example.com\" ] }\n",
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
    ));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert!(
        report
            .sections
            .values()
            .all(|section| section.status == SectionStatus::Unchanged),
        "{report:?}"
    );
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));
}

#[tokio::test]
async fn a_server_header_change_is_applied() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(SERVER_B, ""));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "server"), SectionStatus::Applied);
    assert_eq!(
        report.sections["server"].applied,
        ["server.server_header", "server.user_agent_header"]
    );
    assert_eq!(report.applied, report.sections["server"].applied);
    assert!(report.restart_required.is_empty());
    assert_eq!(fixture.server().as_deref(), Some("edge-b"));
    assert_eq!(fixture.user_agent().as_deref(), Some("edge-b-agent"));

    // The baseline moved with it: the same file again is unchanged.
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "server"), SectionStatus::Unchanged);
}

/// Taking the key out restores what an unset key means at startup.
#[tokio::test]
async fn removing_the_key_reverts_to_the_product_default() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document("  drain_secs: 10\n", ""));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "server"), SectionStatus::Applied);
    assert_eq!(fixture.server().as_deref(), Some("SIPhon/9.9.9"));
    assert_eq!(fixture.user_agent().as_deref(), Some("SIPhon/9.9.9"));

    // Gone from the baseline too, so the next reload is quiet.
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "server"), SectionStatus::Unchanged);

    // And the whole section going is the same as its keys going.
    fixture.rewrite(&document("  drain_secs: 10\n", "").replace("server:\n  drain_secs: 10\n", ""));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "server"), SectionStatus::RestartRequired);
    assert_eq!(report.restart_required, ["server.drain_secs"]);
}

#[tokio::test]
async fn a_file_that_does_not_parse_changes_nothing() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite("server: [unterminated\n");
    let error = fixture.reloader.reload().await.expect_err("refused");
    assert!(matches!(error, ConfigReloadError::Invalid(_)), "{error}");
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));

    // A valid file afterwards diffs against the document the node started on.
    fixture.rewrite(&document(SERVER_B, ""));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "server"), SectionStatus::Applied);
    assert_eq!(fixture.server().as_deref(), Some("edge-b"));
}

#[tokio::test]
async fn a_missing_file_changes_nothing() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    std::fs::remove_file(&fixture.path).expect("remove the config");
    let error = fixture.reloader.reload().await.expect_err("refused");
    assert!(matches!(error, ConfigReloadError::Invalid(_)), "{error}");
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));
}

/// A validator refusing another section stops the header change with it.
#[tokio::test]
async fn a_validator_failure_beside_a_header_change_changes_nothing() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(
        SERVER_B,
        "advertised_address: \"198.51.100.7:5070\"\n",
    ));
    let error = fixture.reloader.reload().await.expect_err("refused");
    assert!(error.to_string().contains("advertised_address"), "{error}");
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));
    assert_eq!(fixture.user_agent().as_deref(), Some("edge-a-agent"));

    // The baseline did not move: a valid file still sees the header change.
    fixture.rewrite(&document(SERVER_B, ""));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(
        report.sections["server"].applied,
        ["server.server_header", "server.user_agent_header"]
    );
}

/// Moving `advertised_address` would move dialogs already in progress, so it
/// waits for a restart, and keeps saying so until one happens.
#[tokio::test]
async fn advertised_address_is_restart_required_until_a_restart() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(
        SERVER_A,
        "advertised_address: \"198.51.100.7\"\n",
    ));
    for _ in 0..2 {
        let report = fixture
            .reloader
            .reload()
            .await
            .expect("the reload validates");
        assert_eq!(
            status(&report, "advertised_address"),
            SectionStatus::RestartRequired
        );
        assert_eq!(report.restart_required, ["advertised_address"]);
        assert_eq!(status(&report, "server"), SectionStatus::Unchanged);
    }
}

/// A section holding a hot and a restart-only change applies the one and
/// names the other.
#[tokio::test]
async fn a_mixed_server_section_applies_the_hot_field_and_names_the_other() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(
        concat!(
            "  server_header: \"edge-b\"\n",
            "  user_agent_header: \"edge-a-agent\"\n",
            "  drain_secs: 20\n",
        ),
        "",
    ));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    let server = &report.sections["server"];
    assert_eq!(server.status, SectionStatus::RestartRequired);
    assert_eq!(server.applied, ["server.server_header"]);
    assert_eq!(server.restart_required, ["server.drain_secs"]);
    assert_eq!(fixture.server().as_deref(), Some("edge-b"));

    // Only the applied field joined the baseline.
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    let server = &report.sections["server"];
    assert!(server.applied.is_empty());
    assert_eq!(server.restart_required, ["server.drain_secs"]);
}

/// A key siphon does not read is still reported, so a typo is visible.
#[tokio::test]
async fn an_unknown_top_level_key_is_reported() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(SERVER_A, "sever:\n  server_header: \"edge-b\"\n"));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "sever"), SectionStatus::RestartRequired);
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));
}

#[tokio::test]
async fn the_report_serialises_to_the_documented_shape() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(
        SERVER_A,
        "advertised_address: \"198.51.100.7\"\n",
    ));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    let json = serde_json::to_value(&report).expect("serialises");
    assert_eq!(
        json["sections"]["advertised_address"],
        serde_json::json!({
            "status": "restart_required",
            "applied": [],
            "restart_required": ["advertised_address"],
        })
    );
    assert_eq!(
        json["sections"]["listen"],
        serde_json::json!({ "status": "unchanged", "applied": [], "restart_required": [] })
    );
    assert_eq!(json["applied"], serde_json::json!([]));
    assert_eq!(
        json["restart_required"],
        serde_json::json!(["advertised_address"])
    );
    assert_eq!(json["warnings"], serde_json::json!([]));
}

/// Reloads run one at a time: of many racing over one change, exactly one
/// applies it and every other one finds it already in the baseline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reloads_serialise() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    fixture.rewrite(&document(SERVER_B, ""));

    // Held, the lock keeps a reload from starting at all.
    let held = fixture.reloader.baseline.lock().await;
    let blocked = tokio::spawn({
        let reloader = Arc::clone(&fixture.reloader);
        async move { reloader.reload().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!blocked.is_finished());
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));
    drop(held);
    let first = blocked.await.expect("joins").expect("validates");
    assert_eq!(status(&first, "server"), SectionStatus::Applied);

    fixture.rewrite(&document(SERVER_A, ""));
    let racers: Vec<_> = (0..16)
        .map(|_| {
            let reloader = Arc::clone(&fixture.reloader);
            tokio::spawn(async move { reloader.reload().await })
        })
        .collect();
    let mut applied = 0;
    for racer in racers {
        let report = racer.await.expect("joins").expect("validates");
        if status(&report, "server") == SectionStatus::Applied {
            applied += 1;
        } else {
            assert_eq!(status(&report, "server"), SectionStatus::Unchanged);
        }
    }
    assert_eq!(applied, 1);
    assert_eq!(fixture.server().as_deref(), Some("edge-a"));
}

/// The UAC sender and the registrant read the same shared value, so a reload
/// reaches both on their next request.
#[tokio::test]
async fn uac_and_registrant_requests_carry_the_reloaded_user_agent() {
    let fixture = Fixture::new(&document(SERVER_A, ""));
    let (udp_sender, udp) = flume::unbounded();
    let (stream_sender, _stream) = flume::unbounded();
    let router = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: std::collections::HashMap::new(),
        tcp: stream_sender.clone(),
        tls: stream_sender.clone(),
        ws: stream_sender.clone(),
        wss: stream_sender.clone(),
        sctp: Some(stream_sender),
    });
    let uac = crate::uac::UacSender::new(
        router,
        "192.0.2.1:5060".parse().expect("an address"),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        None,
        None,
        Arc::clone(&fixture.identity),
    );
    let registrant = RegistrantManager::new(
        3600,
        Duration::from_secs(60),
        Duration::from_secs(300),
        Arc::clone(&fixture.identity),
    );
    registrant.add(RegistrantEntry::new(
        "sip:trunk@example.com".to_string(),
        "sip:registrar.example.com".to_string(),
        "198.51.100.20:5060".parse().expect("an address"),
        Transport::Udp,
        RegistrantCredentials::password("trunk".to_string(), "secret".to_string(), None),
        3600,
        None,
    ));

    let options_user_agent = || {
        let _response = uac.send_options(
            "198.51.100.10:5060".parse().expect("an address"),
            Transport::Udp,
            SipUri::new("198.51.100.10".to_string()),
        );
        let sent = udp.try_recv().expect("the OPTIONS went out");
        crate::sip::parser::parse_sip_message_bytes(&sent.data)
            .expect("parses")
            .headers
            .get("User-Agent")
            .cloned()
    };
    let register_user_agent = || {
        let (register, _, _, _) = registrant
            .build_register(
                "sip:trunk@example.com",
                "192.0.2.1:5060".parse().expect("an address"),
                &std::collections::HashMap::new(),
                3600,
            )
            .expect("a REGISTER");
        register.headers.get("User-Agent").cloned()
    };

    assert_eq!(options_user_agent().as_deref(), Some("edge-a-agent"));
    assert_eq!(register_user_agent().as_deref(), Some("edge-a-agent"));

    fixture.rewrite(&document(SERVER_B, ""));
    fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(options_user_agent().as_deref(), Some("edge-b-agent"));
    assert_eq!(register_user_agent().as_deref(), Some("edge-b-agent"));

    fixture.rewrite(&document("  drain_secs: 10\n", ""));
    fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(options_user_agent().as_deref(), Some("SIPhon/9.9.9"));
    assert_eq!(register_user_agent().as_deref(), Some("SIPhon/9.9.9"));
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

/// Leak gate: reloading alternating files holds nothing per reload. The
/// runtime's live-task count returns to where it was (each reload's blocking
/// read finishes), every replaced `IdentityHeaders` is freed, and resident
/// memory plateaus across a steady batch after a warm-up batch.
///
/// Runs in its own process: RSS belongs to the whole test binary.
#[test]
fn reload_cycles_do_not_leak() {
    crate::own_process::run(
        concat!(module_path!(), "::reload_cycles_do_not_leak"),
        measure_reload_cycles,
    );
}

fn measure_reload_cycles() {
    const CYCLES: usize = 1_000;
    const PER_RELOAD_BUDGET_BYTES: u64 = 1_024;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let fixture = Fixture::new(&document(SERVER_A, ""));
        let first = document(SERVER_A, "");
        let second = document(SERVER_B, "");
        let cycle = |count: usize| {
            let fixture = &fixture;
            let (first, second) = (&first, &second);
            async move {
                for index in 0..count {
                    fixture.rewrite(if index % 2 == 0 { second } else { first });
                    let report = fixture.reloader.reload().await.expect("validates");
                    assert_eq!(status(&report, "server"), SectionStatus::Applied);
                }
            }
        };

        let replaced = Arc::downgrade(&fixture.identity.load_full());
        let tasks_before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();

        // Warm-up: allocator free lists, the blocking pool's threads.
        cycle(CYCLES).await;
        let rss_baseline = read_rss_kb();
        cycle(CYCLES).await;
        let rss_after = read_rss_kb();

        assert!(
            replaced.upgrade().is_none(),
            "a replaced IdentityHeaders is still alive"
        );
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            tasks_before,
            "a reload left a task behind"
        );
        if let (Some(baseline), Some(after)) = (rss_baseline, rss_after) {
            let delta_kb = after.saturating_sub(baseline);
            let budget_kb = (CYCLES as u64 * PER_RELOAD_BUDGET_BYTES) / 1024;
            assert!(
                delta_kb < budget_kb,
                "RSS grew {delta_kb} KB across {CYCLES} steady-state reloads \
                 (budget {budget_kb} KB) — likely a leak",
            );
        } else {
            eprintln!("[reload_cycles_do_not_leak] no /proc/self/status — RSS check skipped");
        }
    });
}

fn security_document(security: &str) -> String {
    document(SERVER_A, &format!("security:\n{security}"))
}

/// Without the security runtime (a reloader nothing installed the controls
/// for) the security fields cannot be applied, so they are named as needing a
/// restart rather than reported applied.
#[tokio::test]
async fn security_fields_without_a_runtime_need_a_restart() {
    let fixture = Fixture::new(&security_document("  trusted_cidrs: []\n"));
    fixture.rewrite(&security_document(
        "  trusted_cidrs: [\"198.51.100.0/24\"]\n",
    ));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(report.restart_required, ["security.trusted_cidrs"]);
}

/// The four runtime fields apply; every other `security` key waits for a
/// restart and is named.
#[tokio::test]
async fn the_runtime_security_fields_apply_and_the_rest_wait_for_a_restart() {
    let text = security_document("  trusted_cidrs: []\n");
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("siphon.yaml");
    std::fs::write(&path, &text).expect("write the config");
    let (_, baseline) = Config::load_with_document(&path).expect("the config loads");
    let security = Arc::new(SecurityRuntime::detached(&[], None, None, || None));
    let reloader = ConfigReloader::new(
        path.clone(),
        baseline,
        ReloadTargets::new(
            IdentityHeaders::default().shared(),
            PRODUCT_NAME,
            PRODUCT_VERSION,
        )
        .with_security(Arc::clone(&security)),
    );
    std::fs::write(
        &path,
        security_document(concat!(
            "  trusted_cidrs: [\"198.51.100.0/24\", \"bogus\"]\n",
            "  rate_limit: { window_secs: 60, max_requests: 5 }\n",
            "  scanner_block: { user_agents: [\"friendly-scanner\"] }\n",
            "  failed_auth_ban: { threshold: 3, window_secs: 600, ban_duration_secs: 3600 }\n",
            "  trust_gateways: true\n",
            "  max_message_bytes: 65536\n",
            "  connection_limits: { max_connections: 100 }\n",
        )),
    )
    .expect("rewrite");
    let report = reloader.reload().await.expect("the reload validates");
    let section = &report.sections["security"];
    assert_eq!(section.status, SectionStatus::RestartRequired);
    assert_eq!(
        section.applied,
        [
            "security.failed_auth_ban",
            "security.rate_limit",
            "security.scanner_block",
            "security.trusted_cidrs",
        ]
    );
    assert_eq!(
        section.restart_required,
        [
            "security.connection_limits",
            "security.max_message_bytes",
            "security.trust_gateways",
        ]
    );
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(report.warnings[0].contains("bogus"));
    assert_eq!(security.trusted().load().len(), 1);
    assert!(security.auto_ban().is_some_and(|store| store.is_enabled()));
    assert!(security
        .security_filter()
        .is_some_and(|filter| filter.is_enabled()));

    // Removing the section turns each control off. The restart-only keys
    // were never running, so with them gone from the file nothing waits.
    std::fs::write(&path, document(SERVER_A, "")).expect("rewrite");
    let report = reloader.reload().await.expect("the reload validates");
    let section = &report.sections["security"];
    assert_eq!(
        section.applied,
        [
            "security.failed_auth_ban",
            "security.rate_limit",
            "security.scanner_block",
            "security.trusted_cidrs",
        ]
    );
    assert!(section.restart_required.is_empty());
    assert!(security.trusted().load().is_empty());
    assert!(security.auto_ban().is_some_and(|store| !store.is_enabled()));
    assert!(security
        .security_filter()
        .is_some_and(|filter| !filter.is_enabled()));
}

/// An APIBAN poller that never reaches a feed: a closed loopback port.
async fn offline_apiban(api_key: &str) -> crate::apiban::ApiBanControl {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let url = format!("http://{}", closed.local_addr().expect("its address"));
    drop(closed);
    crate::apiban::ApiBanClient::new(
        &crate::config::ApiBanConfig {
            api_key: api_key.to_owned(),
            interval_secs: 3600,
            ban_ttl_secs: 604_800,
        },
        &[],
    )
    .expect("client builds")
    .with_base_url(url)
    .spawn_poller()
}

fn apiban_block(api_key: &str, interval_secs: u64) -> String {
    format!("  apiban: {{ api_key: \"{api_key}\", interval_secs: {interval_secs} }}\n")
}

/// A reloader over `text` with a security runtime, its APIBAN poller attached
/// when `apiban` is given.
async fn security_fixture(
    text: &str,
    apiban: Option<crate::apiban::ApiBanControl>,
) -> (tempfile::TempDir, PathBuf, ConfigReloader) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("siphon.yaml");
    std::fs::write(&path, text).expect("write the config");
    let (_, baseline) = Config::load_with_document(&path).expect("the config loads");
    let security = Arc::new(SecurityRuntime::detached(&[], None, None, || None));
    if let Some(control) = apiban {
        security.attach_apiban(control);
    }
    let reloader = ConfigReloader::new(
        path.clone(),
        baseline,
        ReloadTargets::new(
            IdentityHeaders::default().shared(),
            PRODUCT_NAME,
            PRODUCT_VERSION,
        )
        .with_security(security),
    );
    (directory, path, reloader)
}

/// New APIBAN parameters reach the running poller; the key never appears in
/// the report, nor in the error of a file that fails validation beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apiban_parameter_changes_apply_to_the_running_poller() {
    let control = offline_apiban("first-secret-key").await;
    let (_directory, path, reloader) = security_fixture(
        &security_document(&apiban_block("first-secret-key", 3600)),
        Some(control.clone()),
    )
    .await;

    std::fs::write(
        &path,
        security_document(&apiban_block("second-secret-key", 60)),
    )
    .expect("rewrite");
    let report = reloader.reload().await.expect("the reload validates");
    assert_eq!(report.applied, ["security.apiban"]);
    assert!(report.restart_required.is_empty());
    assert_eq!(
        *control.params(),
        crate::apiban::ApiBanParams::from_config(&crate::config::ApiBanConfig {
            api_key: "second-secret-key".to_owned(),
            interval_secs: 60,
            ban_ttl_secs: 604_800,
        })
    );
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(!json.contains("secret-key"), "{json}");

    std::fs::write(
        &path,
        security_document(&format!(
            "{}  max_message_bytes: lots\n",
            apiban_block("third-secret-key", 60)
        )),
    )
    .expect("rewrite");
    let error = reloader.reload().await.expect_err("fails validation");
    assert!(!error.to_string().contains("secret-key"), "{error}");
}

/// Turning APIBAN on or off waits for a restart: off at start-up the ACL holds
/// no blocklist at all. Only that transition is named, and nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_apiban_on_or_off_needs_a_restart() {
    // Off at start-up, on in the file.
    let (_directory, path, reloader) =
        security_fixture(&security_document("  trusted_cidrs: []\n"), None).await;
    std::fs::write(
        &path,
        security_document(&format!(
            "  trusted_cidrs: [\"198.51.100.0/24\"]\n{}",
            apiban_block("a-secret-key", 300)
        )),
    )
    .expect("rewrite");
    let report = reloader.reload().await.expect("the reload validates");
    assert_eq!(report.applied, ["security.trusted_cidrs"]);
    assert_eq!(report.restart_required, ["security.apiban"]);
    // And keeps being named until a restart.
    let report = reloader.reload().await.expect("the reload validates");
    assert_eq!(report.restart_required, ["security.apiban"]);

    // On at start-up, gone from the file: the poller keeps what it had.
    let control = offline_apiban("b-secret-key").await;
    let before = control.params();
    let (_directory, path, reloader) = security_fixture(
        &security_document(&apiban_block("b-secret-key", 300)),
        Some(control.clone()),
    )
    .await;
    std::fs::write(&path, security_document("  trusted_cidrs: []\n")).expect("rewrite");
    let report = reloader.reload().await.expect("the reload validates");
    assert_eq!(report.restart_required, ["security.apiban"]);
    assert_eq!(control.params(), before);
}

fn gateway_block(allow_methods: &str) -> String {
    format!(
        concat!(
            "gateway:\n",
            "  groups:\n",
            "    - name: \"trunk\"\n",
            "      probe:\n",
            "        enabled: false\n",
            "{}",
            "      destinations:\n",
            "        - uri: \"sip:198.51.100.7:5060\"\n",
        ),
        allow_methods
    )
}

/// `gateway.groups[].allow_methods` is read when the groups are built, like the
/// rest of a group: a change is reported as waiting for a restart, never taken
/// silently, and an invalid set is refused outright.
#[tokio::test]
async fn a_gateway_allow_methods_change_is_restart_required_and_an_invalid_one_refused() {
    let fixture = Fixture::new(&document(SERVER_A, &gateway_block("")));
    fixture.rewrite(&document(
        SERVER_A,
        &gateway_block("      allow_methods: [INVITE, ACK, CANCEL, BYE, OPTIONS]\n"),
    ));
    let report = fixture
        .reloader
        .reload()
        .await
        .expect("the reload validates");
    assert_eq!(status(&report, "gateway"), SectionStatus::RestartRequired);
    assert_eq!(report.restart_required, ["gateway"]);

    fixture.rewrite(&document(
        SERVER_A,
        &gateway_block("      allow_methods: [INVITE, ACK, OPTIONS]\n"),
    ));
    let error = fixture.reloader.reload().await.expect_err("refused");
    assert!(
        error
            .to_string()
            .contains("gateway.groups[trunk].allow_methods"),
        "{error}"
    );
}
