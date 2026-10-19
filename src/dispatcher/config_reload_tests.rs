//! `POST /admin/config/reload` seen on the wire: a reloaded `Server` /
//! `User-Agent` is what the next message siphon builds carries, a refused
//! reload leaves the wire as it was, and a restart-only change does not reach
//! it.
//!
//! Driven through the dispatcher's entry point and its UAC sender, with what
//! siphon sent read back off the UDP egress.

use std::path::PathBuf;

use super::originate_test_harness::{drain, socket};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::config::{Config, IdentityHeaders};
use crate::server::config_reload::{ConfigReloader, ReloadTargets, SectionStatus};

const PEER: &str = "198.51.100.10:5060";

fn config_file(server_header: Option<&str>, extra: &str) -> String {
    let mut text = String::from(concat!(
        "listen:\n",
        "  udp: [\"0.0.0.0:5060\"]\n",
        "domain:\n",
        "  local: [\"siphon.example.com\"]\n",
        "server:\n",
        "  drain_secs: 10\n",
    ));
    if let Some(value) = server_header {
        text.push_str(&format!(
            "  server_header: \"{value}\"\n  user_agent_header: \"{value}-agent\"\n"
        ));
    }
    text.push_str(extra);
    text
}

struct Node {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    reloader: ConfigReloader,
    path: PathBuf,
    _directory: tempfile::TempDir,
}

impl Node {
    /// A dispatcher started from a file setting `server_header: edge-a`.
    fn start() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("siphon.yaml");
        std::fs::write(&path, config_file(Some("edge-a"), "")).expect("write the config");
        let (config, baseline) = Config::load_with_document(&path).expect("the config loads");
        let TestDispatcher { state, udp } = test_dispatcher();
        state.identity.store(Arc::new(IdentityHeaders::resolve(
            config.server.as_ref(),
            "SIPhon",
            "9.9.9",
        )));
        let reloader = ConfigReloader::new(
            path.clone(),
            baseline,
            ReloadTargets::new(Arc::clone(&state.identity), "SIPhon", "9.9.9"),
        );
        Self {
            state: Arc::new(state),
            udp,
            reloader,
            path,
            _directory: directory,
        }
    }

    fn rewrite(&self, text: &str) {
        std::fs::write(&self.path, text).expect("rewrite the config");
    }

    /// Probe siphon with an OPTIONS no script claims and return the `Server`
    /// of the 200 it builds itself.
    fn options_server(&self, branch: &str) -> Option<String> {
        let raw = format!(
            concat!(
                "OPTIONS sip:siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP {peer};branch=z9hG4bK-reload-{branch}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:probe@example.com>;tag=probe-{branch}\r\n",
                "To: <sip:siphon.example.com>\r\n",
                "Call-ID: reload-{branch}@198.51.100.10\r\n",
                "CSeq: 1 OPTIONS\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            peer = PEER,
            branch = branch,
        );
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: crate::transport::ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: socket("192.0.2.1:5060"),
            remote_addr: socket(PEER),
            data: Bytes::from(raw),
        };
        tokio::task::block_in_place(|| super::inbound::handle_inbound(inbound, &self.state));
        let sent = drain(&self.udp);
        let response = sent
            .iter()
            .find(|frame| frame.message.status_code() == Some(200))
            .unwrap_or_else(|| panic!("siphon answered the OPTIONS: {} frames", sent.len()));
        response.message.headers.get("Server").cloned()
    }

    /// Have the UAC send an OPTIONS and return it.
    fn uac_options(&self) -> SipMessage {
        let _response = self.state.uac_sender.send_options(
            socket(PEER),
            Transport::Udp,
            crate::sip::uri::SipUri::new("198.51.100.10".to_string()),
        );
        drain(&self.udp)
            .into_iter()
            .next()
            .expect("the UAC sent the OPTIONS")
            .message
    }

    fn uac_user_agent(&self) -> Option<String> {
        self.uac_options().headers.get("User-Agent").cloned()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reloaded_server_header_is_on_the_next_response_and_request() {
    let node = Node::start();
    assert_eq!(node.options_server("a1").as_deref(), Some("edge-a"));
    assert_eq!(node.uac_user_agent().as_deref(), Some("edge-a-agent"));

    node.rewrite(&config_file(Some("edge-b"), ""));
    let report = node.reloader.reload().await.expect("the reload validates");
    assert_eq!(report.sections["server"].status, SectionStatus::Applied);
    assert_eq!(node.options_server("b1").as_deref(), Some("edge-b"));
    assert_eq!(node.uac_user_agent().as_deref(), Some("edge-b-agent"));

    // Taking the keys out puts the product default back on the wire.
    node.rewrite(&config_file(None, ""));
    node.reloader.reload().await.expect("the reload validates");
    assert_eq!(node.options_server("c1").as_deref(), Some("SIPhon/9.9.9"));
    assert_eq!(node.uac_user_agent().as_deref(), Some("SIPhon/9.9.9"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_reload_leaves_the_wire_as_it_was() {
    let node = Node::start();

    node.rewrite("server: [unterminated\n");
    node.reloader.reload().await.expect_err("does not parse");
    assert_eq!(node.options_server("x1").as_deref(), Some("edge-a"));

    // Valid YAML and a header change, beside a value a validator refuses.
    node.rewrite(&config_file(
        Some("edge-b"),
        "advertised_address: \"198.51.100.7:5070\"\n",
    ));
    node.reloader.reload().await.expect_err("fails validation");
    assert_eq!(node.options_server("x2").as_deref(), Some("edge-a"));
    assert_eq!(node.uac_user_agent().as_deref(), Some("edge-a-agent"));

    // The next good file is diffed against what the node started on.
    node.rewrite(&config_file(Some("edge-b"), ""));
    let report = node.reloader.reload().await.expect("the reload validates");
    assert_eq!(
        report.sections["server"].applied,
        ["server.server_header", "server.user_agent_header"]
    );
    assert_eq!(node.options_server("x3").as_deref(), Some("edge-b"));
}

/// `advertised_address` is reported as needing a restart, and the Via of a
/// request built after the reload still carries the address siphon started
/// with.
#[tokio::test(flavor = "multi_thread")]
async fn an_advertised_address_change_does_not_reach_the_wire() {
    let node = Node::start();
    let via_before = node.uac_options().headers.get("Via").cloned();

    node.rewrite(&config_file(
        Some("edge-a"),
        "advertised_address: \"198.51.100.7\"\n",
    ));
    let report = node.reloader.reload().await.expect("the reload validates");
    assert_eq!(
        report.sections["advertised_address"].status,
        SectionStatus::RestartRequired
    );
    assert_eq!(report.restart_required, ["advertised_address"]);

    let via_after = node.uac_options().headers.get("Via").cloned();
    let host = |via: Option<String>| {
        via.and_then(|via| via.split_whitespace().nth(1).map(str::to_owned))
            .and_then(|sent_by| sent_by.split(';').next().map(str::to_owned))
    };
    assert_eq!(host(via_after), host(via_before));
}
