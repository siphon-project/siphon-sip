//! Per-listener client-certificate settings: parsing both `listen` entry
//! forms, the merge over the `tls:` block, and the load-time refusals.

use super::*;
use crate::config::Config;

/// A temp directory holding a CA bundle, kept alive for the test.
struct CaFile {
    _directory: tempfile::TempDir,
    path: String,
}

fn ca_file() -> CaFile {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let key = rcgen::KeyPair::generate().expect("keygen");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&key).expect("self-sign");
    let path = directory.path().join("trunk-ca.pem");
    std::fs::write(&path, certificate.pem()).expect("write the CA");
    CaFile {
        _directory: directory,
        path: path.to_string_lossy().into_owned(),
    }
}

/// A config with `tls_block` (indented two spaces) and `listen_block` (the
/// lines under `listen:`, indented two spaces).
fn config(tls_block: &str, listen_block: &str) -> crate::error::Result<Config> {
    let yaml = format!(
        concat!(
            "listen:\n",
            "{listen}",
            "domain:\n",
            "  local: [\"example.net\"]\n",
            "tls:\n",
            "  certificate: \"/etc/siphon/server.pem\"\n",
            "  private_key: \"/etc/siphon/server.key\"\n",
            "{tls}",
        ),
        listen = listen_block,
        tls = tls_block,
    );
    Config::from_str(&yaml)
}

fn refused(tls_block: &str, listen_block: &str) -> String {
    config(tls_block, listen_block)
        .expect_err("the config must be refused")
        .to_string()
}

#[test]
fn a_plain_string_entry_still_parses_and_overrides_nothing() {
    let config = config("", "  tls: [\"192.0.2.10:5061\"]\n").expect("loads");
    let entry = &config.listen.tls[0];
    assert_eq!(entry.address(), "192.0.2.10:5061");
    assert!(entry.client_auth().is_none());
}

#[test]
fn an_object_entry_without_client_auth_keys_overrides_nothing() {
    let config = config(
        "",
        "  tls:\n    - address: \"192.0.2.10:5061\"\n      advertise: \"sip.example.net\"\n",
    )
    .expect("loads");
    assert!(config.listen.tls[0].client_auth().is_none());
}

#[test]
fn the_object_form_carries_all_three_overrides() {
    let ca = ca_file();
    let config = config(
        "",
        &format!(
            concat!(
                "  tls:\n",
                "    - \"192.0.2.10:5061\"\n",
                "    - address: \"192.0.2.10:5062\"\n",
                "      verify_client: true\n",
                "      client_ca: \"{ca}\"\n",
                "      client_subject: [\"*.sip.example.net\", \"trunk.example.net\"]\n",
            ),
            ca = ca.path
        ),
    )
    .expect("loads");
    assert!(config.listen.tls[0].client_auth().is_none());
    let overrides = config.listen.tls[1].client_auth().expect("overrides");
    assert_eq!(overrides.verify_client, Some(true));
    assert_eq!(overrides.client_ca.as_deref(), Some(ca.path.as_str()));
    assert_eq!(
        overrides.client_subject.as_deref(),
        Some(
            &[
                "*.sip.example.net".to_string(),
                "trunk.example.net".to_string()
            ][..]
        )
    );
}

#[test]
fn for_listener_replaces_only_what_the_entry_sets() {
    let ca = ca_file();
    let config = config(
        "  verify_client: true\n  client_ca: \"/etc/siphon/default-ca.pem\"\n",
        &format!(
            concat!(
                "  tls:\n",
                "    - \"192.0.2.10:5061\"\n",
                "    - address: \"192.0.2.10:5062\"\n",
                "      client_ca: \"{ca}\"\n",
            ),
            ca = ca.path
        ),
    );
    // The plain entry inherits the top-level CA, which does not exist; the
    // shape is fine, and the file is read when that listener starts (as it
    // always was), so this loads.
    let config = config.expect("loads");
    let block = config.tls.as_ref().expect("tls block");

    let plain = block.for_listener(config.listen.tls[0].client_auth());
    assert!(plain.verify_client);
    assert_eq!(
        plain.client_ca.as_deref(),
        Some("/etc/siphon/default-ca.pem")
    );

    let overridden = block.for_listener(config.listen.tls[1].client_auth());
    assert!(overridden.verify_client, "inherited from tls:");
    assert_eq!(overridden.client_ca.as_deref(), Some(ca.path.as_str()));
    assert_eq!(
        overridden.certificate, block.certificate,
        "server cert shared"
    );
}

#[test]
fn a_listener_can_turn_verification_off_and_drops_the_inherited_subject() {
    let block = TlsServerConfig {
        certificate: "c".to_string(),
        private_key: "k".to_string(),
        certificates: Vec::new(),
        method: TlsMethod::default(),
        verify_client: true,
        client_ca: Some("ca".to_string()),
        client_subject: vec!["*.sip.example.net".to_string()],
        client_certificate: None,
        client_private_key: None,
        verify_server: false,
        server_ca: None,
    };
    let off = block.for_listener(Some(&ListenerClientAuth {
        verify_client: Some(false),
        client_ca: None,
        client_subject: None,
    }));
    assert!(!off.verify_client);
    assert!(off.client_subject.is_empty());

    let unchanged = block.for_listener(None);
    assert!(unchanged.verify_client);
    assert_eq!(unchanged.client_subject, block.client_subject);
}

#[test]
fn verify_client_on_a_listener_without_any_client_ca_names_the_listener() {
    let message = refused(
        "",
        "  tls:\n    - address: \"192.0.2.10:5062\"\n      verify_client: true\n",
    );
    assert!(
        message.contains("listen.tls[192.0.2.10:5062]") && message.contains("client_ca"),
        "{message}"
    );
}

#[test]
fn an_unreadable_listener_client_ca_is_refused_at_load() {
    let message = refused(
        "",
        concat!(
            "  tls:\n",
            "    - address: \"192.0.2.10:5062\"\n",
            "      verify_client: true\n",
            "      client_ca: \"/nonexistent/trunk-ca.pem\"\n",
        ),
    );
    assert!(
        message.contains("listen.tls[192.0.2.10:5062].client_ca"),
        "{message}"
    );
}

#[test]
fn client_ca_on_a_listener_that_does_not_verify_is_refused() {
    let ca = ca_file();
    let message = refused(
        "",
        &format!(
            "  tls:\n    - address: \"192.0.2.10:5062\"\n      client_ca: \"{}\"\n",
            ca.path
        ),
    );
    assert!(
        message.contains("listen.tls[192.0.2.10:5062].client_ca") && message.contains("verify"),
        "{message}"
    );
}

#[test]
fn client_subject_on_a_listener_that_does_not_verify_is_refused() {
    let message = refused(
        "",
        concat!(
            "  tls:\n",
            "    - address: \"192.0.2.10:5062\"\n",
            "      client_subject: [\"*.sip.example.net\"]\n",
        ),
    );
    assert!(
        message.contains("listen.tls[192.0.2.10:5062].client_subject"),
        "{message}"
    );
}

#[test]
fn a_malformed_listener_client_subject_is_refused() {
    let ca = ca_file();
    let message = refused(
        "",
        &format!(
            concat!(
                "  tls:\n",
                "    - address: \"192.0.2.10:5062\"\n",
                "      verify_client: true\n",
                "      client_ca: \"{ca}\"\n",
                "      client_subject: [\"edge*.sip.example.net\"]\n",
            ),
            ca = ca.path
        ),
    );
    assert!(
        message.contains("listen.tls[192.0.2.10:5062].client_subject"),
        "{message}"
    );
}

#[test]
fn top_level_client_subject_without_verify_client_is_refused() {
    let message = refused(
        "  client_subject: [\"*.sip.example.net\"]\n",
        "  tls: [\"192.0.2.10:5061\"]\n",
    );
    assert!(message.contains("tls.client_subject"), "{message}");
}

#[test]
fn top_level_verify_client_without_client_ca_is_refused_at_load() {
    let message = refused("  verify_client: true\n", "  tls: [\"192.0.2.10:5061\"]\n");
    assert!(
        message.contains("tls.verify_client") && message.contains("client_ca"),
        "{message}"
    );
}

#[test]
fn client_auth_keys_on_a_plaintext_listener_are_refused() {
    for transport in ["udp", "tcp", "ws"] {
        let message = refused(
            "",
            &format!(
                "  {transport}:\n    - address: \"192.0.2.10:5060\"\n      verify_client: true\n"
            ),
        );
        assert!(
            message.contains(&format!("listen.{transport}[192.0.2.10:5060]"))
                && message.contains("listen.tls and listen.wss"),
            "{transport}: {message}"
        );
    }
}

#[test]
fn listener_overrides_without_a_tls_block_are_refused() {
    let yaml = concat!(
        "listen:\n",
        "  tls:\n",
        "    - address: \"192.0.2.10:5062\"\n",
        "      verify_client: false\n",
        "domain:\n",
        "  local: [\"example.net\"]\n",
    );
    let message = Config::from_str(yaml).expect_err("needs tls:").to_string();
    assert!(
        message.contains("listen.tls[192.0.2.10:5062]") && message.contains("tls: block"),
        "{message}"
    );
}

#[test]
fn wss_entries_take_the_same_overrides() {
    let ca = ca_file();
    let config = config(
        "",
        &format!(
            concat!(
                "  wss:\n",
                "    - address: \"192.0.2.10:8443\"\n",
                "      verify_client: true\n",
                "      client_ca: \"{ca}\"\n",
            ),
            ca = ca.path
        ),
    )
    .expect("loads");
    let block = config.tls.as_ref().expect("tls block");
    assert!(
        block
            .for_listener(config.listen.wss[0].client_auth())
            .verify_client
    );
}

#[test]
fn a_shared_tls_and_wss_address_must_agree() {
    let ca = ca_file();
    let message = refused(
        "",
        &format!(
            concat!(
                "  tls:\n",
                "    - address: \"192.0.2.10:5061\"\n",
                "      verify_client: true\n",
                "      client_ca: \"{ca}\"\n",
                "  wss: [\"192.0.2.10:5061\"]\n",
            ),
            ca = ca.path
        ),
    );
    assert!(
        message.contains("listen.tls[192.0.2.10:5061]") && message.contains("listen.wss"),
        "{message}"
    );

    // The same settings on both halves load.
    let entry = format!(
        concat!(
            "    - address: \"192.0.2.10:5061\"\n",
            "      verify_client: true\n",
            "      client_ca: \"{ca}\"\n",
        ),
        ca = ca.path
    );
    config("", &format!("  tls:\n{entry}  wss:\n{entry}")).expect("agreeing halves load");
}

#[test]
fn a_shared_address_is_recognised_however_it_is_spelled() {
    // The server pairs tls+wss by parsed socket address, so the check must
    // too: two spellings of one IPv6 address are one muxed socket.
    let ca = ca_file();
    let message = refused(
        "",
        &format!(
            concat!(
                "  tls:\n",
                "    - address: \"[2001:db8::1]:5061\"\n",
                "      verify_client: true\n",
                "      client_ca: \"{ca}\"\n",
                "  wss: [\"[2001:0db8:0::1]:5061\"]\n",
            ),
            ca = ca.path
        ),
    );
    assert!(message.contains("share one socket"), "{message}");
}
