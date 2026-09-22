use super::*;
use crate::rtpengine::profile::{WsTeeDirection, WsVadEngine};

fn control_yaml(block: &str) -> Result<Config> {
    Config::from_str(&format!(
        "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\ncontrol:\n{block}"
    ))
}

fn control_config(app_block: &str) -> Result<Config> {
    Config::from_str(&format!(
        "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\ncontrol:\n  apps:\n{app_block}"
    ))
}

#[test]
fn control_tls_without_a_listener_is_refused() {
    // It says the operator believes the rail is encrypted, and there is no
    // inbound rail at all — the most dangerous shape of wrong.
    let error = control_yaml(
        "  apps:\n    - name: \"pbx\"\n  tls:\n    certificate: \"/etc/siphon/c.pem\"\n    private_key: \"/etc/siphon/k.pem\"\n",
    )
    .expect_err("control.tls without control.listen must be refused");
    let message = error.to_string();
    assert!(message.contains("control.listen"), "{message}");
}

#[test]
fn teardown_secs_defaults_to_five_and_can_be_switched_off() {
    // The default matters: a node upgraded without touching its config starts
    // ending the calls a drain deadline holds, which is the whole point. `0` is
    // the documented way back to exiting on top of them.
    let with_default = Config::from_str(
        "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\n\
         server:\n  drain_secs: 10\n",
    )
    .expect("config loads");
    assert_eq!(with_default.server.expect("server").teardown_secs, 5);

    let switched_off = Config::from_str(
        "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\n\
         server:\n  drain_secs: 10\n  teardown_secs: 0\n",
    )
    .expect("config loads");
    assert_eq!(switched_off.server.expect("server").teardown_secs, 0);
}

#[test]
fn admin_tls_with_an_unreadable_certificate_is_refused_at_load() {
    // Same reasoning as control.tls: a listener that binds, looks healthy and
    // fails every handshake reads to an operator as a broken client rather than
    // an unreadable key — and on this listener the fallback is a bearer token
    // crossing the wire in the clear.
    let error = Config::from_str(
        "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\n\
         admin:\n  listen: \"127.0.0.1:9091\"\n  tls:\n    \
         certificate: \"/nonexistent/siphon-admin.pem\"\n    \
         private_key: \"/nonexistent/siphon-admin.key\"\n",
    )
    .expect_err("an unreadable admin certificate must be refused");
    let message = error.to_string();
    assert!(message.contains("admin.tls.certificate"), "{message}");
    assert!(
        message.contains("/nonexistent/siphon-admin.pem"),
        "{message}"
    );
}

#[test]
fn admin_without_tls_still_loads() {
    // The block is optional and plaintext stays the default, so a node that
    // never had it keeps working on upgrade.
    let config = Config::from_str(
        "listen:\n  udp: [\"0.0.0.0:5060\"]\ndomain:\n  local: [\"example.com\"]\n\
         admin:\n  listen: \"127.0.0.1:9091\"\n",
    )
    .expect("admin without tls must load");
    assert!(config.admin.expect("admin").tls.is_none());
}

#[test]
fn control_tls_with_an_unreadable_certificate_is_refused_at_load() {
    // Otherwise the listener binds, looks healthy, and fails every
    // handshake — which reads as a broken client, not a missing file.
    let error = control_yaml(
        "  listen: \"127.0.0.1:9092\"\n  tls:\n    certificate: \"/nonexistent/siphon-control.pem\"\n    private_key: \"/nonexistent/siphon-control.key\"\n",
    )
    .expect_err("an unreadable certificate must be refused");
    let message = error.to_string();
    assert!(message.contains("control.tls.certificate"), "{message}");
    assert!(
        message.contains("/nonexistent/siphon-control.pem"),
        "{message}"
    );
}

#[test]
fn a_control_app_dialing_an_unsupported_scheme_is_refused_at_load() {
    // At load, not at the first handover: an unreachable controller means
    // every handed-over call ends on the handoff default, so the box comes
    // up healthy and times out every call, which reads as an outage rather
    // than a typo.
    let error = control_config(
        "    - name: \"pbx\"\n      per_call_connect: true\n      connect_url: \"https://controller.example\"\n",
    )
    .expect_err("https:// is not a WebSocket scheme");
    let message = error.to_string();
    assert!(message.contains("ws:// or wss://"), "{message}");
    assert!(message.contains("pbx"), "{message}");
}

#[test]
fn a_ca_file_on_a_plaintext_control_app_is_refused() {
    // Not merely redundant: it says the operator believes the connection is
    // verified, and it is not encrypted at all.
    let error = control_config(
        "    - name: \"pbx\"\n      per_call_connect: true\n      connect_url: \"ws://controller.example:9092\"\n      ca_file: \"/etc/siphon/ca.pem\"\n",
    )
    .expect_err("a ca_file on ws:// must be refused");
    let message = error.to_string();
    assert!(message.contains("not encrypted"), "{message}");
}

#[test]
fn a_ca_file_that_cannot_be_read_is_refused_at_load() {
    let error = control_config(
        "    - name: \"pbx\"\n      per_call_connect: true\n      connect_url: \"wss://controller.example\"\n      ca_file: \"/nonexistent/siphon-control-ca.pem\"\n",
    )
    .expect_err("an unreadable ca_file must be refused");
    let message = error.to_string();
    assert!(message.contains("ca_file"), "{message}");
    assert!(
        message.contains("/nonexistent/siphon-control-ca.pem"),
        "{message}"
    );
}

#[test]
fn a_control_listener_without_tls_still_loads() {
    // Plaintext stays valid: a loopback or trusted-segment deployment is
    // the common case and must not be forced to generate certificates.
    let config = control_yaml("  listen: \"127.0.0.1:9092\"\n")
        .expect("a plaintext control listener must load");
    assert!(config.control.expect("control").tls.is_none());
}

#[test]
fn a_wss_control_app_without_a_ca_file_loads_on_the_public_roots() {
    let config = control_config(
        "    - name: \"pbx\"\n      per_call_connect: true\n      connect_url: \"wss://controller.example\"\n",
    )
    .expect("wss:// on the public roots must load");
    let app = &config.control.expect("control").apps[0];
    assert_eq!(app.ca_file, None);
}

#[test]
fn an_inbound_only_control_app_needs_no_connect_url() {
    // The persistent mode dials in, so there is nothing to validate.
    let config = control_config("    - name: \"pbx\"\n      token: \"t\"\n")
        .expect("an app with no connect_url must load");
    assert!(config.control.expect("control").apps[0]
        .connect_url
        .is_none());
}

/// `server.auto_options` defaults ON, and it has to default ON from *both*
/// directions: an absent `server:` block (the common case — nobody adds one
/// to get an OPTIONS answered) and a present block that simply does not
/// mention the key. A `#[serde(default)]` covers the second; only the
/// dispatcher's own `map_or(true, …)` on the absent block covers the first,
/// which is why the no-block case is asserted through that same shape
/// rather than against the struct alone. (`map_or` and not `is_none_or`
/// there and here: the latter is stable since 1.82 and the crate's MSRV is
/// 1.80.)
#[test]
fn auto_options_defaults_on() {
    let with_block = Config::from_str(concat!(
        "listen:\n",
        "  udp: [\"0.0.0.0:5060\"]\n",
        "domain:\n",
        "  local: [\"example.com\"]\n",
        "script:\n",
        "  path: \"/dev/null\"\n",
        "server:\n",
        "  drain_secs: 5\n",
    ))
    .expect("config must parse");
    assert!(
        with_block
            .server
            .as_ref()
            .map_or(true, |server| server.auto_options),
        "a server: block that omits auto_options must still answer OPTIONS"
    );

    let without_block = Config::from_str(concat!(
        "listen:\n",
        "  udp: [\"0.0.0.0:5060\"]\n",
        "domain:\n",
        "  local: [\"example.com\"]\n",
        "script:\n",
        "  path: \"/dev/null\"\n",
    ))
    .expect("config must parse");
    assert!(
        without_block
            .server
            .as_ref()
            .map_or(true, |server| server.auto_options),
        "no server: block at all must still answer OPTIONS"
    );
}

#[test]
fn auto_options_can_be_turned_off() {
    let config = Config::from_str(concat!(
        "listen:\n",
        "  udp: [\"0.0.0.0:5060\"]\n",
        "domain:\n",
        "  local: [\"example.com\"]\n",
        "script:\n",
        "  path: \"/dev/null\"\n",
        "server:\n",
        "  auto_options: false\n",
    ))
    .expect("config must parse");
    assert!(!config
        .server
        .as_ref()
        .map_or(true, |server| server.auto_options));
}

/// Codec manipulation is an rtpengine NG capability. The native engine's
/// `ProfileFlags` has no codec fields and rtpproxy is a plain relay, so a
/// profile asking for it there is refused at load rather than reading as
/// "restricted to PCMA/PCMU" while every offered codec crosses untouched.
#[test]
fn codec_flags_are_rtpengine_only() {
    let flags = NgFlagsConfig {
        codec: CodecFlagsConfig {
            offer: vec!["PCMA".to_string(), "PCMU".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(
        MediaBackendKind::Rtpengine
            .unsupported_profile_fields(&flags)
            .is_empty(),
        "rtpengine speaks the codec dict"
    );
    // The native engine implements the same codec model, reading it off the
    // flag list — so an `offer` list is honoured there, not refused.
    assert!(
        MediaBackendKind::SiphonRtp
            .unsupported_profile_fields(&flags)
            .is_empty(),
        "siphon-rtp implements codec manipulation and must accept it"
    );
    // rtpproxy is a plain relay: no transcoder, no codec control.
    assert!(
        MediaBackendKind::Rtpproxy
            .unsupported_profile_fields(&flags)
            .contains(&"codec"),
        "rtpproxy cannot express codec manipulation and must refuse it"
    );

    // The two ops with no native equivalent ARE refused on siphon-rtp,
    // rather than silently dropped when the block is flattened to flags.
    let unmappable = NgFlagsConfig {
        codec: CodecFlagsConfig {
            ignore: vec!["G729".to_string()],
            set: vec!["opus/48000/2".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let native = MediaBackendKind::SiphonRtp.unsupported_profile_fields(&unmappable);
    assert!(native.contains(&"codec.ignore"), "got {native:?}");
    assert!(native.contains(&"codec.set"), "got {native:?}");
    assert!(
        MediaBackendKind::Rtpengine
            .unsupported_profile_fields(&unmappable)
            .is_empty(),
        "rtpengine takes every op"
    );

    // An unset codec block is inert on every backend.
    let bare = NgFlagsConfig::default();
    for backend in [
        MediaBackendKind::Rtpengine,
        MediaBackendKind::SiphonRtp,
        MediaBackendKind::Rtpproxy,
    ] {
        assert!(!backend.unsupported_profile_fields(&bare).contains(&"codec"));
    }
}

/// The codec block is a DICT of named lists. The shape that shipped in the
/// Teams example (`codec: ["offer", "PCMA,PCMU"]`) is not it, and now fails
/// the config load instead of being silently dropped — which is how it went
/// unnoticed while implying siphon was restricting codecs.
#[test]
fn codec_block_parses_as_a_dict_and_rejects_the_old_list_form() {
    let good: NgFlagsConfig = serde_yaml_ng::from_str(
        r#"
transport_protocol: "RTP/AVP"
codec:
  strip: ["SILK", "G722"]
  offer: ["PCMA", "PCMU", "telephone-event"]
"#,
    )
    .expect("the dict form must parse");
    assert_eq!(good.codec.strip, vec!["SILK", "G722"]);
    assert_eq!(good.codec.offer, vec!["PCMA", "PCMU", "telephone-event"]);
    assert!(good.codec.transcode.is_empty());

    assert!(
        serde_yaml_ng::from_str::<NgFlagsConfig>("codec: [\"offer\", \"PCMA,PCMU\"]").is_err(),
        "the old list form must be rejected, not ignored"
    );
    assert!(
        serde_yaml_ng::from_str::<NgFlagsConfig>("codec:\n  bogus: [\"PCMA\"]").is_err(),
        "an unknown codec key must be rejected, not ignored"
    );
}

/// The `Replaces` takeover is a capability, not a default: an upgrade must
/// never hand every party that can reach this node the ability to
/// disconnect someone from a live call and take their place (RFC 3891 §5).
#[test]
fn replaces_takeover_is_off_unless_enabled() {
    assert!(
        !B2buaConfig::default().replaces_takeover_enabled(),
        "an operator opts into call takeover; it is never inherited"
    );
    assert!(!B2buaConfig {
        accept_replaces: Some(false),
        ..Default::default()
    }
    .replaces_takeover_enabled());
    assert!(B2buaConfig {
        accept_replaces: Some(true),
        ..Default::default()
    }
    .replaces_takeover_enabled());
}

/// One `info` line per call on the busiest path siphon has is an
/// operator's decision, not an upgrade's — the LCR lines that already log
/// at `info` fire only on failover, which is why they carry no knob.
#[test]
fn dial_logging_is_off_unless_enabled() {
    assert!(
        !B2buaConfig::default().log_dial_enabled(),
        "per-call dial logging is opt-in"
    );
    assert!(!B2buaConfig {
        log_dial: Some(false),
        ..Default::default()
    }
    .log_dial_enabled());
    assert!(B2buaConfig {
        log_dial: Some(true),
        ..Default::default()
    }
    .log_dial_enabled());
}

#[test]
fn dial_logging_parses_from_yaml() {
    let config: B2buaConfig =
        serde_yaml_ng::from_str("log_dial: true").expect("b2bua block must parse");
    assert!(config.log_dial_enabled());
    let empty: B2buaConfig =
        serde_yaml_ng::from_str("default_refer_mode: terminate").expect("must parse");
    assert!(!empty.log_dial_enabled());
}

#[test]
fn replaces_takeover_parses_from_yaml() {
    let config: B2buaConfig =
        serde_yaml_ng::from_str("accept_replaces: true").expect("b2bua block must parse");
    assert!(config.replaces_takeover_enabled());
    // An omitted key leaves the capability off.
    let empty: B2buaConfig =
        serde_yaml_ng::from_str("default_refer_mode: terminate").expect("must parse");
    assert!(!empty.replaces_takeover_enabled());
}

fn minimal_yaml() -> &'static str {
    r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar:
  backend: memory
auth:
  realm: "example.com"
log:
  level: info
  format: pretty
"#
}

#[test]
fn parses_sni_certificates() {
    let yaml = format!(
        "{}{}",
        minimal_yaml(),
        r#"
tls:
  certificate: "/etc/siphon/tls/default.crt"
  private_key: "/etc/siphon/tls/default.key"
  certificates:
    - server_names: ["sip.tenant-a.example", "sip.tenant-a.net"]
      certificate: "/etc/siphon/tls/tenant-a.crt"
      private_key: "/etc/siphon/tls/tenant-a.key"
    - server_names: ["*.tenant-b.example"]
      certificate: "/etc/siphon/tls/tenant-b.crt"
      private_key: "/etc/siphon/tls/tenant-b.key"
"#
    );
    let config = Config::from_str(&yaml).unwrap();
    let tls = config.tls.expect("tls block");
    assert_eq!(tls.certificate, "/etc/siphon/tls/default.crt");
    assert_eq!(tls.certificates.len(), 2);
    assert_eq!(
        tls.certificates[0].server_names,
        vec!["sip.tenant-a.example", "sip.tenant-a.net"]
    );
    assert_eq!(
        tls.certificates[0].certificate,
        "/etc/siphon/tls/tenant-a.crt"
    );
    assert_eq!(tls.certificates[1].server_names, vec!["*.tenant-b.example"]);
}

#[test]
fn tls_certificates_defaults_to_empty() {
    // A pre-SNI config must keep parsing, with the single-cert behaviour.
    let yaml = format!(
        "{}{}",
        minimal_yaml(),
        r#"
tls:
  certificate: "/etc/siphon/tls/default.crt"
  private_key: "/etc/siphon/tls/default.key"
"#
    );
    let config = Config::from_str(&yaml).unwrap();
    assert!(config.tls.expect("tls block").certificates.is_empty());
}

#[test]
fn parses_minimal_config() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert_eq!(config.listen.udp[0].address(), "0.0.0.0:5060");
    assert!(config.listen.tcp.is_empty());
    assert_eq!(config.domain.local, vec!["example.com"]);
    assert_eq!(config.script.path, "scripts/proxy_default.py");
    assert_eq!(config.script.reload, ReloadMode::Auto);
    assert!(config.script.include_paths.is_empty());
    assert_eq!(config.registrar.backend, RegistrarBackendType::Memory);
    assert_eq!(config.registrar.default_expires, 3600);
    assert_eq!(config.registrar.max_expires, 7200);
    assert_eq!(config.auth.realm, "example.com");
    assert_eq!(config.auth.backend, AuthBackendType::Static);
    assert_eq!(config.log.level, LogLevel::Info);
    assert_eq!(config.log.format, LogFormat::Pretty);
    // All optional sections absent
    assert!(config.advertised_address.is_none());
    assert!(config.tls.is_none());
    assert!(config.security.is_none());
    assert!(config.nat.is_none());
    assert!(config.tracing.is_none());
    assert!(config.metrics.is_none());
    assert!(config.server.is_none());
    assert!(config.transaction.is_none());
    assert!(config.dialog.is_none());
    assert!(config.cache.is_none());
    assert!(config.media.is_none());
    assert!(config.gateway.is_none());
    assert!(config.session_timer.is_none());
    assert!(config.registrant.is_none());
    assert!(config.lawful_intercept.is_none());
    assert!(config.diameter.is_none());
}

// --- script path anchoring (Config::from_file) ---

/// Build a config dir holding `siphon.yaml` plus a `scripts/main.py`, and
/// return `(tempdir, config_path)`.
fn config_dir_with_script(script_body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("scripts")).unwrap();
    std::fs::write(dir.path().join("scripts/main.py"), script_body).unwrap();
    let config_path = dir.path().join("siphon.yaml");
    std::fs::write(
        &config_path,
        r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
  include_paths:
    - "lib"
    - "/etc/siphon/shared"
auth:
  realm: "example.com"
"#,
    )
    .unwrap();
    (dir, config_path)
}

/// The systemd case: the working directory is not the config directory, so
/// a relative `script.path` must still resolve.
#[test]
fn relative_script_path_anchors_on_config_dir() {
    let (dir, config_path) = config_dir_with_script("# script\n");

    let config = Config::from_file(&config_path).unwrap();

    assert_eq!(
        config.script.path,
        dir.path().join("scripts/main.py").to_string_lossy()
    );
    assert!(std::path::Path::new(&config.script.path).exists());
}

#[test]
fn relative_include_paths_anchor_on_config_dir() {
    let (dir, config_path) = config_dir_with_script("# script\n");
    std::fs::create_dir(dir.path().join("lib")).unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert_eq!(
        config.script.include_paths,
        vec![
            dir.path().join("lib").to_string_lossy().into_owned(),
            // Absolute entries are never touched.
            "/etc/siphon/shared".to_string(),
        ]
    );
}

/// Anchoring must not change a config that already worked: when there is no
/// config-relative candidate, the value is left alone so the process
/// working directory still resolves it (and the same "script not found"
/// error still names what the operator wrote).
#[test]
fn missing_config_relative_candidate_leaves_path_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("siphon.yaml");
    std::fs::write(
        &config_path,
        r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/absent.py"
  include_paths:
    - "absent-lib"
auth:
  realm: "example.com"
"#,
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert_eq!(config.script.path, "scripts/absent.py");
    assert_eq!(config.script.include_paths, vec!["absent-lib".to_string()]);
}

/// An absolute `script.path` is never rewritten, even when a same-named
/// file sits beside the config.
#[test]
fn absolute_script_path_is_not_anchored() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere.py");
    std::fs::write(&elsewhere, "# script\n").unwrap();
    let config_path = dir.path().join("siphon.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "{}"
auth:
  realm: "example.com"
"#,
            elsewhere.display()
        ),
    )
    .unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert_eq!(config.script.path, elsewhere.to_string_lossy());
}

/// `from_str` has no file to anchor on and must stay byte-for-byte what the
/// caller wrote (embedding / `--config-string` path).
#[test]
fn from_str_does_not_anchor_script_path() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
auth:
  realm: "example.com"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.script.path, "scripts/main.py");
}

/// A bare filename config (`siphon --config siphon.yaml`) has an empty
/// parent — anchoring is a no-op rather than a self-join.
#[test]
fn bare_config_filename_anchors_nothing() {
    let mut config = Config::from_str(minimal_yaml()).unwrap();
    config.script.path = "scripts/main.py".to_string();

    config.anchor_script_paths(std::path::Path::new("siphon.yaml"));

    assert_eq!(config.script.path, "scripts/main.py");
}

#[test]
fn parses_script_include_paths() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
  include_paths:
    - "/etc/siphon/lib"
    - "shared"
auth:
  realm: "example.com"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(
        config.script.include_paths,
        vec!["/etc/siphon/lib".to_string(), "shared".to_string()]
    );
}

#[test]
fn parses_metrics_and_admin_cors() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
auth:
  realm: "example.com"
metrics:
  prometheus:
    listen: "0.0.0.0:8888"
    cors:
      allowed_origins:
        - "http://localhost:5173"
        - "https://dash.example.com"
admin:
  listen: "0.0.0.0:9091"
  cors:
    allowed_origins:
      - "*"
"#;
    let config = Config::from_str(yaml).unwrap();

    let prom_cors = config
        .metrics
        .as_ref()
        .and_then(|metrics| metrics.prometheus.as_ref())
        .and_then(|prom| prom.cors.as_ref())
        .expect("metrics.prometheus.cors must parse");
    assert_eq!(
        prom_cors.allowed_origins,
        vec![
            "http://localhost:5173".to_string(),
            "https://dash.example.com".to_string()
        ]
    );

    let admin_cors = config
        .admin
        .as_ref()
        .and_then(|admin| admin.cors.as_ref())
        .expect("admin.cors must parse");
    assert_eq!(admin_cors.allowed_origins, vec!["*".to_string()]);
}

#[test]
fn metrics_without_cors_leaves_it_none() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
auth:
  realm: "example.com"
metrics:
  prometheus:
    listen: "0.0.0.0:8888"
admin:
  listen: "0.0.0.0:9091"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert!(config
        .metrics
        .as_ref()
        .and_then(|metrics| metrics.prometheus.as_ref())
        .and_then(|prom| prom.cors.as_ref())
        .is_none());
    assert!(config
        .admin
        .as_ref()
        .and_then(|admin| admin.cors.as_ref())
        .is_none());
}

#[test]
fn parses_full_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
    - "192.168.1.1:5060"
  tcp:
    - "0.0.0.0:5060"
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
    - "127.0.0.1"
    - "192.168.1.1"
script:
  path: "scripts/custom.py"
  reload: sighup
registrar:
  backend: redis
  default_expires: 1800
  max_expires: 3600
  redis:
    url: "redis://127.0.0.1:6379"
auth:
  realm: "example.com"
  backend: static
  users:
    alice: "secret"
    bob: "hunter2"
log:
  level: debug
  format: json
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.udp.len(), 2);
    assert_eq!(config.listen.tcp[0].address(), "0.0.0.0:5060");
    assert_eq!(config.listen.tls[0].address(), "0.0.0.0:5061");
    assert_eq!(config.domain.local.len(), 3);
    assert_eq!(config.script.reload, ReloadMode::Sighup);
    assert_eq!(config.registrar.backend, RegistrarBackendType::Redis);
    assert_eq!(config.registrar.default_expires, 1800);
    assert_eq!(
        config.registrar.redis.as_ref().unwrap().url,
        "redis://127.0.0.1:6379"
    );
    assert_eq!(config.auth.users.get("alice").unwrap(), "secret");
    assert_eq!(config.log.level, LogLevel::Debug);
    assert_eq!(config.log.format, LogFormat::Json);
}

#[test]
fn rejects_invalid_yaml() {
    let result = Config::from_str("this: is: not: valid: yaml:");
    assert!(result.is_err());
}

#[test]
fn is_local_matches_configured_domains() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.is_local("example.com"));
    assert!(!config.is_local("other.com"));
}

#[test]
fn defaults_are_applied_when_fields_omitted() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar: {}
auth:
  realm: "example.com"
log: {}
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.registrar.backend, RegistrarBackendType::Memory);
    assert_eq!(config.registrar.default_expires, 3600);
    assert_eq!(config.log.level, LogLevel::Info);
    assert_eq!(config.log.format, LogFormat::Pretty);
    assert_eq!(config.script.reload, ReloadMode::Auto);
}

#[test]
fn parses_auth_http_backend() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
auth:
  realm: "example.com"
  backend: http
  http:
    url: "http://127.0.0.1:8000/sip/auth/{username}"
    timeout_ms: 2000
    connect_timeout_ms: 500
    ha1: true
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.auth.backend, AuthBackendType::Http);
    let http = config.auth.http.unwrap();
    assert!(http.url.contains("{username}"));
    assert_eq!(http.timeout_ms, 2000);
    assert!(http.ha1);
    // HA1 caching is opt-in: absent `cache_ttl_secs` defaults to 0 (disabled),
    // preserving the per-request blocking-fetch behaviour.
    assert_eq!(http.cache_ttl_secs, 0);
}

#[test]
fn parses_auth_http_cache_ttl() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
auth:
  realm: "example.com"
  backend: http
  http:
    url: "http://127.0.0.1:8000/sip/auth/{username}"
    cache_ttl_secs: 300
"#;
    let config = Config::from_str(yaml).unwrap();
    let http = config.auth.http.unwrap();
    assert_eq!(http.cache_ttl_secs, 300);
}

#[test]
fn script_executor_defaults_and_overrides() {
    // Defaults: watchdog at 30 s, bounded queue at 1024, pool sizes auto.
    let default_script = ScriptConfig::default();
    assert_eq!(default_script.handler_stall_abort_secs, 30);
    assert_eq!(default_script.executor_queue_capacity, 1024);
    assert_eq!(default_script.sync_pool_size, None);
    assert_eq!(default_script.sync_pool_max, None);

    // Defaults survive a YAML that omits the executor knobs.
    let minimal = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(minimal).unwrap();
    assert_eq!(config.script.handler_stall_abort_secs, 30);
    assert_eq!(config.script.executor_queue_capacity, 1024);

    // Explicit overrides parse, including disabling the watchdog (0).
    let overridden = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
  sync_pool_size: 16
  sync_pool_max: 128
  handler_stall_abort_secs: 0
  executor_queue_capacity: 4096
"#;
    let config = Config::from_str(overridden).unwrap();
    assert_eq!(config.script.sync_pool_size, Some(16));
    assert_eq!(config.script.sync_pool_max, Some(128));
    assert_eq!(config.script.handler_stall_abort_secs, 0);
    assert_eq!(config.script.executor_queue_capacity, 4096);
}

#[test]
fn parses_registrar_min_expires_and_max_contacts() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar:
  backend: memory
  default_expires: 300
  max_expires: 600
  min_expires: 60
  max_contacts: 1
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.registrar.min_expires, Some(60));
    assert_eq!(config.registrar.max_contacts, Some(1));
    assert_eq!(config.registrar.default_expires, 300);
}

#[test]
fn parses_registrant_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrant:
  default_interval: 1800
  retry_interval: 30
  max_retry_interval: 120
  entries:
    - aor: "sip:alice@carrier.com"
      registrar: "sip:registrar.carrier.com:5060"
      user: "alice"
      password: "secret123"
      realm: "carrier.com"
      interval: 900
      contact: "sip:alice@1.2.3.4"
      transport: "tcp"
    - aor: "sip:bob@carrier.com"
      registrar: "sip:registrar.carrier.com:5060"
      user: "bob"
      password: "hunter2"
"#;
    let config = Config::from_str(yaml).unwrap();
    let registrant = config.registrant.unwrap();
    assert_eq!(registrant.default_interval, 1800);
    assert_eq!(registrant.retry_interval, 30);
    assert_eq!(registrant.max_retry_interval, 120);
    assert_eq!(registrant.entries.len(), 2);

    let alice = &registrant.entries[0];
    assert_eq!(alice.aor, "sip:alice@carrier.com");
    assert_eq!(alice.registrar, "sip:registrar.carrier.com:5060");
    assert_eq!(alice.user, "alice");
    assert_eq!(alice.password, "secret123");
    assert_eq!(alice.realm.as_deref(), Some("carrier.com"));
    assert_eq!(alice.interval, Some(900));
    assert_eq!(alice.contact.as_deref(), Some("sip:alice@1.2.3.4"));
    assert_eq!(alice.transport, "tcp");

    let bob = &registrant.entries[1];
    assert_eq!(bob.aor, "sip:bob@carrier.com");
    assert_eq!(bob.user, "bob");
    assert_eq!(bob.realm, None);
    assert_eq!(bob.interval, None);
    assert_eq!(bob.contact, None);
    assert_eq!(bob.transport, "udp"); // default

    // Digest entries carry no AKA / IPsec blocks.
    assert!(alice.auth.is_none());
    assert!(alice.aka.is_none());
    assert!(alice.ipsec.is_none());
}

#[test]
fn parses_registrant_aka_ipsec_config() {
    // 3GPP test range (MCC 001 / MNC 01) + TS 35.208 Test Set 1 secrets.
    let yaml = r#"
listen:
  udp:
    - "10.0.0.20:5060"
    - "10.0.0.20:6100"
    - "10.0.0.20:6101"
domain:
  local:
    - "10.0.0.20"
script:
  path: "examples/ims_ue_b2bua.py"
ipsec:
  backend: netlink
registrant:
  entries:
    - aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
      registrar: "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060"
      user: "001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
      auth: "aka"
      aka:
        k: "465b5ce8b199b49faa5f0a2ee238a6bc"
        opc: "cd63cb71954a9f4e48a5994e37a02baf"
        amf: "b9b9"
      ipsec:
        ue_port_c: 6100
        ue_port_s: 6101
"#;
    let config = Config::from_str(yaml).unwrap();
    let registrant = config.registrant.unwrap();
    let ue = &registrant.entries[0];
    assert_eq!(ue.auth.as_deref(), Some("aka"));
    // password omitted (unused for AKA) defaults to empty.
    assert_eq!(ue.password, "");

    let aka = ue.aka.as_ref().expect("aka block");
    assert_eq!(aka.k, "465b5ce8b199b49faa5f0a2ee238a6bc");
    assert_eq!(aka.opc.as_deref(), Some("cd63cb71954a9f4e48a5994e37a02baf"));
    assert_eq!(aka.op, None);
    assert_eq!(aka.amf, "b9b9");
    assert_eq!(aka.sqn, "000000000000"); // default

    let ipsec = ue.ipsec.as_ref().expect("ipsec block");
    assert_eq!(ipsec.ue_port_c, 6100);
    assert_eq!(ipsec.ue_port_s, 6101);
    assert_eq!(ipsec.alg, "hmac-sha-1-96"); // default
    assert_eq!(ipsec.ealg, "null"); // default
}

/// The shipped IMS UE B2BUA example config must actually parse (env vars
/// fall back to their `${VAR:-default}` defaults here). Guards against the
/// example silently rotting.
#[test]
fn example_ims_ue_b2bua_yaml_parses() {
    let yaml = include_str!("../../examples/ims_ue_b2bua.yaml");
    let config = Config::from_str(yaml).expect("example yaml must parse");
    let registrant = config.registrant.expect("registrant block");
    assert_eq!(registrant.entries.len(), 1);
    let ue = &registrant.entries[0];
    assert_eq!(ue.auth.as_deref(), Some("aka"));
    let aka = ue.aka.as_ref().expect("aka block");
    assert_eq!(aka.k.len(), 32); // 128-bit K as hex
    let ipsec = ue.ipsec.as_ref().expect("ipsec block");
    assert_eq!(ipsec.ue_port_c, 6100);
    assert_eq!(ipsec.ue_port_s, 6101);
    let ims = ue.ims.as_ref().expect("ims block");
    assert!(ims.imei.is_some());
    assert!(ims.features.iter().any(|f| f == "mmtel"));
}

/// The shipped WhatsApp Business Calling gateway example must parse, and its
/// WhatsApp-specific invariants must hold: no mutual-TLS client cert (Meta is
/// server-auth only), no session timer (a re-INVITE would fail the WhatsApp
/// leg), the whatsapp + internal gateway groups (WhatsApp probe disabled —
/// Meta does not answer OPTIONS), and the DTLS-SRTP media profiles. Guards
/// against the example silently rotting.
#[test]
fn example_whatsapp_calling_yaml_parses() {
    let yaml = include_str!("../../examples/whatsapp_calling.yaml");
    let config = Config::from_str(yaml).expect("example yaml must parse");

    // Server-auth TLS only — no outbound client certificate toward Meta.
    let tls = config.tls.expect("tls block");
    assert!(tls.client_certificate.is_none());
    assert!(tls.client_private_key.is_none());

    // SIPhon must never originate a re-INVITE toward the WhatsApp leg.
    assert!(config.session_timer.is_none());

    let gateway = config.gateway.expect("gateway block");
    let whatsapp = gateway
        .groups
        .iter()
        .find(|g| g.name == "whatsapp")
        .expect("whatsapp gateway group");
    assert!(!whatsapp.probe.enabled);
    // Meta's source ranges drive call.from_gateway("whatsapp") direction
    // detection — the group must carry source_networks.
    assert!(!whatsapp.source_networks.is_empty());
    assert!(gateway.groups.iter().any(|g| g.name == "internal"));

    // DTLS-SRTP profiles for the Meta leg (the SDES default reuses built-ins).
    let media = config.media.expect("media block");
    let dtls_in = media
        .profiles
        .get("whatsapp_dtls_in")
        .expect("whatsapp_dtls_in profile");
    assert_eq!(
        dtls_in.answer.transport_protocol.as_deref(),
        Some("RTP/SAVPF")
    );
    assert_eq!(dtls_in.answer.dtls.as_deref(), Some("passive"));
    let dtls_out = media
        .profiles
        .get("whatsapp_dtls_out")
        .expect("whatsapp_dtls_out profile");
    assert_eq!(dtls_out.offer.dtls.as_deref(), Some("passive"));
}

#[test]
fn parses_security_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
security:
  rate_limit:
    window_secs: 10
    max_requests: 30
    ban_duration_secs: 3600
  scanner_block:
    user_agents:
      - "sipvicious"
      - "friendly-scanner"
  trusted_cidrs:
    - "10.0.0.0/8"
  failed_auth_ban:
    threshold: 10
    ban_duration_secs: 300
"#;
    let config = Config::from_str(yaml).unwrap();
    let sec = config.security.unwrap();
    let rl = sec.rate_limit.unwrap();
    assert_eq!(rl.window_secs, 10);
    assert_eq!(rl.max_requests, 30);
    assert_eq!(rl.ban_duration_secs, 3600);
    let sb = sec.scanner_block.unwrap();
    assert_eq!(sb.user_agents.len(), 2);
    assert_eq!(sec.trusted_cidrs, vec!["10.0.0.0/8"]);
    let fab = sec.failed_auth_ban.unwrap();
    assert_eq!(fab.threshold, 10);
    assert_eq!(fab.ban_duration_secs, 300);
    assert_eq!(fab.window_secs, 600); // serde default when omitted
}

#[test]
fn parses_tracing_hep_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tracing:
  hep:
    endpoint: "127.0.0.1:9060"
    version: 3
    transport: udp
    agent_id: "siphon-registrar"
"#;
    let config = Config::from_str(yaml).unwrap();
    let hep = config.tracing.unwrap().hep.unwrap();
    assert_eq!(hep.endpoint, "127.0.0.1:9060");
    assert_eq!(hep.version, 3);
    assert_eq!(hep.transport, HepTransport::Udp);
    assert_eq!(hep.agent_id.unwrap(), "siphon-registrar");
}

#[test]
fn parses_metrics_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
metrics:
  prometheus:
    listen: "0.0.0.0:8888"
    path: "/metrics"
"#;
    let config = Config::from_str(yaml).unwrap();
    let prom = config.metrics.unwrap().prometheus.unwrap();
    assert_eq!(prom.listen, "0.0.0.0:8888");
    assert_eq!(prom.path, "/metrics");
}

#[test]
fn parses_nat_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
nat:
  fix_contact: true
  keepalive:
    enabled: true
    interval_secs: 30
    failure_threshold: 10
"#;
    let config = Config::from_str(yaml).unwrap();
    let nat = config.nat.unwrap();
    assert!(nat.fix_contact);
    let ka = nat.keepalive.unwrap();
    assert!(ka.enabled);
    assert_eq!(ka.interval_secs, 30);
}

#[test]
fn nat_config_ignores_removed_legacy_keys() {
    // The no-op `force_rport` / `fix_register` keys were removed; a config
    // that still carries them must keep parsing (serde ignores unknown
    // fields) so existing siphon.yaml files don't break on upgrade.
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
nat:
  force_rport: true
  fix_contact: true
  fix_register: true
"#;
    let config = Config::from_str(yaml).unwrap();
    let nat = config.nat.unwrap();
    assert!(nat.fix_contact);
}

#[test]
fn parses_cache_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
cache:
  - name: "cnam"
    url: "redis://192.0.2.131:6379"
    local_ttl_secs: 60
    local_max_entries: 10000
"#;
    let config = Config::from_str(yaml).unwrap();
    let caches = config.cache.unwrap();
    assert_eq!(caches.len(), 1);
    assert_eq!(caches[0].name, "cnam");
    assert_eq!(caches[0].local_ttl_secs, Some(60));
    assert_eq!(caches[0].local_max_entries, Some(10000));
}

#[test]
fn parses_transaction_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
transaction:
  timeout_secs: 5
  invite_timeout_secs: 30
"#;
    let config = Config::from_str(yaml).unwrap();
    let tx = config.transaction.unwrap();
    assert_eq!(tx.timeout_secs, 5);
    assert_eq!(tx.invite_timeout_secs, 30);
}

#[test]
fn parses_memory_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
memory:
  glibc:
    arena_max: 2
    trim_interval_secs: 30
"#;
    let config = Config::from_str(yaml).unwrap();
    let memory = config.memory.expect("memory block present");
    assert_eq!(memory.glibc.arena_max, Some(2));
    assert_eq!(memory.glibc.trim_interval_secs, 30);
}

#[test]
fn memory_config_absent_and_partial_defaults() {
    // Absent → None (gauges still always-on; only the knobs are gated).
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.memory.is_none());

    // Partial → unspecified knobs take their defaults (arena_max None,
    // trim disabled), so a bare `memory:` block is valid.
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
memory:
  glibc:
    arena_max: 4
"#;
    let config = Config::from_str(yaml).unwrap();
    let glibc = config.memory.unwrap().glibc;
    assert_eq!(glibc.arena_max, Some(4));
    assert_eq!(glibc.trim_interval_secs, 0);
}

#[test]
fn parses_tls_server_config() {
    let yaml = r#"
listen:
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key: "/etc/siphon/tls/example.com.key"
  method: "TLSv1_3"
  verify_client: false
"#;
    let config = Config::from_str(yaml).unwrap();
    let tls = config.tls.unwrap();
    assert_eq!(tls.certificate, "/etc/siphon/tls/example.com.crt");
    assert_eq!(tls.method, TlsMethod::Tls13);
    assert!(!tls.verify_client);
    // Outbound client-certificate (mutual TLS) fields default to None.
    assert!(tls.client_certificate.is_none());
    assert!(tls.client_private_key.is_none());
}

#[test]
fn tls_method_defaults_to_tls12_floor() {
    // Unset `method` must keep serving what siphon has always served
    // (TLS 1.2 + 1.3). A 1.3 default here would silently drop every TLS 1.2
    // peer on upgrade.
    let yaml = r#"
listen:
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key: "/etc/siphon/tls/example.com.key"
"#;
    let config = Config::from_str(yaml).unwrap();
    let tls = config.tls.unwrap();
    assert_eq!(tls.method, TlsMethod::Tls12);
}

#[test]
fn tls_method_accepts_openssl_and_kamailio_spellings() {
    for spelling in [
        "TLSv1_2",
        "TLSv1.2",
        "tlsv1_2",
        " TLSv1_2 ",
        "TLSv1.2+",
        "1.2",
    ] {
        assert_eq!(
            spelling.parse::<TlsMethod>(),
            Ok(TlsMethod::Tls12),
            "{spelling} should parse as the TLS 1.2 floor"
        );
    }
    for spelling in ["TLSv1_3", "TLSv1.3", "tlsv1_3", "TLSv1.3+", "1.3"] {
        assert_eq!(
            spelling.parse::<TlsMethod>(),
            Ok(TlsMethod::Tls13),
            "{spelling} should parse as the TLS 1.3 floor"
        );
    }
}

#[test]
fn tls_method_rejects_deprecated_versions() {
    for spelling in ["TLSv1", "TLSv1_0", "TLSv1_1", "SSLv3", "SSLv23"] {
        let error = spelling
            .parse::<TlsMethod>()
            .expect_err("deprecated TLS/SSL versions must be rejected");
        assert!(
            error.contains("RFC 8996"),
            "error should name the deprecation: {error}"
        );
    }
}

#[test]
fn tls_method_rejects_unknown_value_at_config_load() {
    // Fail closed and loud: an unrecognised value used to be accepted and
    // ignored, so a typo read as a hardened config while nothing enforced it.
    let yaml = r#"
listen:
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key: "/etc/siphon/tls/example.com.key"
  method: "TLSv1_4"
"#;
    let error = Config::from_str(yaml).expect_err("unknown tls.method must fail config load");
    let error = error.to_string();
    assert!(
        error.contains("TLSv1_2") && error.contains("TLSv1_3"),
        "error should list the accepted values: {error}"
    );
}

#[test]
fn tls_method_display_round_trips() {
    for method in [TlsMethod::Tls12, TlsMethod::Tls13] {
        assert_eq!(method.to_string().parse::<TlsMethod>(), Ok(method));
    }
}

#[test]
fn parses_tls_outbound_client_certificate() {
    let yaml = r#"
listen:
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key: "/etc/siphon/tls/example.com.key"
  client_certificate: "/etc/siphon/tls/client.crt"
  client_private_key: "/etc/siphon/tls/client.key"
"#;
    let config = Config::from_str(yaml).unwrap();
    let tls = config.tls.unwrap();
    assert_eq!(
        tls.client_certificate.as_deref(),
        Some("/etc/siphon/tls/client.crt")
    );
    assert_eq!(
        tls.client_private_key.as_deref(),
        Some("/etc/siphon/tls/client.key")
    );
}

#[test]
fn parses_media_single_rtpengine() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
    timeout_ms: 500
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    let rtpengine = media.rtpengine.expect("rtpengine block configured");
    let instances = rtpengine.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].address, "127.0.0.1:22222");
    assert_eq!(instances[0].timeout_ms, 500);
    assert_eq!(instances[0].weight, 1);
}

#[test]
fn parses_media_multiple_rtpengines() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    instances:
      - address: "10.0.0.1:22222"
        weight: 2
      - address: "10.0.0.2:22222"
        weight: 1
        timeout_ms: 2000
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    let rtpengine = media.rtpengine.expect("rtpengine block configured");
    let instances = rtpengine.instances();
    assert_eq!(instances.len(), 2);
    assert_eq!(instances[0].address, "10.0.0.1:22222");
    assert_eq!(instances[0].weight, 2);
    assert_eq!(instances[0].timeout_ms, 1000); // default
    assert_eq!(instances[1].address, "10.0.0.2:22222");
    assert_eq!(instances[1].weight, 1);
    assert_eq!(instances[1].timeout_ms, 2000);
}

#[test]
fn parses_media_rtpengine_defaults() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    let rtpengine = media.rtpengine.expect("rtpengine block configured");
    let instances = rtpengine.instances();
    assert_eq!(instances[0].timeout_ms, 1000); // default
    assert_eq!(instances[0].weight, 1); // default
}

/// The reap deletes live media sessions, so it has to be asked for. It is
/// also unsafe on an rtpengine shared between nodes, where `list` is unscoped —
/// defaulting it on would tear down another node's calls on every restart.
#[test]
fn media_orphan_reap_is_off_by_default() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert!(!media.reap_orphans_at_startup);
    assert_eq!(media.reap_limit, 10_000);
}

#[test]
fn parses_media_orphan_reap_knobs() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  reap_orphans_at_startup: true
  reap_limit: 250
  rtpengine:
    address: "127.0.0.1:22222"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert!(media.reap_orphans_at_startup);
    assert_eq!(media.reap_limit, 250);
}

#[test]
fn media_backend_defaults_to_rtpengine() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(media.backend(), MediaBackendKind::Rtpengine);
    assert!(media.rtpengine.is_some());
    assert!(media.siphon_rtp.is_none());
}

#[test]
fn parses_media_backend_siphon_rtp() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  backend: siphon-rtp
  siphon_rtp:
    address: "127.0.0.1:8080"
    control_secret: "s3cret"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(media.backend(), MediaBackendKind::SiphonRtp);
    assert!(media.rtpengine.is_none());
    let siphon_rtp = media.siphon_rtp.expect("siphon_rtp block configured");
    assert_eq!(siphon_rtp.address.as_deref(), Some("127.0.0.1:8080"));
    assert_eq!(siphon_rtp.control_secret.as_deref(), Some("s3cret"));
    assert_eq!(siphon_rtp.timeout_ms, 2000); // default
                                             // Single `address` normalizes to one (address, timeout, weight) tuple.
    let instances = siphon_rtp.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0], ("127.0.0.1:8080".to_string(), 2000, 1));
}

#[test]
fn parses_media_siphon_rtp_multiple_instances() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  backend: siphon-rtp
  siphon_rtp:
    control_secret: "shared"
    timeout_ms: 1500
    instances:
      - address: "10.0.0.1:8080"
        weight: 2
      - address: "10.0.0.2:8080"
        weight: 1
        timeout_ms: 3000
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(media.backend(), MediaBackendKind::SiphonRtp);
    let siphon_rtp = media.siphon_rtp.expect("siphon_rtp block configured");
    assert_eq!(siphon_rtp.control_secret.as_deref(), Some("shared"));
    let instances = siphon_rtp.instances();
    assert_eq!(instances.len(), 2);
    // First inherits the parent timeout; second overrides it.
    assert_eq!(instances[0], ("10.0.0.1:8080".to_string(), 1500, 2));
    assert_eq!(instances[1], ("10.0.0.2:8080".to_string(), 3000, 1));
}

#[test]
fn parses_media_backend_rtpproxy() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  backend: rtpproxy
  rtpproxy:
    address: "127.0.0.1:22222"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(media.backend(), MediaBackendKind::Rtpproxy);
    assert!(media.rtpengine.is_none());
    assert!(media.siphon_rtp.is_none());
    let rtpproxy = media.rtpproxy.expect("rtpproxy block configured");
    assert_eq!(rtpproxy.address.as_deref(), Some("127.0.0.1:22222"));
    assert_eq!(rtpproxy.timeout_ms, 1000); // default
    assert_eq!(rtpproxy.retries, 2); // default
    let instances = rtpproxy.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0], ("127.0.0.1:22222".to_string(), 1000, 1));
}

#[test]
fn parses_media_rtpproxy_multiple_instances() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  backend: rtpproxy
  rtpproxy:
    timeout_ms: 1500
    retries: 3
    instances:
      - address: "10.0.0.1:22222"
        weight: 2
      - address: "10.0.0.2:22222"
        weight: 1
        timeout_ms: 3000
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(media.backend(), MediaBackendKind::Rtpproxy);
    let rtpproxy = media.rtpproxy.expect("rtpproxy block configured");
    assert_eq!(rtpproxy.retries, 3);
    let instances = rtpproxy.instances();
    assert_eq!(instances.len(), 2);
    // First inherits the parent timeout; second overrides it.
    assert_eq!(instances[0], ("10.0.0.1:22222".to_string(), 1500, 2));
    assert_eq!(instances[1], ("10.0.0.2:22222".to_string(), 3000, 1));
}

/// A `media:` block carrying only SDP handling asks for no media engine: the
/// `o=`/`s=` topology hiding and the attribute strip run on a B2BUA that anchors
/// no media at all.
#[test]
fn a_media_block_with_only_sdp_settings_expects_no_engine() {
    for media in [
        "  sdp_name: \"SIPhon\"\n",
        "  sdp_strip_attributes: [\"msid\"]\n",
        "  sdp_name: \"SIPhon\"\n  sdp_strip_attributes: [\"msid\"]\n",
    ] {
        let config = config_with(&format!("media:\n{media}")).unwrap();
        assert!(!config.media.unwrap().expects_engine(), "{media:?}");
    }
}

/// Naming a backend, giving an engine's connection block, or setting something
/// only an engine uses (media profiles, the rtpengine event listener) asks for an
/// engine, so a missing one is still worth an error at boot.
#[test]
fn a_media_block_that_names_or_configures_an_engine_expects_one() {
    for media in [
        "  backend: rtpengine\n",
        "  backend: siphon-rtp\n",
        "  backend: rtpproxy\n",
        "  rtpengine:\n    address: \"127.0.0.1:22222\"\n",
        "  siphon_rtp:\n    address: \"127.0.0.1:8080\"\n",
        "  rtpproxy:\n    address: \"127.0.0.1:22222\"\n",
        "  events:\n    listen_addr: \"127.0.0.1:22226\"\n",
        "  profiles:\n    custom:\n      offer: {}\n      answer: {}\n",
    ] {
        let config = config_with(&format!("media:\n  sdp_name: \"SIPhon\"\n{media}")).unwrap();
        assert!(config.media.unwrap().expects_engine(), "{media:?}");
    }
}

/// Telling an unset `backend` from a written one changes nothing about what it
/// resolves to.
#[test]
fn an_unset_media_backend_still_resolves_to_rtpengine() {
    let config = config_with("media:\n  sdp_name: \"SIPhon\"\n").unwrap();
    assert_eq!(config.media.unwrap().backend(), MediaBackendKind::Rtpengine);
}

/// Minimum config the loader accepts, plus whatever the test is about.
fn config_with(extra: &str) -> Result<Config> {
    Config::from_str(&format!(
        concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "{}"
        ),
        extra
    ))
}

#[test]
fn parses_header_policies_in_both_forms() {
    let config = config_with(concat!(
        "header_policies:\n",
        "  \"trunk-edge-plus@1\":\n",
        "    extends: \"sip-trunk-edge@2026\"\n",
        "    request:\n",
        "      copy: [\"X-Account-Ref\"]\n",
        "      strip: [\"Alert-Info\"]\n",
        "      translate:\n",
        "        Diversion: diversion-to-history-info\n",
        "      rewrite:\n",
        "        P-Asserted-Identity: host-to-advertised\n",
        "    response:\n",
        "      strip: [\"Server\"]\n",
        "  \"locked-down@1\":\n",
        "    request:\n",
        "      default: strip\n",
        "      copy: [\"Allow\", \"Supported\"]\n",
        "    response:\n",
        "      default: copy\n",
        "      strip: [\"P-*\"]\n",
        "b2bua:\n",
        "  default_header_policy: \"trunk-edge-plus@1\"\n",
    ))
    .expect("both policy forms should load");

    assert_eq!(config.header_policies.len(), 2);
    let extended = config
        .header_policies
        .get("trunk-edge-plus@1")
        .expect("policy present");
    assert_eq!(extended.extends.as_deref(), Some("sip-trunk-edge@2026"));
    let request = extended.request.as_ref().expect("request block present");
    assert_eq!(request.copy, vec!["X-Account-Ref".to_string()]);
    assert_eq!(
        request
            .rewrite
            .get("P-Asserted-Identity")
            .map(String::as_str),
        Some("host-to-advertised")
    );

    let standalone = config
        .header_policies
        .get("locked-down@1")
        .expect("policy present");
    assert!(standalone.extends.is_none());
    assert_eq!(
        standalone
            .request
            .as_ref()
            .and_then(|direction| direction.default),
        Some(crate::b2bua::header_policy::DefaultVerb::Strip)
    );

    assert_eq!(
        config.b2bua.resolved_default_header_policy(),
        "trunk-edge-plus@1"
    );
}

#[test]
fn header_policies_default_to_empty() {
    let config = config_with("").expect("config without header_policies should load");
    assert!(config.header_policies.is_empty());
    assert_eq!(
        config.b2bua.resolved_default_header_policy(),
        crate::b2bua::header_policy::DEFAULT_PRESET_NAME
    );
}

#[test]
fn rejects_a_header_policy_that_cannot_compile() {
    // The load-time gate: an op token nobody implements would otherwise
    // surface as a header silently not being rewritten, mid-call.
    let error = config_with(concat!(
        "header_policies:\n",
        "  \"broken@1\":\n",
        "    extends: \"transparent-b2bua@2026\"\n",
        "    request:\n",
        "      rewrite:\n",
        "        P-Asserted-Identity: make-it-nice\n",
    ))
    .expect_err("an unknown rewrite op must refuse to load");
    let message = error.to_string();
    assert!(message.contains("broken@1"), "{message}");
    assert!(message.contains("make-it-nice"), "{message}");
}

#[test]
fn rejects_an_undefined_default_header_policy() {
    // Used to warn and fall back to transparent-b2bua@2026 — the most
    // permissive posture — so a typo opened the boundary it was meant to
    // close, on a node that came up healthy.
    let error = config_with(concat!(
        "b2bua:\n",
        "  default_header_policy: \"trunk-edge-pluss@1\"\n",
    ))
    .expect_err("an undefined default must refuse to load");
    let message = error.to_string();
    assert!(message.contains("trunk-edge-pluss@1"), "{message}");
    assert!(
        message.contains("sip-trunk-edge@2026"),
        "the error should list what is available: {message}"
    );
}

#[test]
fn accepts_a_default_naming_an_operator_defined_policy() {
    let config = config_with(concat!(
        "header_policies:\n",
        "  \"our-trunk@1\":\n",
        "    extends: \"sip-trunk-edge@2026\"\n",
        "b2bua:\n",
        "  default_header_policy: \"our-trunk@1\"\n",
    ))
    .expect("a default naming a custom policy should load");
    assert_eq!(config.b2bua.resolved_default_header_policy(), "our-trunk@1");
}

#[test]
fn accepts_a_default_naming_a_builtin_preset() {
    let config = config_with(concat!(
        "b2bua:\n",
        "  default_header_policy: \"ims-trust-domain-boundary@2026\"\n",
    ))
    .expect("a built-in name should still load");
    assert_eq!(
        config.b2bua.resolved_default_header_policy(),
        "ims-trust-domain-boundary@2026"
    );
}

#[test]
fn parses_media_custom_profiles() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
  profiles:
    srtp_to_srtp:
      offer:
        transport_protocol: "RTP/SAVP"
        ice: "remove"
        replace: ["origin"]
        direction: ["external", "internal"]
      answer:
        transport_protocol: "RTP/SAVP"
        ice: "remove"
        replace: ["origin"]
        direction: ["internal", "external"]
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(media.profiles.len(), 1);
    let profile = media.profiles.get("srtp_to_srtp").unwrap();
    assert_eq!(
        profile.offer.transport_protocol.as_deref(),
        Some("RTP/SAVP")
    );
    assert_eq!(profile.offer.ice.as_deref(), Some("remove"));
    assert!(profile.offer.dtls.is_none());
    assert_eq!(profile.offer.direction, vec!["external", "internal"]);
    assert_eq!(profile.answer.direction, vec!["internal", "external"]);
    // Unset unless the profile asks for a family.
    assert!(profile.offer.address_family.is_none());
    assert!(profile.answer.address_family.is_none());
}

/// A v6 VoLTE access side bridged to a v4 core: the profile used toward the
/// core pins `IP4`.  Accepted case-insensitively with `ipv4`/`ipv6` aliases,
/// always canonicalised to the SDP `addrtype` spelling the engines want.
#[test]
fn parses_media_profile_address_family() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
  profiles:
    v6_access_to_v4_core:
      offer:
        replace: ["origin"]
        address_family: "IP4"
      answer:
        replace: ["origin"]
        address_family: "ipv6"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    let profile = media.profiles.get("v6_access_to_v4_core").unwrap();
    assert_eq!(profile.offer.address_family.as_deref(), Some("IP4"));
    assert_eq!(profile.answer.address_family.as_deref(), Some("IP6"));
}

/// The engines drop an unknown family silently, so a typo has to fail the
/// config load — otherwise it lands as a relay in the wrong family.
#[test]
fn rejects_media_profile_bad_address_family() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
  profiles:
    broken:
      offer:
        address_family: "IP5"
      answer: {}
"#;
    let error = Config::from_str(yaml).expect_err("IP5 must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("address_family"),
        "error should name the field: {message}"
    );
}

// -----------------------------------------------------------------------
// media.sdp_strip_attributes
// -----------------------------------------------------------------------

fn sdp_strip_yaml(media_lines: &str) -> String {
    format!(
        "listen:\n  udp:\n    - \"0.0.0.0:5060\"\ndomain:\n  local:\n    - \"example.com\"\n\
         media:\n  rtpengine:\n    address: \"127.0.0.1:22222\"\n{media_lines}"
    )
}

/// Unset or empty, nothing is stripped and the relay stays byte-identical.
#[test]
fn sdp_strip_attributes_defaults_to_empty() {
    for media_lines in ["", "  sdp_strip_attributes: []\n"] {
        let config = Config::from_str(&sdp_strip_yaml(media_lines)).unwrap();
        assert!(
            config.media.unwrap().sdp_strip_attributes.is_empty(),
            "{media_lines:?}"
        );
    }
}

#[test]
fn parses_sdp_strip_attributes() {
    let config = Config::from_str(&sdp_strip_yaml(
        "  sdp_strip_attributes: [\"msid\", \"X-Vendor-Tag\"]\n",
    ))
    .unwrap();
    // Kept as written: matching is case-insensitive, so there is nothing to
    // normalise, and an operator reading the config back sees their own spelling.
    assert_eq!(
        config.media.unwrap().sdp_strip_attributes,
        vec!["msid".to_string(), "X-Vendor-Tag".to_string()]
    );
}

/// A name that is not an RFC 8866 §9 token can never equal the name on an `a=`
/// line, so the relay would read as scrubbed and strip nothing. Refused at load,
/// with the offending entry named.
#[test]
fn rejects_an_sdp_strip_attribute_that_is_not_an_attribute_name() {
    for bad in ["", "a=msid", "msid:1", "ms id"] {
        let yaml = sdp_strip_yaml(&format!("  sdp_strip_attributes: [\"{bad}\"]\n"));
        let message = Config::from_str(&yaml)
            .expect_err("a non-token attribute name must be refused")
            .to_string();
        assert!(message.contains("sdp_strip_attributes"), "{message}");
        assert!(message.contains(&format!("{bad:?}")), "{message}");
    }
}

// -----------------------------------------------------------------------
// Media profiles: WebSocket bridge / DSP / received_from / rtcp_mux
// -----------------------------------------------------------------------

/// Base config for the WS-profile cases, parameterised on backend + profile
/// body so each test states only what it is about.
fn ws_profile_yaml(backend_block: &str, profile_body: &str) -> String {
    format!(
        "listen:\n  udp:\n    - \"0.0.0.0:5060\"\ndomain:\n  local:\n    \
             - \"example.com\"\nscript:\n  path: \"scripts/proxy_default.py\"\n\
             media:\n{backend_block}  profiles:\n    voice_ai_custom:\n{profile_body}"
    )
}

const SIPHON_RTP_BACKEND: &str =
    "  backend: siphon-rtp\n  siphon_rtp:\n    address: \"127.0.0.1:9000\"\n";
const RTPENGINE_BACKEND: &str = "  rtpengine:\n    address: \"127.0.0.1:22222\"\n";
const RTPPROXY_BACKEND: &str =
    "  backend: rtpproxy\n  rtpproxy:\n    address: \"127.0.0.1:22222\"\n";

#[test]
fn parses_media_profile_websocket_and_dsp_fields() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        replace: [\"origin\"]\n        \
             ws_uri: \"wss://ai.example.com/stream/{call_id}\"\n        \
             ws_vad: true\n        ws_barge_in: true\n        \
             ws_vad_threshold: 2000000\n        ws_vad_hangover_ms: 300\n        \
             noise_suppression: true\n        echo_cancellation: true\n        \
             received_from: true\n        rtcp_mux: [\"require\"]\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
    assert_eq!(
        offer.ws_uri.as_deref(),
        Some("wss://ai.example.com/stream/{call_id}")
    );
    assert!(offer.ws_vad);
    assert!(offer.ws_barge_in);
    assert_eq!(offer.ws_vad_threshold, Some(2_000_000));
    assert_eq!(offer.ws_vad_hangover_ms, Some(300));
    assert!(offer.noise_suppression);
    assert!(offer.echo_cancellation);
    assert!(offer.received_from);
    assert_eq!(offer.rtcp_mux, vec!["require"]);
}

/// Defaults must stay off, so an existing profile emits exactly the command
/// it did before these knobs existed.
#[test]
fn media_profile_websocket_fields_default_off() {
    let yaml = ws_profile_yaml(
        RTPENGINE_BACKEND,
        "      offer:\n        replace: [\"origin\"]\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
    assert!(offer.ws_uri.is_none());
    assert!(!offer.ws_vad);
    assert!(!offer.ws_barge_in);
    assert!(offer.ws_vad_threshold.is_none());
    assert!(offer.ws_vad_hangover_ms.is_none());
    assert!(!offer.noise_suppression);
    assert!(!offer.echo_cancellation);
    assert!(!offer.received_from);
    assert!(offer.rtcp_mux.is_empty());
}

#[test]
fn rejects_media_profile_non_websocket_ws_uri_scheme() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_uri: \"https://ai.example.com/stream\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("https:// must be rejected");
    assert!(
        error.to_string().contains("ws_uri"),
        "error should name the field: {error}"
    );
}

/// The three echo-tuning knobs reach the config, and the search window is
/// carried as a number rather than being flattened into the `flags` list.
///
/// The 600 ms here is deliberately a *long-tail* value above the old 512 ms
/// tail ceiling.  This fixture used to assert that a profile the engine
/// refused on every offer loaded cleanly, which is precisely the mismatch
/// the mode-dependent bounds close.
#[test]
fn parses_media_profile_echo_tuning() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        echo_cancellation: true\n        \
             echo_delay_search_ms: 600\n        echo_long_tail: true\n        \
             echo_residual_suppression: true\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
    assert!(offer.echo_cancellation);
    assert_eq!(offer.echo_delay_search_ms, Some(600));
    assert!(offer.echo_long_tail);
    assert!(offer.echo_residual_suppression);
}

/// Absent means "engine default" for all three, so upgrading the pin does
/// not change what an existing profile asks for.
#[test]
fn media_profile_echo_tuning_defaults_off() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        echo_cancellation: true\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
    assert!(offer.echo_delay_search_ms.is_none());
    assert!(!offer.echo_long_tail);
    assert!(!offer.echo_residual_suppression);
}

/// Out of range is refused at load, in **both** readings of the field. The
/// engine refuses it too, but only per offer — which is a node that boots
/// healthy and then fails every call, so the boot failure is the one worth
/// having.
#[test]
fn rejects_media_profile_echo_delay_search_out_of_range() {
    for long_tail in [false, true] {
        for window in ["15", "1001"] {
            let yaml = ws_profile_yaml(
                SIPHON_RTP_BACKEND,
                &format!(
                    "      offer:\n        echo_cancellation: true\n        \
                         echo_long_tail: {long_tail}\n        \
                         echo_delay_search_ms: {window}\n      answer: {{}}\n"
                ),
            );
            let error = Config::from_str(&yaml)
                .expect_err("a value outside the accepted range must be refused at load");
            assert!(
                error.to_string().contains("echo_delay_search_ms"),
                "error should name the field: {error}"
            );
        }
    }
}

/// The refusal names which reading it applied, because the two bounds are
/// separate and an operator otherwise cannot tell why their value was
/// rejected — the failure this whole check exists to make legible.
#[test]
fn the_echo_delay_search_refusal_names_the_reading_it_applied() {
    let refuse = |long_tail: bool| {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            &format!(
                "      offer:\n        echo_cancellation: true\n        \
                     echo_long_tail: {long_tail}\n        \
                     echo_delay_search_ms: 1001\n      answer: {{}}\n"
            ),
        );
        Config::from_str(&yaml)
            .expect_err("out of range")
            .to_string()
    };
    assert!(refuse(true).contains("tail length"), "{}", refuse(true));
    assert!(refuse(false).contains("search window"), "{}", refuse(false));
}

/// The bounds themselves are accepted — the check is inclusive, so a config
/// sitting exactly on 16 or 1000 is not refused by an off-by-one — and that
/// holds for the tail reading too, which is the one that used to be checked
/// against the wrong number.
#[test]
fn accepts_media_profile_echo_delay_search_at_the_bounds() {
    for long_tail in [false, true] {
        for window in ["16", "1000"] {
            let yaml = ws_profile_yaml(
                SIPHON_RTP_BACKEND,
                &format!(
                    "      offer:\n        echo_cancellation: true\n        \
                         echo_long_tail: {long_tail}\n        \
                         echo_delay_search_ms: {window}\n      answer: {{}}\n"
                ),
            );
            Config::from_str(&yaml).expect("the range bounds must be accepted");
        }
    }
}

/// The validator checks against the engine's own published constants rather
/// than a copy of the digits. Restating them is what let a long-tail profile
/// load, register and report healthy while the engine refused it on every
/// offer, so this pins the source rather than the value.
#[test]
fn the_echo_bounds_come_from_the_engine_contract() {
    assert_eq!(siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MIN, 16);
    assert_eq!(siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MAX, 1_000);
    assert_eq!(siphon_rtp_proto::ECHO_LONG_TAIL_MS_MIN, 16);
    assert_eq!(siphon_rtp_proto::ECHO_LONG_TAIL_MS_MAX, 1_000);
}

/// All three are native siphon-rtp extensions with no NG or rtpproxy
/// equivalent, so a profile that sets them on those backends is refused
/// rather than silently ignored by an engine that never sees them.
#[test]
fn rejects_echo_tuning_on_backends_that_cannot_express_it() {
    for backend in [RTPENGINE_BACKEND, RTPPROXY_BACKEND] {
        for (field, value) in [
            ("echo_delay_search_ms", "600"),
            ("echo_long_tail", "true"),
            ("echo_residual_suppression", "true"),
        ] {
            let yaml = ws_profile_yaml(
                backend,
                &format!("      offer:\n        {field}: {value}\n      answer: {{}}\n"),
            );
            let error = Config::from_str(&yaml)
                .expect_err("a native-only field must be refused on this backend");
            assert!(
                error.to_string().contains(field),
                "error should name {field}: {error}"
            );
        }
    }
}

#[test]
fn rejects_media_profile_bad_rtcp_mux_token() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        rtcp_mux: [\"mux-please\"]\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("unknown token must be rejected");
    assert!(
        error.to_string().contains("rtcp_mux"),
        "error should name the field: {error}"
    );
}

#[test]
fn accepts_media_profile_rtcp_mux_case_insensitively() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        rtcp_mux: [\"OFFER\", \" Require \"]\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(
        media
            .profiles
            .get("voice_ai_custom")
            .unwrap()
            .offer
            .rtcp_mux,
        vec!["offer", "require"]
    );
}

/// A `ws_uri` the engine never receives means the leg is answered and bridged
/// nowhere — silence for the call's whole duration.  So it fails the load
/// rather than warning, unlike `address_family` on rtpproxy (which only
/// loses IPv4/IPv6 interworking on an otherwise working call).
#[test]
fn rejects_websocket_profile_on_rtpengine_backend() {
    let yaml = ws_profile_yaml(
        RTPENGINE_BACKEND,
        "      offer:\n        ws_uri: \"wss://ai.example.com/stream\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("ws_uri on rtpengine must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("ws_uri") && message.contains("rtpengine"),
        "error should name the field and the backend: {message}"
    );
    assert!(
        message.contains("voice_ai_custom"),
        "error should name the profile: {message}"
    );
}

#[test]
fn parses_media_profile_websocket_tee_fields() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_tee: \"wss://asr.example.com/{call_id}\"\n        \
             ws_tee_direction: \"callee\"\n        ws_tee_channels: 1\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
    assert_eq!(
        offer.ws_tee.as_deref(),
        Some("wss://asr.example.com/{call_id}")
    );
    assert_eq!(offer.ws_tee_direction, Some(WsTeeDirection::Callee));
    assert_eq!(offer.ws_tee_channels, Some(1));
}

/// A profile that does not ask for a tee must stay byte-identical on the
/// wire to what it emitted before these knobs existed.
#[test]
fn media_profile_websocket_tee_fields_default_off() {
    let yaml = ws_profile_yaml(
        RTPENGINE_BACKEND,
        "      offer:\n        replace: [\"origin\"]\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
    assert!(offer.ws_tee.is_none());
    assert!(offer.ws_tee_direction.is_none());
    assert!(offer.ws_tee_channels.is_none());
}

#[test]
fn accepts_media_profile_ws_tee_direction_case_insensitively() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n        \
             ws_tee_direction: \" Caller \"\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.unwrap();
    assert_eq!(
        media
            .profiles
            .get("voice_ai_custom")
            .unwrap()
            .offer
            .ws_tee_direction,
        Some(WsTeeDirection::Caller)
    );
}

/// The six fields added with the 0.3.0 media contract must parse on the
/// native backend and land on the profile.
#[test]
fn parses_media_profile_beep_and_vad_engine_fields() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_uri: \"wss://ai.example.com/s\"\n        \
             ws_vad: true\n        ws_sample_rate: 16000\n        \
             ws_vad_engine: \"neural\"\n        ws_vad_min_speech_ms: 80\n        \
             beep_detection: true\n        beep_cadence_guard_ms: 3000\n        \
             ws_tee: \"wss://asr.example.com/t\"\n        \
             ws_tee_sample_rate: 48000\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).unwrap();
    let media = config.media.expect("media block");
    let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;

    assert_eq!(offer.ws_sample_rate, Some(16_000));
    assert_eq!(offer.ws_vad_engine, Some(WsVadEngine::Neural));
    assert_eq!(offer.ws_vad_min_speech_ms, Some(80));
    assert!(offer.beep_detection);
    assert_eq!(offer.beep_cadence_guard_ms, Some(3_000));
    assert_eq!(offer.ws_tee_sample_rate, Some(48_000));
}

/// A backend nothing dispatches to has to refuse at boot. Each of these
/// used to load clean and then fail at the first request instead: the
/// registrar one behaved as `memory` (bindings silently not persisted), the
/// auth ones returned `Unavailable` for every credential check (nobody
/// could register).
/// Minimal loadable config plus whatever the case is actually about.
fn backend_yaml(block: &str) -> String {
    format!(
        "listen:\n  udp:\n    - \"0.0.0.0:5060\"\ndomain:\n  local:\n    \
             - \"example.com\"\nscript:\n  path: \"scripts/proxy_default.py\"\n{block}"
    )
}

// -----------------------------------------------------------------------
// CDR sinks
// -----------------------------------------------------------------------

/// The single form is what every existing deployment has written, so it has
/// to keep meaning exactly one sink of exactly that kind.
#[test]
fn cdr_single_backend_form_is_one_sink() {
    let config = Config::from_str(&backend_yaml(
        "cdr:\n  enabled: true\n  backend: http\n  http:\n    url: \"https://collector.example/cdr\"\n",
    ))
    .expect("the single form must load");
    let runtime = config.cdr.as_ref().expect("cdr block").to_cdr_config();
    assert_eq!(runtime.backends.len(), 1);
    match &runtime.backends[0] {
        crate::cdr::CdrBackendType::Http { url, .. } => {
            assert_eq!(url, "https://collector.example/cdr")
        }
        other => panic!("expected the http sink, got {other:?}"),
    }
    // The single-sink field still reads true for a consumer that looks at it.
    assert!(matches!(
        runtime.backend,
        crate::cdr::CdrBackendType::Http { .. }
    ));
}

/// The list form is the point: a durable file beside a collector.
#[test]
fn cdr_backends_list_form_parses_every_sink() {
    let config = Config::from_str(&backend_yaml(
        "cdr:\n  enabled: true\n  backends:\n    - type: file\n      path: /var/log/siphon/cdr.jsonl\n    \
             - type: http\n      url: \"https://collector.example/cdr\"\n      auth_header: \"Bearer t\"\n",
    ))
    .expect("the list form must load");
    let runtime = config.cdr.as_ref().expect("cdr block").to_cdr_config();
    assert_eq!(runtime.backends.len(), 2, "both sinks are kept");
    assert!(matches!(
        runtime.backends[0],
        crate::cdr::CdrBackendType::File { .. }
    ));
    match &runtime.backends[1] {
        crate::cdr::CdrBackendType::Http { url, auth_header } => {
            assert_eq!(url, "https://collector.example/cdr");
            assert_eq!(auth_header.as_deref(), Some("Bearer t"));
        }
        other => panic!("expected the http sink, got {other:?}"),
    }
}

/// Two spellings of the same setting: guessing would send records somewhere
/// the operator did not intend, so it is a load error naming both keys.
#[test]
fn rejects_cdr_backend_and_backends_together() {
    let error = Config::from_str(&backend_yaml(
        "cdr:\n  enabled: true\n  backend: file\n  backends:\n    - type: syslog\n      \
             target: \"192.0.2.9:514\"\n",
    ))
    .expect_err("naming the sinks twice must be refused");
    let message = error.to_string();
    assert!(
        message.contains("backend") && message.contains("backends"),
        "the error should name both keys: {message}"
    );
}

/// A `cdr` block with neither key is the historical default: one file sink.
#[test]
fn cdr_with_no_backend_named_is_the_file_sink() {
    let config = Config::from_str(&backend_yaml("cdr:\n  enabled: true\n"))
        .expect("a cdr block with no backend must load");
    let runtime = config.cdr.as_ref().expect("cdr block").to_cdr_config();
    assert_eq!(runtime.backends.len(), 1);
    assert!(matches!(
        runtime.backends[0],
        crate::cdr::CdrBackendType::File { .. }
    ));
}

/// A typo in `events` is silent: `events` is read at start-up, not asked
/// for at run time, so the app subscribes to nothing and waits for events
/// that never come with no reply to carry the mistake back.
#[test]
fn rejects_an_unknown_control_app_event_class() {
    let error = Config::from_str(&backend_yaml(
        "control:\n  apps:\n    - name: pbx\n      token: \"t\"\n      events: [registrations]\n",
    ))
    .expect_err("an unknown event class must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("registrations") && message.contains("registration"),
        "the error should name the typo and the class that exists: {message}"
    );
}

/// The class that exists loads, and the default is no app-level events at
/// all — an app that only places calls must not be handed a registration
/// storm it never asked for.
#[test]
fn control_app_events_are_opt_in() {
    let config = Config::from_str(&backend_yaml(
        "control:\n  apps:\n    - name: pbx\n      token: \"t\"\n      events: [registration]\n",
    ))
    .expect("a known event class must load");
    let apps = &config.control.as_ref().expect("control block").apps;
    assert_eq!(apps[0].events, vec!["registration".to_string()]);

    let config = Config::from_str(&backend_yaml(
        "control:\n  apps:\n    - name: pbx\n      token: \"t\"\n",
    ))
    .expect("an app with no events must load");
    assert!(
        config.control.as_ref().expect("control block").apps[0]
            .events
            .is_empty(),
        "app-level events are opt-in"
    );
}

/// `fallback` parsed and then behaved as `hangup`, so an operator who set
/// it to keep calls alive when a controller dies got exactly the opposite,
/// on every call, with nothing saying so.
#[test]
fn rejects_an_unimplemented_control_loss_policy() {
    let error = Config::from_str(&backend_yaml(
        "control:\n  apps:\n    - name: pbx\n      token: \"t\"\n      on_lost: fallback\n",
    ))
    .expect_err("an unimplemented on_lost must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("on_lost") && message.contains("fallback"),
        "the error should name the setting and the value: {message}"
    );
    assert!(
        message.contains("hangup") && message.contains("continue"),
        "and the policies that do exist: {message}"
    );
}

/// The two that are implemented still load.
#[test]
fn accepts_the_implemented_control_loss_policies() {
    for policy in ["hangup", "continue"] {
        Config::from_str(&backend_yaml(&format!(
            "control:\n  apps:\n    - name: pbx\n      token: \"t\"\n      on_lost: {policy}\n"
        )))
        .unwrap_or_else(|error| panic!("on_lost: {policy} must load: {error}"));
    }
}

// -----------------------------------------------------------------------
// control.inbound — script-free handover
// -----------------------------------------------------------------------

fn control_inbound_yaml(block: &str) -> String {
    backend_yaml(&format!("control:\n  listen: \"127.0.0.1:9092\"\n{block}"))
}

/// Naming an app nothing serves would hand every inbound call to something
/// that cannot connect, so every call would end on the handoff default.
/// A box that boots and answers every call with its timeout default is
/// worse than one that refuses to start.
#[test]
fn rejects_control_inbound_naming_an_unknown_app() {
    let error = Config::from_str(&control_inbound_yaml(
        "  apps:\n    - name: pbx\n      token: \"t\"\n  inbound:\n    app: typo\n",
    ))
    .expect_err("an unknown inbound app must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("control.inbound.app") && message.contains("pbx"),
        "the error should name the setting and the apps that do exist: {message}"
    );
}

/// A mode that is neither of the two would otherwise fall back silently to
/// deferred, which is the opposite of what someone writing `answer` meant.
#[test]
fn rejects_control_inbound_with_an_unknown_mode() {
    let error = Config::from_str(&control_inbound_yaml(
        "  apps:\n    - name: pbx\n      token: \"t\"\n  inbound:\n    app: pbx\n    \
             mode: answer-first\n",
    ))
    .expect_err("an unknown mode must be rejected");
    assert!(
        error.to_string().contains("control.inbound.mode"),
        "the error should name the setting: {error}"
    );
}

/// The happy path, and the default mode.
#[test]
fn accepts_control_inbound_naming_a_configured_app() {
    let config = Config::from_str(&control_inbound_yaml(
        "  apps:\n    - name: pbx\n      token: \"t\"\n  inbound:\n    app: pbx\n",
    ))
    .expect("a configured app must load");
    let inbound = config
        .control
        .as_ref()
        .and_then(|control| control.inbound.as_ref())
        .expect("the inbound block should parse");
    assert_eq!(inbound.app, "pbx");
    assert!(
        !inbound.answer_first(),
        "the default holds the INVITE unanswered"
    );
}

/// `mode: answer` is what answers and anchors before handing over.
#[test]
fn control_inbound_answer_mode_answers_first() {
    let config = Config::from_str(&control_inbound_yaml(
        "  apps:\n    - name: pbx\n      token: \"t\"\n  inbound:\n    app: pbx\n    \
             mode: answer\n",
    ))
    .expect("answer mode must load");
    assert!(config
        .control
        .as_ref()
        .and_then(|control| control.inbound.as_ref())
        .expect("inbound block")
        .answer_first());
}

#[test]
fn rejects_registrar_python_backend() {
    let error = Config::from_str(&backend_yaml("registrar:\n  backend: python\n"))
        .expect_err("python registrar backend must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("registrar.backend: python"),
        "error should name the setting: {message}"
    );
    assert!(
        message.contains("redis") && message.contains("postgres"),
        "error should point at the backends that do persist: {message}"
    );
}

#[test]
fn rejects_undispatched_auth_backends() {
    // The serde name has no underscore; `siphon.yaml` documented
    // `diameter_cx`, which never parsed in the first place.
    let error = Config::from_str(&backend_yaml("auth:\n  backend: diametercx\n"))
        .expect_err("undispatched auth backend must be rejected");
    assert!(
        error.to_string().contains("auth.backend: diameter_cx"),
        "error should name the setting: {error}"
    );
}

// -----------------------------------------------------------------------
// auth.algorithms — the digest challenge set
// -----------------------------------------------------------------------

#[test]
fn auth_algorithms_defaults_to_the_set_siphon_has_always_sent() {
    let config = Config::from_str(&backend_yaml("auth:\n  realm: \"example.com\"\n"))
        .expect("a config without auth.algorithms must load");
    assert_eq!(config.auth.algorithms, ["MD5", "SHA-256", "SHA-512-256"]);
}

#[test]
fn auth_algorithms_takes_a_narrowed_set_in_the_configured_order() {
    let config = Config::from_str(&backend_yaml(
        "auth:\n  realm: \"example.com\"\n  algorithms: [\"SHA-256\", \"MD5\"]\n",
    ))
    .expect("a narrowed set must load");
    assert_eq!(config.auth.algorithms, ["SHA-256", "MD5"]);
}

/// A name siphon cannot challenge with is refused, not skipped: a silently
/// dropped entry is a challenge set the operator did not choose, and the
/// difference is invisible until a client population stops registering.
#[test]
fn rejects_an_unknown_auth_algorithm_naming_it() {
    let error = Config::from_str(&backend_yaml(
        "auth:\n  realm: \"example.com\"\n  algorithms: [\"MD5\", \"SHA-3\"]\n",
    ))
    .expect_err("an unknown algorithm must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("SHA-3"),
        "error should name the offending entry: {message}"
    );
    assert!(
        message.contains("SHA-512-256"),
        "error should list what is accepted: {message}"
    );
}

/// AKA is network-selected and its challenge carries the AKA nonce plus
/// ck=/ik=, so it cannot be one entry in an RFC 7616 negotiation. Accepting it
/// here would emit a challenge with no auth vector behind it.
#[test]
fn rejects_aka_in_the_auth_algorithm_list_and_points_at_the_right_call() {
    let error = Config::from_str(&backend_yaml(
        "auth:\n  realm: \"example.com\"\n  algorithms: [\"AKAv1-MD5\"]\n",
    ))
    .expect_err("AKAv1-MD5 must be rejected here");
    let message = error.to_string();
    assert!(
        message.contains("AKAv1-MD5"),
        "error should name the offending entry: {message}"
    );
    assert!(
        message.contains("require_aka_digest") && message.contains("require_ims_digest"),
        "error should point at the calls that do build an AKA challenge: {message}"
    );
}

/// An empty list would emit a 401 carrying no `WWW-Authenticate` at all, which
/// a client reads as a malformed response rather than as "try again".
#[test]
fn rejects_an_empty_auth_algorithm_list() {
    let error = Config::from_str(&backend_yaml(
        "auth:\n  realm: \"example.com\"\n  algorithms: []\n",
    ))
    .expect_err("an empty challenge set must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("auth.algorithms is empty"),
        "error should name the setting: {message}"
    );
}

/// `backend: database` with no `auth.database` block has no credential
/// source, so every digest check would come back `Unavailable` and nobody
/// could register. A box that boots healthy and rejects every REGISTER is
/// worse than one that refuses to start.
#[test]
fn rejects_database_auth_without_a_source() {
    let error = Config::from_str(&backend_yaml("auth:\n  backend: database\n"))
        .expect_err("database auth with no source must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("auth.database"),
        "error should name the missing block: {message}"
    );
}

/// A query that never binds `$1` returns the same row for every subscriber,
/// which authenticates all of them against one credential.
#[test]
fn rejects_database_auth_query_that_ignores_the_username() {
    let error = Config::from_str(&backend_yaml(
        "auth:\n  backend: database\n  database:\n    url: \"postgresql://db/siphon\"\n    \
             query: \"SELECT password FROM subscribers LIMIT 1\"\n",
    ))
    .expect_err("a query that ignores the username must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("$1"),
        "error should say which parameter is missing: {message}"
    );
}

/// The happy path: a source with a username-bound query loads, and the
/// defaults fill in.
#[test]
fn accepts_database_auth_with_a_source() {
    let config = Config::from_str(&backend_yaml(
        "auth:\n  backend: database\n  database:\n    url: \"postgresql://db/siphon\"\n",
    ))
    .expect("database auth with a source must load");
    let database = config
        .auth
        .database
        .as_ref()
        .expect("the database block should be parsed");
    assert!(
        database.query.contains("$1"),
        "the default query must bind the username: {}",
        database.query
    );
    assert!(!database.ha1, "default is a plaintext password column");
    assert_eq!(database.cache_ttl_secs, 0, "caching is opt-in");
}

#[test]
fn accepts_the_dispatchable_backends() {
    for block in [
        "registrar:\n  backend: memory\n",
        "auth:\n  backend: static\n",
        "auth:\n  backend: http\n",
    ] {
        let yaml = backend_yaml(block);
        Config::from_str(&yaml)
            .unwrap_or_else(|error| panic!("dispatchable backend must load: {block:?} -> {error}"));
    }
}

/// `ws_vad_engine` is a closed selector: an unknown detector must be a hard
/// config error, never a quiet fall back to the detector the operator was
/// explicitly avoiding.
#[test]
fn rejects_media_profile_bad_ws_vad_engine() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_vad_engine: \"telepathy\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("unknown detector must be rejected");
    assert!(
        error.to_string().contains("ws_vad_engine"),
        "error should name the field: {error}"
    );
}

/// The engine *fails* an offer carrying an out-of-range wire rate rather
/// than clamping it, so a bad value must be caught at boot — otherwise the
/// box comes up healthy and every call answers with no media.
#[test]
fn rejects_media_profile_bad_ws_sample_rates() {
    for (field, value) in [
        ("ws_sample_rate", "44100"), // not a whole kHz
        ("ws_sample_rate", "4000"),  // below the floor
        ("ws_sample_rate", "96000"), // above the ceiling
        ("ws_tee_sample_rate", "12345"),
        ("ws_tee_sample_rate", "0"),
    ] {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            &format!("      offer:\n        {field}: {value}\n      answer: {{}}\n"),
        );
        let error = Config::from_str(&yaml).expect_err("{field}={value} must be rejected");
        assert!(
            error.to_string().contains(field),
            "error should name {field}: {error}"
        );
    }
}

/// The boundary values must be accepted — a validator that is merely strict
/// is as wrong as one that is merely lax.
#[test]
fn accepts_media_profile_boundary_ws_sample_rates() {
    for value in ["8000", "48000", "16000"] {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            &format!("      offer:\n        ws_sample_rate: {value}\n      answer: {{}}\n"),
        );
        Config::from_str(&yaml).unwrap_or_else(|error| panic!("{value} Hz rejected: {error}"));
    }
}

/// All six are native `siphon-rtp` extensions.  On any other backend the
/// engine never sees them, so the call answers into a media path that was
/// never wired — a hard config error, not a warning.
#[test]
fn rejects_new_media_fields_on_non_native_backends() {
    for field_line in [
        "ws_sample_rate: 16000",
        "ws_vad_engine: \"neural\"",
        "ws_vad_min_speech_ms: 80",
        "beep_detection: true",
        "beep_cadence_guard_ms: 3000",
        "ws_tee_sample_rate: 16000",
    ] {
        let field = field_line.split(':').next().expect("field name");
        for backend in [RTPENGINE_BACKEND, RTPPROXY_BACKEND] {
            let yaml = ws_profile_yaml(
                backend,
                &format!("      offer:\n        {field_line}\n      answer: {{}}\n"),
            );
            let error = Config::from_str(&yaml)
                .err()
                .unwrap_or_else(|| panic!("{field} must be rejected on backend block {backend:?}"))
                .to_string();
            assert!(
                error.contains(field),
                "error should name {field} on {backend:?}: {error}"
            );
        }

        // ...and must be accepted on the native backend, so the gate is
        // proven to be backend-specific rather than a blanket refusal.
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            &format!("      offer:\n        {field_line}\n      answer: {{}}\n"),
        );
        Config::from_str(&yaml)
            .unwrap_or_else(|error| panic!("{field} rejected on siphon-rtp: {error}"));
    }
}

#[test]
fn rejects_media_profile_bad_ws_tee_direction() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n        \
             ws_tee_direction: \"send\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("unknown direction must be rejected");
    assert!(
        error.to_string().contains("ws_tee_direction"),
        "error should name the field: {error}"
    );
}

#[test]
fn rejects_media_profile_non_websocket_ws_tee_scheme() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_tee: \"https://asr.example.com/s\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("https:// must be rejected");
    assert!(
        error.to_string().contains("ws_tee"),
        "error should name the field: {error}"
    );
}

/// Same reasoning as `ws_uri`: a tee the engine never receives streams
/// nothing, so the consumer sits silent on a call that looks healthy.
#[test]
fn rejects_websocket_tee_profile_on_rtpengine_backend() {
    let yaml = ws_profile_yaml(
        RTPENGINE_BACKEND,
        "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("ws_tee on rtpengine must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("ws_tee") && message.contains("rtpengine"),
        "error should name the field and the backend: {message}"
    );
    assert!(
        message.contains("voice_ai_custom"),
        "error should name the profile: {message}"
    );
}

#[test]
fn rejects_websocket_tee_profile_on_rtpproxy_backend() {
    let yaml = ws_profile_yaml(
        RTPPROXY_BACKEND,
        "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("ws_tee on rtpproxy must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("ws_tee") && message.contains("rtpproxy"),
        "error should name the field and the backend: {message}"
    );
}

#[test]
fn rejects_dsp_profile_on_rtpproxy_backend() {
    let yaml = ws_profile_yaml(
        RTPPROXY_BACKEND,
        "      offer:\n        noise_suppression: true\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("noise_suppression must be rejected");
    assert!(
        error.to_string().contains("noise_suppression"),
        "error should name the field: {error}"
    );
}

/// The answer direction is checked too — a profile is only half-validated if
/// only its offer flags are.
#[test]
fn rejects_websocket_profile_set_on_answer_direction_only() {
    let yaml = ws_profile_yaml(
        RTPENGINE_BACKEND,
        "      offer: {}\n      answer:\n        ws_barge_in: true\n",
    );
    let error = Config::from_str(&yaml).expect_err("answer-side ws_barge_in must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("ws_barge_in") && message.contains("answer"),
        "error should name the field and direction: {message}"
    );
}

/// `received_from` and `rtcp_mux` are real rtpengine NG keys, so only
/// rtpproxy rejects them.
#[test]
fn accepts_received_from_and_rtcp_mux_on_rtpengine_backend() {
    let yaml = ws_profile_yaml(
        RTPENGINE_BACKEND,
        "      offer:\n        received_from: true\n        \
             rtcp_mux: [\"require\"]\n      answer: {}\n",
    );
    let config = Config::from_str(&yaml).expect("rtpengine honours both");
    let media = config.media.unwrap();
    assert!(
        media
            .profiles
            .get("voice_ai_custom")
            .unwrap()
            .offer
            .received_from
    );
}

#[test]
fn rejects_received_from_on_rtpproxy_backend() {
    let yaml = ws_profile_yaml(
        RTPPROXY_BACKEND,
        "      offer:\n        received_from: true\n      answer: {}\n",
    );
    let error = Config::from_str(&yaml).expect_err("rtpproxy cannot gate on received_from");
    assert!(
        error.to_string().contains("received_from"),
        "error should name the field: {error}"
    );
}

#[test]
fn accepts_websocket_profile_on_siphon_rtp_backend() {
    let yaml = ws_profile_yaml(
        SIPHON_RTP_BACKEND,
        "      offer:\n        ws_uri: \"wss://ai.example.com/stream\"\n        \
             noise_suppression: true\n      answer: {}\n",
    );
    Config::from_str(&yaml).expect("siphon-rtp honours the WS bridge");
}

/// The check must not fire on a config with no `media` block at all.
#[test]
fn media_profile_validation_skips_config_without_media() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert!(config.media.is_none());
}

#[test]
fn unsupported_profile_fields_is_empty_for_plain_profile() {
    let plain = NgFlagsConfig {
        replace: vec!["origin".into()],
        ..NgFlagsConfig::default()
    };
    for backend in [
        MediaBackendKind::Rtpengine,
        MediaBackendKind::SiphonRtp,
        MediaBackendKind::Rtpproxy,
    ] {
        assert!(
            backend.unsupported_profile_fields(&plain).is_empty(),
            "{} rejected a plain profile",
            backend.as_str()
        );
    }
}

/// `text_events` drives the engine's RFC 4103 text processor, which only
/// siphon-rtp has.  It must be a hard config error on the other two rather
/// than a silent no-op: a script waiting on `@rtpengine.on_text` for events
/// that can never arrive looks identical to a caller who typed nothing.
#[test]
fn unsupported_profile_fields_rejects_text_events_off_siphon_rtp() {
    let flags = NgFlagsConfig {
        text_events: true,
        ..NgFlagsConfig::default()
    };
    for backend in [MediaBackendKind::Rtpengine, MediaBackendKind::Rtpproxy] {
        assert!(
            backend
                .unsupported_profile_fields(&flags)
                .contains(&"text_events"),
            "{} accepted text_events it cannot honour",
            backend.as_str()
        );
    }
    assert!(
        MediaBackendKind::SiphonRtp
            .unsupported_profile_fields(&flags)
            .is_empty(),
        "siphon-rtp rejected text_events it supports"
    );
}

#[test]
fn parses_media_no_profiles_defaults_to_empty() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
"#;
    let config = Config::from_str(yaml).unwrap();
    let media = config.media.unwrap();
    assert!(media.profiles.is_empty());
}

#[test]
fn parses_gateway_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
gateway:
  groups:
    - name: "carriers"
      algorithm: weighted
      probe:
        enabled: true
        interval_secs: 15
        failure_threshold: 5
      destinations:
        - uri: "sip:gw1.carrier.com:5060"
          address: "10.0.0.1:5060"
          weight: 3
          priority: 1
          attrs:
            region: "us-east"
        - uri: "sip:gw2.carrier.com:5060"
          address: "10.0.0.2:5060"
          transport: "tcp"
          weight: 1
          priority: 2
    - name: "sbc-pool"
      algorithm: hash
      destinations:
        - uri: "sip:sbc1.example.com:5060"
          address: "10.1.0.1:5060"
"#;
    let config = Config::from_str(yaml).unwrap();
    let disp = config.gateway.unwrap();
    assert_eq!(disp.groups.len(), 2);

    let group1 = &disp.groups[0];
    assert_eq!(group1.name, "carriers");
    assert_eq!(group1.algorithm, "weighted");
    assert!(group1.probe.enabled);
    assert_eq!(group1.probe.interval_secs, 15);
    assert_eq!(group1.probe.failure_threshold, 5);
    assert_eq!(group1.destinations.len(), 2);
    assert_eq!(group1.destinations[0].uri, "sip:gw1.carrier.com:5060");
    assert_eq!(group1.destinations[0].weight, 3);
    assert_eq!(group1.destinations[0].transport, None); // omitted
    assert_eq!(group1.destinations[0].effective_transport(), "udp"); // default
    assert_eq!(
        group1.destinations[0].attrs.get("region").unwrap(),
        "us-east"
    );
    assert_eq!(group1.destinations[1].transport, Some("tcp".to_string()));
    assert_eq!(group1.destinations[1].priority, 2);

    let group2 = &disp.groups[1];
    assert_eq!(group2.name, "sbc-pool");
    assert_eq!(group2.algorithm, "hash");
    assert_eq!(group2.destinations[0].weight, 1); // default
    assert_eq!(group2.destinations[0].priority, 1); // default
}

#[test]
fn parses_b2bua_max_call_duration() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
b2bua:
  max_call_duration_secs: 14400
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.b2bua.max_call_duration_secs, Some(14400));
    assert_eq!(config.b2bua.resolved_max_call_duration_secs(), Some(14400));
}

#[test]
fn max_call_duration_absent_or_zero_is_uncapped() {
    // Absent is the historical behaviour (an answered call is bounded only
    // by a peer BYE or the session timer). An explicit 0 is how an operator
    // writes "no limit" down, and must mean the same thing as leaving it
    // out — it is also the per-call `max_duration=0` opt-out's value.
    let base = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let absent = Config::from_str(base).unwrap();
    assert_eq!(absent.b2bua.max_call_duration_secs, None);
    assert_eq!(absent.b2bua.resolved_max_call_duration_secs(), None);

    let zero = Config::from_str(&format!("{base}b2bua:\n  max_call_duration_secs: 0\n")).unwrap();
    assert_eq!(zero.b2bua.resolved_max_call_duration_secs(), None);
}

#[test]
fn parses_session_timer_config() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer:
  session_expires: 1800
  min_se: 90
  refresher: uac
  enabled: true
"#;
    let config = Config::from_str(yaml).unwrap();
    let timer = config.session_timer.unwrap();
    assert_eq!(timer.session_expires, 1800);
    assert_eq!(timer.min_se, 90);
    assert_eq!(timer.refresher, SessionRefresher::Uac);
    assert!(timer.enabled);
}

#[test]
fn parses_session_timer_defaults() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer: {}
"#;
    let config = Config::from_str(yaml).unwrap();
    let timer = config.session_timer.unwrap();
    assert_eq!(timer.session_expires, 1800);
    assert_eq!(timer.min_se, 90);
    assert_eq!(timer.refresher, SessionRefresher::Uac);
    assert!(timer.enabled);
}

#[test]
fn session_timer_absent_when_not_configured() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.session_timer.is_none());
}

#[test]
fn parses_session_timer_refresher_variants() {
    for (variant, expected) in [
        ("uac", SessionRefresher::Uac),
        ("uas", SessionRefresher::Uas),
    ] {
        let yaml = format!(
            r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer:
  refresher: {variant}
"#
        );
        let config = Config::from_str(&yaml).unwrap();
        assert_eq!(config.session_timer.unwrap().refresher, expected);
    }
}

#[test]
fn parses_cdr_file_config() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "cdr:\n",
        "  enabled: true\n",
        "  include_register: true\n",
        "  channel_size: 5000\n",
        "  backend: file\n",
        "  file:\n",
        "    path: \"/tmp/cdr.jsonl\"\n",
        "    rotate_size_mb: 50\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let cdr = config.cdr.unwrap();
    assert!(cdr.enabled);
    assert!(cdr.include_register);
    assert_eq!(cdr.channel_size, 5000);
    assert_eq!(cdr.backend.as_deref(), Some("file"));

    let runtime = cdr.to_cdr_config();
    assert!(runtime.enabled);
    assert!(runtime.include_register);
    assert_eq!(runtime.channel_size, 5000);
    assert!(
        matches!(runtime.backend, crate::cdr::CdrBackendType::File { ref path, rotate_size_mb } if path == "/tmp/cdr.jsonl" && rotate_size_mb == 50)
    );
}

#[test]
fn parses_cdr_http_config() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "cdr:\n",
        "  enabled: true\n",
        "  backend: http\n",
        "  http:\n",
        "    url: \"https://collector.example.com/v1/cdr\"\n",
        "    auth_header: \"Bearer secret\"\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let cdr = config.cdr.unwrap();
    assert_eq!(cdr.backend.as_deref(), Some("http"));

    let runtime = cdr.to_cdr_config();
    assert!(
        matches!(runtime.backend, crate::cdr::CdrBackendType::Http { ref url, ref auth_header } if url == "https://collector.example.com/v1/cdr" && auth_header.as_deref() == Some("Bearer secret"))
    );
}

#[test]
fn parses_cdr_syslog_config() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "cdr:\n",
        "  enabled: true\n",
        "  backend: syslog\n",
        "  syslog:\n",
        "    target: \"10.0.0.5:514\"\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let runtime = config.cdr.unwrap().to_cdr_config();
    assert!(
        matches!(runtime.backend, crate::cdr::CdrBackendType::Syslog { ref target } if target == "10.0.0.5:514")
    );
}

#[test]
fn cdr_absent_when_not_configured() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.cdr.is_none());
}

#[test]
fn parses_lawful_intercept_config() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  audit_log: \"/var/log/siphon/li-audit.log\"\n",
        "  x1:\n",
        "    listen: \"127.0.0.1:8443\"\n",
        "    ne_identifier: \"siphon-ne-1\"\n",
        "    admf_identifier: \"admf-id\"\n",
        "    tls:\n",
        "      certificate: \"/etc/siphon/li/x1.crt\"\n",
        "      private_key: \"/etc/siphon/li/x1.key\"\n",
        "      client_ca: \"/etc/siphon/li/admf-ca.pem\"\n",
        "    admf:\n",
        "      endpoint: \"https://admf.example/X1/ADMF\"\n",
        "      client_certificate: \"/etc/siphon/li/ne.pem\"\n",
        "      client_private_key: \"/etc/siphon/li/ne.key\"\n",
        "      keepalive_secs: 45\n",
        "  x2:\n",
        "    delivery_address: \"10.0.0.50:6543\"\n",
        "    transport: tls\n",
        "    reconnect_interval_secs: 10\n",
        "    channel_size: 5000\n",
        "    tls:\n",
        "      ca_cert: \"/etc/siphon/li/mediation-ca.pem\"\n",
        "  x3:\n",
        "    enabled: true\n",
        "  siprec:\n",
        "    srs_uri: \"sip:srs@recorder.example.com\"\n",
        "    session_copies: 2\n",
        "    transport: tls\n",
        // X3 content delivery is only possible on the native media
        // engine, and the config-load gate enforces that.
        "media:\n",
        "  backend: siphon-rtp\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let li = config.lawful_intercept.unwrap();
    assert!(li.enabled);
    assert_eq!(li.audit_log.unwrap(), "/var/log/siphon/li-audit.log");

    // X1
    let x1 = li.x1.unwrap();
    assert_eq!(x1.listen, "127.0.0.1:8443");
    assert_eq!(x1.ne_identifier, "siphon-ne-1");
    assert_eq!(x1.admf_identifier.as_deref(), Some("admf-id"));
    // The endpoint path and declared schema version default rather than
    // being spelled out in every deployment.
    assert_eq!(x1.path, "/X1/NE");
    assert_eq!(x1.version, crate::li::x1::types::DEFAULT_VERSION);
    assert!(x1.bind_admf_identifier_to_certificate);
    assert_eq!(x1.tls.certificate, "/etc/siphon/li/x1.crt");
    assert_eq!(x1.tls.private_key, "/etc/siphon/li/x1.key");
    assert_eq!(x1.tls.client_ca, "/etc/siphon/li/admf-ca.pem");

    // The network-element-to-ADMF direction.
    let admf = x1.admf.unwrap();
    assert_eq!(admf.endpoint, "https://admf.example/X1/ADMF");
    assert_eq!(admf.client_certificate, "/etc/siphon/li/ne.pem");
    assert_eq!(admf.keepalive_secs, 45);
    assert!(admf.reconcile_on_start);

    // X2
    let x2 = li.x2.unwrap();
    assert_eq!(x2.delivery_address, "10.0.0.50:6543");
    assert_eq!(x2.transport, "tls");
    assert_eq!(x2.reconnect_interval_secs, 10);
    assert_eq!(x2.channel_size, 5000);
    assert_eq!(
        x2.tls.unwrap().ca_cert.unwrap(),
        "/etc/siphon/li/mediation-ca.pem"
    );

    // X3 is a switch and nothing more: the media engine frames the content
    // and delivers it to the destinations provisioned over X1.
    assert!(li.x3.unwrap().enabled);

    // SIPREC
    let siprec = li.siprec.unwrap();
    assert_eq!(siprec.srs_uri, "sip:srs@recorder.example.com");
    assert_eq!(siprec.session_copies, 2);
    assert_eq!(siprec.transport, "tls");
}

#[test]
fn parses_lawful_intercept_defaults() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: false\n",
        "  x2:\n",
        "    delivery_address: \"10.0.0.50:6543\"\n",
        "  x3:\n",
        "    enabled: true\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let li = config.lawful_intercept.unwrap();
    assert!(!li.enabled);
    assert!(li.x1.is_none());
    assert!(li.siprec.is_none());

    let x2 = li.x2.unwrap();
    assert_eq!(x2.transport, "tcp");
    assert_eq!(x2.reconnect_interval_secs, 5);
    assert_eq!(x2.channel_size, 10_000);

    // An empty block is enough to switch content delivery on.
    assert!(li.x3.unwrap().enabled);
}

#[test]
fn lawful_intercept_absent_when_not_configured() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.lawful_intercept.is_none());
}

#[test]
fn parses_diameter_config() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "diameter:\n",
        "  origin_host: \"siphon.ims.example.com\"\n",
        "  origin_realm: \"ims.example.com\"\n",
        "  product_name: \"SIPhon-Test\"\n",
        "  transport: tcp\n",
        "  watchdog_interval: 20\n",
        "  reconnect_delay: 3\n",
        "  peers:\n",
        "    - name: \"hss1\"\n",
        "      host: \"hss1.example.com\"\n",
        "      port: 3868\n",
        "      destination_realm: \"example.com\"\n",
        "    - name: \"hss2\"\n",
        "      host: \"hss2.example.com\"\n",
        "      port: 3869\n",
        "      destination_realm: \"example.com\"\n",
        "      transport: sctp\n",
        "      watchdog_interval: 60\n",
        "    - name: \"ocs1\"\n",
        "      host: \"ocs.example.com\"\n",
        "      destination_realm: \"charging.example.com\"\n",
        "      destination_host: \"ocs-primary.charging.example.com\"\n",
        "  routes:\n",
        "    - application: cx\n",
        "      realm: \"example.com\"\n",
        "      peers: [\"hss1\", \"hss2\"]\n",
        "      algorithm: failover\n",
        "    - application: sh\n",
        "      peers: [\"hss1\"]\n",
        "    - application: ro\n",
        "      peers: [\"ocs1\"]\n",
        "      algorithm: round_robin\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let diameter = config.diameter.unwrap();

    assert_eq!(diameter.origin_host, "siphon.ims.example.com");
    assert_eq!(diameter.origin_realm, "ims.example.com");
    assert_eq!(diameter.product_name.as_deref(), Some("SIPhon-Test"));
    assert_eq!(diameter.transport, "tcp");
    assert_eq!(diameter.watchdog_interval, 20);
    assert_eq!(diameter.reconnect_delay, 3);

    // Peers
    assert_eq!(diameter.peers.len(), 3);
    assert_eq!(diameter.peers[0].name, "hss1");
    assert_eq!(diameter.peers[0].port, 3868);
    assert_eq!(diameter.peers[0].transport, None);
    assert_eq!(diameter.peers[1].name, "hss2");
    assert_eq!(diameter.peers[1].port, 3869);
    assert_eq!(diameter.peers[1].transport.as_deref(), Some("sctp"));
    assert_eq!(diameter.peers[1].watchdog_interval, Some(60));
    assert_eq!(diameter.peers[2].name, "ocs1");
    assert_eq!(
        diameter.peers[2].destination_host.as_deref(),
        Some("ocs-primary.charging.example.com")
    );
    assert_eq!(diameter.peers[2].port, 3868); // default

    // Routes
    assert_eq!(diameter.routes.len(), 3);
    assert_eq!(diameter.routes[0].application, DiameterApplication::Cx);
    assert_eq!(diameter.routes[0].realm.as_deref(), Some("example.com"));
    assert_eq!(diameter.routes[0].peers, vec!["hss1", "hss2"]);
    assert_eq!(diameter.routes[0].algorithm, "failover");
    assert_eq!(diameter.routes[1].application, DiameterApplication::Sh);
    assert!(diameter.routes[1].realm.is_none());
    assert_eq!(diameter.routes[2].application, DiameterApplication::Ro);
    assert_eq!(diameter.routes[2].algorithm, "round_robin");
}

#[test]
fn diameter_to_peer_config_merges_defaults() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "diameter:\n",
        "  origin_host: \"siphon.example.com\"\n",
        "  origin_realm: \"example.com\"\n",
        "  watchdog_interval: 25\n",
        "  reconnect_delay: 7\n",
        "  peers:\n",
        "    - name: \"hss1\"\n",
        "      host: \"hss1.example.com\"\n",
        "      destination_realm: \"example.com\"\n",
        "    - name: \"hss2\"\n",
        "      host: \"hss2.example.com\"\n",
        "      destination_realm: \"example.com\"\n",
        "      watchdog_interval: 60\n",
        "      reconnect_delay: 10\n",
        "  routes:\n",
        "    - application: cx\n",
        "      peers: [\"hss1\", \"hss2\"]\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let diameter = config.diameter.as_ref().unwrap();

    // hss1: inherits parent defaults
    let peer1 = diameter.to_peer_config(&diameter.peers[0], "SIPhon", "1.2.3");
    assert_eq!(peer1.origin_host, "siphon.example.com");
    assert_eq!(peer1.origin_realm, "example.com");
    assert_eq!(peer1.host, "hss1.example.com");
    assert_eq!(peer1.watchdog_interval, 25);
    assert_eq!(peer1.reconnect_delay, 7);
    assert_eq!(peer1.product_name, "SIPhon"); // builder fallback
    assert_eq!(peer1.firmware_revision, 10203); // 1.2.3 → 1*10000+2*100+3

    // hss2: overrides parent defaults
    let peer2 = diameter.to_peer_config(&diameter.peers[1], "SIPhon", "1.2.3");
    assert_eq!(peer2.watchdog_interval, 60);
    assert_eq!(peer2.reconnect_delay, 10);
}

#[test]
fn diameter_to_peer_config_collects_app_ids() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "diameter:\n",
        "  origin_host: \"siphon.example.com\"\n",
        "  origin_realm: \"example.com\"\n",
        "  peers:\n",
        "    - name: \"hss1\"\n",
        "      host: \"hss1.example.com\"\n",
        "      destination_realm: \"example.com\"\n",
        "  routes:\n",
        "    - application: cx\n",
        "      peers: [\"hss1\"]\n",
        "    - application: sh\n",
        "      peers: [\"hss1\"]\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let diameter = config.diameter.as_ref().unwrap();
    let peer_config = diameter.to_peer_config(&diameter.peers[0], "SIPhon", "1.2.3");

    // hss1 is in both Cx and Sh routes — should get both app IDs
    assert_eq!(peer_config.application_ids.len(), 2);
    assert_eq!(
        peer_config.application_ids[0],
        DiameterApplication::Cx.to_app_id()
    );
    assert_eq!(
        peer_config.application_ids[1],
        DiameterApplication::Sh.to_app_id()
    );
}

#[test]
fn diameter_peers_for_application() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "diameter:\n",
        "  origin_host: \"siphon.example.com\"\n",
        "  origin_realm: \"example.com\"\n",
        "  peers:\n",
        "    - name: \"hss1\"\n",
        "      host: \"hss1.example.com\"\n",
        "      destination_realm: \"example.com\"\n",
        "    - name: \"hss2\"\n",
        "      host: \"hss2.example.com\"\n",
        "      destination_realm: \"example.com\"\n",
        "    - name: \"ocs1\"\n",
        "      host: \"ocs.example.com\"\n",
        "      destination_realm: \"charging.example.com\"\n",
        "  routes:\n",
        "    - application: cx\n",
        "      realm: \"example.com\"\n",
        "      peers: [\"hss1\", \"hss2\"]\n",
        "    - application: ro\n",
        "      peers: [\"ocs1\"]\n",
    );
    let config = Config::from_str(yaml).unwrap();
    let diameter = config.diameter.as_ref().unwrap();

    // Cx with matching realm
    let cx_peers = diameter.peers_for_application(&DiameterApplication::Cx, Some("example.com"));
    assert_eq!(cx_peers.len(), 2);
    assert_eq!(cx_peers[0].name, "hss1");
    assert_eq!(cx_peers[1].name, "hss2");

    // Cx with non-matching realm
    let cx_wrong = diameter.peers_for_application(&DiameterApplication::Cx, Some("other.com"));
    assert!(cx_wrong.is_empty());

    // Cx with no realm filter — still matches (route realm is optional filter)
    let cx_any = diameter.peers_for_application(&DiameterApplication::Cx, None);
    assert_eq!(cx_any.len(), 2);

    // Ro — no realm on route
    let ro_peers = diameter.peers_for_application(&DiameterApplication::Ro, None);
    assert_eq!(ro_peers.len(), 1);
    assert_eq!(ro_peers[0].name, "ocs1");

    // Rx — not configured
    let rx_peers = diameter.peers_for_application(&DiameterApplication::Rx, None);
    assert!(rx_peers.is_empty());
}

#[test]
fn diameter_absent_when_not_configured() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.diameter.is_none());
}

#[test]
fn absent_isc_and_sbi() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.isc.is_none());
    assert!(config.sbi.is_none());
}

// -----------------------------------------------------------------------
// Environment variable expansion
// -----------------------------------------------------------------------

#[test]
fn expand_env_var_set() {
    std::env::set_var("SIPHON_TEST_HOST", "10.0.0.1");
    let result = expand_env_vars("host: ${SIPHON_TEST_HOST}");
    assert_eq!(result, "host: 10.0.0.1");
    std::env::remove_var("SIPHON_TEST_HOST");
}

#[test]
fn expand_env_var_unset_no_default() {
    std::env::remove_var("SIPHON_TEST_MISSING");
    let result = expand_env_vars("host: ${SIPHON_TEST_MISSING}");
    assert_eq!(result, "host: ");
}

#[test]
fn expand_env_var_unset_with_default() {
    std::env::remove_var("SIPHON_TEST_MISSING2");
    let result = expand_env_vars("host: ${SIPHON_TEST_MISSING2:-localhost}");
    assert_eq!(result, "host: localhost");
}

#[test]
fn expand_env_var_empty_uses_default() {
    std::env::set_var("SIPHON_TEST_EMPTY", "");
    let result = expand_env_vars("host: ${SIPHON_TEST_EMPTY:-fallback}");
    assert_eq!(result, "host: fallback");
    std::env::remove_var("SIPHON_TEST_EMPTY");
}

#[test]
fn expand_env_var_set_ignores_default() {
    std::env::set_var("SIPHON_TEST_PRIO", "actual");
    let result = expand_env_vars("val: ${SIPHON_TEST_PRIO:-ignored}");
    assert_eq!(result, "val: actual");
    std::env::remove_var("SIPHON_TEST_PRIO");
}

#[test]
fn expand_env_var_multiple() {
    std::env::set_var("SIPHON_TEST_A", "alpha");
    std::env::set_var("SIPHON_TEST_B", "beta");
    let result = expand_env_vars("${SIPHON_TEST_A}:${SIPHON_TEST_B}");
    assert_eq!(result, "alpha:beta");
    std::env::remove_var("SIPHON_TEST_A");
    std::env::remove_var("SIPHON_TEST_B");
}

#[test]
fn expand_env_var_no_placeholders() {
    let input = "listen:\n  udp: \"0.0.0.0:5060\"";
    assert_eq!(expand_env_vars(input), input);
}

#[test]
fn expand_env_var_in_config_parse() {
    std::env::set_var("SIPHON_TEST_DOMAIN", "test.example.com");
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "${SIPHON_TEST_DOMAIN}"
script:
  path: "scripts/proxy_default.py"
registrar:
  enabled: false
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.domain.local[0], "test.example.com");
    std::env::remove_var("SIPHON_TEST_DOMAIN");
}

// --- DSCP / DiffServ tests ---

#[test]
fn parse_dscp_named_values() {
    assert_eq!(parse_dscp("CS0").unwrap(), 0);
    assert_eq!(parse_dscp("BE").unwrap(), 0);
    assert_eq!(parse_dscp("CS1").unwrap(), 8);
    assert_eq!(parse_dscp("AF11").unwrap(), 10);
    assert_eq!(parse_dscp("AF12").unwrap(), 12);
    assert_eq!(parse_dscp("AF13").unwrap(), 14);
    assert_eq!(parse_dscp("CS2").unwrap(), 16);
    assert_eq!(parse_dscp("AF21").unwrap(), 18);
    assert_eq!(parse_dscp("AF22").unwrap(), 20);
    assert_eq!(parse_dscp("AF23").unwrap(), 22);
    assert_eq!(parse_dscp("CS3").unwrap(), 24);
    assert_eq!(parse_dscp("AF31").unwrap(), 26);
    assert_eq!(parse_dscp("AF32").unwrap(), 28);
    assert_eq!(parse_dscp("AF33").unwrap(), 30);
    assert_eq!(parse_dscp("CS4").unwrap(), 32);
    assert_eq!(parse_dscp("AF41").unwrap(), 34);
    assert_eq!(parse_dscp("AF42").unwrap(), 36);
    assert_eq!(parse_dscp("AF43").unwrap(), 38);
    assert_eq!(parse_dscp("CS5").unwrap(), 40);
    assert_eq!(parse_dscp("EF").unwrap(), 46);
    assert_eq!(parse_dscp("CS6").unwrap(), 48);
    assert_eq!(parse_dscp("CS7").unwrap(), 56);
}

#[test]
fn parse_dscp_case_insensitive() {
    assert_eq!(parse_dscp("cs3").unwrap(), 24);
    assert_eq!(parse_dscp("ef").unwrap(), 46);
    assert_eq!(parse_dscp("af41").unwrap(), 34);
    assert_eq!(parse_dscp("Cs3").unwrap(), 24);
}

#[test]
fn parse_dscp_raw_integers() {
    assert_eq!(parse_dscp("0").unwrap(), 0);
    assert_eq!(parse_dscp("24").unwrap(), 24);
    assert_eq!(parse_dscp("46").unwrap(), 46);
    assert_eq!(parse_dscp("63").unwrap(), 63);
}

#[test]
fn parse_dscp_rejects_out_of_range() {
    assert!(parse_dscp("64").is_err());
    assert!(parse_dscp("255").is_err());
}

#[test]
fn parse_dscp_rejects_invalid() {
    assert!(parse_dscp("INVALID").is_err());
    assert!(parse_dscp("CS8").is_err());
    assert!(parse_dscp("").is_err());
}

#[test]
fn udp_recv_buffer_defaults_and_overrides() {
    // Absent → the 1 MiB default.
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert_eq!(config.listen.udp_recv_buffer_bytes, 1024 * 1024);

    // Explicit value wins.
    let yaml = r#"
listen:
  udp_recv_buffer_bytes: 4194304
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.udp_recv_buffer_bytes, 4 * 1024 * 1024);

    // 0 is the documented "leave the kernel default alone" escape hatch.
    let yaml = r#"
listen:
  udp_recv_buffer_bytes: 0
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.udp_recv_buffer_bytes, 0);
}

#[test]
fn dscp_to_tos_conversion() {
    assert_eq!(dscp_to_tos(0), 0); // BE
    assert_eq!(dscp_to_tos(24), 96); // CS3 → signaling
    assert_eq!(dscp_to_tos(46), 184); // EF  → voice media
    assert_eq!(dscp_to_tos(34), 136); // AF41 → video
    assert_eq!(dscp_to_tos(63), 252); // max DSCP
}

#[test]
fn listen_config_defaults_to_cs3() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert_eq!(
        config.listen.dscp,
        Some(24),
        "default DSCP should be CS3 (24)"
    );
}

#[test]
fn listen_config_dscp_from_yaml_string() {
    let yaml = r#"
listen:
  dscp: EF
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.dscp, Some(46));
}

#[test]
fn listen_config_mtu_from_yaml() {
    let yaml = r#"
listen:
  mtu: 1280
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.mtu, Some(1280));
}

#[test]
fn listen_config_mtu_defaults_off() {
    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(
        config.listen.mtu, None,
        "mtu must default to off (no behaviour change on a bump)"
    );
}

#[test]
fn diameter_server_config_parses() {
    let yaml = r#"
listen:
  udp:
    - "127.0.0.1:5099"
domain:
  local:
    - "epc.mnc001.mcc001.3gppnetwork.org"
script:
  path: "examples/diameter_server.py"
diameter:
  listen:
    tcp: "0.0.0.0:3868"
    sctp: "0.0.0.0:3868"
  event_sink:
    backend: file
    file:
      path: "/tmp/diameter.jsonl"
  tenants:
    default:
      identity:
        origin_host: "diam.epc.mnc001.mcc001.3gppnetwork.org"
        origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
      clients:
        - name: mme
          allowed_ips: ["192.0.2.0/24"]
          expected_origin_host: "mme.epc.example.org"
      servers:
        - { name: hss, host: "192.0.2.164", port: 3868, transport: tcp }
"#;
    let config = Config::from_str(yaml).expect("Diameter server config should parse");
    let diameter = config.diameter.expect("diameter section");
    let listen = diameter.listen.expect("listen");
    assert_eq!(listen.tcp.as_deref(), Some("0.0.0.0:3868"));
    assert_eq!(listen.sctp.as_deref(), Some("0.0.0.0:3868"));
    // Flat client-only fields default cleanly when omitted.
    assert!(diameter.origin_host.is_empty());

    let tenant = diameter.tenants.get("default").expect("default tenant");
    assert_eq!(
        tenant.identity.origin_host,
        "diam.epc.mnc001.mcc001.3gppnetwork.org"
    );
    assert_eq!(tenant.clients[0].name, "mme");
    assert_eq!(tenant.clients[0].allowed_ips, vec!["192.0.2.0/24"]);
    assert_eq!(tenant.servers[0].name, "hss");
    assert_eq!(tenant.servers[0].port, 3868);

    let event_sink = diameter.event_sink.expect("event_sink");
    assert_eq!(event_sink.backend, "file");
}

#[test]
fn hss_connect_to_server_config_parses() {
    // An HSS that dials a Diameter server: no listener, a tenant with connect_to.
    let yaml = r#"
listen:
  udp:
    - "127.0.0.1:5099"
domain:
  local:
    - "epc.mnc001.mcc001.3gppnetwork.org"
script:
  path: "examples/hss_s6a.py"
diameter:
  tenants:
    default:
      identity:
        origin_host: "hss.epc.example.org"
        origin_realm: "epc.example.org"
      connect_to:
        - { name: upstream, host: "192.0.2.137", port: 3868, transport: sctp }
"#;
    let config = Config::from_str(yaml).expect("HSS connect_to config should parse");
    let diameter = config.diameter.expect("diameter section");
    assert!(diameter.listen.is_none(), "HSS dials out, no listener");
    let tenant = diameter.tenants.get("default").unwrap();
    assert_eq!(tenant.connect_to.len(), 1);
    assert_eq!(tenant.connect_to[0].name, "upstream");
    assert_eq!(tenant.connect_to[0].transport, "sctp");
}

#[test]
fn example_diameter_server_yaml_loads() {
    // The shipped example must always parse (acceptance artifact).
    let config = Config::from_file("examples/diameter_server.yaml")
        .expect("examples/diameter_server.yaml must parse");
    let diameter = config.diameter.expect("diameter section");
    assert!(diameter.listen.is_some());
    // Flat single-domain shape: no `tenants:` block — the server runs
    // against the implicit "default" tenant synthesized from the flat
    // fields by effective_tenants().
    assert!(diameter.tenants.is_empty());
    assert!(!diameter.origin_host.is_empty());
    assert_eq!(diameter.clients[0].name, "client-a");
    assert_eq!(diameter.servers[0].name, "backend");

    let effective = diameter.effective_tenants();
    let default = effective
        .get("default")
        .expect("synthesized default tenant");
    assert_eq!(default.identity.origin_host, diameter.origin_host);
    assert_eq!(default.identity.origin_realm, diameter.origin_realm);
    assert_eq!(default.clients[0].name, "client-a");
    assert_eq!(default.servers[0].name, "backend");
}

#[test]
fn effective_tenants_prefers_explicit_over_flat() {
    // When `tenants:` is declared, the flat fields are ignored.
    let yaml = r#"
listen:
  udp: ["127.0.0.1:5099"]
domain:
  local: ["example.org"]
script:
  path: "examples/diameter_server.py"
diameter:
  origin_host: "flat.example.org"
  servers:
    - { name: flatbackend, host: "10.0.0.1" }
  tenants:
    alpha:
      identity: { origin_host: "alpha.example.org", origin_realm: "example.org" }
"#;
    let diameter = Config::from_str(yaml).unwrap().diameter.unwrap();
    let effective = diameter.effective_tenants();
    assert!(effective.contains_key("alpha"));
    assert!(!effective.contains_key("default"));
}

#[test]
fn effective_tenants_empty_for_client_only() {
    // Pure client-mode NFs set origin_host (for their CER) but no server
    // fields (clients/servers/connect_to) — they synthesize no tenant.
    let yaml = r#"
listen:
  udp: ["127.0.0.1:5099"]
domain:
  local: ["example.org"]
script:
  path: "examples/diameter_server.py"
diameter:
  origin_host: "client.example.org"
  origin_realm: "example.org"
"#;
    let diameter = Config::from_str(yaml).unwrap().diameter.unwrap();
    assert!(diameter.effective_tenants().is_empty());
}

#[test]
fn listen_config_dscp_from_yaml_integer() {
    let yaml = r#"
listen:
  dscp: 24
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.dscp, Some(24));
}

#[test]
fn listen_entry_per_listener_dscp_override() {
    let yaml = r#"
listen:
  dscp: CS3
  udp:
    - address: "0.0.0.0:5060"
      dscp: EF
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert_eq!(config.listen.dscp, Some(24));
    assert_eq!(config.listen.udp[0].dscp(), Some(46));
}

#[test]
fn listen_entry_parses_the_proxy_protocol_allowlist() {
    let yaml = r#"
listen:
  tls:
    - address: "0.0.0.0:5061"
      proxy_protocol:
        from:
          - "198.51.100.7/32"
          - "192.0.2.0/24"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    let proxy = config.listen.tls[0]
        .proxy_protocol()
        .expect("the allowlist must survive parsing");
    assert_eq!(proxy.from, vec!["198.51.100.7/32", "192.0.2.0/24"]);
}

#[test]
fn proxy_protocol_without_an_allowlist_is_refused() {
    // A header lets its sender claim any source address, so "enabled" without
    // "from whom" is refused rather than defaulted — there is deliberately no
    // fallback to security.trusted_cidrs, which means something else.
    let yaml = r#"
listen:
  tls:
    - address: "0.0.0.0:5061"
      proxy_protocol:
        from: []
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let message = Config::from_str(yaml).expect_err("an empty allowlist must be refused");
    let message = message.to_string();
    assert!(
        message.contains("proxy_protocol.from"),
        "the error must name the key: {message}"
    );
}

#[test]
fn a_proxy_protocol_entry_that_is_not_a_cidr_is_refused() {
    // The trusted_cidrs consumers each drop an unparseable entry silently, so
    // an operator's typo quietly widens or narrows nothing. Not here.
    let yaml = r#"
listen:
  tls:
    - address: "0.0.0.0:5061"
      proxy_protocol:
        from:
          - "198.51.100.7"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let message = Config::from_str(yaml).expect_err("a bare address must be refused");
    let message = message.to_string();
    assert!(
        message.contains("198.51.100.7") && message.contains("/32"),
        "the error must name the entry and show the fix: {message}"
    );
}

#[test]
fn proxy_protocol_on_a_udp_listener_is_refused() {
    // A UDP reply goes to the peer address, so taking the client's from a
    // header would send every answer past the front.
    let yaml = r#"
listen:
  udp:
    - address: "0.0.0.0:5060"
      proxy_protocol:
        from:
          - "198.51.100.7/32"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let message = Config::from_str(yaml).expect_err("proxy_protocol on UDP must be refused");
    let message = message.to_string();
    assert!(
        message.contains("listen.udp") && message.contains("stream"),
        "the error must name the listener and say why: {message}"
    );
}

#[test]
fn a_listener_without_proxy_protocol_has_none() {
    // Off unless configured: a bump must not start honouring a header that
    // lets its sender claim any source address.
    let yaml = r#"
listen:
  tcp:
    - "0.0.0.0:5060"
    - address: "0.0.0.0:5070"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
    let config = Config::from_str(yaml).unwrap();
    assert!(config.listen.tcp[0].proxy_protocol().is_none());
    assert!(config.listen.tcp[1].proxy_protocol().is_none());
}

#[test]
fn listen_entry_plain_has_no_dscp() {
    let entry = ListenEntry::Plain("0.0.0.0:5060".to_string());
    assert_eq!(entry.dscp(), None);
}

// --- GatewayDestConfig::effective_transport tests ---

fn gateway_dest(uri: &str, transport: Option<&str>) -> GatewayDestConfig {
    GatewayDestConfig {
        uri: uri.to_string(),
        address: None,
        transport: transport.map(|s| s.to_string()),
        weight: 1,
        priority: 1,
        attrs: Default::default(),
        auth: None,
        registers: None,
        require_registration: false,
    }
}

#[test]
fn effective_transport_explicit_field_wins() {
    let dest = gateway_dest("sip:gw.example.com;transport=tls", Some("tcp"));
    assert_eq!(dest.effective_transport(), "tcp");
}

#[test]
fn effective_transport_from_uri_tls() {
    let dest = gateway_dest("sip:gw.example.com:5061;transport=tls", None);
    assert_eq!(dest.effective_transport(), "tls");
}

#[test]
fn effective_transport_from_uri_tcp() {
    let dest = gateway_dest("sip:gw.example.com;transport=tcp", None);
    assert_eq!(dest.effective_transport(), "tcp");
}

#[test]
fn effective_transport_case_insensitive() {
    let dest = gateway_dest("sip:gw.example.com;Transport=TLS", None);
    assert_eq!(dest.effective_transport(), "tls");
}

#[test]
fn effective_transport_param_not_last() {
    let dest = gateway_dest("sip:gw.example.com;transport=tcp;lr", None);
    assert_eq!(dest.effective_transport(), "tcp");
}

#[test]
fn effective_transport_defaults_to_udp() {
    let dest = gateway_dest("sip:gw.example.com:5060", None);
    assert_eq!(dest.effective_transport(), "udp");
}

// -----------------------------------------------------------------------
// extensions: section
// -----------------------------------------------------------------------

fn extensions_yaml(extensions_block: &str) -> String {
    format!(
        r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar:
  backend: memory
auth:
  realm: "example.com"
log:
  level: info
  format: pretty
{extensions_block}
"#
    )
}

#[test]
fn extensions_absent_when_unset() {
    let config = Config::from_str(minimal_yaml()).unwrap();
    assert!(config.extensions.is_none());
    assert!(config.extension_path("anything").is_none());
    assert!(config.extension_config("anything").is_none());
}

#[test]
fn extensions_path_form() {
    let yaml = extensions_yaml(
        r#"extensions:
  foo: /etc/siphon/foo.yaml
"#,
    );
    let config = Config::from_str(&yaml).unwrap();
    let path = config
        .extension_path("foo")
        .expect("foo extension should resolve to a path");
    assert_eq!(path, Path::new("/etc/siphon/foo.yaml"));
}

#[test]
fn extensions_inline_form() {
    let yaml = extensions_yaml(
        r#"extensions:
  bar:
    listen: "0.0.0.0:8080"
    workers: 4
"#,
    );
    let config = Config::from_str(&yaml).unwrap();
    // The path accessor returns None for non-string entries.
    assert!(config.extension_path("bar").is_none());

    let value = config
        .extension_config("bar")
        .expect("bar extension should resolve to a value");
    let mapping = value.as_mapping().expect("bar should be a mapping");
    let listen = mapping
        .get(serde_yaml_ng::Value::String("listen".to_owned()))
        .and_then(|v| v.as_str())
        .expect("listen key");
    assert_eq!(listen, "0.0.0.0:8080");
    let workers = mapping
        .get(serde_yaml_ng::Value::String("workers".to_owned()))
        .and_then(|v| v.as_u64())
        .expect("workers key");
    assert_eq!(workers, 4);
}

#[test]
fn extensions_mixed_forms_coexist() {
    let yaml = extensions_yaml(
        r#"extensions:
  foo: /etc/siphon/foo.yaml
  bar:
    key: value
  baz: 42
"#,
    );
    let config = Config::from_str(&yaml).unwrap();
    assert_eq!(
        config.extension_path("foo"),
        Some(Path::new("/etc/siphon/foo.yaml")),
    );
    assert!(config.extension_path("bar").is_none());
    assert!(config.extension_config("bar").is_some());
    // Numeric scalar — neither a path nor an inline mapping.
    assert!(config.extension_path("baz").is_none());
    assert_eq!(
        config.extension_config("baz").and_then(|v| v.as_u64()),
        Some(42),
    );
}

#[test]
fn extensions_unknown_name_returns_none() {
    let yaml = extensions_yaml(
        r#"extensions:
  foo: /etc/siphon/foo.yaml
"#,
    );
    let config = Config::from_str(&yaml).unwrap();
    assert!(config.extension_path("missing").is_none());
    assert!(config.extension_config("missing").is_none());
}

#[test]
fn extensions_preserve_yaml_order() {
    let yaml = extensions_yaml(
        r#"extensions:
  zeta: /a
  alpha: /b
  middle: /c
"#,
    );
    let config = Config::from_str(&yaml).unwrap();
    let extensions = config.extensions.expect("extensions present");
    let names: Vec<&str> = extensions.keys().map(String::as_str).collect();
    assert_eq!(names, vec!["zeta", "alpha", "middle"]);
}
