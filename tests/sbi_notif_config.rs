use siphon::config::SbiYamlConfig;

#[test]
fn sbi_notif_tls_config_defaults_and_pairs() {
    let parse = |yaml: &str| serde_saphyr::from_str::<SbiYamlConfig>(yaml);
    assert!(parse("{}").unwrap().notif_tls.is_none());
    for yaml in [
        "notif_tls: {}",
        "notif_tls: {cert: '', key: '', client_ca: ''}",
    ] {
        let tls = parse(yaml).unwrap().notif_tls.unwrap();
        assert!(tls.cert.is_none() && tls.key.is_none() && tls.client_ca.is_none());
    }
    for yaml in [
        "notif_tls: {cert: cert.pem}",
        "notif_tls: {key: key.pem}",
        "notif_tls: {cert: '', key: key.pem}",
        "notif_tls: {cert: cert.pem, key: ''}",
    ] {
        let error = parse(yaml).unwrap_err().to_string();
        assert!(error.contains("notif_tls.cert") && error.contains("notif_tls.key"));
    }
    for ca in ["", ", client_ca: ''", ", client_ca: ca.pem"] {
        let tls = parse(&format!("notif_tls: {{cert: cert.pem, key: key.pem{ca}}}"))
            .unwrap()
            .notif_tls
            .unwrap();
        assert_eq!(tls.cert.as_deref(), Some("cert.pem"));
        assert_eq!(
            tls.client_ca.as_deref(),
            if ca.contains("ca.pem") {
                Some("ca.pem")
            } else {
                None
            }
        );
    }
    let advertised = parse("notif_uri: https://notif.example.net/sbi/events\nnotif_tls: {cert: cert.pem, key: key.pem}").unwrap();
    assert_eq!(
        advertised.notif_uri.as_deref(),
        Some("https://notif.example.net/sbi/events")
    );
    let expanded = siphon::config::expand_env_vars(
        "notif_tls: {cert: '${SBI_NOTIF_TEST_CERT_UNSET:-}', key: '${SBI_NOTIF_TEST_KEY_UNSET:-}'}",
    );
    assert!(parse(&expanded).unwrap().notif_tls.unwrap().cert.is_none());
}
