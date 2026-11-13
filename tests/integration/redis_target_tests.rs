use siphon::config::{NamedCacheConfig, RedisBackendConfig};

#[test]
fn existing_url_config_still_parses() {
    assert!(serde_saphyr::from_str::<RedisBackendConfig>("url: redis://localhost:6379/2").is_ok());
    assert!(serde_saphyr::from_str::<NamedCacheConfig>(
        "name: data\nurl: redis://localhost:6379/2"
    )
    .is_ok());
}

#[test]
fn sentinel_config_parses_for_registrar_and_cache() {
    let target = "sentinel:\n  addresses: [localhost:26379]\n  master: primary\n  password: data-secret\n  sentinel_password: sentinel-secret\n  db: 2\n";
    assert!(serde_saphyr::from_str::<RedisBackendConfig>(target).is_ok());
    assert!(serde_saphyr::from_str::<NamedCacheConfig>(&format!("name: data\n{target}")).is_ok());
}

#[test]
fn ambiguous_and_invalid_targets_are_rejected() {
    for yaml in [
        "url: redis://localhost:6379\nsentinel: {addresses: [localhost:26379], master: primary}",
        "sentinel: {addresses: [], master: primary}",
        "sentinel: {addresses: [localhost:26379], master: ''}",
        "sentinel: {addresses: [localhost:26379], master: primary, db: -1}",
        "{}",
    ] {
        let error = serde_saphyr::from_str::<RedisBackendConfig>(yaml).unwrap_err();
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn sharded_registrar_accepts_mixed_targets_and_checks_count() {
    let yaml = "shard_count: 2\nurls: [redis://localhost:6379, {sentinel: {addresses: [localhost:26379], master: second}}]";
    let config = serde_saphyr::from_str::<RedisBackendConfig>(yaml).unwrap();
    assert_eq!(config.urls.len(), 2);
    assert!(serde_saphyr::from_str::<RedisBackendConfig>(
        &yaml.replace("shard_count: 2", "shard_count: 3")
    )
    .is_err());
}

#[test]
fn sentinel_environment_expansion_uses_existing_config_path() {
    let yaml = "sentinel: {addresses: ['${SIPHON_SENTINEL_TEST_UNSET:-localhost:26379}'], master: '${SIPHON_MASTER_TEST_UNSET:-primary}'}";
    let expanded = siphon::config::expand_env_vars(yaml);
    let config: RedisBackendConfig = serde_saphyr::from_str(&expanded).unwrap();
    assert!(format!("{:?}", config.target).contains("primary"));
}

/// A self-signed CA certificate in a file, as `tls.ca_file` reads one.
fn ca_file() -> (tempfile::TempDir, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["Redis Test CA".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.pem");
    std::fs::write(&path, params.self_signed(&key).unwrap().pem()).unwrap();
    let path = path.to_str().unwrap().to_string();
    (directory, path)
}

#[test]
fn registrar_cache_and_shards_take_a_ca_file() {
    use siphon::redis_target::{RedisTarget, RedisTls};
    let (_directory, path) = ca_file();
    let url = RedisTarget::Url(format!("rediss://192.0.2.10:6380/2?ca_file={path}"));
    let structured = format!("url: rediss://192.0.2.10:6380/2\ntls:\n  ca_file: {path}\n");
    let in_url = format!("url: \"rediss://192.0.2.10:6380/2?ca_file={path}\"\n");
    for target in [&structured, &in_url] {
        let registrar = serde_saphyr::from_str::<RedisBackendConfig>(target).unwrap();
        assert_eq!(registrar.target, url, "{target}");
        let cache =
            serde_saphyr::from_str::<NamedCacheConfig>(&format!("name: data\n{target}")).unwrap();
        assert_eq!(cache.target, url, "{target}");
    }
    let sentinel = format!(
        "sentinel: {{addresses: [192.0.2.10:26379], master: primary}}\ntls: {{ca_file: {path}}}"
    );
    let with_ca = Some(RedisTls {
        ca_file: Some(path.clone()),
    });
    let registrar = serde_saphyr::from_str::<RedisBackendConfig>(&sentinel).unwrap();
    assert!(matches!(&registrar.target, RedisTarget::Sentinel(config) if config.tls == with_ca));
    let cache =
        serde_saphyr::from_str::<NamedCacheConfig>(&format!("name: data\n{sentinel}")).unwrap();
    assert!(matches!(&cache.target, RedisTarget::Sentinel(config) if config.tls == with_ca));

    let shards = format!(
        "shard_count: 3\nurls:\n  - \"rediss://192.0.2.10:6380/2?ca_file={path}\"\n  - {{url: rediss://192.0.2.10:6380/2, tls: {{ca_file: {path}}}}}\n  - {{sentinel: {{addresses: [192.0.2.10:26379], master: primary}}, tls: {{ca_file: {path}}}}}\n"
    );
    let config = serde_saphyr::from_str::<RedisBackendConfig>(&shards).unwrap();
    assert_eq!(config.urls[0], url);
    assert_eq!(config.urls[1], url);
    assert!(matches!(&config.urls[2], RedisTarget::Sentinel(config) if config.tls == with_ca));
    assert_eq!(config.target, url);
}

#[test]
fn a_ca_file_that_cannot_be_read_stops_the_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pem");
    let missing = missing.to_str().unwrap();
    for target in [
        format!("url: rediss://192.0.2.10:6380\ntls: {{ca_file: {missing}}}"),
        format!("url: rediss://192.0.2.10:6380?ca_file={missing}"),
        format!("shard_count: 1\nurls: [\"rediss://192.0.2.10:6380?ca_file={missing}\"]"),
    ] {
        let error = serde_saphyr::from_str::<RedisBackendConfig>(&target)
            .unwrap_err()
            .to_string();
        assert!(error.contains(missing), "{target}: {error}");
        if target.starts_with("url") {
            let error =
                serde_saphyr::from_str::<NamedCacheConfig>(&format!("name: data\n{target}"))
                    .unwrap_err()
                    .to_string();
            assert!(error.contains(missing), "{target}: {error}");
        }
    }
}
