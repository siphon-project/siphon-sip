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
