//! Shared Redis/Valkey destination configuration.
use serde::{Deserialize, Deserializer};

/// Exactly one URL or Sentinel master set. Flatten into Redis consumers.
#[derive(Clone, PartialEq, Eq)]
pub enum RedisTarget {
    Url(String),
    Sentinel(SentinelConfig),
}

/// Sentinel discovery and separate credentials for data and Sentinel nodes.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SentinelConfig {
    pub addresses: Vec<String>,
    pub master: String,
    pub password: Option<String>,
    pub sentinel_password: Option<String>,
    #[serde(default)]
    pub db: u32,
}

impl std::fmt::Debug for RedisTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(_) => formatter.write_str("RedisTarget::Url(<redacted>)"),
            Self::Sentinel(config) => formatter
                .debug_struct("RedisTarget::Sentinel")
                .field("master", &config.master)
                .field("addresses", &config.addresses)
                .field("db", &config.db)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct TargetFields {
    pub url: Option<String>,
    pub sentinel: Option<SentinelConfig>,
}

impl<'de> Deserialize<'de> for RedisTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        TargetFields::deserialize(deserializer)?
            .resolve()
            .map_err(serde::de::Error::custom)
    }
}

impl TargetFields {
    pub(crate) fn resolve(self) -> Result<RedisTarget, String> {
        match (self.url, self.sentinel) {
            (Some(url), None) if !url.is_empty() => Ok(RedisTarget::Url(url)),
            (None, Some(config)) => {
                if config.addresses.is_empty()
                    || config
                        .addresses
                        .iter()
                        .any(|address| address.trim().is_empty())
                {
                    return Err("sentinel.addresses must contain at least one host:port".into());
                }
                if config.master.trim().is_empty() {
                    return Err("sentinel.master must not be empty".into());
                }
                Ok(RedisTarget::Sentinel(config))
            }
            _ => Err("Redis requires exactly one of url or sentinel".into()),
        }
    }
}

impl Default for RedisTarget {
    fn default() -> Self {
        Self::Url("redis://127.0.0.1:6379".into())
    }
}

impl From<String> for RedisTarget {
    fn from(url: String) -> Self {
        Self::Url(url)
    }
}

/// Legacy shard URL strings and the shared mapping form are both accepted.
pub fn deserialize_shards<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RedisTarget>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Shard {
        Url(String),
        Target(RedisTarget),
    }
    Ok(Vec::<Shard>::deserialize(deserializer)?
        .into_iter()
        .map(|shard| match shard {
            Shard::Url(url) => RedisTarget::Url(url),
            Shard::Target(target) => target,
        })
        .collect())
}

#[cfg(feature = "redis-backend")]
mod connection;
#[cfg(feature = "redis-backend")]
pub use connection::RedisConnection;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_sentinel_and_invalid_combinations() {
        assert_eq!(
            serde_saphyr::from_str::<RedisTarget>("url: redis://localhost:6379/2").unwrap(),
            RedisTarget::Url("redis://localhost:6379/2".into())
        );
        assert!(serde_saphyr::from_str::<RedisTarget>(
            "sentinel: {addresses: [localhost:26379], master: primary}"
        )
        .is_ok());
        for yaml in [
            "{}",
            "url: redis://localhost\nsentinel: {addresses: [localhost:26379], master: primary}",
            "sentinel: {addresses: [], master: primary}",
            "sentinel: {addresses: [localhost:26379], master: ''}",
        ] {
            let message = serde_saphyr::from_str::<RedisTarget>(yaml)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains("exactly one") || message.contains("must"),
                "{message}"
            );
        }
        assert_eq!(
            RedisTarget::default(),
            RedisTarget::from("redis://127.0.0.1:6379".to_owned())
        );
    }

    #[test]
    fn credentials_are_redacted() {
        let target: RedisTarget = serde_saphyr::from_str("sentinel: {addresses: [localhost:26379], master: primary, password: secret, sentinel_password: other}").unwrap();
        let debug = format!("{target:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("other"));
        assert!(
            !format!("{:?}", RedisTarget::Url("redis://:secret@localhost".into()))
                .contains("secret")
        );
    }
    #[test]
    fn mixed_shards_parse() {
        #[derive(Deserialize)]
        struct Shards {
            #[serde(deserialize_with = "deserialize_shards")]
            urls: Vec<RedisTarget>,
        }
        let shards: Shards = serde_saphyr::from_str("urls: [redis://localhost:6379, {sentinel: {addresses: [localhost:26379], master: primary}}]").unwrap();
        assert_eq!(shards.urls.len(), 2);
    }
}
