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
            (Some(url), None) if !url.is_empty() => RedisTarget::from_url(url),
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

const SENTINEL_SCHEME: &str = "redis+sentinel://";
const SENTINEL_PORT: u16 = 26379;

impl RedisTarget {
    /// A target from a URL: `redis://` and `rediss://` as they are, and a
    /// Sentinel set written as one URL,
    /// `redis+sentinel://[:password@]host[:port][,host[:port]...]/master[/db][?sentinel_password=...]`,
    /// so that a configuration switches between the two by its environment
    /// alone. The port defaults to 26379; credentials are percent-decoded.
    pub fn from_url(url: String) -> Result<Self, String> {
        match url.strip_prefix(SENTINEL_SCHEME) {
            None => Ok(Self::Url(url)),
            Some(rest) => parse_sentinel(rest).map(Self::Sentinel),
        }
    }
}

fn parse_sentinel(rest: &str) -> Result<SentinelConfig, String> {
    let malformed = |what: &str| format!("redis+sentinel URL: {what}");
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, Some(query)),
        None => (rest, None),
    };
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| malformed("no /master after the hosts"))?;
    let (credentials, hosts) = match authority.rsplit_once('@') {
        Some((credentials, hosts)) => (Some(credentials), hosts),
        None => (None, authority),
    };
    let password = match credentials {
        None => None,
        Some(credentials) => {
            let secret = credentials
                .split_once(':')
                .map_or(credentials, |(_, secret)| secret);
            Some(
                percent_decode(secret)
                    .ok_or_else(|| malformed("bad percent-encoding in the password"))?,
            )
        }
    }
    .filter(|password| !password.is_empty());
    let mut addresses = Vec::new();
    for host in hosts.split(',') {
        let host = host.trim();
        if host.is_empty() {
            return Err(malformed("an empty host"));
        }
        // A bracketed IPv6 address has a port only after its `]`.
        let port = match host.strip_prefix('[') {
            Some(bracketed) => match bracketed.split_once(']') {
                Some((_, "")) => None,
                Some((_, after)) => Some(after.strip_prefix(':').unwrap_or(after)),
                None => return Err(malformed(&format!("unclosed [ in {host}"))),
            },
            None => host.rsplit_once(':').map(|(_, port)| port),
        };
        if let Some(port) = port {
            if port.parse::<u16>().is_err() {
                return Err(malformed(&format!("bad port in {host}")));
            }
        }
        let has_port = port.is_some();
        addresses.push(if has_port {
            host.to_string()
        } else {
            format!("{host}:{SENTINEL_PORT}")
        });
    }
    let mut segments = path.split('/');
    let master = segments.next().unwrap_or_default().trim();
    if master.is_empty() {
        return Err(malformed("no master name"));
    }
    let db = match segments.next() {
        None | Some("") => 0,
        Some(db) => db
            .parse::<u32>()
            .map_err(|_| malformed(&format!("bad database {db}")))?,
    };
    if segments.next().is_some() {
        return Err(malformed("more than /master/db in the path"));
    }
    let mut sentinel_password = None;
    for pair in query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter(|pair| !pair.is_empty())
    {
        match pair.split_once('=') {
            Some(("sentinel_password", value)) => {
                sentinel_password = Some(
                    percent_decode(value)
                        .ok_or_else(|| malformed("bad percent-encoding in sentinel_password"))?,
                )
                .filter(|value| !value.is_empty());
            }
            _ => {
                return Err(malformed(&format!(
                    "unknown parameter {}",
                    pair.split('=').next().unwrap_or(pair)
                )))
            }
        }
    }
    Ok(SentinelConfig {
        addresses,
        master: master.to_string(),
        password,
        sentinel_password,
        db,
    })
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = text.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
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
    Vec::<Shard>::deserialize(deserializer)?
        .into_iter()
        .map(|shard| match shard {
            Shard::Url(url) => RedisTarget::from_url(url).map_err(serde::de::Error::custom),
            Shard::Target(target) => Ok(target),
        })
        .collect()
}

#[cfg(feature = "redis-backend")]
mod connection;
#[cfg(feature = "redis-backend")]
pub use connection::RedisConnection;

#[cfg(test)]
mod tests {
    use super::*;

    fn sentinel(url: &str) -> SentinelConfig {
        match RedisTarget::from_url(url.to_string()).expect("a valid sentinel URL") {
            RedisTarget::Sentinel(config) => config,
            RedisTarget::Url(_) => panic!("{url} read as a plain URL"),
        }
    }

    #[test]
    fn a_sentinel_url_is_a_sentinel_target() {
        let config =
            sentinel("redis+sentinel://192.0.2.10:26380,192.0.2.11,valkey.example.net/primary/2");
        assert_eq!(
            config.addresses,
            [
                "192.0.2.10:26380",
                "192.0.2.11:26379",
                "valkey.example.net:26379"
            ]
        );
        assert_eq!(config.master, "primary");
        assert_eq!(config.db, 2);
        assert_eq!(config.password, None);
        assert_eq!(config.sentinel_password, None);
    }

    #[test]
    fn a_sentinel_url_carries_both_passwords_percent_decoded() {
        let config =
            sentinel("redis+sentinel://:p%40ss@192.0.2.10/primary?sentinel_password=s%2Fcret");
        assert_eq!(config.password.as_deref(), Some("p@ss"));
        assert_eq!(config.sentinel_password.as_deref(), Some("s/cret"));
        assert_eq!(config.db, 0);
        let user = sentinel("redis+sentinel://default:secret@192.0.2.10/primary");
        assert_eq!(user.password.as_deref(), Some("secret"));
    }

    #[test]
    fn a_bracketed_ipv6_sentinel_takes_the_default_port_or_its_own() {
        let config = sentinel("redis+sentinel://[2001:db8::1],[2001:db8::2]:26390/primary");
        assert_eq!(
            config.addresses,
            ["[2001:db8::1]:26379", "[2001:db8::2]:26390"]
        );
    }

    #[test]
    fn a_malformed_sentinel_url_is_refused() {
        for url in [
            "redis+sentinel://192.0.2.10",
            "redis+sentinel://192.0.2.10/",
            "redis+sentinel://,192.0.2.10/primary",
            "redis+sentinel://192.0.2.10:notaport/primary",
            "redis+sentinel://192.0.2.10/primary/x",
            "redis+sentinel://192.0.2.10/primary/1/2",
            "redis+sentinel://192.0.2.10/primary?other=1",
            "redis+sentinel://:%zz@192.0.2.10/primary",
        ] {
            assert!(RedisTarget::from_url(url.to_string()).is_err(), "{url}");
        }
    }

    #[test]
    fn a_plain_url_stays_a_url() {
        assert_eq!(
            RedisTarget::from_url("rediss://192.0.2.10:6380/1".to_string()).unwrap(),
            RedisTarget::Url("rediss://192.0.2.10:6380/1".into())
        );
    }

    #[test]
    fn config_url_and_shard_strings_read_a_sentinel_url() {
        let target: RedisTarget =
            serde_saphyr::from_str("url: redis+sentinel://192.0.2.10/primary").unwrap();
        assert!(matches!(target, RedisTarget::Sentinel(ref config) if config.master == "primary"));
        #[derive(serde::Deserialize)]
        struct Shards {
            #[serde(deserialize_with = "deserialize_shards")]
            urls: Vec<RedisTarget>,
        }
        let shards: Shards = serde_saphyr::from_str(
            "urls: [\"redis://192.0.2.20:6379\", \"redis+sentinel://192.0.2.10/primary\"]",
        )
        .unwrap();
        assert!(matches!(shards.urls[0], RedisTarget::Url(_)));
        assert!(matches!(shards.urls[1], RedisTarget::Sentinel(_)));
        assert!(serde_saphyr::from_str::<RedisTarget>("url: redis+sentinel://192.0.2.10").is_err());
    }
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
