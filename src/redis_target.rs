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
    /// TLS to the sentinels and to the data nodes they name. Set by `tls:`
    /// beside `sentinel:` or by a `rediss+sentinel://` URL, never inside the
    /// `sentinel:` mapping.
    #[serde(skip)]
    pub tls: Option<RedisTls>,
}

/// TLS to a Redis target. The server certificate and its name are always
/// verified; there is no setting that turns that off.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisTls {
    /// PEM bundle of the CA certificates the server certificate must chain
    /// to, for a private CA. Without it the public web roots apply.
    pub ca_file: Option<String>,
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
                .field("tls", &config.tls)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct TargetFields {
    pub url: Option<String>,
    pub sentinel: Option<SentinelConfig>,
    pub tls: Option<RedisTls>,
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
            (Some(url), None) if !url.is_empty() => RedisTarget::from_url(url)?.with_tls(self.tls),
            (None, Some(mut config)) => {
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
                if let Some(path) = self.tls.as_ref().and_then(|tls| tls.ca_file.as_deref()) {
                    load_ca(path)?;
                }
                config.tls = self.tls;
                Ok(RedisTarget::Sentinel(config))
            }
            _ => Err("Redis requires exactly one of url or sentinel".into()),
        }
    }
}

const SENTINEL_SCHEME: &str = "redis+sentinel://";
const SENTINEL_TLS_SCHEME: &str = "rediss+sentinel://";
/// The URL parameter that names the CA bundle, taken off before the URL
/// reaches the Redis client.
const CA_FILE: &str = "ca_file";
const SENTINEL_PORT: u16 = 26379;

impl RedisTarget {
    /// A target from a URL: `redis://` and `rediss://` as they are, and a
    /// Sentinel set written as one URL,
    /// `redis+sentinel://[:password@]host[:port][,host[:port]...]/master[/db][?sentinel_password=...]`,
    /// so that a configuration switches between the two by its environment
    /// alone. The port defaults to 26379; credentials are percent-decoded.
    ///
    /// A TLS target (`rediss://`, `rediss+sentinel://`) takes `?ca_file=<path>`,
    /// percent-decoded: the PEM bundle of the CA its certificates are verified
    /// against. The file is read here, so one that cannot be used is an error.
    pub fn from_url(url: String) -> Result<Self, String> {
        for (scheme, tls) in [(SENTINEL_SCHEME, false), (SENTINEL_TLS_SCHEME, true)] {
            if let Some(rest) = url.strip_prefix(scheme) {
                return parse_sentinel(rest, tls).map(Self::Sentinel);
            }
        }
        if let (_, Some(path)) = split_ca_file(&url)? {
            if !is_tls_url(&url) {
                return Err(format!("{CA_FILE} needs a rediss:// URL"));
            }
            load_ca(&path)?;
        }
        Ok(Self::Url(url))
    }

    /// Applies a `tls:` mapping written beside the target. A URL target keeps
    /// the CA as its `ca_file` parameter, the one form the connection reads.
    fn with_tls(self, tls: Option<RedisTls>) -> Result<Self, String> {
        let Some(tls) = tls else {
            return Ok(self);
        };
        let twice = || format!("{CA_FILE} is given both in tls and in the URL");
        match self {
            Self::Url(url) => {
                if !is_tls_url(&url) {
                    return Err("tls needs a rediss:// URL".into());
                }
                let Some(path) = tls.ca_file else {
                    return Ok(Self::Url(url));
                };
                if split_ca_file(&url)?.1.is_some() {
                    return Err(twice());
                }
                load_ca(&path)?;
                let (base, fragment) = match url.split_once('#') {
                    Some((base, fragment)) => (base, format!("#{fragment}")),
                    None => (url.as_str(), String::new()),
                };
                let separator = if base.contains('?') { '&' } else { '?' };
                Ok(Self::Url(format!(
                    "{base}{separator}{CA_FILE}={}{fragment}",
                    percent_encode(&path)
                )))
            }
            Self::Sentinel(mut config) => {
                let Some(from_url) = config.tls.as_mut() else {
                    return Err("tls needs a rediss+sentinel:// URL".into());
                };
                if let Some(path) = tls.ca_file {
                    if from_url.ca_file.is_some() {
                        return Err(twice());
                    }
                    load_ca(&path)?;
                    from_url.ca_file = Some(path);
                }
                Ok(Self::Sentinel(config))
            }
        }
    }
}

fn is_tls_url(url: &str) -> bool {
    url.starts_with("rediss://") || url.starts_with("valkeys://")
}

/// Takes the `ca_file` parameter off a URL: the URL as the Redis client reads
/// it, and the percent-decoded path.
pub(crate) fn split_ca_file(url: &str) -> Result<(String, Option<String>), String> {
    let (base, fragment) = match url.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (url, None),
    };
    let Some((head, query)) = base.split_once('?') else {
        return Ok((url.to_string(), None));
    };
    let mut kept = Vec::new();
    let mut ca_file = None;
    for pair in query.split('&') {
        match pair.split_once('=').unwrap_or((pair, "")) {
            (CA_FILE, value) => {
                if ca_file.is_some() {
                    return Err(format!("{CA_FILE} is given twice in the URL"));
                }
                ca_file = Some(ca_file_value(value)?);
            }
            _ => kept.push(pair),
        }
    }
    let mut stripped = head.to_string();
    if !kept.is_empty() {
        stripped.push('?');
        stripped.push_str(&kept.join("&"));
    }
    if let Some(fragment) = fragment {
        stripped.push('#');
        stripped.push_str(fragment);
    }
    Ok((stripped, ca_file))
}

fn ca_file_value(value: &str) -> Result<String, String> {
    percent_decode(value)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| format!("{CA_FILE} in the URL is empty or badly percent-encoded"))
}

/// Reads a PEM CA bundle and checks that it can anchor a verification: at
/// least one certificate, every one of them usable as a trust anchor.
pub(crate) fn load_ca(path: &str) -> Result<Vec<u8>, String> {
    use rustls_pki_types::{pem::PemObject, CertificateDer};
    let unusable = |why: String| format!("Redis TLS {CA_FILE} {path}: {why}");
    let pem = std::fs::read(path).map_err(|error| unusable(error.to_string()))?;
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        let certificate =
            certificate.map_err(|error| unusable(format!("not a PEM certificate: {error}")))?;
        roots
            .add(certificate)
            .map_err(|error| unusable(format!("not a usable CA certificate: {error}")))?;
    }
    if roots.is_empty() {
        return Err(unusable("holds no PEM certificate".into()));
    }
    Ok(pem)
}

fn parse_sentinel(rest: &str, tls: bool) -> Result<SentinelConfig, String> {
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
    let mut ca_file = None;
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
            Some((CA_FILE, value)) => {
                if !tls {
                    return Err(malformed(&format!(
                        "{CA_FILE} needs a rediss+sentinel:// URL"
                    )));
                }
                if ca_file.is_some() {
                    return Err(malformed(&format!("{CA_FILE} is given twice")));
                }
                let path = ca_file_value(value).map_err(|error| malformed(&error))?;
                load_ca(&path)?;
                ca_file = Some(path);
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
        tls: tls.then_some(RedisTls { ca_file }),
    })
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
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
    fn ca_file() -> (tempfile::TempDir, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ca.pem");
        let ca = crate::transport::outbound_tls::tests::test_ca("Redis Test CA");
        std::fs::write(&path, ca.pem()).unwrap();
        let path = path.to_str().unwrap().to_string();
        (directory, path)
    }

    #[test]
    fn a_ca_file_rides_in_the_url_or_beside_it() {
        let (_directory, path) = ca_file();
        let url = format!("rediss://192.0.2.10:6380/1?ca_file={path}");
        assert_eq!(
            RedisTarget::from_url(url.clone()).unwrap(),
            RedisTarget::Url(url.clone())
        );
        for yaml in [
            format!("url: \"{url}\""),
            format!("url: rediss://192.0.2.10:6380/1\ntls: {{ca_file: {path}}}"),
            format!("url: rediss://192.0.2.10:6380/1\ntls:\n  ca_file: {path}"),
        ] {
            assert_eq!(
                serde_saphyr::from_str::<RedisTarget>(&yaml).unwrap(),
                RedisTarget::Url(url.clone()),
                "{yaml}"
            );
        }
        assert_eq!(
            serde_saphyr::from_str::<RedisTarget>("url: rediss://192.0.2.10:6380\ntls: {}")
                .unwrap(),
            RedisTarget::Url("rediss://192.0.2.10:6380".into())
        );
    }

    #[test]
    fn the_ca_file_is_taken_off_the_url_the_client_reads() {
        for (url, stripped, ca_file) in [
            ("redis://192.0.2.10:6379/2", "redis://192.0.2.10:6379/2", None),
            (
                "rediss://192.0.2.10:6380/2?ca_file=/etc/ca.pem",
                "rediss://192.0.2.10:6380/2",
                Some("/etc/ca.pem"),
            ),
            (
                "rediss://:p%40ss@valkey.example.invalid?protocol=resp3&ca_file=%2Fetc%2Fmy%20ca.pem",
                "rediss://:p%40ss@valkey.example.invalid?protocol=resp3",
                Some("/etc/my ca.pem"),
            ),
            (
                "rediss://192.0.2.10?ca_file=/etc/ca.pem&protocol=resp3#fragment",
                "rediss://192.0.2.10?protocol=resp3#fragment",
                Some("/etc/ca.pem"),
            ),
        ] {
            assert_eq!(
                split_ca_file(url).unwrap(),
                (stripped.to_string(), ca_file.map(str::to_string)),
                "{url}"
            );
        }
        for url in [
            "rediss://192.0.2.10?ca_file",
            "rediss://192.0.2.10?ca_file=",
            "rediss://192.0.2.10?ca_file=%zz",
            "rediss://192.0.2.10?ca_file=/a.pem&ca_file=/b.pem",
        ] {
            assert!(split_ca_file(url).is_err(), "{url}");
        }
    }

    #[test]
    fn a_ca_file_beside_the_url_is_percent_encoded_into_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("my ca&1.pem");
        let ca = crate::transport::outbound_tls::tests::test_ca("Redis Test CA");
        std::fs::write(&path, ca.pem()).unwrap();
        let path = path.to_str().unwrap();
        let yaml = format!(
            "url: rediss://192.0.2.10:6380/1?protocol=resp3#fragment\ntls: {{ca_file: \"{path}\"}}"
        );
        let RedisTarget::Url(url) = serde_saphyr::from_str::<RedisTarget>(&yaml).unwrap() else {
            panic!("a URL target");
        };
        assert!(url.ends_with("my%20ca%261.pem#fragment"), "{url}");
        assert_eq!(
            split_ca_file(&url).unwrap(),
            (
                "rediss://192.0.2.10:6380/1?protocol=resp3#fragment".to_string(),
                Some(path.to_string())
            )
        );
    }

    #[test]
    fn a_sentinel_set_takes_tls_from_its_scheme_or_from_beside_it() {
        let (_directory, path) = ca_file();
        let with_ca = Some(RedisTls {
            ca_file: Some(path.clone()),
        });
        let public_roots = Some(RedisTls { ca_file: None });
        for (yaml, tls) in [
            (
                "url: redis+sentinel://192.0.2.10/primary".to_string(),
                None,
            ),
            (
                "sentinel: {addresses: [192.0.2.10:26379], master: primary}".to_string(),
                None,
            ),
            (
                "url: rediss+sentinel://192.0.2.10/primary".to_string(),
                public_roots.clone(),
            ),
            (
                "sentinel: {addresses: [192.0.2.10:26379], master: primary}\ntls: {}".to_string(),
                public_roots,
            ),
            (
                format!("url: rediss+sentinel://192.0.2.10/primary?ca_file={path}"),
                with_ca.clone(),
            ),
            (
                format!(
                    "url: rediss+sentinel://:secret@192.0.2.10/primary/2?sentinel_password=other&ca_file={path}"
                ),
                with_ca.clone(),
            ),
            (
                format!("url: rediss+sentinel://192.0.2.10/primary\ntls: {{ca_file: {path}}}"),
                with_ca.clone(),
            ),
            (
                format!(
                    "sentinel: {{addresses: [192.0.2.10:26379], master: primary}}\ntls: {{ca_file: {path}}}"
                ),
                with_ca,
            ),
        ] {
            match serde_saphyr::from_str::<RedisTarget>(&yaml).expect(&yaml) {
                RedisTarget::Sentinel(config) => {
                    assert_eq!(config.tls, tls, "{yaml}");
                    assert_eq!(config.addresses, ["192.0.2.10:26379"], "{yaml}");
                    assert_eq!(config.master, "primary", "{yaml}");
                }
                RedisTarget::Url(_) => panic!("{yaml} read as a plain URL"),
            }
        }
        assert!(serde_saphyr::from_str::<RedisTarget>(&format!(
            "url: rediss+sentinel://192.0.2.10/primary?ca_file={path}\ntls: {{ca_file: {path}}}"
        ))
        .is_err());
    }

    #[test]
    fn a_ca_file_that_cannot_be_used_is_a_configuration_error() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.pem");
        let missing = missing.to_str().unwrap();
        let garbage = directory.path().join("garbage.pem");
        std::fs::write(&garbage, "not a certificate\n").unwrap();
        let garbage = garbage.to_str().unwrap();
        for path in [missing, garbage] {
            for yaml in [
                format!("url: rediss://192.0.2.10:6380?ca_file={path}"),
                format!("url: rediss://192.0.2.10:6380\ntls: {{ca_file: {path}}}"),
                format!("url: rediss+sentinel://192.0.2.10/primary?ca_file={path}"),
                format!(
                    "sentinel: {{addresses: [192.0.2.10:26379], master: primary}}\ntls: {{ca_file: {path}}}"
                ),
            ] {
                let message = serde_saphyr::from_str::<RedisTarget>(&yaml)
                    .expect_err(&yaml)
                    .to_string();
                assert!(message.contains(path), "{yaml}: {message}");
            }
        }
    }

    #[test]
    fn tls_settings_on_a_plaintext_target_are_refused() {
        let (_directory, path) = ca_file();
        for yaml in [
            format!("url: redis://192.0.2.10:6379?ca_file={path}"),
            format!("url: redis://192.0.2.10:6379\ntls: {{ca_file: {path}}}"),
            "url: redis://192.0.2.10:6379\ntls: {}".to_string(),
            format!("url: redis+sentinel://192.0.2.10/primary?ca_file={path}"),
            format!("url: redis+sentinel://192.0.2.10/primary\ntls: {{ca_file: {path}}}"),
            format!(
                "url: rediss://192.0.2.10:6380?ca_file={path}\ntls: {{ca_file: {path}}}"
            ),
            format!("url: rediss://192.0.2.10:6380?ca_file={path}&ca_file={path}"),
            "url: rediss://192.0.2.10:6380?ca_file=".to_string(),
            "url: rediss://192.0.2.10:6380\ntls: {insecure: true}".to_string(),
            format!(
                "sentinel: {{addresses: [192.0.2.10:26379], master: primary, tls: {{ca_file: {path}}}}}"
            ),
        ] {
            assert!(
                serde_saphyr::from_str::<RedisTarget>(&yaml).is_err(),
                "{yaml}"
            );
        }
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
