//! `tls:` server certificates (the listeners live under `listen.tls`).

use serde::{Deserialize, Deserializer};

// ---------------------------------------------------------------------------
// TLS server config (certificates — listeners are under `listen.tls`)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct TlsServerConfig {
    pub certificate: String,
    pub private_key: String,
    /// Additional certificate pairs selected by the TLS SNI extension
    /// (RFC 6066) on `listen.tls` and `listen.wss`. Empty (the default) serves
    /// `certificate`/`private_key` to every client, exactly as before.
    #[serde(default)]
    pub certificates: Vec<SniCertificate>,
    /// Minimum TLS protocol version siphon negotiates — on the `listen.tls` /
    /// `listen.wss` listeners this block serves, and on outbound SIP TLS
    /// connections from the connection pool.
    ///
    /// This is a **floor**, not an exact version: `TLSv1_2` (the default)
    /// negotiates TLS 1.2 or 1.3, `TLSv1_3` negotiates 1.3 only. TLS 1.0/1.1
    /// are rejected at config load — RFC 8996 deprecates them and the rustls
    /// stack siphon is built on does not implement them.
    #[serde(default)]
    pub method: TlsMethod,
    /// If true, client certificates are required and verified against
    /// `client_ca`. Requires `client_ca` to be set, else startup fails.
    #[serde(default)]
    pub verify_client: bool,
    /// PEM bundle of CA certificates that client certificates must chain to,
    /// used only when `verify_client` is true (mutual TLS).
    #[serde(default)]
    pub client_ca: Option<String>,
    /// PEM certificate chain siphon presents as a TLS *client* on OUTBOUND
    /// connections when the upstream peer requests one (mutual TLS — upstream
    /// SIP trunks that require client-certificate auth). Optional; when unset,
    /// siphon presents no client certificate (prior behavior).
    #[serde(default)]
    pub client_certificate: Option<String>,
    /// PEM private key for `client_certificate`. Must be set if and only if
    /// `client_certificate` is set; a one-sided setting is a startup error.
    #[serde(default)]
    pub client_private_key: Option<String>,
}

/// One additional certificate/key pair, selected by the server name the client
/// sends in the TLS SNI extension (RFC 6066).
///
/// Serving several domains from a single TLS/WSS listener otherwise needs one
/// SAN certificate covering all of them, which couples every domain to a single
/// renewal — one failed ACME validation blocks the cert for all of them, and
/// every peer sees the full list. Each entry here is an independent pair.
///
/// The top-level `certificate`/`private_key` remains the default: it is served
/// to a client that sends no SNI (including any IP-literal peer, which RFC 6066
/// forbids from sending one) or whose server name matches no entry. Selection
/// never aborts a handshake.
#[derive(Debug, Deserialize, Clone)]
pub struct SniCertificate {
    /// Server names this pair serves, matched case-insensitively.
    ///
    /// A leading-label wildcard (`*.example.com`) matches exactly one label per
    /// RFC 6125 §6.4.3 — `ue.example.com` matches, `example.com` and
    /// `a.b.example.com` do not. A name may appear only once across all
    /// entries; a duplicate is a startup error rather than a silent
    /// last-one-wins.
    pub server_names: Vec<String>,
    /// PEM certificate chain served for `server_names`.
    pub certificate: String,
    /// PEM private key matching `certificate`.
    pub private_key: String,
}

/// Minimum TLS protocol version, from `tls.method`.
///
/// Named `method` after the OpenSSL/Kamailio spelling operators already have in
/// their configs, but the semantics are a floor: `TLSv1_2` serves TLS 1.2 *and*
/// 1.3, `TLSv1_3` serves 1.3 only. Only these two exist — RFC 8996 deprecates
/// TLS 1.0/1.1 and rustls does not implement them, so a config asking for one
/// fails at load rather than silently getting something newer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMethod {
    /// TLS 1.2 and above. The default, and what siphon has always served.
    #[default]
    Tls12,
    /// TLS 1.3 only — TLS 1.2 handshakes are refused.
    Tls13,
}

impl TlsMethod {
    /// The spelling used in `siphon.yaml`.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMethod::Tls12 => "TLSv1_2",
            TlsMethod::Tls13 => "TLSv1_3",
        }
    }
}

impl std::fmt::Display for TlsMethod {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for TlsMethod {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        // Accept every spelling an operator plausibly carries over from
        // OpenSSL/Kamailio/OpenSIPS: `TLSv1_2`, `TLSv1.2`, `TLSv1.2+`, `1.2`.
        // The `+` suffix (Kamailio's "this version or higher") is redundant
        // here because the value is already a floor, so it is accepted and
        // ignored rather than rejected.
        let normalized = value
            .trim()
            .trim_end_matches('+')
            .trim()
            .to_ascii_lowercase()
            .replace('_', ".");
        let version = normalized
            .strip_prefix("tlsv")
            .or_else(|| normalized.strip_prefix("tls"))
            .unwrap_or(normalized.as_str());

        match version {
            "1.2" => Ok(TlsMethod::Tls12),
            "1.3" => Ok(TlsMethod::Tls13),
            "1" | "1.0" | "1.1" | "sslv2" | "sslv3" | "sslv23" | "ssl" => Err(format!(
                "tls.method '{value}': TLS 1.0/1.1 and SSL are deprecated (RFC 8996) and \
                 are not implemented — use TLSv1_2 (minimum 1.2, negotiates 1.2 or \
                 1.3) or TLSv1_3 (1.3 only)"
            )),
            _ => Err(format!(
                "tls.method '{value}' is not a TLS version siphon supports — use TLSv1_2 \
                 (minimum 1.2, negotiates 1.2 or 1.3) or TLSv1_3 (1.3 only)"
            )),
        }
    }
}

impl<'de> Deserialize<'de> for TlsMethod {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}
