//! `tls:` server certificates (the listeners live under `listen.tls`).

use serde::{Deserialize, Deserializer};

use super::listen::{ListenConfig, ListenEntry, ListenerClientAuth};

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
    ///
    /// The default for every `listen.tls` / `listen.wss` listener; an entry in
    /// the object form can override it (and `client_ca` / `client_subject`)
    /// for that listener alone.
    #[serde(default)]
    pub verify_client: bool,
    /// PEM bundle of CA certificates that client certificates must chain to,
    /// used only when `verify_client` is true (mutual TLS).
    #[serde(default)]
    pub client_ca: Option<String>,
    /// DNS identities a client certificate must carry, on top of chaining to
    /// `client_ca`: exact names or a whole-leftmost-label wildcard
    /// (`*.sip.example.net`, one label, RFC 6125 §6.4.3). Matched against the
    /// certificate's dNSName subjectAltNames, or its subject Common Name only
    /// when it carries none (RFC 6125 §6.4.4). A certificate from the right CA
    /// that names none of them is refused at the handshake. Empty (the
    /// default) checks the chain only. Requires `verify_client: true`.
    #[serde(default)]
    pub client_subject: Vec<String>,
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

impl TlsServerConfig {
    /// This block as one listener sees it: the server certificates unchanged,
    /// and `verify_client` / `client_ca` / `client_subject` replaced by
    /// whichever of them the listener's entry sets.
    ///
    /// A listener that sets none of them gets an identical copy, so it behaves
    /// exactly as every listener did before the override existed.
    pub fn for_listener(&self, overrides: Option<&ListenerClientAuth>) -> TlsServerConfig {
        let mut effective = self.clone();
        let Some(overrides) = overrides else {
            return effective;
        };
        if let Some(verify_client) = overrides.verify_client {
            effective.verify_client = verify_client;
        }
        if let Some(client_ca) = &overrides.client_ca {
            effective.client_ca = Some(client_ca.clone());
        }
        match &overrides.client_subject {
            Some(client_subject) => effective.client_subject = client_subject.clone(),
            // A listener that turns verification off drops the inherited
            // subject list with it: there is no certificate to check it on.
            None if !effective.verify_client => effective.client_subject.clear(),
            None => {}
        }
        effective
    }
}

/// Refuse client-certificate settings on a listener that cannot honour them,
/// naming the listener.
///
/// At load (and so on every config reload too), because the failure it
/// replaces is quiet: an untagged listen entry ignores keys it does not know,
/// so `verify_client: true` on a listener that could not apply it would read
/// as mutual TLS and be none. Every rule fails closed:
///
/// - the overrides exist only on `listen.tls` and `listen.wss`;
/// - they need the top-level `tls:` block (it holds the server certificate);
/// - `client_ca` or `client_subject` on a listener that does not end up
///   verifying clients is refused rather than ignored;
/// - a verifying listener must have a readable, non-empty `client_ca` and
///   well-formed `client_subject` patterns — built here exactly as the
///   listener will build them;
/// - a `listen.tls` and `listen.wss` entry sharing one address share one
///   socket and one handshake, so their settings must agree.
pub(super) fn validate_listener_client_auth(
    listen: &ListenConfig,
    tls: Option<&TlsServerConfig>,
) -> Result<(), String> {
    for (transport, entries) in [
        ("udp", &listen.udp),
        ("tcp", &listen.tcp),
        ("ws", &listen.ws),
        ("sctp", &listen.sctp),
    ] {
        if let Some(entry) = entries.iter().find(|entry| entry.client_auth().is_some()) {
            return Err(format!(
                "listen.{transport}[{}]: verify_client / client_ca / client_subject apply only \
                 to listen.tls and listen.wss — a {transport} listener has no TLS handshake to \
                 check a client certificate in",
                entry.address()
            ));
        }
    }

    if let Some(tls) = tls {
        if !tls.verify_client && !tls.client_subject.is_empty() {
            return Err(
                "tls.client_subject is set but tls.verify_client is not true — a \
                 subject can only be checked on a certificate the client was required to \
                 present"
                    .to_string(),
            );
        }
    }

    for (transport, entries) in [("tls", &listen.tls), ("wss", &listen.wss)] {
        for entry in entries {
            validate_tls_listener(transport, entry, tls)?;
        }
    }

    for tls_entry in &listen.tls {
        let shared = listen
            .wss
            .iter()
            .find(|wss_entry| same_socket(wss_entry.address(), tls_entry.address()));
        if let Some(wss_entry) = shared {
            if tls_entry.client_auth() != wss_entry.client_auth() {
                return Err(format!(
                    "listen.tls[{address}] and listen.wss[{address}] share one socket but set \
                     different verify_client / client_ca / client_subject — the TLS handshake \
                     happens before siphon can tell SIP from WebSocket, so both entries must \
                     carry the same settings",
                    address = tls_entry.address()
                ));
            }
        }
    }
    Ok(())
}

/// Whether two listen addresses name one socket, compared the way the server
/// pairs tls+wss listeners for the mux (as parsed socket addresses).
fn same_socket(left: &str, right: &str) -> bool {
    match (
        left.parse::<std::net::SocketAddr>(),
        right.parse::<std::net::SocketAddr>(),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn validate_tls_listener(
    transport: &str,
    entry: &ListenEntry,
    tls: Option<&TlsServerConfig>,
) -> Result<(), String> {
    let overrides = entry.client_auth();
    let Some(tls) = tls else {
        if overrides.is_some() {
            return Err(format!(
                "listen.{transport}[{}]: client-certificate settings need the top-level tls: \
                 block, which holds the server certificate this listener presents",
                entry.address()
            ));
        }
        return Ok(());
    };
    let Some(overrides) = overrides else {
        // No override: the listener uses the `tls:` block as-is, whose
        // certificate files are read when the listener starts, as before.
        // Only the structural rules are checked here.
        return validate_client_auth_shape(tls, "tls");
    };
    let label = format!("listen.{transport}[{}]", entry.address());
    let effective = tls.for_listener(Some(overrides));
    if !effective.verify_client && overrides.client_ca.is_some() {
        return Err(format!(
            "{label}.client_ca is set but this listener does not verify clients — set \
             verify_client: true on it (or in tls:), or remove client_ca"
        ));
    }
    crate::transport::tls_client_auth::client_cert_verifier(&effective, &label)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The rules on `verify_client` / `client_ca` / `client_subject` that need no
/// file read.
fn validate_client_auth_shape(tls: &TlsServerConfig, label: &str) -> Result<(), String> {
    if !tls.verify_client {
        if !tls.client_subject.is_empty() {
            return Err(format!(
                "{label}.client_subject is set but verify_client is not true — a subject can \
                 only be checked on a certificate the client was required to present"
            ));
        }
        return Ok(());
    }
    if tls.client_ca.is_none() {
        return Err(format!(
            "{label}.verify_client is true but no client_ca (PEM CA bundle for client \
             certificates) is set"
        ));
    }
    if !tls.client_subject.is_empty() {
        crate::transport::tls_client_auth::ClientSubjectMatcher::new(&tls.client_subject)
            .map_err(|error| format!("{label}.client_subject: {error}"))?;
    }
    Ok(())
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

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
