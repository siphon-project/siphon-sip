//! TLS transport — wraps TCP connections with rustls.
//!
//! Structurally identical to the TCP listener but performs a TLS handshake
//! on each accepted connection before splitting into read/write halves.
//! Failed handshakes are logged and the connection is dropped without
//! affecting other connections or the accept loop.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::{TlsMethod, TlsServerConfig};
use crate::transport::acl::TransportAcl;
use crate::transport::crlf_keepalive::CrlfPongTracker;
use crate::transport::pool::ConnectionPool;
use crate::transport::proxy_protocol::{accept_proxied, ProxyProtocolAcl};
use crate::transport::stream::{
    bind_tcp_listener, serve_sip_stream, sniff_sip_or_drop, spawn_outbound_distributor,
    PrefixedStream, StreamContext,
};
use crate::transport::{
    configure_tcp_socket, next_connection_id, ConnectionId, InboundMessage, OutboundMessage,
    StreamConnections, Transport,
};

/// Live-swappable TLS acceptor — read by every accept loop, replaced
/// atomically by the file watcher when the cert or key on disk changes.
pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Maximum time allowed for a TLS handshake to complete. tokio imposes no
/// default, so without this a peer that connects and then stalls mid-handshake
/// (slowloris) would pin a task + socket until the OS killed it. Generous
/// enough for slow mobile clients, short enough to bound half-open handshakes.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The crypto provider used to parse private keys outside a `ServerConfig`
/// builder. `server.rs` installs ring as the process default before any
/// listener starts; the fallback keeps unit tests and library embedders that
/// never installed one working instead of failing to load a valid key.
///
/// Shared with [`client_tls`](crate::transport::client_tls), which needs the
/// same fallback for the same reason on the dialing side.
pub(crate) fn crypto_provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    tokio_rustls::rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
}

/// Build a rustls `ServerConfig` for a plain (non-SNI) HTTPS/WSS listener.
///
/// The SIP listener above resolves a certificate per SNI name and so needs the
/// `CertifiedKey` shape; a management listener serves one identity, which is a
/// different enough job to be worth its own entry point rather than a second
/// resolver with one entry in it.
///
/// `client_ca` turns on mutual TLS: when set, a client presenting no
/// certificate, or one no CA in the bundle signed, is refused at the handshake.
/// An unreadable or empty bundle is an error, never a downgrade to accepting any
/// client — the same fail-closed rule the rest of this module applies.
///
/// `field_prefix` names the config block in every error (`control.tls`, …), so
/// a failure points at the key the operator has to fix rather than at "TLS".
pub(crate) fn server_config(
    certificate_path: &str,
    private_key_path: &str,
    client_ca_path: Option<&str>,
    field_prefix: &str,
) -> io::Result<tokio_rustls::rustls::ServerConfig> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls;

    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(certificate_path)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{field_prefix}.certificate '{certificate_path}': {error}"),
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parsing {field_prefix}.certificate '{certificate_path}': {error}"),
                )
            })?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_prefix}.certificate '{certificate_path}' contains no certificates"),
        ));
    }

    let key = PrivateKeyDer::from_pem_file(private_key_path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_prefix}.private_key '{private_key_path}': {error}"),
        )
    })?;

    // TLS 1.3 preferred, 1.2 as the floor — the same pair the X1 listener pins.
    let builder = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{field_prefix}: no usable TLS protocol versions: {error}"),
            )
        })?;

    let config = match client_ca_path {
        Some(ca_path) => {
            let mut roots = rustls::RootCertStore::empty();
            let authorities: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(ca_path)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{field_prefix}.client_ca '{ca_path}': {error}"),
                    )
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("parsing {field_prefix}.client_ca '{ca_path}': {error}"),
                    )
                })?;
            if authorities.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{field_prefix}.client_ca '{ca_path}' contains no certificates —                          mutual TLS would accept no client at all"
                    ),
                ));
            }
            for authority in authorities {
                roots.add(authority).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("adding a CA from {field_prefix}.client_ca '{ca_path}': {error}"),
                    )
                })?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                crypto_provider(),
            )
            .build()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{field_prefix}: building the client certificate verifier: {error}"),
                )
            })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    config.with_single_cert(certificates, key).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{field_prefix}: certificate and private key do not form a usable pair: {error}"
            ),
        )
    })
}

/// Read one PEM certificate chain, end-entity certificate first.
///
/// Shared by [`load_certified_key`], which pairs the chain with its private key,
/// and [`certificate_ip_addresses`], which reads only its names, so a missing,
/// unparseable or empty file reports the same path-tagged error either way.
fn load_certificate_chain(
    certificate_path: &str,
) -> io::Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;
    use std::fs::File;
    use std::io::BufReader;

    let certificate_file = File::open(certificate_path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to open certificate file '{certificate_path}': {error}"),
        )
    })?;
    let certificates: Vec<_> =
        CertificateDer::pem_reader_iter(&mut BufReader::new(certificate_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse certificate PEM '{certificate_path}': {error}"),
                )
            })?;

    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("certificate file '{certificate_path}' contains no certificates"),
        ));
    }
    Ok(certificates)
}

/// Load one PEM certificate chain + private key into a rustls `CertifiedKey`.
///
/// Shared by the default `tls.certificate`/`tls.private_key` pair and by every
/// `tls.certificates[]` SNI entry, so a broken pair reports the same
/// path-tagged error wherever it is configured.
fn load_certified_key(
    certificate_path: &str,
    private_key_path: &str,
) -> io::Result<Arc<CertifiedKey>> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::PrivateKeyDer;
    use std::fs::File;
    use std::io::BufReader;

    // Load certificate chain
    let certificates = load_certificate_chain(certificate_path)?;

    // Load private key
    let key_file = File::open(private_key_path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to open private key file '{private_key_path}': {error}"),
        )
    })?;
    let key = PrivateKeyDer::from_pem_reader(&mut BufReader::new(key_file)).map_err(|error| {
        // `from_pem_reader` returns `Err(NoItemsFound)` when the file held no
        // private key — the case `rustls_pemfile::private_key` signalled with
        // `Ok(None)`. Preserve the original "contains no private key" message
        // for that case, and the "failed to parse" message for everything else.
        match error {
            rustls_pki_types::pem::Error::NoItemsFound => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("private key file '{private_key_path}' contains no private key"),
            ),
            other => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse private key PEM '{private_key_path}': {other}"),
            ),
        }
    })?;

    // Parses the key with the active provider AND checks it against the
    // certificate's public key. `with_single_cert` did both before the resolver
    // replaced it, so a cert/key mismatch still fails at boot rather than at the
    // first handshake.
    CertifiedKey::from_der(certificates, key, &crypto_provider())
        .map(Arc::new)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "certificate '{certificate_path}' and private key \
                     '{private_key_path}' are not a usable pair: {error}"
                ),
            )
        })
}

/// The iPAddress subjectAltNames (RFC 5280 §4.2.1.6) of the end-entity
/// certificate in `certificate_path`, in the order the certificate lists them.
///
/// These are the only names a peer that dials siphon by IP can validate it
/// against. Such a peer sends no SNI (RFC 6066 §3 forbids a literal there), so
/// it is served the default `tls.certificate` and never a `tls.certificates`
/// entry, and certificate validation matches an IP reference identity against
/// iPAddress entries only, never a dNSName or the subject Common Name.
pub(crate) fn certificate_ip_addresses(certificate_path: &str) -> io::Result<Vec<IpAddr>> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let chain = load_certificate_chain(certificate_path)?;
    let end_entity = chain.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("certificate file '{certificate_path}' contains no certificates"),
        )
    })?;
    let certificate = x509_cert::Certificate::from_der(end_entity.as_ref()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode certificate '{certificate_path}': {error}"),
        )
    })?;
    let subject_alt_names = certificate
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to decode the subjectAltName extension of '{certificate_path}': {error}"
                ),
            )
        })?;
    let Some((_critical, SubjectAltName(names))) = subject_alt_names else {
        return Ok(Vec::new());
    };

    Ok(names
        .iter()
        .filter_map(|name| match name {
            // Four octets for IPv4, sixteen for IPv6, in network byte order. Any
            // other length names no address a peer could have dialled.
            GeneralName::IpAddress(octets) => {
                let bytes = octets.as_bytes();
                <[u8; 4]>::try_from(bytes)
                    .map(IpAddr::from)
                    .or_else(|_| <[u8; 16]>::try_from(bytes).map(IpAddr::from))
                    .ok()
            }
            _ => None,
        })
        .collect())
}

/// Why a peer that dials siphon at an advertised IP literal cannot validate the
/// certificate it is served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdvertisedIpProblem {
    /// The certificate carries no iPAddress subjectAltName equal to the IP.
    NotInCertificate,
    /// The certificate could not be read, so the check was not possible.
    CertificateUnreadable(String),
}

/// Whether a listener that advertises `advertised_host` hands TLS peers an IP
/// literal they cannot validate siphon's certificate against, and why.
///
/// A problem only on TLS and WSS, and only for an IPv4 or IPv6 literal (bare, or
/// bracketed as a SIP header carries it) that `certificate_ip_addresses` does
/// not contain. A certificate that could not be read counts as not containing
/// it: a check that could not run must not read as one that passed. A DNS name
/// is never a problem here, whatever the certificate holds.
///
/// Pure, so the rule is testable without a listener; the dispatcher's startup
/// warning runs it for every host a TLS or WSS listener advertises.
pub(crate) fn advertised_ip_problem(
    transport: Transport,
    advertised_host: &str,
    certificate_ip_addresses: Result<&[IpAddr], &str>,
) -> Option<(IpAddr, AdvertisedIpProblem)> {
    if !matches!(transport, Transport::Tls | Transport::WebSocketSecure) {
        return None;
    }
    let ip = crate::sip::uri::strip_ipv6_brackets(advertised_host)
        .parse::<IpAddr>()
        .ok()?;
    match certificate_ip_addresses {
        Ok(addresses) if addresses.contains(&ip) => None,
        Ok(_) => Some((ip, AdvertisedIpProblem::NotInCertificate)),
        Err(error) => Some((
            ip,
            AdvertisedIpProblem::CertificateUnreadable(error.to_string()),
        )),
    }
}

/// Picks the server certificate from the SNI server name in the ClientHello
/// (RFC 6066), the server-side counterpart to the SNI siphon already *sends* on
/// outbound TLS.
///
/// Never returns `None`: an unknown or absent server name falls back to the
/// default pair, so a peer that addresses siphon by IP — or any deployment that
/// configures no `tls.certificates` at all — behaves exactly as it did before
/// SNI selection existed.
#[derive(Debug)]
struct SniCertResolver {
    /// Exact server name (lowercased) → pair.
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// Wildcard parent domain (lowercased, `*.` stripped) → pair. Matches
    /// exactly one leading label, per RFC 6125 §6.4.3.
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    /// `tls.certificate`/`tls.private_key` — served when nothing matches.
    default: Arc<CertifiedKey>,
}

impl SniCertResolver {
    /// Resolve a server name against the configured pairs. Split out from the
    /// `ResolvesServerCert` impl so the matching rules are unit-testable
    /// without synthesising a `ClientHello`.
    fn lookup(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
        let Some(server_name) = server_name else {
            return Arc::clone(&self.default);
        };
        // rustls already rejects a non-ASCII/invalid DnsName during parsing, but
        // it does not case-normalise; DNS names are case-insensitive (RFC 4343).
        let server_name = server_name.to_ascii_lowercase();

        if let Some(certified_key) = self.exact.get(&server_name) {
            return Arc::clone(certified_key);
        }
        // One label off the front only: `ue.example.com` matches
        // `*.example.com`, `a.b.example.com` does not.
        if let Some((_label, parent)) = server_name.split_once('.') {
            if let Some(certified_key) = self.wildcard.get(parent) {
                return Arc::clone(certified_key);
            }
        }
        Arc::clone(&self.default)
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.lookup(client_hello.server_name()))
    }
}

/// Build the SNI resolver from config, loading every configured pair.
///
/// Fails closed at startup on the same server name claimed by two entries (in
/// either the exact or the wildcard form), an entry with no server names, or a
/// malformed wildcard — all of which would otherwise degrade silently into
/// "some tenant gets the wrong certificate". `example.com` and `*.example.com`
/// are different names, so configuring both is fine: the exact one wins for
/// `example.com`, the wildcard covers its subdomains.
fn build_cert_resolver(tls_config: &TlsServerConfig) -> io::Result<SniCertResolver> {
    let default = load_certified_key(&tls_config.certificate, &tls_config.private_key)?;

    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcard: HashMap<String, Arc<CertifiedKey>> = HashMap::new();

    for entry in &tls_config.certificates {
        if entry.server_names.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tls.certificates entry for '{}' has an empty server_names list — \
                     it could never be selected",
                    entry.certificate
                ),
            ));
        }
        let certified_key = load_certified_key(&entry.certificate, &entry.private_key)?;

        for name in &entry.server_names {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "tls.certificates entry for '{}' has an empty server name",
                        entry.certificate
                    ),
                ));
            }
            let (map, key) = match name.strip_prefix("*.") {
                Some(parent) => {
                    if parent.is_empty() || parent.starts_with('.') {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("tls.certificates: malformed wildcard server name '{name}'"),
                        ));
                    }
                    (&mut wildcard, parent.to_string())
                }
                None => {
                    if name.contains('*') {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "tls.certificates: '{name}' — a wildcard is only valid as the \
                                 whole leading label (`*.example.com`)"
                            ),
                        ));
                    }
                    (&mut exact, name.clone())
                }
            };
            if map.insert(key, Arc::clone(&certified_key)).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "tls.certificates: server name '{name}' is configured more than once — \
                         which certificate wins would be arbitrary"
                    ),
                ));
            }
        }
    }

    if !tls_config.certificates.is_empty() {
        info!(
            exact = exact.len(),
            wildcard = wildcard.len(),
            "TLS SNI certificate selection enabled"
        );
    }

    Ok(SniCertResolver {
        exact,
        wildcard,
        default,
    })
}

/// The rustls protocol-version list for a configured `tls.method` floor.
///
/// `tls.method` is a minimum, so `Tls12` yields rustls' own default set (1.2 +
/// 1.3) and only `Tls13` narrows it. Used by both the inbound acceptor here and
/// the outbound client config in [`crate::transport::pool`], so one setting
/// governs the TLS versions siphon negotiates in either direction.
pub(crate) fn protocol_versions(
    method: TlsMethod,
) -> &'static [&'static tokio_rustls::rustls::SupportedProtocolVersion] {
    use tokio_rustls::rustls::version::{TLS12, TLS13};

    static TLS12_FLOOR: &[&tokio_rustls::rustls::SupportedProtocolVersion] = &[&TLS12, &TLS13];
    static TLS13_ONLY: &[&tokio_rustls::rustls::SupportedProtocolVersion] = &[&TLS13];

    match method {
        TlsMethod::Tls12 => TLS12_FLOOR,
        TlsMethod::Tls13 => TLS13_ONLY,
    }
}

/// Build a `TlsAcceptor` from the certificate and key paths in config.
pub fn build_tls_acceptor(tls_config: &TlsServerConfig) -> io::Result<TlsAcceptor> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls;

    let resolver = Arc::new(build_cert_resolver(tls_config)?);

    // Honor `verify_client` (mutual TLS). Previously this was hardcoded to
    // `with_no_client_auth()`, so the config option was silently ignored —
    // setting `verify_client: true` gave false assurance. When enabled we
    // require a client certificate that chains to `client_ca`; a missing CA is
    // a hard startup error (fail closed) rather than a silent downgrade.
    // Honor `tls.method` as the minimum protocol version. Previously this was a
    // bare `builder()` (rustls default = TLS 1.2 + 1.3) and the config value was
    // parsed but never read, so `method: TLSv1_3` claimed a floor nothing
    // enforced — a TLS 1.2 peer still handshook fine.
    let builder =
        rustls::ServerConfig::builder_with_protocol_versions(protocol_versions(tls_config.method));
    info!(
        min_version = %tls_config.method,
        "TLS listener minimum protocol version"
    );
    let server_config = if tls_config.verify_client {
        let ca_path = tls_config.client_ca.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls.verify_client is true but tls.client_ca (PEM CA bundle for \
                 client certificates) is not set",
            )
        })?;
        let ca_file = File::open(ca_path).map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to open client CA file '{ca_path}': {error}"),
            )
        })?;
        let ca_certs: Vec<_> = CertificateDer::pem_reader_iter(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse client CA PEM: {error}"),
                )
            })?;
        if ca_certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client CA file contains no certificates",
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for ca in ca_certs {
            roots.add(ca).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to add client CA to root store: {error}"),
                )
            })?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to build client-certificate verifier: {error}"),
                )
            })?;
        info!(client_ca = %ca_path, "mutual TLS enabled — client certificate required");
        // Client-certificate verification stays listener-wide: rustls can only
        // vary it per SNI name via a custom `ServerConfig` per handshake, and a
        // per-tenant trust anchor is a different feature from a per-tenant
        // server certificate.
        builder
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver)
    } else {
        builder.with_no_client_auth().with_cert_resolver(resolver)
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a `SharedTlsAcceptor` and spawn a watcher that rebuilds it whenever
/// the certificate or private-key file on disk changes (atomic rename, in-place
/// rewrite, or directory swap — handled like the script hot-reload in
/// [`crate::script::engine::spawn_file_watcher`]).
///
/// Existing connections continue using whatever acceptor accepted them — only
/// new handshakes pick up the new cert. That matches the standard cert-renewal
/// model: ACME/cert-manager writes the new pair, siphon picks it up, sessions
/// transition naturally over the renewal window.
pub fn build_hot_reload_acceptor(tls_config: &TlsServerConfig) -> io::Result<SharedTlsAcceptor> {
    let initial = build_tls_acceptor(tls_config)?;
    let shared: SharedTlsAcceptor = Arc::new(ArcSwap::from(Arc::new(initial)));

    // Every configured pair is watched, not just the default — an SNI tenant
    // renews on its own ACME schedule, and a cert that hot-reloads only when
    // some *other* tenant happens to renew is worse than not reloading at all.
    let mut watched_paths: Vec<PathBuf> = vec![
        PathBuf::from(&tls_config.certificate),
        PathBuf::from(&tls_config.private_key),
    ];
    for entry in &tls_config.certificates {
        watched_paths.push(PathBuf::from(&entry.certificate));
        watched_paths.push(PathBuf::from(&entry.private_key));
    }
    let watch_config = tls_config.clone();
    // Weak ref so the watcher exits when the last strong reference (the
    // listener) is dropped. Without this, tests that build an acceptor
    // would leak the spawned task and block runtime shutdown.
    let weak = Arc::downgrade(&shared);

    tokio::task::spawn_blocking(move || {
        use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc;

        let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
            Ok(watcher) => watcher,
            Err(error) => {
                error!(%error, "TLS watcher: failed to create file watcher");
                return;
            }
        };

        // Watch the parent directories so atomic rename (cert-manager, certbot)
        // is observed — they typically swap the file rather than rewrite it.
        // Several pairs commonly share one directory, so de-duplicate: watching
        // the same directory twice yields duplicate events per change.
        let mut watched_dirs: Vec<&std::path::Path> = Vec::new();
        for path in &watched_paths {
            let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            if watched_dirs.contains(&dir) {
                continue;
            }
            if let Err(error) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                warn!(%error, path = %dir.display(),
                    "TLS watcher: failed to watch directory; cert hot-reload disabled");
                return;
            }
            watched_dirs.push(dir);
        }
        info!(
            pairs = watched_paths.len() / 2,
            directories = watched_dirs.len(),
            "TLS cert hot-reload watcher started"
        );

        // Match events by file name — the watch is on the directory, and a
        // rename-into-place reports the destination name.
        let watched_names: Vec<_> = watched_paths
            .iter()
            .filter_map(|path| path.file_name().map(|name| name.to_owned()))
            .collect();

        loop {
            // Poll with a 1s timeout so we can check Weak::upgrade between
            // events — when the listener drops the SharedTlsAcceptor we exit.
            let event = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if weak.upgrade().is_none() {
                        break;
                    }
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let target = match weak.upgrade() {
                Some(target) => target,
                None => break,
            };
            match event {
                Ok(Event {
                    kind: EventKind::Modify(_) | EventKind::Create(_),
                    paths,
                    ..
                }) => {
                    let touched = paths.iter().any(|path| {
                        path.file_name()
                            .is_some_and(|name| watched_names.iter().any(|watched| watched == name))
                    });
                    if !touched {
                        continue;
                    }
                    // Debounce — typical cert renewal writes the key first,
                    // then the cert; wait for the pair to settle.
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    match build_tls_acceptor(&watch_config) {
                        Ok(new_acceptor) => {
                            target.store(Arc::new(new_acceptor));
                            info!("TLS cert hot-reloaded — new handshakes use the updated cert");
                        }
                        Err(error) => {
                            warn!(%error,
                                "TLS hot-reload failed — keeping previous cert. Renewal half-written?");
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "TLS watcher: file event error"),
            }
        }
        debug!("TLS watcher exiting (acceptor dropped)");
    });

    Ok(shared)
}

/// Spawn a TLS listener. Mirrors the TCP listener but wraps each accepted
/// connection in a TLS handshake before spawning read/write tasks.
///
/// Returns the address the listener bound, which carries the port the kernel
/// picked when `local_addr` asks for port 0.
pub async fn listen(
    local_addr: SocketAddr,
    tls_config: &TlsServerConfig,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    stream_connections: StreamConnections,
    tos: Option<u32>,
    pool: Option<Arc<ConnectionPool>>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
    // When set, this listener sits behind a connection-terminating front and
    // every connection must open with a PROXY header from one of these senders.
    proxy_protocol: Option<Arc<ProxyProtocolAcl>>,
) -> std::io::Result<SocketAddr> {
    let acceptor = build_hot_reload_acceptor(tls_config).unwrap_or_else(|error| {
        eprintln!("Failed to build TLS acceptor: {error}");
        std::process::exit(1);
    });

    // Bind before spawning, so that awaiting `listen` means the socket is
    // already accepting. With the bind inside the task, the caller returned
    // first and the listener appeared whenever the runtime got round to it —
    // a peer (or a test) could connect in between and be refused. It also
    // means a bind failure is ordered before the caller continues instead of
    // surfacing as a listener that silently never exists, and before any task
    // is spawned that a failed listener would leave behind.
    let listener = bind_tcp_listener(local_addr, tos)?;
    let bound = listener.local_addr()?;
    info!("TLS listener on {}", bound);

    // Distribute outbound messages to per-connection senders. When no existing
    // connection matches, the distributor falls back to the connection pool to
    // create a new outbound TLS connection (registrant, probes, etc.).
    spawn_outbound_distributor(outbound_rx, connection_map.clone(), Transport::Tls, pool);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut tcp_stream, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        debug!("TLS rejected {} by ACL", remote_addr);
                        continue;
                    }
                    // A listener behind a front talks to the front and nobody
                    // else. Refused before the spawn, so a sender that may not
                    // speak for anyone costs one accept() and nothing more.
                    // Not a ban signal: the likeliest cause is a second front
                    // never added to the list, and banning it would turn a
                    // misconfiguration into an outage.
                    if let Some(allowlist) = &proxy_protocol {
                        if !allowlist.allows(remote_addr.ip()) {
                            warn!(
                                "TLS refusing {remote_addr} on the proxy_protocol listener \
                                 {bound}: not in proxy_protocol.from"
                            );
                            continue;
                        }
                    }
                    // Take the connection + handshake slots before spawning, so
                    // a refusal costs one accept() and nothing else — no task,
                    // no TLS handshake, no CPU. Dropped silently: a port that
                    // answers a probe fingerprints itself, and this is not a ban
                    // signal (a NAT whose UEs all re-register after a flap is
                    // bursty, not abusive).
                    let mut permit = match crate::security::try_accept_connection(remote_addr.ip())
                    {
                        Ok(permit) => permit,
                        Err(reason) => {
                            debug!("TLS refused {} by connection limit: {reason}", remote_addr);
                            crate::security::record_connection_refused(reason);
                            continue;
                        }
                    };
                    // Read the *current* acceptor — it may have been swapped
                    // by the hot-reload watcher since the previous accept().
                    let acceptor = (**acceptor.load()).clone();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();
                    let stream_connections = stream_connections.clone();
                    let crlf_pong_tracker = crlf_pong_tracker.clone();
                    let close_tx = close_tx.clone();
                    let proxy_protocol = proxy_protocol.clone();
                    let acl = Arc::clone(&acl);

                    configure_tcp_socket(&tcp_stream, tos);

                    tokio::spawn(async move {
                        // Captured before anything wraps the socket: once the
                        // stream is a `PrefixedStream`, `get_ref().0` is no
                        // longer the `TcpStream` and cannot answer local_addr.
                        let local_addr = tcp_stream.local_addr().unwrap_or(bound);
                        // The PROXY header is cleartext and arrives ahead of the
                        // ClientHello, so it is read before the handshake. That
                        // ordering is the whole point for a re-encrypting front:
                        // it terminates the phone's TLS and opens its own, and
                        // this is the only place the phone's address exists.
                        let (remote_addr, edge_tls, replay) = if proxy_protocol.is_some() {
                            match accept_proxied(
                                &mut tcp_stream,
                                remote_addr,
                                Transport::Tls,
                                &bound.to_string(),
                            )
                            .await
                            {
                                Some(accepted) => accepted,
                                None => return,
                            }
                        } else {
                            (remote_addr, None, bytes::BytesMut::new())
                        };
                        // Re-check the client the header named: the accept loop
                        // could only test the front, where the ceiling never
                        // trips and a ban never matches. Before the handshake, so
                        // a banned client costs no TLS.
                        if proxy_protocol.is_some() {
                            match crate::transport::proxy_protocol::admit_proxied_client(
                                remote_addr,
                                &acl,
                                Transport::Tls,
                            ) {
                                Some(client_permit) => permit = client_permit,
                                None => return,
                            }
                        }
                        // A front that re-encrypts onto this TLS hop still
                        // reports the client's own session; it agrees with the
                        // hop here rather than contradicting it.
                        let client_transport = crate::transport::proxy_protocol::client_transport(
                            edge_tls.as_ref(),
                            Transport::Tls,
                        );
                        // Replay the over-read into the acceptor, so a
                        // ClientHello that shared a segment with the header is
                        // not lost.
                        let tcp_stream = PrefixedStream::new(tcp_stream, replay);
                        // Perform TLS handshake under a bounded timeout so a peer
                        // that connects and stalls mid-handshake (slowloris) cannot
                        // pin a task + socket indefinitely.
                        let mut tls_stream = match tokio::time::timeout(
                            TLS_HANDSHAKE_TIMEOUT,
                            acceptor.accept(tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                warn!("TLS handshake failed from {}: {}", remote_addr, error);
                                crate::security::record_handshake_failure(remote_addr.ip(), "TLS");
                                return;
                            }
                            Err(_) => {
                                warn!("TLS handshake timed out from {}", remote_addr);
                                crate::security::record_handshake_failure(remote_addr.ip(), "TLS");
                                return;
                            }
                        };

                        // The ACL cleared this source at accept, but the
                        // handshake takes long enough for a sibling connection
                        // from the same burst to have banned it since. Re-check
                        // before spending anything else on the peer.
                        if crate::security::is_source_banned(remote_addr.ip()) {
                            debug!(
                                "TLS dropping {remote_addr}: source banned during its handshake"
                            );
                            return;
                        }

                        // Decide from the first line that this really is SIP,
                        // before any byte reaches the framer — an HTTP probe
                        // frames as a complete "message" and would otherwise
                        // be caught only by the parser, too late to close the
                        // connection or count the source. Classifying ahead of
                        // the connection id also keeps a probe out of the
                        // connection map and out of the accept log.
                        let Some(seed) =
                            sniff_sip_or_drop(&mut tls_stream, remote_addr, Transport::Tls).await
                        else {
                            return;
                        };
                        // Confirmed SIP: give the handshake slot back. The
                        // connection slot stays with `permit` for the life of
                        // the connection below.
                        permit.handshake_done();

                        let connection_id = next_connection_id();
                        debug!("TLS accepted {} as {:?}", remote_addr, connection_id);

                        let (reader, writer) = tokio::io::split(tls_stream);
                        serve_sip_stream(
                            reader,
                            writer,
                            StreamContext {
                                transport: Transport::Tls,
                                client_transport,
                                connection_id,
                                local_addr,
                                remote_addr,
                            },
                            seed,
                            inbound_tx,
                            connection_map,
                            Some(stream_connections),
                            crlf_pong_tracker,
                            close_tx,
                        )
                        .await;
                    });
                }
                Err(error) => {
                    error!("TLS accept error: {}", error);
                }
            }
        }
    });

    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;

    fn test_acl() -> Arc<TransportAcl> {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }

    fn ensure_crypto_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    fn generate_test_cert() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("failed to create cert params");
        let certificate = certificate_params
            .self_signed(&key_pair)
            .expect("self-sign");
        let cert_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();
        (cert_pem, key_pem)
    }

    fn write_test_cert(directory: &tempfile::TempDir) -> TlsServerConfig {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            certificates: vec![],
            method: TlsMethod::default(),
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        }
    }

    #[test]
    fn tls_acceptor_builds_from_valid_config() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_ok(),
            "build_tls_acceptor failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn tls_acceptor_fails_on_missing_cert() {
        ensure_crypto_provider();
        let tls_config = TlsServerConfig {
            certificate: "/nonexistent/cert.pem".to_string(),
            private_key: "/nonexistent/key.pem".to_string(),
            certificates: vec![],
            method: TlsMethod::default(),
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
        let error = result.as_ref().err().unwrap().to_string();
        assert!(
            error.contains("cert"),
            "error should mention cert: {}",
            error
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_acceptor_is_atomically_swappable() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        // Build the SharedTlsAcceptor (this also spawns a watcher task — we don't
        // exercise the file-change path here because it depends on inotify timing
        // that's flaky in CI; just verify the swap mechanism itself works).
        let shared = build_hot_reload_acceptor(&tls_config).unwrap();
        let initial = Arc::clone(&shared.load());

        // Manually rebuild + store a new acceptor.
        let replacement = build_tls_acceptor(&tls_config).unwrap();
        shared.store(Arc::new(replacement));

        let after = Arc::clone(&shared.load());
        assert!(
            !Arc::ptr_eq(&initial, &after),
            "SharedTlsAcceptor did not swap the inner Arc after store()"
        );
    }

    #[test]
    fn tls_acceptor_fails_on_bad_cert_content() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, b"not a certificate").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();

        let tls_config = TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            certificates: vec![],
            method: TlsMethod::default(),
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
    }

    #[test]
    fn verify_client_without_ca_fails_closed() {
        // mTLS: verify_client must be honored. Enabling it without a client_ca
        // is a hard error (fail closed), never a silent no-client-auth downgrade.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.verify_client = true;
        tls_config.client_ca = None;
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_err(),
            "verify_client=true without client_ca must fail closed"
        );
    }

    /// Drive one real handshake against `build_tls_acceptor` with a client
    /// pinned to `client_versions`, and report the version that got negotiated.
    ///
    /// Version enforcement is only observable on the wire — a `ServerConfig`
    /// exposes no "which versions did you enable" accessor — so this is the only
    /// way to prove `tls.method` is honored rather than merely parsed.
    async fn handshake_version(
        tls_config: &TlsServerConfig,
        client_versions: &[&'static tokio_rustls::rustls::SupportedProtocolVersion],
    ) -> Result<tokio_rustls::rustls::ProtocolVersion, String> {
        use rustls_pki_types::pem::PemObject;
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let acceptor = build_tls_acceptor(tls_config).map_err(|error| error.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            // Result deliberately ignored: on a version mismatch the server
            // errors too, and the assertion under test is the client's.
            let _ = acceptor.accept(stream).await;
        });

        let cert_pem = std::fs::read(&tls_config.certificate).expect("read test cert");
        let mut cursor = std::io::Cursor::new(cert_pem);
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse test cert");
        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).expect("trust test cert");
        }

        let client_config = rustls::ClientConfig::builder_with_protocol_versions(client_versions)
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let server_name = rustls_pki_types::ServerName::try_from("localhost").expect("server name");

        let outcome = connector
            .connect(server_name, tcp_stream)
            .await
            .map(|stream| {
                stream
                    .get_ref()
                    .1
                    .protocol_version()
                    .expect("negotiated protocol version")
            })
            .map_err(|error| error.to_string());

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
        outcome
    }

    #[tokio::test]
    async fn tls_method_tls13_refuses_a_tls12_client() {
        // `method: TLSv1_3` used to be parsed and dropped on the floor, so a TLS
        // 1.2 peer handshook fine against a config that claimed 1.3-only.
        ensure_crypto_provider();
        use tokio_rustls::rustls::version::{TLS12, TLS13};

        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.method = TlsMethod::Tls13;

        let refused = handshake_version(&tls_config, &[&TLS12]).await;
        assert!(
            refused.is_err(),
            "tls.method TLSv1_3 must refuse a TLS 1.2 client, got {refused:?}"
        );

        let accepted = handshake_version(&tls_config, &[&TLS13]).await;
        assert_eq!(
            accepted,
            Ok(tokio_rustls::rustls::ProtocolVersion::TLSv1_3),
            "tls.method TLSv1_3 must still serve TLS 1.3"
        );
    }

    #[tokio::test]
    async fn tls_method_tls12_is_a_floor_not_a_pin() {
        // TLSv1_2 is a minimum: a 1.3-capable peer must still get 1.3, or
        // "require at least 1.2" would silently become "downgrade everyone".
        ensure_crypto_provider();
        use tokio_rustls::rustls::version::{TLS12, TLS13};

        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.method = TlsMethod::Tls12;

        assert_eq!(
            handshake_version(&tls_config, &[&TLS12]).await,
            Ok(tokio_rustls::rustls::ProtocolVersion::TLSv1_2)
        );
        assert_eq!(
            handshake_version(&tls_config, &[&TLS13]).await,
            Ok(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
        );
    }

    #[tokio::test]
    async fn default_tls_method_keeps_serving_tls12_and_tls13() {
        // The default must not tighten on upgrade: a config with no `method` line
        // serves exactly what siphon served before the setting was wired.
        ensure_crypto_provider();
        use tokio_rustls::rustls::version::{TLS12, TLS13};

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);
        assert_eq!(tls_config.method, TlsMethod::Tls12, "default floor");

        assert_eq!(
            handshake_version(&tls_config, &[&TLS12]).await,
            Ok(tokio_rustls::rustls::ProtocolVersion::TLSv1_2)
        );
        assert_eq!(
            handshake_version(&tls_config, &[&TLS13]).await,
            Ok(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
        );
    }

    #[tokio::test]
    async fn tls_connection_lifecycle() {
        ensure_crypto_provider();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        // Start the TLS listener on a port the kernel picks.
        let bound_addr = listen(
            "127.0.0.1:0".parse().unwrap(),
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            StreamConnections::new(),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("tls listener must bind");
        assert_ne!(bound_addr.port(), 0, "listen must return the port it bound");

        // Read the cert back to build a client config that trusts it
        let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(cert_pem);
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        // Connect as a TLS client
        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send a SIP REGISTER
        let sip_message = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS 10.0.0.1:5061;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=abc123\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: test-tls-lifecycle@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        tls_stream.write_all(sip_message.as_bytes()).await.unwrap();

        // Receive the inbound message
        let message =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv_async())
                .await
                .expect("timed out waiting for inbound message")
                .expect("inbound channel closed");

        assert_eq!(message.transport, Transport::Tls);
        assert_eq!(message.local_addr, bound_addr);
        assert!(!message.data.is_empty());
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(
            data_str.contains("REGISTER"),
            "expected REGISTER in data: {}",
            data_str
        );

        // Verify connection is tracked
        assert!(connection_map.contains_key(&message.connection_id));
    }

    #[tokio::test]
    async fn tls_connection_cleanup_on_client_drop() {
        ensure_crypto_provider();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let stream_connections = StreamConnections::new();

        let bound_addr = listen(
            "127.0.0.1:0".parse().unwrap(),
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            stream_connections.clone(),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("tls listener must bind");
        assert_ne!(bound_addr.port(), 0, "listen must return the port it bound");

        // Build TLS client
        let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(cert_pem);
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send data so the connection gets an ID
        tls_stream
            .write_all(b"REGISTER sip:test SIP/2.0\r\n\r\n")
            .await
            .unwrap();
        let message =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv_async())
                .await
                .unwrap()
                .unwrap();

        let connection_id = message.connection_id;
        let remote_addr = message.remote_addr;
        assert!(connection_map.contains_key(&connection_id));
        // Verify the registry is populated for connection reuse (tagged TLS).
        assert_eq!(
            stream_connections.reuse(remote_addr, Transport::Tls),
            Some(connection_id),
            "stream registry should track the TLS connection by remote address"
        );
        assert_eq!(
            stream_connections.get(&remote_addr),
            Some((Transport::Tls, connection_id)),
        );

        // Drop the client
        drop(tls_stream);

        // Wait for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !connection_map.contains_key(&connection_id),
            "connection should have been cleaned up after client drop"
        );
        assert_eq!(
            stream_connections.reuse(remote_addr, Transport::Tls),
            None,
            "stream registry should be cleaned up after client drop"
        );
    }

    // --- SNI certificate selection (RFC 6066) -----------------------------

    /// Self-signed cert + key PEM for the given SAN DNS names.
    fn generate_cert_for(names: &[&str]) -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let certificate_params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .expect("failed to create cert params");
        let certificate = certificate_params
            .self_signed(&key_pair)
            .expect("self-sign");
        (certificate.pem(), key_pair.serialize_pem())
    }

    /// Write a cert/key pair into `directory` under `stem`, returning the paths.
    fn write_pair(directory: &tempfile::TempDir, stem: &str, names: &[&str]) -> (String, String) {
        let (cert_pem, key_pem) = generate_cert_for(names);
        let cert_path = directory.path().join(format!("{stem}-cert.pem"));
        let key_path = directory.path().join(format!("{stem}-key.pem"));
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        (
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        )
    }

    fn sni_entry(
        directory: &tempfile::TempDir,
        stem: &str,
        names: &[&str],
    ) -> crate::config::SniCertificate {
        let (certificate, private_key) = write_pair(directory, stem, names);
        crate::config::SniCertificate {
            server_names: names.iter().map(|n| n.to_string()).collect(),
            certificate,
            private_key,
        }
    }

    /// DER of the end-entity cert a resolver hands back for `server_name`.
    fn resolved_der(resolver: &SniCertResolver, server_name: Option<&str>) -> Vec<u8> {
        resolver.lookup(server_name).cert[0].as_ref().to_vec()
    }

    /// DER of the end-entity cert in a PEM file on disk.
    fn der_of(certificate_path: &str) -> Vec<u8> {
        use rustls_pki_types::pem::PemObject;
        let pem = std::fs::read(certificate_path).unwrap();
        let mut cursor = std::io::Cursor::new(pem);
        let certificates: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        certificates[0].as_ref().to_vec()
    }

    #[test]
    fn sni_resolver_picks_exact_match_and_falls_back_to_default() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let tenant = sni_entry(&directory, "tenant-a", &["sip.tenant-a.test"]);
        let tenant_der = der_of(&tenant.certificate);
        let default_der = der_of(&tls_config.certificate);
        tls_config.certificates = vec![tenant];

        let resolver = build_cert_resolver(&tls_config).expect("resolver");

        assert_eq!(
            resolved_der(&resolver, Some("sip.tenant-a.test")),
            tenant_der,
            "exact SNI match must serve that tenant's certificate"
        );
        // A name nobody configured, and a client that sent no SNI at all (every
        // IP-literal peer — RFC 6066 forbids SNI for an IP), both get the
        // default pair. Neither may abort the handshake.
        assert_eq!(
            resolved_der(&resolver, Some("unconfigured.test")),
            default_der,
            "unknown SNI must fall back to the default certificate"
        );
        assert_eq!(
            resolved_der(&resolver, None),
            default_der,
            "absent SNI must fall back to the default certificate"
        );
    }

    #[test]
    fn sni_resolver_matches_one_wildcard_label_only() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let wild = sni_entry(&directory, "wild", &["*.wild.test"]);
        let wild_der = der_of(&wild.certificate);
        let default_der = der_of(&tls_config.certificate);
        tls_config.certificates = vec![wild];

        let resolver = build_cert_resolver(&tls_config).expect("resolver");

        assert_eq!(
            resolved_der(&resolver, Some("ue.wild.test")),
            wild_der,
            "`*.wild.test` must match a single leading label"
        );
        // RFC 6125 §6.4.3: a wildcard matches exactly one label — not the bare
        // domain, and not a deeper subdomain.
        assert_eq!(
            resolved_der(&resolver, Some("wild.test")),
            default_der,
            "`*.wild.test` must NOT match the bare domain"
        );
        assert_eq!(
            resolved_der(&resolver, Some("a.b.wild.test")),
            default_der,
            "`*.wild.test` must NOT match a multi-label subdomain"
        );
    }

    #[test]
    fn sni_resolver_is_case_insensitive() {
        // DNS names are case-insensitive (RFC 4343); rustls does not normalise
        // the ClientHello value, so the resolver must.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let mut tenant = sni_entry(&directory, "tenant-b", &["sip.tenant-b.test"]);
        tenant.server_names = vec!["SIP.Tenant-B.TEST".to_string()];
        let tenant_der = der_of(&tenant.certificate);
        tls_config.certificates = vec![tenant];

        let resolver = build_cert_resolver(&tls_config).expect("resolver");

        for probe in [
            "sip.tenant-b.test",
            "SIP.TENANT-B.TEST",
            "Sip.Tenant-b.Test",
        ] {
            assert_eq!(
                resolved_der(&resolver, Some(probe)),
                tenant_der,
                "SNI matching must be case-insensitive (probe: {probe})"
            );
        }
    }

    #[test]
    fn sni_exact_match_wins_over_wildcard() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let wild = sni_entry(&directory, "wild", &["*.shared.test"]);
        let exact = sni_entry(&directory, "exact", &["vip.shared.test"]);
        let exact_der = der_of(&exact.certificate);
        let wild_der = der_of(&wild.certificate);
        tls_config.certificates = vec![wild, exact];

        let resolver = build_cert_resolver(&tls_config).expect("resolver");

        assert_eq!(
            resolved_der(&resolver, Some("vip.shared.test")),
            exact_der,
            "a specific name must win over a wildcard covering it"
        );
        assert_eq!(
            resolved_der(&resolver, Some("other.shared.test")),
            wild_der,
            "names not called out explicitly still take the wildcard"
        );
    }

    #[test]
    fn empty_certificates_list_preserves_single_cert_behaviour() {
        // The no-SNI-configured path must be indistinguishable from the
        // pre-SNI build: one cert served to everyone, whatever they ask for.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);
        let default_der = der_of(&tls_config.certificate);

        let resolver = build_cert_resolver(&tls_config).expect("resolver");

        for probe in [None, Some("anything.test"), Some("localhost")] {
            assert_eq!(resolved_der(&resolver, probe), default_der);
        }
    }

    #[test]
    fn duplicate_server_name_fails_closed() {
        // Two pairs claiming one name: whichever won would be arbitrary, and an
        // operator would only find out by watching which cert peers received.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.certificates = vec![
            sni_entry(&directory, "first", &["dup.test"]),
            sni_entry(&directory, "second", &["dup.test"]),
        ];

        let error = build_cert_resolver(&tls_config)
            .expect_err("duplicate server name must fail closed")
            .to_string();
        assert!(
            error.contains("dup.test"),
            "error should name the duplicate: {error}"
        );
    }

    #[test]
    fn duplicate_wildcard_server_name_fails_closed() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.certificates = vec![
            sni_entry(&directory, "first", &["*.dup.test"]),
            sni_entry(&directory, "second", &["*.dup.test"]),
        ];

        assert!(
            build_cert_resolver(&tls_config).is_err(),
            "duplicate wildcard server name must fail closed"
        );
    }

    #[test]
    fn empty_server_names_fails_closed() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let mut entry = sni_entry(&directory, "orphan", &["orphan.test"]);
        entry.server_names = vec![];
        tls_config.certificates = vec![entry];

        assert!(
            build_cert_resolver(&tls_config).is_err(),
            "an entry that can never be selected must fail closed, not load silently"
        );
    }

    #[test]
    fn malformed_wildcard_fails_closed() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let base = write_test_cert(&directory);

        // A wildcard is only meaningful as the entire leading label. `sip*.x`
        // and a bare `*` would silently never match anything.
        for bad in ["*", "*.", "sip*.example.test", "a.*.example.test"] {
            let mut tls_config = base.clone();
            let mut entry = sni_entry(&directory, "bad", &["placeholder.test"]);
            entry.server_names = vec![bad.to_string()];
            tls_config.certificates = vec![entry];
            assert!(
                build_cert_resolver(&tls_config).is_err(),
                "malformed wildcard '{bad}' must fail closed"
            );
        }
    }

    #[test]
    fn missing_sni_certificate_file_fails_closed_naming_the_path() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.certificates = vec![crate::config::SniCertificate {
            server_names: vec!["ghost.test".to_string()],
            certificate: "/nonexistent/tenant-cert.pem".to_string(),
            private_key: "/nonexistent/tenant-key.pem".to_string(),
        }];

        let error = build_cert_resolver(&tls_config)
            .expect_err("missing SNI cert file must fail closed")
            .to_string();
        assert!(
            error.contains("/nonexistent/tenant-cert.pem"),
            "error must name the offending path, not just 'certificate': {error}"
        );
    }

    #[test]
    fn acceptor_builds_with_sni_certificates() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.certificates = vec![
            sni_entry(&directory, "tenant-a", &["sip.tenant-a.test"]),
            sni_entry(&directory, "wild", &["*.wild.test"]),
        ];

        assert!(
            build_tls_acceptor(&tls_config).is_ok(),
            "acceptor must build with SNI certificates configured"
        );
    }

    #[test]
    fn sni_certificates_work_with_mutual_tls() {
        // mTLS is listener-wide and must keep working alongside per-name certs.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let (ca_path, _ca_key) = write_pair(&directory, "ca", &["ca.test"]);
        tls_config.verify_client = true;
        tls_config.client_ca = Some(ca_path);
        tls_config.certificates = vec![sni_entry(&directory, "tenant-a", &["sip.tenant-a.test"])];

        assert!(
            build_tls_acceptor(&tls_config).is_ok(),
            "SNI selection must compose with verify_client"
        );
    }

    /// Drive one real TLS handshake against `acceptor`, asking for `server_name`,
    /// and return the DER of the end-entity certificate the server presented.
    async fn handshake_peer_cert(
        tls_config: &TlsServerConfig,
        server_name: &str,
        trusted: &[&str],
    ) -> Vec<u8> {
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let acceptor = build_tls_acceptor(tls_config).expect("acceptor");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // The handshake is all this test needs; the client drops right after.
            let _ = acceptor.accept(stream).await;
        });

        let mut root_store = rustls::RootCertStore::empty();
        for certificate_path in trusted {
            use rustls_pki_types::pem::PemObject;
            let pem = std::fs::read(certificate_path).unwrap();
            let mut cursor = std::io::Cursor::new(pem);
            for certificate in rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor) {
                root_store.add(certificate.unwrap()).unwrap();
            }
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let tls_stream = connector
            .connect(name, tcp_stream)
            .await
            .unwrap_or_else(|error| panic!("client handshake for '{server_name}' failed: {error}"));
        let peer = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .expect("server presented no certificate")[0]
            .as_ref()
            .to_vec();
        drop(tls_stream);
        let _ = server.await;
        peer
    }

    #[tokio::test]
    async fn handshake_serves_the_certificate_matching_the_client_sni() {
        // End-to-end proof over a real handshake: the cert a client receives is
        // chosen by the name it asked for, and it validates against that name.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        let tenant = sni_entry(&directory, "tenant-a", &["sip.tenant-a.test"]);
        let wild = sni_entry(&directory, "wild", &["*.wild.test"]);
        let tenant_cert_path = tenant.certificate.clone();
        let wild_cert_path = wild.certificate.clone();
        let default_cert_path = tls_config.certificate.clone();
        tls_config.certificates = vec![tenant, wild];

        let trusted = [
            default_cert_path.as_str(),
            tenant_cert_path.as_str(),
            wild_cert_path.as_str(),
        ];

        assert_eq!(
            handshake_peer_cert(&tls_config, "sip.tenant-a.test", &trusted).await,
            der_of(&tenant_cert_path),
            "SNI 'sip.tenant-a.test' must be served the tenant certificate"
        );
        assert_eq!(
            handshake_peer_cert(&tls_config, "ue.wild.test", &trusted).await,
            der_of(&wild_cert_path),
            "SNI 'ue.wild.test' must be served the wildcard certificate"
        );
        assert_eq!(
            handshake_peer_cert(&tls_config, "localhost", &trusted).await,
            der_of(&default_cert_path),
            "an unmatched SNI must be served the default certificate"
        );
    }

    // --- Advertised IP literal vs the certificate's iPAddress SANs ---------

    /// Write a self-signed certificate for `names` and read back its iPAddress
    /// subjectAltNames the way startup does. rcgen writes an IP literal as an
    /// iPAddress SAN and anything else as a dNSName.
    fn ip_addresses_of_certificate_for(names: &[&str]) -> Vec<IpAddr> {
        let directory = tempfile::tempdir().unwrap();
        let (certificate_path, _private_key_path) = write_pair(&directory, "advertised", names);
        certificate_ip_addresses(&certificate_path).expect("read the certificate SANs")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn certificate_ip_addresses_reads_only_ip_subject_alt_names() {
        assert_eq!(
            ip_addresses_of_certificate_for(&["sip.example.com", "192.0.2.10", "2001:db8::10"]),
            vec![ip("192.0.2.10"), ip("2001:db8::10")]
        );
        assert!(ip_addresses_of_certificate_for(&["sip.example.com"]).is_empty());
    }

    #[test]
    fn certificate_ip_addresses_fails_without_a_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let error = certificate_ip_addresses(empty.to_str().unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("contains no certificates"),
            "{error}"
        );

        let missing = directory.path().join("missing.pem");
        let error = certificate_ip_addresses(missing.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("missing.pem"), "{error}");
    }

    #[test]
    fn advertised_ipv4_literal_the_certificate_lacks_is_a_problem() {
        let certificate = ip_addresses_of_certificate_for(&["sip.example.com"]);
        assert_eq!(
            advertised_ip_problem(Transport::Tls, "192.0.2.10", Ok(certificate.as_slice())),
            Some((ip("192.0.2.10"), AdvertisedIpProblem::NotInCertificate))
        );
    }

    #[test]
    fn advertised_ipv6_literal_the_certificate_lacks_is_a_problem() {
        let certificate = ip_addresses_of_certificate_for(&["sip.example.com"]);
        // Bracketed, as the resolver formats it for a SIP header, and bare.
        for host in ["[2001:db8::10]", "2001:db8::10"] {
            assert_eq!(
                advertised_ip_problem(Transport::Tls, host, Ok(certificate.as_slice())),
                Some((ip("2001:db8::10"), AdvertisedIpProblem::NotInCertificate)),
                "{host}"
            );
        }
    }

    #[test]
    fn advertised_dns_name_is_never_a_problem() {
        let certificate = ip_addresses_of_certificate_for(&["192.0.2.10"]);
        assert_eq!(certificate, vec![ip("192.0.2.10")], "fixture");
        assert_eq!(
            advertised_ip_problem(
                Transport::Tls,
                "sip.example.com",
                Ok(certificate.as_slice())
            ),
            None
        );
        // Not even when the certificate could not be read: a DNS name needs no
        // iPAddress SAN.
        assert_eq!(
            advertised_ip_problem(Transport::Tls, "sip.example.com", Err("unreadable")),
            None
        );
    }

    #[test]
    fn advertised_ip_carried_as_an_ip_subject_alt_name_is_not_a_problem() {
        let certificate =
            ip_addresses_of_certificate_for(&["sip.example.com", "192.0.2.10", "2001:db8::10"]);
        // Guard: without it an unread certificate would pass this vacuously.
        assert_eq!(certificate.len(), 2, "fixture: {certificate:?}");
        for host in ["192.0.2.10", "[2001:db8::10]"] {
            assert_eq!(
                advertised_ip_problem(Transport::Tls, host, Ok(certificate.as_slice())),
                None,
                "{host}"
            );
        }
    }

    #[test]
    fn advertised_ip_not_matching_the_certificate_ip_subject_alt_name_is_a_problem() {
        let certificate = ip_addresses_of_certificate_for(&["192.0.2.11", "2001:db8::11"]);
        assert_eq!(certificate.len(), 2, "fixture: {certificate:?}");
        assert_eq!(
            advertised_ip_problem(Transport::Tls, "192.0.2.10", Ok(certificate.as_slice())),
            Some((ip("192.0.2.10"), AdvertisedIpProblem::NotInCertificate))
        );
        assert_eq!(
            advertised_ip_problem(Transport::Tls, "[2001:db8::10]", Ok(certificate.as_slice())),
            Some((ip("2001:db8::10"), AdvertisedIpProblem::NotInCertificate))
        );
    }

    #[test]
    fn unreadable_certificate_is_a_problem_for_an_ip_literal() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.pem");
        let error = certificate_ip_addresses(missing.to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert_eq!(
            advertised_ip_problem(Transport::Tls, "192.0.2.10", Err(&error)),
            Some((
                ip("192.0.2.10"),
                AdvertisedIpProblem::CertificateUnreadable(error.clone())
            ))
        );
    }

    #[test]
    fn wss_follows_the_same_rules_and_plaintext_transports_are_never_checked() {
        let certificate = ip_addresses_of_certificate_for(&["sip.example.com", "192.0.2.10"]);
        assert_eq!(certificate, vec![ip("192.0.2.10")], "fixture");
        for transport in [Transport::Tls, Transport::WebSocketSecure] {
            assert_eq!(
                advertised_ip_problem(transport, "198.51.100.1", Ok(certificate.as_slice())),
                Some((ip("198.51.100.1"), AdvertisedIpProblem::NotInCertificate)),
                "{transport}"
            );
            assert_eq!(
                advertised_ip_problem(transport, "192.0.2.10", Ok(certificate.as_slice())),
                None,
                "{transport}"
            );
            assert_eq!(
                advertised_ip_problem(transport, "sip.example.com", Ok(certificate.as_slice())),
                None,
                "{transport}"
            );
            assert_eq!(
                advertised_ip_problem(transport, "198.51.100.1", Err("unreadable")),
                Some((
                    ip("198.51.100.1"),
                    AdvertisedIpProblem::CertificateUnreadable("unreadable".to_string())
                )),
                "{transport}"
            );
        }
        for transport in [
            Transport::Udp,
            Transport::Tcp,
            Transport::WebSocket,
            Transport::Sctp,
        ] {
            assert_eq!(
                advertised_ip_problem(transport, "198.51.100.1", Ok(certificate.as_slice())),
                None,
                "{transport}"
            );
            assert_eq!(
                advertised_ip_problem(transport, "198.51.100.1", Err("unreadable")),
                None,
                "{transport}"
            );
        }
    }
}
