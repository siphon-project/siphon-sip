//! Client-side TLS for the outbound SIP connection pool, and whether it
//! authenticates the server it dials.
//!
//! [`client_tls`](crate::transport::client_tls) serves siphon's other outbound
//! TLS feeds (CDR, HEP, the control plane), which always verify. The SIP pool is
//! different: trunks and interconnect peers often present certificates that do
//! not chain to anything a deployment trusts, so the pool has always dialled
//! without verifying the server, the same default as Kamailio/OpenSIPS
//! `verify_server = 0`. That keeps the connection encrypted but not
//! authenticated: the caller identity and any SDES keys in the SDP go to
//! whoever answers on the address.
//!
//! Verification is opt-in, globally (`tls.verify_server`) or per destination
//! (a gateway destination or group, a control `dial` target). The pool holds
//! two client configs side by side, [`OutboundTlsConfigs`], and a connection
//! opened with one is never reused for a send that asked for the other (see
//! the pool key in [`crate::transport::pool`]).
//!
//! What a verified connection checks:
//!
//! * the chain, against `tls.server_ca` or the bundled Mozilla roots;
//! * the name the connection was opened for, never the address it resolved to.
//!   For a hostname that is the host of the URI siphon routed on (RFC 5922 §4:
//!   the domain of the URI being resolved, not an SRV target, which DNS without
//!   DNSSEC cannot vouch for), matched as a SIP domain per RFC 5922 §7.1-7.2: a
//!   `sip:` URI subjectAltName without a user part wins over dNSName entries,
//!   matching is exact, and a wildcard never matches. For an IP-literal target
//!   it is an iPAddress subjectAltName (RFC 6125 §6.2.1 via rustls/webpki).
//!
//! The common name is not consulted (RFC 5922 §7.1 permits but does not require
//! it, and RFC 6125 §6.4.4 deprecates it).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::config::TlsMethod;

/// A client identity siphon presents on OUTBOUND TLS connections when the
/// upstream peer requests one (mutual TLS — SIP trunks that require
/// client-certificate auth, e.g. carrier interconnects).
///
/// Owned (`'static`) so it can be moved into the long-lived `ClientConfig`.
pub struct OutboundClientIdentity {
    pub chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    pub key: tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>,
}

/// Load an [`OutboundClientIdentity`] from a PEM certificate-chain path and a
/// PEM private-key path.
///
/// Mirrors the loading/validation in [`crate::transport::tls::build_tls_acceptor`]:
/// the files must be readable, the chain must contain at least one certificate,
/// and the key must parse. Returns a clear `io::Error` otherwise.
pub fn load_outbound_client_identity(
    certificate_path: &str,
    private_key_path: &str,
) -> Result<OutboundClientIdentity, std::io::Error> {
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_file = File::open(certificate_path).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("failed to open outbound client certificate '{certificate_path}': {error}"),
        )
    })?;
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse outbound client certificate PEM: {error}"),
                )
            })?;
    if chain.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "outbound client certificate file contains no certificates",
        ));
    }

    let key_file = File::open(private_key_path).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("failed to open outbound client private key '{private_key_path}': {error}"),
        )
    })?;
    let key =
        PrivateKeyDer::from_pem_reader(&mut BufReader::new(key_file)).map_err(
            |error| match error {
                tokio_rustls::rustls::pki_types::pem::Error::NoItemsFound => std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "outbound client private key file contains no private key",
                ),
                other => std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse outbound client private key PEM: {other}"),
                ),
            },
        )?;

    Ok(OutboundClientIdentity { chain, key })
}

impl OutboundClientIdentity {
    /// A second copy, for the second client config: a `ClientConfig` takes its
    /// identity by value, and the pool builds a verifying and a non-verifying
    /// one from the same files.
    fn duplicate(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

/// Build the TLS client config that accepts any server certificate.
///
/// This is the pool's default, and what every outbound SIP TLS connection used
/// before verification existed: trunks and interconnect peers rarely present
/// certificates chained to public CAs, so the server is not verified (the same
/// default as OpenSIPS/Kamailio `verify_server = 0`). Its verifying counterpart
/// is built by [`build_outbound_tls_configs`].
///
/// When `identity` is `Some`, siphon presents that client certificate chain +
/// key; when `None`, no client certificate is presented (prior behavior).
///
/// `method` is the `tls.method` floor, applied here as well as on the inbound
/// acceptor: it is one process-wide statement about which TLS versions siphon
/// speaks, so `TLSv1_3` refuses to *dial* a TLS 1.2 trunk just as it refuses to
/// accept a TLS 1.2 client. Without a `tls:` block the default floor (1.2)
/// applies, which is what outbound TLS has always negotiated.
pub fn build_outbound_tls_config(
    identity: Option<OutboundClientIdentity>,
    method: TlsMethod,
) -> Result<Arc<ClientConfig>, io::Error> {
    let builder = ClientConfig::builder_with_protocol_versions(
        crate::transport::tls::protocol_versions(method),
    )
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerify));
    with_identity(builder, identity)
}

/// Finish a client config builder with the client identity, or without one.
fn with_identity(
    builder: rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
    identity: Option<OutboundClientIdentity>,
) -> Result<Arc<ClientConfig>, io::Error> {
    let config = match identity {
        Some(identity) => builder
            .with_client_auth_cert(identity.chain, identity.key)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to build outbound client-auth TLS config: {error}"),
                )
            })?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// The trust siphon verifies outbound SIP TLS servers against, and whether it
/// does so for a destination that says nothing either way.
///
/// From `tls.verify_server` and `tls.server_ca`. The roots are built even when
/// the default is off, because a gateway or a `dial` target can still ask for
/// verification on its own.
#[derive(Clone)]
pub struct ServerVerification {
    roots: Arc<RootCertStore>,
    verify_by_default: bool,
}

impl ServerVerification {
    /// Trust `server_ca` (a PEM bundle, which **replaces** the public roots
    /// rather than adding to them: see
    /// [`client_tls::client_config`](crate::transport::client_tls::client_config)),
    /// or the bundled Mozilla roots when it is `None`.
    ///
    /// An unreadable, empty or non-PEM bundle is an error naming the path, so
    /// a typo fails the load instead of leaving a store that trusts nothing and
    /// refuses every trunk with an error that reads like the trunk's fault.
    pub fn new(verify_by_default: bool, server_ca: Option<&str>) -> io::Result<Self> {
        Ok(Self {
            roots: Arc::new(crate::transport::client_tls::root_store(server_ca)?),
            verify_by_default,
        })
    }

    /// The bundled Mozilla roots, which cannot fail to load.
    pub fn public_roots(verify_by_default: bool) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            roots: Arc::new(roots),
            verify_by_default,
        }
    }

    /// Whether a destination with no `verify_server` of its own is verified.
    pub fn verify_by_default(&self) -> bool {
        self.verify_by_default
    }
}

/// The pool's two client configs: one that verifies the server and one that
/// does not, built from the same client identity and version floor.
pub struct OutboundTlsConfigs {
    /// Accepts any server certificate ([`build_outbound_tls_config`]).
    pub unverified: Arc<ClientConfig>,
    /// Verifies the chain and the name the connection was opened for.
    pub verified: Arc<ClientConfig>,
    /// Whether a send that names no policy of its own takes `verified`.
    pub verify_by_default: bool,
}

/// Build both client configs the pool dials with.
///
/// Both present `identity` when the peer asks for a client certificate, so
/// outbound mutual TLS keeps working with verification on.
pub fn build_outbound_tls_configs(
    identity: Option<OutboundClientIdentity>,
    method: TlsMethod,
    verification: &ServerVerification,
) -> Result<OutboundTlsConfigs, io::Error> {
    let verified_identity = identity.as_ref().map(OutboundClientIdentity::duplicate);
    let unverified = build_outbound_tls_config(identity, method)?;
    let verified =
        build_verifying_tls_config(verified_identity, method, Arc::clone(&verification.roots))?;
    Ok(OutboundTlsConfigs {
        unverified,
        verified,
        verify_by_default: verification.verify_by_default,
    })
}

/// The verifying client config: [`SipServerVerifier`] over `roots`.
fn build_verifying_tls_config(
    identity: Option<OutboundClientIdentity>,
    method: TlsMethod,
    roots: Arc<RootCertStore>,
) -> Result<Arc<ClientConfig>, io::Error> {
    let provider = crate::transport::tls::crypto_provider();
    let verifier = SipServerVerifier::new(roots, Arc::clone(&provider))?;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(crate::transport::tls::protocol_versions(method))
        .map_err(|error| io::Error::other(format!("no usable TLS protocol versions: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    with_identity(builder, identity)
}

/// The name a verified connection to `destination` is checked against, as the
/// pool keys it: the routed host, lowercased and without IPv6 brackets or a
/// trailing dot, or the destination's IP literal when nothing named a host.
pub(crate) fn expected_server_name(destination: SocketAddr, server_name: Option<&str>) -> String {
    match server_name {
        Some(host) => normalize_host(host),
        None => destination.ip().to_string(),
    }
}

/// Lowercase, unbracket and drop a trailing root dot, so two spellings of one
/// host compare equal.
fn normalize_host(host: &str) -> String {
    let host = crate::sip::uri::strip_ipv6_brackets(host);
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// The name a REGISTER over TLS presents and, with `tls.verify_server`, checks
/// the registrar's certificate against: the host of its Request-URI, which is
/// the registrar's domain (RFC 3261 §10.2) and the URI it was routed on
/// (RFC 5922 §4), never the address that resolved to. `None` off TLS.
pub(crate) fn registrar_server_name(
    message: &crate::sip::message::SipMessage,
    transport: crate::transport::Transport,
) -> Option<String> {
    (transport == crate::transport::Transport::Tls)
        .then(|| message.request_uri().map(|uri| uri.host.clone()))
        .flatten()
}

/// Resolve the TLS `ServerName` (SNI / certificate name) for an outbound
/// handshake.
///
/// When `sni` is `Some(host)`, the hostname is used (RFC 6066 SNI is emitted so
/// a hostname-vhost front-end can route the handshake), and an IP literal in it
/// (brackets allowed) becomes an IP-address name, which sends no SNI. When
/// `None`, the destination IP literal is used.
pub(crate) fn resolve_server_name(
    destination: SocketAddr,
    sni: Option<&str>,
) -> Result<ServerName<'static>, io::Error> {
    let name = match sni {
        Some(host) => crate::sip::uri::strip_ipv6_brackets(host).to_owned(),
        None => destination.ip().to_string(),
    };
    ServerName::try_from(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

/// Verifies an outbound SIP server: chain to `roots`, then the name.
///
/// An IP-address name goes to rustls' own verifier, which checks an iPAddress
/// subjectAltName. A DNS name is checked as a SIP domain ([`sip_domain_identities`]),
/// because rustls' dNSName matching accepts wildcards and ignores `sip:` URI
/// entries, both of which RFC 5922 §7 rules the other way.
#[derive(Debug)]
struct SipServerVerifier {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    webpki: Arc<WebPkiServerVerifier>,
}

impl SipServerVerifier {
    fn new(roots: Arc<RootCertStore>, provider: Arc<CryptoProvider>) -> io::Result<Self> {
        let webpki =
            WebPkiServerVerifier::builder_with_provider(Arc::clone(&roots), Arc::clone(&provider))
                .build()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("cannot build the outbound TLS server verifier: {error}"),
                    )
                })?;
        Ok(Self {
            roots,
            provider,
            webpki,
        })
    }
}

impl ServerCertVerifier for SipServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ServerName::DnsName(dns_name) = server_name else {
            return self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        };
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        let identities = sip_domain_identities(end_entity.as_ref());
        if matches_sip_domain(dns_name.as_ref(), &identities) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext {
                    expected: server_name.to_owned(),
                    presented: identities,
                },
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// The SIP domain identities a certificate asserts (RFC 5922 §7.1).
///
/// Every `sip:` URI subjectAltName without a user part names a domain; when
/// there is at least one, those are the identities and the dNSName entries are
/// not consulted. Otherwise the dNSName entries are. A URI of another scheme,
/// or one naming a user, is no domain identity. A certificate that does not
/// parse, or carries no (or more than one) subjectAltName extension, asserts
/// none.
fn sip_domain_identities(certificate: &[u8]) -> Vec<String> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let Ok(certificate) = x509_cert::Certificate::from_der(certificate) else {
        return Vec::new();
    };
    let Ok(Some((_critical, SubjectAltName(names)))) = certificate
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
    else {
        return Vec::new();
    };
    let mut uri_domains = Vec::new();
    let mut dns_names = Vec::new();
    for name in &names {
        match name {
            GeneralName::UniformResourceIdentifier(uri) => {
                if let Some(domain) = sip_uri_domain(uri.as_str()) {
                    uri_domains.push(domain);
                }
            }
            GeneralName::DnsName(dns) => dns_names.push(normalize_host(dns.as_str())),
            _ => {}
        }
    }
    if uri_domains.is_empty() {
        dns_names
    } else {
        uri_domains
    }
}

/// The domain of a `sip:` URI subjectAltName, or `None` when it is not one
/// (another scheme, `sips:` included, or a URI with a user part, which names a
/// user and not a domain).
fn sip_uri_domain(uri: &str) -> Option<String> {
    let scheme_length = "sip:".len();
    if uri.len() <= scheme_length || !uri[..scheme_length].eq_ignore_ascii_case("sip:") {
        return None;
    }
    let rest = &uri[scheme_length..];
    if rest.contains('@') {
        return None;
    }
    let host = match rest.strip_prefix('[') {
        Some(bracketed) => &bracketed[..bracketed.find(']')?],
        None => rest.split([':', ';', '?']).next().unwrap_or(rest),
    };
    (!host.is_empty()).then(|| normalize_host(host))
}

/// Whether `expected` is one of `identities`, exactly (RFC 5922 §7.2): case
/// does not matter, a trailing root dot does not matter, and a wildcard entry
/// matches nothing but itself.
fn matches_sip_domain(expected: &str, identities: &[String]) -> bool {
    let expected = normalize_host(expected);
    identities.contains(&expected)
}

/// Certificate verifier that accepts any server certificate (no verification).
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
#[path = "outbound_tls_tests.rs"]
pub(crate) mod tests;
