//! Client-certificate verification for the SIP TLS and WSS listeners.
//!
//! Two layers, both built from one (already per-listener merged)
//! [`TlsServerConfig`]:
//!
//! - **chain**: `verify_client` + `client_ca` — the client must present a
//!   certificate that chains to a CA in the bundle (rustls' WebPKI verifier);
//! - **identity**: `client_subject` — on top of the chain, the certificate must
//!   name one of the configured DNS identities. A certificate from the right CA
//!   issued to someone else is refused at the handshake with an
//!   `access_denied` alert (RFC 8446 §6.2: "a valid certificate was received,
//!   but when access control was applied, the sender decided not to proceed").
//!
//! The identity check runs inside the verifier rather than after the
//! handshake, so it holds for every listener that builds its acceptor here —
//! plain TLS, WSS and the TLS+WSS mux — and a refused peer never gets a
//! completed session to send a byte on. The accept loop logs the refusal with
//! the peer address and counts it in `siphon_handshake_failures_total`.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use rustls_pki_types::{CertificateDer, UnixTime};
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tracing::{info, warn};

use crate::config::TlsServerConfig;

/// The client-certificate verifier for one listener, or `None` when the
/// listener does not ask for a client certificate.
///
/// `field_prefix` names the config block in every error (`tls`,
/// `listen.tls[192.0.2.10:5061]`, …) so a failure points at the key to fix.
/// Fails closed: `verify_client` without `client_ca`, an unreadable or empty
/// bundle, or a malformed `client_subject` pattern is an error, never a
/// downgrade to accepting any client.
pub(crate) fn client_cert_verifier(
    tls_config: &TlsServerConfig,
    field_prefix: &str,
) -> io::Result<Option<Arc<dyn ClientCertVerifier>>> {
    use rustls_pki_types::pem::PemObject;

    if !tls_config.verify_client {
        if !tls_config.client_subject.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{field_prefix}.client_subject is set but verify_client is not true — \
                     a subject can only be checked on a certificate the client was required \
                     to present"
                ),
            ));
        }
        return Ok(None);
    }

    let ca_path = tls_config.client_ca.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{field_prefix}.verify_client is true but no client_ca (PEM CA bundle for \
                 client certificates) is set"
            ),
        )
    })?;
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
                "{field_prefix}.client_ca '{ca_path}' contains no certificates — mutual TLS \
                 would accept no client at all"
            ),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for authority in authorities {
        roots.add(authority).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("adding a CA from {field_prefix}.client_ca '{ca_path}': {error}"),
            )
        })?;
    }
    let chain_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        crate::transport::tls::crypto_provider(),
    )
    .build()
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_prefix}: building the client certificate verifier: {error}"),
        )
    })?;

    if tls_config.client_subject.is_empty() {
        info!(client_ca = %ca_path, listener = %field_prefix,
            "mutual TLS enabled — client certificate required");
        return Ok(Some(chain_verifier));
    }
    let subjects = ClientSubjectMatcher::new(&tls_config.client_subject).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field_prefix}.client_subject: {error}"),
        )
    })?;
    info!(client_ca = %ca_path, client_subject = ?tls_config.client_subject,
        listener = %field_prefix,
        "mutual TLS enabled — client certificate required and its subject checked");
    Ok(Some(Arc::new(SubjectCheckingVerifier {
        inner: chain_verifier,
        subjects,
    })))
}

/// The DNS identities a `client_subject` list allows, matched
/// case-insensitively.
///
/// A pattern is an exact name (`trunk.sip.example.net`) or a wildcard whose
/// whole leftmost label is `*` (`*.sip.example.net`), which matches exactly one
/// label in that position, per RFC 6125 §6.4.3: `edge1.sip.example.net`
/// matches, `sip.example.net` and `a.b.sip.example.net` do not. A certificate
/// that itself carries a wildcard name matches only a pattern that covers it
/// (`*.sip.example.net` presented matches the `*.sip.example.net` pattern).
#[derive(Debug, Clone)]
pub(crate) struct ClientSubjectMatcher {
    exact: HashSet<String>,
    /// Wildcard patterns with the `*.` stripped.
    wildcard_parents: HashSet<String>,
    /// The patterns as configured, for log lines.
    patterns: Vec<String>,
}

/// One DNS name, normalised the way both sides of a comparison need it: ASCII
/// lowercase (RFC 4343) and no trailing root dot.
fn normalise_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl ClientSubjectMatcher {
    /// Parse the configured patterns, refusing any that could never match or
    /// would match more than a label: empty, `*` other than as the whole
    /// leftmost label, or a wildcard with nothing after it.
    pub(crate) fn new(patterns: &[String]) -> Result<Self, String> {
        let mut exact = HashSet::new();
        let mut wildcard_parents = HashSet::new();
        for raw in patterns {
            let pattern = normalise_dns_name(raw);
            if pattern.is_empty() {
                return Err("an empty pattern can never match a certificate".to_string());
            }
            match pattern.strip_prefix("*.") {
                Some(parent) => {
                    if parent.is_empty() || parent.starts_with('.') || parent.contains('*') {
                        return Err(format!("'{raw}' is not a valid wildcard pattern"));
                    }
                    if !parent.contains('.') {
                        return Err(format!(
                            "'{raw}': a wildcard directly under a single label would accept \
                             every name in a top-level domain — name the parent domain"
                        ));
                    }
                    wildcard_parents.insert(parent.to_string());
                }
                None => {
                    if pattern.contains('*') {
                        return Err(format!(
                            "'{raw}': a wildcard is only valid as the whole leftmost label \
                             (`*.sip.example.net`)"
                        ));
                    }
                    exact.insert(pattern);
                }
            }
        }
        if exact.is_empty() && wildcard_parents.is_empty() {
            return Err("the list is empty — it would refuse every client".to_string());
        }
        Ok(Self {
            exact,
            wildcard_parents,
            patterns: patterns.to_vec(),
        })
    }

    /// Whether one presented name is allowed.
    fn matches_name(&self, presented: &str) -> bool {
        let name = normalise_dns_name(presented);
        if self.exact.contains(&name) {
            return true;
        }
        match name.split_once('.') {
            Some((label, parent)) => !label.is_empty() && self.wildcard_parents.contains(parent),
            None => false,
        }
    }

    /// Whether the certificate's identity is allowed: any of its DNS
    /// subjectAltNames, or — only when it carries none — its subject Common
    /// Name (RFC 6125 §6.4.4).
    pub(crate) fn matches(&self, names: &PresentedNames) -> bool {
        if names.dns.is_empty() {
            return names
                .common_name
                .as_deref()
                .is_some_and(|common_name| self.matches_name(common_name));
        }
        names.dns.iter().any(|name| self.matches_name(name))
    }
}

/// The identities a client certificate claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PresentedNames {
    /// dNSName subjectAltNames, in certificate order.
    pub(crate) dns: Vec<String>,
    /// The first subject Common Name, if any.
    pub(crate) common_name: Option<String>,
}

/// Read the DNS subjectAltNames and subject Common Name of a DER certificate.
pub(crate) fn presented_names(certificate: &[u8]) -> Result<PresentedNames, String> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let certificate = x509_cert::Certificate::from_der(certificate)
        .map_err(|error| format!("decoding the client certificate: {error}"))?;
    let tbs = certificate.tbs_certificate();
    let dns = match tbs
        .get_extension::<SubjectAltName>()
        .map_err(|error| format!("decoding the client certificate subjectAltName: {error}"))?
    {
        Some((_critical, SubjectAltName(names))) => names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DnsName(dns_name) => Some(dns_name.to_string()),
                _ => None,
            })
            .collect(),
        None => Vec::new(),
    };
    let common_name = tbs
        .subject()
        .common_name()
        .map_err(|error| format!("decoding the client certificate subject: {error}"))?
        .map(|value| value.value().into_owned());
    Ok(PresentedNames { dns, common_name })
}

/// The chain verifier plus a `client_subject` identity check.
#[derive(Debug)]
struct SubjectCheckingVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    subjects: ClientSubjectMatcher,
}

impl ClientCertVerifier for SubjectCheckingVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Chain first: an identity read off a certificate nobody vouched for
        // means nothing.
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let names = presented_names(end_entity.as_ref()).map_err(|error| {
            warn!(%error, "TLS client certificate refused: its names could not be read");
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if self.subjects.matches(&names) {
            return Ok(verified);
        }
        warn!(
            presented_dns = ?names.dns,
            presented_common_name = ?names.common_name,
            allowed = ?self.subjects.patterns,
            "TLS client certificate refused: it chains to client_ca but names none of the \
             client_subject identities"
        );
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

#[cfg(test)]
#[path = "tls_client_auth_tests.rs"]
mod tests;
