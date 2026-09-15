//! Client-side TLS for siphon's **outbound** connections.
//!
//! [`tls`](crate::transport::tls) is the other half — it terminates TLS on a
//! listener. This is what siphon uses when it is the one dialing: the CDR HTTP
//! backend, the HEP capture feed, and the control plane's `wss://` connect_url.
//!
//! One place on purpose. Each of those grew its own root store and connector,
//! which is three chances to trust a different set of roots than the rest of the
//! process, and a private-CA deployment that works on one feed and silently
//! fails on another reads as a broken peer rather than a missing option.

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Build a rustls client config trusting `ca_path`, or the Mozilla roots.
///
/// A `ca_path` **replaces** the public roots rather than adding to them. That is
/// the point of naming one: a deployment whose peer uses a private CA wants
/// exactly that CA to be acceptable, and quietly keeping the public roots
/// alongside it would make a mis-issued public certificate work too.
pub fn client_config(ca_path: Option<&str>) -> io::Result<ClientConfig> {
    // Explicit provider rather than the process default, which panics when
    // nothing installed one. `server.rs` installs ring before any listener
    // starts, but an embedder that only uses the CDR or HEP feed never goes
    // through it, and neither do these tests.
    Ok(
        ClientConfig::builder_with_provider(crate::transport::tls::crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|error| io::Error::other(format!("no usable TLS protocol versions: {error}")))?
            .with_root_certificates(root_store(ca_path)?)
            .with_no_client_auth(),
    )
}

/// The root store [`client_config`] builds on. Split out because a built
/// `ClientConfig` does not expose its roots, and "which roots does naming a CA
/// leave acceptable" is the question worth a test.
fn root_store(ca_path: Option<&str>) -> io::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();

    match ca_path {
        Some(path) => {
            use tokio_rustls::rustls::pki_types::pem::PemObject;
            let pem = std::fs::read(path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("reading the CA bundle at {path}: {error}"),
                )
            })?;
            let mut cursor = io::Cursor::new(pem);
            let certificates: Vec<_> =
                tokio_rustls::rustls::pki_types::CertificateDer::pem_reader_iter(&mut cursor)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("parsing the CA bundle at {path}: {error}"),
                        )
                    })?;
            // An empty-but-readable file is the failure worth naming: it leaves
            // a root store that trusts nothing, so every handshake fails with an
            // unknown-issuer error that points at the peer instead of the file.
            if certificates.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the CA bundle at {path} contains no certificates"),
                ));
            }
            for certificate in certificates {
                root_store.add(certificate).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("adding a certificate from {path}: {error}"),
                    )
                })?;
            }
        }
        None => root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }

    Ok(root_store)
}

/// Dial `address` and complete a TLS handshake, verifying the peer against
/// `server_name`.
///
/// `server_name` is the name the certificate is checked against (SNI + hostname
/// verification), which is the host from the configured URL — never the address
/// it resolved to, or the check would be satisfied by whatever answered.
pub async fn connect(
    address: &str,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(server_name.to_string()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{server_name:?} is not a valid TLS server name: {error}"),
        )
    })?;
    let stream = TcpStream::connect(address).await?;
    TlsConnector::from(config).connect(name, stream).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed CA certificate, generated in process into `directory`, so
    /// the CA-bundle paths are exercised against a real PEM rather than a
    /// hand-built vector.
    ///
    /// In process rather than through an `openssl` binary: a subprocess per
    /// test failed to generate under a loaded parallel run, and the test then
    /// failed for a reason that has nothing to do with root stores.
    fn write_test_ca(directory: &std::path::Path) -> std::path::PathBuf {
        let key_pair = rcgen::KeyPair::generate().expect("generate the test CA key");
        let mut params = rcgen::CertificateParams::new(vec!["siphon-client-tls-test".to_string()])
            .expect("test CA parameters");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let certificate = params
            .self_signed(&key_pair)
            .expect("self-sign the test CA");
        let path = directory.join("ca.pem");
        std::fs::write(&path, certificate.pem()).expect("write the test CA");
        path
    }

    /// A directory of this test's own, removed when it drops.
    ///
    /// A fixed name under the system temp dir is shared by every process running
    /// the test at once, the lib binaries of two checkouts say, and each one's
    /// cleanup deleted the bundle another was about to read.
    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn no_ca_path_trusts_the_public_roots() {
        let roots = root_store(None).expect("public roots must build");
        // Not an empty store — an empty one would fail every handshake with an
        // unknown-issuer error that reads like the peer's fault.
        assert!(roots.len() > 100, "{}", roots.len());
        assert!(client_config(None).is_ok());
    }

    #[test]
    fn a_ca_path_replaces_the_public_roots_rather_than_extending_them() {
        let directory = temp_dir();
        let ca = write_test_ca(directory.path());
        let roots = root_store(Some(&ca.to_string_lossy())).expect("custom CA must build");
        assert_eq!(
            roots.len(),
            1,
            "naming a CA must not leave the public roots acceptable too"
        );
        assert!(client_config(Some(&ca.to_string_lossy())).is_ok());
    }

    #[test]
    fn a_missing_ca_file_names_the_path() {
        let error = client_config(Some("/nonexistent/siphon-ca.pem"))
            .expect_err("a missing CA bundle must fail");
        assert!(
            error.to_string().contains("/nonexistent/siphon-ca.pem"),
            "{error}"
        );
    }

    #[test]
    fn an_empty_ca_file_is_rejected_rather_than_trusting_nothing() {
        let directory = temp_dir();
        let path = directory.path().join("empty.pem");
        std::fs::write(&path, b"").expect("write");
        let error =
            client_config(Some(&path.to_string_lossy())).expect_err("an empty CA bundle must fail");
        assert!(error.to_string().contains("no certificates"), "{error}");
    }

    #[test]
    fn a_ca_file_that_is_not_pem_is_rejected() {
        let directory = temp_dir();
        let path = directory.path().join("garbage.pem");
        std::fs::write(&path, b"this is not a certificate").expect("write");
        let error = client_config(Some(&path.to_string_lossy()))
            .expect_err("a non-PEM CA bundle must fail");
        assert!(error.to_string().contains("no certificates"), "{error}");
    }

    #[tokio::test]
    async fn an_invalid_server_name_is_refused_before_any_connection() {
        let config = Arc::new(client_config(None).expect("config"));
        // Port 9 on a host that cannot be named: if the name check did not come
        // first this would hang on connect instead of returning.
        let error = connect("127.0.0.1:9", "not a host name", config)
            .await
            .expect_err("an invalid SNI name must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
