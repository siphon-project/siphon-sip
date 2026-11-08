//! Startup TLS material and per-connection serving for PCF notifications.
use std::{sync::Arc, time::Duration};

use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};
use tracing::{debug, warn};

use crate::config::SbiNotifTlsConfig;

fn certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|error| format!("sbi.notif_tls file '{path}': {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("sbi.notif_tls file '{path}': {error}"))?;
    if certificates.is_empty() {
        return Err(format!(
            "sbi.notif_tls file '{path}': no certificates found"
        ));
    }
    Ok(certificates)
}

/// Load once before spawning, so a bad TLS configuration fails startup.
pub(super) fn load(config: Option<&SbiNotifTlsConfig>) -> Result<Option<TlsAcceptor>, String> {
    let Some(config) = config else {
        return Ok(None);
    };
    let Some((cert, key)) = config.identity()? else {
        return Ok(None);
    };
    let chain = certificates(cert)?;
    // Consume the whole PEM file, including malformed trailing key blocks.
    let keys = PrivateKeyDer::pem_file_iter(key)
        .map_err(|error| format!("sbi.notif_tls key '{key}': {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("sbi.notif_tls key '{key}': {error}"))?;
    let private_key = keys
        .into_iter()
        .next()
        .ok_or_else(|| format!("sbi.notif_tls key '{key}': no private key found"))?;
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("sbi.notif_tls: {error}"))?;
    let builder = if let Some(ca) = config.client_ca.as_deref().filter(|path| !path.is_empty()) {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in certificates(ca)? {
            roots
                .add(certificate)
                .map_err(|error| format!("sbi.notif_tls client_ca '{ca}': {error}"))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .map_err(|error| format!("sbi.notif_tls client_ca '{ca}': {error}"))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut server = builder
        .with_single_cert(chain, private_key)
        .map_err(|error| format!("sbi.notif_tls cert '{cert}' and key '{key}': {error}"))?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

/// Accept independently: a stalled or invalid handshake cannot stop callbacks.
pub(super) async fn serve(listener: TcpListener, app: Router, acceptor: TlsAcceptor) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                warn!(%error, "SBI TLS accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let stream = match tokio::time::timeout(
                Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    debug!(%peer, %error, "SBI TLS handshake failed");
                    return;
                }
                Err(_) => {
                    debug!(%peer, "SBI TLS handshake timed out");
                    return;
                }
            };
            if let Err(error) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!(%peer, %error, "SBI TLS connection failed");
            }
        });
    }
}
