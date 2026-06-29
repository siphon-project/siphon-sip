//! Server mode connection acceptance.
//!
//! The existing [`peer::accept`] does CER→CEA in one shot with a fixed
//! identity — fine for a simple server NF. A Diameter server needs a
//! **staged** handshake so two Rust-only auth gates and a per-tenant identity
//! decision land between reading the CER and writing the CEA:
//!
//! ```text
//! accept socket
//!   └─ Gate 1: source-IP ACL (before reading any bytes)
//!   └─ read CER
//!   └─ Gate 2: Origin-Host validation → CEA 3010 + close on mismatch
//!   └─ resolve identity (Python @on_inbound_cer, or a closure here)
//!        └─ Reject(code) → CEA(code) + close
//!        └─ Accept{origin_host, origin_realm}
//!   └─ build per-connection PeerConfig with the chosen identity
//!   └─ CEA(SUCCESS) + spawn reader/writer/watchdog
//! ```
//!
//! The per-tenant identity flows into the connection's `PeerConfig`, so the
//! DWR/DWA this connection emits carry the tenant-facing identity for its whole
//! lifetime — not a single global origin.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::info;

use crate::diameter::auth::{AclMatch, OriginHostPolicy, SourceIpAcl};
use crate::diameter::codec;
use crate::diameter::dictionary;
use crate::diameter::peer::{self, DiameterPeer, IncomingRequest, PeerConfig};

/// What identity to advertise back in the CEA — or a rejection. Mirrors the
/// Python `@diameter.on_inbound_cer` return contract: `(origin_host,
/// origin_realm)` to accept, `None` to reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CerDecision {
    Accept {
        origin_host: String,
        origin_realm: String,
    },
    Reject(u32),
}

/// Reason a server-mode handshake did not complete.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("source {0} not in any tenant ACL")]
    UnknownSource(IpAddr),
    #[error("Origin-Host validation failed for peer {peer}: asserted {asserted:?}")]
    OriginHostMismatch { peer: String, asserted: String },
    #[error("CER rejected with result-code {0}")]
    Rejected(u32),
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// The Diameter server's own capabilities/identity used when building CEAs and the
/// per-connection `PeerConfig`.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    /// Identity used for error/reject CEAs (before a tenant identity is chosen).
    pub default_origin_host: String,
    pub default_origin_realm: String,
    pub local_ip: Ipv4Addr,
    pub product_name: String,
    pub firmware_revision: u32,
    pub watchdog_interval: u64,
    /// `(vendor_id, auth_app_id)` advertised in the CEA.
    pub application_ids: Vec<(u32, u32)>,
}

/// The two auth gates plus the Diameter server's identity — everything needed to admit (or
/// refuse) an inbound connection.
pub struct ServerHandshake {
    pub acl: Arc<SourceIpAcl>,
    pub origin_policy: Arc<OriginHostPolicy>,
    pub identity: ServerIdentity,
}

impl ServerHandshake {
    /// Run the staged handshake on a freshly accepted stream. `resolve` decides
    /// the CEA identity for an already-authenticated peer (Phase 5 plugs the
    /// Python `@on_inbound_cer` callback in here; tests pass a closure).
    pub async fn run<S, F>(
        &self,
        mut stream: S,
        peer_addr: SocketAddr,
        incoming_tx: mpsc::Sender<IncomingRequest>,
        resolve: F,
    ) -> Result<(Arc<DiameterPeer>, AclMatch), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce(&AclMatch, &str) -> CerDecision,
    {
        // ── Gate 1: source-IP ACL — before reading a single byte ────────────
        let acl_match = self
            .acl
            .lookup(peer_addr.ip())
            .ok_or_else(|| HandshakeError::UnknownSource(peer_addr.ip()))?;

        // ── Read the CER ────────────────────────────────────────────────────
        let cer_bytes = codec::read_diameter_message(&mut stream)
            .await
            .map_err(|error| HandshakeError::Io(error.to_string()))?;
        let cer = codec::decode_diameter(&cer_bytes)
            .ok_or_else(|| HandshakeError::Protocol("failed to decode CER".into()))?;
        if cer.command_code != dictionary::CMD_CAPABILITIES_EXCHANGE || !cer.is_request {
            return Err(HandshakeError::Protocol(format!(
                "expected CER, got {}",
                codec::command_name(cer.command_code, cer.is_request)
            )));
        }
        let asserted = cer
            .avps
            .get("Origin-Host")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();

        // ── Gate 2: Origin-Host validation ──────────────────────────────────
        if !self.origin_policy.validate(&acl_match.peer, &asserted) {
            self.send_cea(
                &mut stream,
                &self.identity.default_origin_host,
                &self.identity.default_origin_realm,
                dictionary::DIAMETER_UNKNOWN_PEER,
                cer.hop_by_hop,
                cer.end_to_end,
            )
            .await;
            return Err(HandshakeError::OriginHostMismatch {
                peer: acl_match.peer.clone(),
                asserted,
            });
        }

        // ── Identity decision (already-authenticated peer) ──────────────────
        let (origin_host, origin_realm) = match resolve(&acl_match, &asserted) {
            CerDecision::Accept {
                origin_host,
                origin_realm,
            } => (origin_host, origin_realm),
            CerDecision::Reject(code) => {
                self.send_cea(
                    &mut stream,
                    &self.identity.default_origin_host,
                    &self.identity.default_origin_realm,
                    code,
                    cer.hop_by_hop,
                    cer.end_to_end,
                )
                .await;
                return Err(HandshakeError::Rejected(code));
            }
        };

        // ── Accept: CEA(SUCCESS) + spawn connection tasks ───────────────────
        let conn_config = self.config_with_identity(&origin_host, &origin_realm);
        let cea = peer::build_cea(
            &conn_config,
            dictionary::DIAMETER_SUCCESS,
            cer.hop_by_hop,
            cer.end_to_end,
        );
        stream
            .write_all(&cea)
            .await
            .map_err(|error| HandshakeError::Io(error.to_string()))?;

        let admitted = peer::spawn_connection_tasks(conn_config, stream, incoming_tx);
        info!(
            tenant = %acl_match.tenant,
            peer = %acl_match.peer,
            asserted_origin = %asserted,
            advertised_origin = %origin_host,
            "Diameter server: peer admitted"
        );
        Ok((admitted, acl_match))
    }

    async fn send_cea<S>(
        &self,
        stream: &mut S,
        origin_host: &str,
        origin_realm: &str,
        result_code: u32,
        hbh: u32,
        e2e: u32,
    ) where
        S: AsyncWrite + Unpin,
    {
        let config = self.config_with_identity(origin_host, origin_realm);
        let cea = peer::build_cea(&config, result_code, hbh, e2e);
        let _ = stream.write_all(&cea).await;
    }

    fn config_with_identity(&self, origin_host: &str, origin_realm: &str) -> PeerConfig {
        PeerConfig {
            host: String::new(),
            port: 0,
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
            destination_host: None,
            destination_realm: origin_realm.to_string(),
            local_ip: self.identity.local_ip,
            application_ids: self.identity.application_ids.clone(),
            watchdog_interval: self.identity.watchdog_interval,
            reconnect_delay: 5,
            product_name: self.identity.product_name.clone(),
            firmware_revision: self.identity.firmware_revision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::PeerState;

    fn handshake_with(acl: SourceIpAcl, policy: OriginHostPolicy) -> ServerHandshake {
        ServerHandshake {
            acl: Arc::new(acl),
            origin_policy: Arc::new(policy),
            identity: ServerIdentity {
                default_origin_host: "diam.example.org".into(),
                default_origin_realm: "example.org".into(),
                local_ip: "127.0.0.1".parse().unwrap(),
                product_name: "SIPhon-Diameter server".into(),
                firmware_revision: 1,
                watchdog_interval: 300,
                application_ids: vec![],
            },
        }
    }

    fn client_cer(origin_host: &str) -> Vec<u8> {
        let config = PeerConfig {
            host: "x".into(),
            port: 3868,
            origin_host: origin_host.into(),
            origin_realm: "client-realm.org".into(),
            destination_host: None,
            destination_realm: "example.org".into(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "client".into(),
            firmware_revision: 1,
        };
        peer::build_cer(&config, 100, 200)
    }

    fn accept_resolver(_m: &AclMatch, _asserted: &str) -> CerDecision {
        CerDecision::Accept {
            origin_host: "diam.epc.example.org".into(),
            origin_realm: "epc.example.org".into(),
        }
    }

    #[tokio::test]
    async fn unknown_source_rejected_before_reading_cer() {
        // Empty ACL → no source matches. run() must return immediately WITHOUT
        // reading a CER (we never write one; a read attempt would hang).
        let handshake = handshake_with(SourceIpAcl::new(), OriginHostPolicy::new());
        let (server_side, _client_side) = tokio::io::duplex(8192);
        let (incoming_tx, _rx) = mpsc::channel(8);
        let addr: SocketAddr = "203.0.113.9:5000".parse().unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            handshake.run(server_side, addr, incoming_tx, accept_resolver),
        )
        .await
        .expect("must not hang — ACL gate runs before any read");

        assert!(matches!(result, Err(HandshakeError::UnknownSource(_))));
    }

    #[tokio::test]
    async fn origin_host_mismatch_answers_3010_and_closes() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("10.0.0.0/24", "default", "mme").unwrap();
        let mut policy = OriginHostPolicy::new();
        policy.set("mme", "mme.epc.example.org");
        let handshake = handshake_with(acl, policy);

        let (server_side, mut client_side) = tokio::io::duplex(8192);
        let (incoming_tx, _rx) = mpsc::channel(8);
        let addr: SocketAddr = "10.0.0.5:5000".parse().unwrap();

        // Client asserts the WRONG Origin-Host.
        client_side.write_all(&client_cer("spoofed.example.org")).await.unwrap();

        let result = handshake.run(server_side, addr, incoming_tx, accept_resolver).await;
        assert!(matches!(
            result,
            Err(HandshakeError::OriginHostMismatch { .. })
        ));

        // A CEA with 3010 must have been written back.
        let cea_bytes = codec::read_diameter_message(&mut client_side).await.unwrap();
        let cea = codec::decode_diameter(&cea_bytes).unwrap();
        assert!(!cea.is_request);
        assert_eq!(
            cea.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_UNKNOWN_PEER as u64)
        );
    }

    #[tokio::test]
    async fn happy_path_admits_peer_and_relays_inbound_request() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("10.0.0.0/24", "default", "mme").unwrap();
        let handshake = handshake_with(acl, OriginHostPolicy::new());

        let (server_side, mut client_side) = tokio::io::duplex(8192);
        let (incoming_tx, mut incoming_rx) = mpsc::channel(8);
        let addr: SocketAddr = "10.0.0.7:5000".parse().unwrap();

        client_side.write_all(&client_cer("mme.epc.example.org")).await.unwrap();

        let (peer, acl_match) = handshake
            .run(server_side, addr, incoming_tx, accept_resolver)
            .await
            .expect("handshake should succeed");
        assert_eq!(acl_match.peer, "mme");
        assert_eq!(peer.state(), PeerState::Open);
        // CEA carries the tenant identity chosen by the resolver.
        assert_eq!(peer.config().origin_host, "diam.epc.example.org");

        // Read the success CEA off the wire.
        let cea_bytes = codec::read_diameter_message(&mut client_side).await.unwrap();
        let cea = codec::decode_diameter(&cea_bytes).unwrap();
        assert_eq!(
            cea.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_SUCCESS as u64)
        );

        // Now send an application request (e.g. an ACR, command 271) — it must
        // surface on the incoming channel for dispatch.
        let acr = codec::encode_diameter_message(
            codec::FLAG_REQUEST | codec::FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            0xABCD,
            0xEF01,
            &codec::encode_avp_utf8(dictionary::avp::SESSION_ID, "client;9;9"),
        );
        client_side.write_all(&acr).await.unwrap();

        let inbound = tokio::time::timeout(std::time::Duration::from_secs(1), incoming_rx.recv())
            .await
            .expect("request should arrive")
            .expect("channel open");
        assert_eq!(inbound.command_code, dictionary::CMD_ACCOUNTING);
        assert_eq!(inbound.hop_by_hop, 0xABCD);
    }

    #[tokio::test]
    async fn resolver_reject_answers_with_code_and_closes() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("10.0.0.0/24", "default", "mme").unwrap();
        let handshake = handshake_with(acl, OriginHostPolicy::new());

        let (server_side, mut client_side) = tokio::io::duplex(8192);
        let (incoming_tx, _rx) = mpsc::channel(8);
        let addr: SocketAddr = "10.0.0.8:5000".parse().unwrap();
        client_side.write_all(&client_cer("mme.epc.example.org")).await.unwrap();

        let reject = |_m: &AclMatch, _a: &str| CerDecision::Reject(dictionary::DIAMETER_UNABLE_TO_COMPLY);
        let result = handshake.run(server_side, addr, incoming_tx, reject).await;
        assert!(matches!(result, Err(HandshakeError::Rejected(c)) if c == dictionary::DIAMETER_UNABLE_TO_COMPLY));

        let cea_bytes = codec::read_diameter_message(&mut client_side).await.unwrap();
        let cea = codec::decode_diameter(&cea_bytes).unwrap();
        assert_eq!(
            cea.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_UNABLE_TO_COMPLY as u64)
        );
    }
}
