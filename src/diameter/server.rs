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
//!   └─ Gate 3: common application (RFC 6733 §5.3) → CEA 5010 + close
//!   └─ CEA(SUCCESS) + spawn reader/writer/watchdog
//! ```
//!
//! Every CEA sent once the tenant is known lists the applications that tenant
//! serves, the 5010 one included, so a refused peer can read what it was
//! compared against.
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
use crate::diameter::codec::{self, Avp, AvpData};
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
    #[error(
        "no application in common with peer {peer}: its CER advertises {offered:?}, this node serves {served:?}"
    )]
    NoCommonApplication {
        peer: String,
        offered: Vec<u32>,
        served: Vec<u32>,
    },
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
}

/// The applications a tenant serves, as `(vendor_id, application_id)` pairs,
/// given the tenant's name. Asked once per handshake rather than fixed at
/// bind time, because part of the answer comes from the handlers the running
/// script registered and a script reload can change those.
pub type TenantApplications = Arc<dyn Fn(&str) -> Vec<(u32, u32)> + Send + Sync>;

/// The auth gates plus the Diameter server's identity — everything needed to admit (or
/// refuse) an inbound connection.
pub struct ServerHandshake {
    pub acl: Arc<SourceIpAcl>,
    pub origin_policy: Arc<OriginHostPolicy>,
    pub identity: ServerIdentity,
    /// What the CEA advertises, and what the peer's CER is compared against.
    pub applications: TenantApplications,
}

/// The application ids a CER advertises: every Auth-Application-Id and
/// Acct-Application-Id, at the top level or inside a
/// Vendor-Specific-Application-Id. The Vendor-Id of that group is left out on
/// purpose: RFC 6733 §5.3 says it must not take part in the comparison.
fn advertised_application_ids(avps: &[Avp]) -> Vec<u32> {
    use dictionary::avp;
    let mut application_ids = Vec::new();
    for entry in avps {
        match (entry.code, &entry.value) {
            (avp::AUTH_APPLICATION_ID | avp::ACCT_APPLICATION_ID, AvpData::Raw(_)) => {
                application_ids.extend(entry.as_u32());
            }
            (avp::VENDOR_SPECIFIC_APPLICATION_ID, AvpData::Grouped(children)) => {
                application_ids.extend(advertised_application_ids(children));
            }
            _ => {}
        }
    }
    application_ids
}

/// Whether a peer offering `offered` may be admitted by a node serving
/// `served` (RFC 6733 §5.3).
///
/// The two sets have to intersect, with two exceptions. The Relay application
/// on either side is common with everything. And a node that serves nothing it
/// can name admits every peer: that is a script with only bare-command or
/// catch-all handlers and no configured `applications`, which cannot be told
/// apart from an agent and was admitted before this check existed.
fn has_common_application(served: &[(u32, u32)], offered: &[u32]) -> bool {
    served.is_empty()
        || offered.contains(&dictionary::RELAY_APP_ID)
        || served.iter().any(|&(_, application_id)| {
            application_id == dictionary::RELAY_APP_ID || offered.contains(&application_id)
        })
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
        let offered = advertised_application_ids(
            &codec::DiameterMsg::from_wire(&cer_bytes)
                .map_err(|error| HandshakeError::Protocol(format!("malformed CER: {error}")))?
                .avps,
        );
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
                &self.default_config(),
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
                    &self.default_config(),
                    code,
                    cer.hop_by_hop,
                    cer.end_to_end,
                )
                .await;
                return Err(HandshakeError::Rejected(code));
            }
        };
        let conn_config = self.config_with_identity(
            &origin_host,
            &origin_realm,
            (self.applications)(&acl_match.tenant),
        );

        // ── Gate 3: common application (RFC 6733 §5.3) ──────────────────────
        if !has_common_application(&conn_config.application_ids, &offered) {
            self.send_cea(
                &mut stream,
                &conn_config,
                dictionary::DIAMETER_NO_COMMON_APPLICATION,
                cer.hop_by_hop,
                cer.end_to_end,
            )
            .await;
            return Err(HandshakeError::NoCommonApplication {
                peer: acl_match.peer.clone(),
                offered,
                served: conn_config
                    .application_ids
                    .iter()
                    .map(|&(_, application_id)| application_id)
                    .collect(),
            });
        }

        // ── Accept: CEA(SUCCESS) + spawn connection tasks ───────────────────
        let cea = peer::build_cea(
            &conn_config,
            dictionary::DIAMETER_SUCCESS,
            cer.hop_by_hop,
            cer.end_to_end,
        );
        // Bounded: this runs before the connection's writer task exists, so
        // nothing else covers it. A client that connects and then never reads
        // would otherwise pin this handshake task for the life of the process.
        match tokio::time::timeout(peer::HANDSHAKE_TIMEOUT, stream.write_all(&cea)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(HandshakeError::Io(error.to_string())),
            Err(_) => {
                return Err(HandshakeError::Io(format!(
                    "CEA write timed out after {:?}",
                    peer::HANDSHAKE_TIMEOUT
                )))
            }
        }

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

    /// Send a CEA that refuses the connection.
    async fn send_cea<S>(
        &self,
        stream: &mut S,
        config: &PeerConfig,
        result_code: u32,
        hbh: u32,
        e2e: u32,
    ) where
        S: AsyncWrite + Unpin,
    {
        let cea = peer::build_cea(config, result_code, hbh, e2e);
        // Bounded, same reason as the accept path. This is the reject leg, so
        // the result is discarded either way — but discarding it must not mean
        // waiting forever for a client that never reads its own rejection.
        let _ = tokio::time::timeout(peer::HANDSHAKE_TIMEOUT, stream.write_all(&cea)).await;
    }

    /// The identity a CEA is sent under before a tenant identity is chosen.
    /// It lists no application: which ones apply is a per-tenant answer.
    fn default_config(&self) -> PeerConfig {
        self.config_with_identity(
            &self.identity.default_origin_host,
            &self.identity.default_origin_realm,
            Vec::new(),
        )
    }

    fn config_with_identity(
        &self,
        origin_host: &str,
        origin_realm: &str,
        application_ids: Vec<(u32, u32)>,
    ) -> PeerConfig {
        PeerConfig {
            host: String::new(),
            port: 0,
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
            destination_host: None,
            destination_realm: origin_realm.to_string(),
            local_ip: self.identity.local_ip,
            application_ids,
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
        handshake_serving(acl, policy, vec![])
    }

    /// A handshake whose every tenant serves `application_ids`.
    fn handshake_serving(
        acl: SourceIpAcl,
        policy: OriginHostPolicy,
        application_ids: Vec<(u32, u32)>,
    ) -> ServerHandshake {
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
            },
            applications: Arc::new(move |_tenant| application_ids.clone()),
        }
    }

    fn client_cer(origin_host: &str) -> Vec<u8> {
        client_cer_offering(origin_host, vec![])
    }

    /// A CER advertising `application_ids`, built by the client-side encoder.
    fn client_cer_offering(origin_host: &str, application_ids: Vec<(u32, u32)>) -> Vec<u8> {
        let config = PeerConfig {
            host: "x".into(),
            port: 3868,
            origin_host: origin_host.into(),
            origin_realm: "client-realm.org".into(),
            destination_host: None,
            destination_realm: "example.org".into(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids,
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
        client_side
            .write_all(&client_cer("spoofed.example.org"))
            .await
            .unwrap();

        let result = handshake
            .run(server_side, addr, incoming_tx, accept_resolver)
            .await;
        assert!(matches!(
            result,
            Err(HandshakeError::OriginHostMismatch { .. })
        ));

        // A CEA with 3010 must have been written back.
        let cea_bytes = codec::read_diameter_message(&mut client_side)
            .await
            .unwrap();
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

        client_side
            .write_all(&client_cer("mme.epc.example.org"))
            .await
            .unwrap();

        let (peer, acl_match) = handshake
            .run(server_side, addr, incoming_tx, accept_resolver)
            .await
            .expect("handshake should succeed");
        assert_eq!(acl_match.peer, "mme");
        assert_eq!(peer.state(), PeerState::Open);
        // CEA carries the tenant identity chosen by the resolver.
        assert_eq!(peer.config().origin_host, "diam.epc.example.org");

        // Read the success CEA off the wire.
        let cea_bytes = codec::read_diameter_message(&mut client_side)
            .await
            .unwrap();
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
        client_side
            .write_all(&client_cer("mme.epc.example.org"))
            .await
            .unwrap();

        let reject =
            |_m: &AclMatch, _a: &str| CerDecision::Reject(dictionary::DIAMETER_UNABLE_TO_COMPLY);
        let result = handshake.run(server_side, addr, incoming_tx, reject).await;
        assert!(
            matches!(result, Err(HandshakeError::Rejected(c)) if c == dictionary::DIAMETER_UNABLE_TO_COMPLY)
        );

        let cea_bytes = codec::read_diameter_message(&mut client_side)
            .await
            .unwrap();
        let cea = codec::decode_diameter(&cea_bytes).unwrap();
        assert_eq!(
            cea.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_UNABLE_TO_COMPLY as u64)
        );
    }

    // ── Capabilities exchange: applications (RFC 6733 §5.3) ─────────────────

    const S6A: (u32, u32) = (dictionary::VENDOR_3GPP, dictionary::S6A_APP_ID);
    const CX: (u32, u32) = (dictionary::VENDOR_3GPP, dictionary::CX_APP_ID);
    const RF: (u32, u32) = (0, dictionary::RF_APP_ID);
    const RELAY: (u32, u32) = (0, dictionary::RELAY_APP_ID);

    /// What one handshake did: its outcome, and the CEA the client read.
    struct Exchange {
        result: Result<(Arc<DiameterPeer>, AclMatch), HandshakeError>,
        cea: codec::DiameterMsg,
        cea_wire: Vec<u8>,
    }

    impl Exchange {
        fn result_code(&self) -> u32 {
            self.cea
                .find(dictionary::avp::RESULT_CODE, 0)
                .and_then(Avp::as_u32)
                .expect("a CEA carries a Result-Code")
        }
    }

    /// Run one handshake between a node serving `served` and a client whose
    /// CER offers `offered`.
    async fn exchange(served: Vec<(u32, u32)>, offered: Vec<(u32, u32)>) -> Exchange {
        let mut acl = SourceIpAcl::new();
        acl.add_str("192.0.2.0/24", "default", "mme").unwrap();
        let handshake = handshake_serving(acl, OriginHostPolicy::new(), served);

        let (server_side, mut client_side) = tokio::io::duplex(8192);
        let (incoming_tx, _incoming_rx) = mpsc::channel(8);
        let addr: SocketAddr = "192.0.2.7:5000".parse().unwrap();
        client_side
            .write_all(&client_cer_offering("mme.epc.example.org", offered))
            .await
            .unwrap();

        let result = handshake
            .run(server_side, addr, incoming_tx, accept_resolver)
            .await;
        let cea_wire = codec::read_diameter_message(&mut client_side)
            .await
            .expect("every CER is answered");
        let cea = codec::DiameterMsg::from_wire(&cea_wire).expect("the CEA should parse");
        Exchange {
            result,
            cea,
            cea_wire,
        }
    }

    #[tokio::test]
    async fn cea_lists_the_served_applications() {
        let exchange = exchange(vec![S6A, RF], vec![S6A]).await;
        assert!(exchange.result.is_ok());
        assert_eq!(exchange.result_code(), dictionary::DIAMETER_SUCCESS);

        // S6a is a 3GPP application: Vendor-Specific-Application-Id holding
        // the vendor and the application, plus the bare Auth-Application-Id.
        let vendor_specific: Vec<&Avp> = exchange
            .cea
            .find_all(dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID, 0)
            .collect();
        assert_eq!(vendor_specific.len(), 1);
        let AvpData::Grouped(children) = &vendor_specific[0].value else {
            panic!("Vendor-Specific-Application-Id is grouped");
        };
        let child = |code: u32| {
            children
                .iter()
                .find(|avp| avp.code == code)
                .and_then(Avp::as_u32)
        };
        assert_eq!(
            child(dictionary::avp::VENDOR_ID),
            Some(dictionary::VENDOR_3GPP)
        );
        assert_eq!(
            child(dictionary::avp::AUTH_APPLICATION_ID),
            Some(dictionary::S6A_APP_ID)
        );

        // Rf is base accounting: Acct-Application-Id, and no vendor group.
        let accounting: Vec<Option<u32>> = exchange
            .cea
            .find_all(dictionary::avp::ACCT_APPLICATION_ID, 0)
            .map(Avp::as_u32)
            .collect();
        assert_eq!(accounting, vec![Some(dictionary::RF_APP_ID)]);
        let authentication: Vec<Option<u32>> = exchange
            .cea
            .find_all(dictionary::avp::AUTH_APPLICATION_ID, 0)
            .map(Avp::as_u32)
            .collect();
        assert_eq!(authentication, vec![Some(dictionary::S6A_APP_ID)]);
    }

    #[tokio::test]
    async fn a_peer_with_a_common_application_is_admitted() {
        let exchange = exchange(vec![S6A, RF], vec![CX, S6A]).await;
        let (peer, _acl_match) = exchange.result.as_ref().expect("S6a is common");
        assert_eq!(peer.state(), PeerState::Open);
        assert_eq!(exchange.result_code(), dictionary::DIAMETER_SUCCESS);
    }

    #[tokio::test]
    async fn an_accounting_application_is_common_too() {
        // The peer names Rf in Acct-Application-Id; the comparison runs over
        // every application-id AVP, not only the authentication ones.
        let exchange = exchange(vec![S6A, RF], vec![RF]).await;
        assert!(exchange.result.is_ok());
    }

    #[tokio::test]
    async fn a_peer_with_no_common_application_gets_5010_and_is_refused() {
        let exchange = exchange(vec![S6A], vec![CX]).await;
        match &exchange.result {
            Err(HandshakeError::NoCommonApplication {
                peer,
                offered,
                served,
            }) => {
                assert_eq!(peer, "mme");
                assert_eq!(offered, &[dictionary::CX_APP_ID, dictionary::CX_APP_ID]);
                assert_eq!(served, &[dictionary::S6A_APP_ID]);
            }
            Err(other) => panic!("expected NoCommonApplication, got {other}"),
            Ok(_) => panic!("a peer with no common application must not be admitted"),
        }
        assert_eq!(
            exchange.result_code(),
            dictionary::DIAMETER_NO_COMMON_APPLICATION
        );
        // The refusal still says what this node serves.
        assert_eq!(
            advertised_application_ids(&exchange.cea.avps),
            vec![dictionary::S6A_APP_ID, dictionary::S6A_APP_ID]
        );
    }

    #[tokio::test]
    async fn a_peer_advertising_nothing_is_refused_by_a_node_that_serves_something() {
        let exchange = exchange(vec![S6A], vec![]).await;
        assert!(matches!(
            exchange.result,
            Err(HandshakeError::NoCommonApplication { .. })
        ));
        assert_eq!(
            exchange.result_code(),
            dictionary::DIAMETER_NO_COMMON_APPLICATION
        );
    }

    #[tokio::test]
    async fn a_relay_peer_is_admitted() {
        let exchange = exchange(vec![S6A], vec![RELAY]).await;
        assert!(exchange.result.is_ok());
        assert_eq!(exchange.result_code(), dictionary::DIAMETER_SUCCESS);
    }

    #[tokio::test]
    async fn a_node_advertising_relay_admits_any_peer() {
        let exchange = exchange(vec![RELAY], vec![CX]).await;
        assert!(exchange.result.is_ok());
        // Relay is not a vendor application: a bare Auth-Application-Id.
        assert_eq!(
            advertised_application_ids(&exchange.cea.avps),
            vec![dictionary::RELAY_APP_ID]
        );
        assert!(exchange
            .cea
            .find(dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID, 0)
            .is_none());
    }

    #[tokio::test]
    async fn a_node_serving_nothing_it_can_name_admits_every_peer() {
        // Only bare-command or catch-all handlers and no configured list: the
        // CEA names no application and nobody is refused, as before.
        let exchange = exchange(vec![], vec![CX]).await;
        assert!(exchange.result.is_ok());
        assert_eq!(exchange.result_code(), dictionary::DIAMETER_SUCCESS);
        assert!(advertised_application_ids(&exchange.cea.avps).is_empty());
    }

    #[tokio::test]
    async fn applications_are_asked_per_handshake_for_the_matched_tenant() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("192.0.2.0/25", "alpha", "mme").unwrap();
        acl.add_str("192.0.2.128/25", "beta", "cscf").unwrap();
        let mut handshake = handshake_with(acl, OriginHostPolicy::new());
        handshake.applications = Arc::new(|tenant| match tenant {
            "alpha" => vec![S6A],
            _ => vec![CX],
        });

        for (source, served) in [
            ("192.0.2.7:5000", dictionary::S6A_APP_ID),
            ("192.0.2.200:5000", dictionary::CX_APP_ID),
        ] {
            let (server_side, mut client_side) = tokio::io::duplex(8192);
            let (incoming_tx, _incoming_rx) = mpsc::channel(8);
            client_side
                .write_all(&client_cer_offering("peer.example.org", vec![RELAY]))
                .await
                .unwrap();
            handshake
                .run(
                    server_side,
                    source.parse().unwrap(),
                    incoming_tx,
                    accept_resolver,
                )
                .await
                .expect("a relay peer is admitted");
            let cea_wire = codec::read_diameter_message(&mut client_side)
                .await
                .unwrap();
            let cea = codec::DiameterMsg::from_wire(&cea_wire).unwrap();
            assert_eq!(
                advertised_application_ids(&cea.avps),
                vec![served, served],
                "{source}"
            );
        }
    }

    /// Emit the CEA of an admitted and of a refused handshake as hex for
    /// [`scripts/validate_diameter_cea.sh`] to feed to tshark.
    ///
    /// The tests above read the CEA back with the decoder that shares a
    /// dictionary with the encoder. tshark decodes the same bytes with its own.
    #[tokio::test]
    async fn emit_cea_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_DIAMETER_CEA_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };

        // `text2pcap`'s hex-dump form: an offset, then the octets. An offset
        // of zero starts the next packet.
        let mut dump = String::new();
        for (served, offered) in [
            (vec![S6A, CX, RF], vec![S6A]),
            (vec![S6A, CX, RF], vec![(0, dictionary::RO_APP_ID)]),
            (vec![RELAY], vec![CX]),
        ] {
            let exchange = exchange(served, offered).await;
            for (offset, chunk) in exchange.cea_wire.chunks(16).enumerate() {
                dump.push_str(&format!("{:06x}", offset * 16));
                for byte in chunk {
                    dump.push_str(&format!(" {byte:02x}"));
                }
                dump.push('\n');
            }
            dump.push('\n');
        }
        std::fs::write(&path, dump).expect("hex dump must be writable");
    }
}
