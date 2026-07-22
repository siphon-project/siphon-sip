//! Diameter protocol support for SIPhon.
//!
//! Implements RFC 6733 (Diameter Base Protocol) with application modules for:
//! - **Cx** (TS 29.228/229): IMS registration — MAR/MAA, SAR/SAA, UAR/UAA, LIR/LIA
//! - **Sh** (TS 29.329): IMS user data — UDR/UDA, PUR/PUA, SNR/SNA
//! - **Rx** (TS 29.214): QoS policy — AAR/AAA, STR/STA, RAR/RAA, ASR/ASA
//! - **Ro** (TS 32.299): IMS online charging — CCR/CCA
//! - **Rf** (TS 32.299): IMS offline charging — ACR/ACA
//!
//! Transport supports both TCP and SCTP with automatic CER/CEA capability
//! exchange and DWR/DWA watchdog keepalives.

pub mod auth;
pub mod codec;
pub mod cx;
pub mod dictionary;
pub mod event_sink;
pub mod forward;
pub mod peer;
pub mod pool;
pub mod server;
pub mod rf;
pub mod rf_service;
pub mod ro;
pub mod ro_service;
pub mod rx;
pub mod s6a;
pub mod s6c;
pub mod sgd;
pub mod sh;
pub mod transport;

use std::sync::Arc;

use crate::diameter::codec::*;
use crate::diameter::dictionary::avp;
use crate::diameter::peer::DiameterPeer;

/// High-level Diameter Cx client for IMS authentication.
///
/// Wraps a connected `DiameterPeer` and provides typed request/response methods
/// for the Cx interface (S-CSCF ↔ HSS).
pub struct DiameterClient {
    peer: Arc<DiameterPeer>,
}

impl DiameterClient {
    /// Create a new client from an already-connected peer.
    pub fn new(peer: Arc<DiameterPeer>) -> Self {
        Self { peer }
    }

    /// Get the underlying peer handle.
    pub fn peer(&self) -> &Arc<DiameterPeer> {
        &self.peer
    }

    /// Send a UAR (User-Authorization-Request) and return the UAA.
    pub async fn send_uar(
        &self,
        public_identity: &str,
        visited_network_id: &str,
        user_auth_type: Option<u32>,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
        avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
            avp::VISITED_NETWORK_IDENTIFIER,
            visited_network_id.as_bytes(),
        ));
        if let Some(auth_type) = user_auth_type {
            avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_AUTHORIZATION_TYPE, auth_type));
        }

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_USER_AUTHORIZATION,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a SAR (Server-Assignment-Request) and return the SAA.
    pub async fn send_sar(
        &self,
        public_identity: &str,
        server_name: &str,
        server_assignment_type: u32,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::SERVER_NAME, server_name));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SERVER_ASSIGNMENT_TYPE, server_assignment_type));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_DATA_ALREADY_AVAILABLE, 0));

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_SERVER_ASSIGNMENT,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a LIR (Location-Info-Request) and return the LIA.
    pub async fn send_lir(
        &self,
        public_identity: &str,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_LOCATION_INFO,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a MAR (Multimedia-Auth-Request) and return the MAA.
    pub async fn send_mar(
        &self,
        public_identity: &str,
        sip_num_auth_items: u32,
        sip_auth_scheme: &str,
        sip_authorization: Option<&[u8]>,
    ) -> Result<codec::DiameterMessage, String> {
        let config = self.peer.config();
        let hbh = self.peer.next_hbh();
        let e2e = self.peer.next_e2e();
        let session_id = self.peer.new_session_id();

        // Build SIP-Auth-Data-Item grouped AVP
        let mut auth_children = Vec::new();
        auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::SIP_AUTHENTICATION_SCHEME,
            sip_auth_scheme,
        ));
        // Include SIP-Authorization AVP for AUTS resynchronization (TS 29.228 §6.3.18).
        // Contains RAND(16) || AUTS(14) = 30 bytes when UE SQN is out of sync.
        if let Some(auth_data) = sip_authorization {
            auth_children.extend_from_slice(&encode_avp_octet_3gpp(
                avp::SIP_AUTHORIZATION,
                auth_data,
            ));
        }
        let sip_auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, &config.destination_realm));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, sip_num_auth_items));
        avp_bytes.extend_from_slice(&sip_auth_data_item);

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_MULTIMEDIA_AUTH,
            dictionary::CX_APP_ID,
            hbh,
            e2e,
            &avp_bytes,
        );

        self.peer.send_request(msg).await
    }

    /// Send a Sh User-Data-Request (AS → HSS) and return the UDA.
    pub async fn send_udr(
        &self,
        public_identity: &str,
        data_references: &[u32],
        service_indication: Option<&str>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = sh::build_user_data_request(
            self.peer.config(),
            &session_id,
            public_identity,
            data_references,
            service_indication,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send a Sh Profile-Update-Request (AS → HSS) and return the PUA.
    pub async fn send_pur(
        &self,
        public_identity: &str,
        data_reference: u32,
        xml_payload: &str,
        service_indication: Option<&str>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = sh::build_profile_update_request(
            self.peer.config(),
            &session_id,
            public_identity,
            data_reference,
            xml_payload,
            service_indication,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send a Sh Subscribe-Notifications-Request (AS → HSS) and return the SNA.
    pub async fn send_snr(
        &self,
        public_identity: &str,
        data_references: &[u32],
        subs_req_type: u32,
        service_indication: Option<&str>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = sh::build_subscribe_notifications_request(
            self.peer.config(),
            &session_id,
            public_identity,
            data_references,
            subs_req_type,
            service_indication,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send an S6c Send-Routing-Info-for-SM-Request (SMSC → HSS) and
    /// return the SRA. Used to discover the served-node (MME or SGSN)
    /// for an MT-SMS delivery.
    pub async fn send_srr(
        &self,
        msisdn: &str,
        sc_address: &str,
        sm_rp_mti: Option<u32>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = s6c::build_send_routing_info_request(
            self.peer.config(),
            &session_id,
            msisdn,
            sc_address,
            sm_rp_mti,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send an S6c Report-SM-Delivery-Status-Request (SMSC → HSS) and
    /// return the RSA. Used after delivery to inform the HSS of the
    /// final outcome.
    pub async fn send_rsr(
        &self,
        user_name: &str,
        sc_address: &str,
        delivery_outcome: u32,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = s6c::build_report_sm_delivery_status_request(
            self.peer.config(),
            &session_id,
            user_name,
            sc_address,
            delivery_outcome,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send an SGd MT-Forward-Short-Message-Request (SMSC → MME) and
    /// return the TFA. `sm_rp_ui` is the SMS-DELIVER TPDU.
    pub async fn send_tfr(
        &self,
        user_name: &str,
        sc_address: &str,
        sm_rp_ui: &[u8],
        smsmi_correlation_id_ref: Option<&str>,
        sm_rp_mti: Option<u32>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = sgd::build_mt_forward_short_message_request(
            self.peer.config(),
            &session_id,
            user_name,
            sc_address,
            sm_rp_ui,
            smsmi_correlation_id_ref,
            sm_rp_mti,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send an S6a Authentication-Information-Request (MME → HSS) and return
    /// the AIA carrying E-UTRAN authentication vectors.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_air(
        &self,
        imsi: &str,
        visited_plmn_id: &[u8],
        num_vectors: u32,
        immediate_response_preferred: bool,
        resync_info: Option<&[u8]>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = s6a::build_authentication_information_request(
            self.peer.config(),
            &session_id,
            imsi,
            visited_plmn_id,
            num_vectors,
            immediate_response_preferred,
            resync_info,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send an S6a Update-Location-Request (MME → HSS) and return the ULA.
    pub async fn send_ulr(
        &self,
        imsi: &str,
        rat_type: u32,
        ulr_flags: u32,
        visited_plmn_id: &[u8],
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = s6a::build_update_location_request(
            self.peer.config(),
            &session_id,
            imsi,
            rat_type,
            ulr_flags,
            visited_plmn_id,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Send an S6a Purge-UE-Request (MME → HSS) and return the PUA. Named
    /// `send_purge_ue` to avoid clashing with the Sh `send_pur` (Profile-Update).
    pub async fn send_purge_ue(
        &self,
        imsi: &str,
        pur_flags: Option<u32>,
    ) -> Result<codec::DiameterMessage, String> {
        let session_id = self.peer.new_session_id();
        let wire = s6a::build_purge_ue_request(
            self.peer.config(),
            &session_id,
            imsi,
            pur_flags,
            self.peer.next_hbh(),
            self.peer.next_e2e(),
        );
        self.peer.send_request(wire).await
    }

    /// Shutdown the underlying peer connection.
    pub fn shutdown(&self) {
        self.peer.shutdown();
    }
}

// ---------------------------------------------------------------------------
// DiameterManager
// ---------------------------------------------------------------------------

use dashmap::DashMap;

/// Manages multiple Diameter peer connections.
///
/// Created at startup from config, holds connected clients indexed by peer name.
pub struct DiameterManager {
    /// Client-mode peers (`diameter.peers`), keyed by peer name. Used by
    /// `send_request` / `send_air` / etc. — never tenant-scoped.
    clients: DashMap<String, Arc<DiameterClient>>,
    /// Server-mode relay backends, keyed by `(tenant, peer name)`. Keeping the
    /// tenant in the key means two tenants can each register a backend called
    /// `hss` without one silently overwriting the other — no naming convention
    /// required of operators.
    backends: DashMap<(String, String), Arc<DiameterClient>>,
}

impl Default for DiameterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DiameterManager {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
            backends: DashMap::new(),
        }
    }

    /// Register a connected client under its peer name.
    pub fn register(&self, name: String, client: Arc<DiameterClient>) {
        self.clients.insert(name, client);
    }

    /// Get a client by peer name.
    pub fn client(&self, name: &str) -> Option<Arc<DiameterClient>> {
        self.clients.get(name).map(|entry| Arc::clone(entry.value()))
    }

    /// Get a client by peer name only if its connection is `Open`.
    ///
    /// This is the "state-as-truth" liveness check the peer pool uses: a
    /// reconnect overwrites the entry under the same key with a fresh `Open`
    /// peer, and a disconnect flips the existing peer's state to `Closed`, so
    /// no separate deregister step is needed for routing correctness.
    pub fn live_client(&self, name: &str) -> Option<Arc<DiameterClient>> {
        self.clients.get(name).and_then(|entry| {
            let client = entry.value();
            if client.peer().is_open() {
                Some(Arc::clone(client))
            } else {
                None
            }
        })
    }

    /// Remove a peer entirely. Only used on config removal — disconnects rely
    /// on state-as-truth, not removal.
    pub fn deregister(&self, name: &str) -> Option<Arc<DiameterClient>> {
        self.clients.remove(name).map(|(_, client)| client)
    }

    /// Register a server-mode relay backend under `(tenant, name)`. A reconnect
    /// swaps the `Arc` under the same key (state-as-truth), exactly like
    /// [`register`](Self::register) does for client peers.
    pub fn register_backend(&self, tenant: &str, name: &str, client: Arc<DiameterClient>) {
        self.backends
            .insert((tenant.to_string(), name.to_string()), client);
    }

    /// Get a server-mode backend by `(tenant, name)`, only if its connection is
    /// `Open`. This is what [`PeerPool`](crate::diameter::pool::PeerPool) uses
    /// to resolve a relay target — tenant-scoped so one tenant's backend can
    /// never resolve another tenant's same-named entry.
    pub fn live_backend(&self, tenant: &str, name: &str) -> Option<Arc<DiameterClient>> {
        self.backends
            .get(&(tenant.to_string(), name.to_string()))
            .and_then(|entry| {
                let client = entry.value();
                if client.peer().is_open() {
                    Some(Arc::clone(client))
                } else {
                    None
                }
            })
    }

    /// Get the first available client (for single-peer setups).
    pub fn any_client(&self) -> Option<Arc<DiameterClient>> {
        self.clients.iter().next().map(|entry| Arc::clone(entry.value()))
    }

    /// Number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.clients.len()
    }

    /// Shutdown all peers.
    pub fn shutdown_all(&self) {
        for entry in self.clients.iter() {
            entry.value().shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::PeerConfig;

    #[test]
    fn manager_empty() {
        let manager = DiameterManager::new();
        assert_eq!(manager.peer_count(), 0);
        assert!(manager.client("hss1").is_none());
        assert!(manager.any_client().is_none());
    }

    #[test]
    fn manager_register_and_lookup() {
        let manager = DiameterManager::new();

        // Create a minimal peer config for testing
        let config = PeerConfig {
            host: "hss1.example.com".to_string(),
            port: 3868,
            origin_host: "siphon.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: None,
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        };

        // We cannot create a real DiameterPeer (requires TCP), so we test
        // the manager's DashMap logic by verifying the API contract.
        // Use a tokio runtime to create a peer via channels.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
            let peer = Arc::new(peer::DiameterPeer::new_for_test(config, write_tx));
            let client = Arc::new(DiameterClient::new(Arc::clone(&peer)));

            manager.register("hss1".to_string(), Arc::clone(&client));
            assert_eq!(manager.peer_count(), 1);
            assert!(manager.client("hss1").is_some());
            assert!(manager.client("hss2").is_none());
            assert!(manager.any_client().is_some());
        });
    }

    #[test]
    fn manager_shutdown_all() {
        let manager = DiameterManager::new();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let config = PeerConfig {
                host: "hss1.example.com".to_string(),
                port: 3868,
                origin_host: "siphon.example.com".to_string(),
                origin_realm: "example.com".to_string(),
                destination_host: None,
                destination_realm: "example.com".to_string(),
                local_ip: "10.0.0.1".parse().unwrap(),
                application_ids: vec![],
                watchdog_interval: 30,
                reconnect_delay: 5,
                product_name: "SIPhon".to_string(),
                firmware_revision: 100,
            };

            let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
            let peer = Arc::new(peer::DiameterPeer::new_for_test(config, write_tx));
            let client = Arc::new(DiameterClient::new(peer));

            manager.register("hss1".to_string(), client);

            // Should not panic
            manager.shutdown_all();
            assert_eq!(manager.peer_count(), 1);
        });
    }

    #[test]
    fn mar_with_sip_authorization_encodes_resync_data() {
        // Build the SIP-Auth-Data-Item with SIP-Authorization AVP the same way
        // send_mar() does when sip_authorization is Some.
        let resync_data: Vec<u8> = {
            let rand = [0xABu8; 16];
            let auts = [0xCDu8; 14];
            let mut data = Vec::with_capacity(30);
            data.extend_from_slice(&rand);
            data.extend_from_slice(&auts);
            data
        };
        assert_eq!(resync_data.len(), 30);

        let mut auth_children = Vec::new();
        auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::SIP_AUTHENTICATION_SCHEME,
            "Digest-AKAv1-MD5",
        ));
        auth_children.extend_from_slice(&encode_avp_octet_3gpp(
            avp::SIP_AUTHORIZATION,
            &resync_data,
        ));
        let sip_auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "scscf.ims.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, "ims.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avp_bytes.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::PUBLIC_IDENTITY,
            "sip:alice@ims.example.com",
        ));
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
        avp_bytes.extend_from_slice(&sip_auth_data_item);

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_MULTIMEDIA_AUTH,
            dictionary::CX_APP_ID,
            100, 200,
            &avp_bytes,
        );

        let decoded = codec::decode_diameter(&msg).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_MULTIMEDIA_AUTH);

        // Verify SIP-Auth-Data-Item contains SIP-Authorization
        let auth_data = decoded.avps.get("SIP-Auth-Data-Item");
        assert!(auth_data.is_some(), "SIP-Auth-Data-Item AVP missing");

        let sip_auth = auth_data.unwrap().get("SIP-Authorization");
        assert!(sip_auth.is_some(), "SIP-Authorization AVP missing in SIP-Auth-Data-Item");

        // The codec hex-encodes OctetString AVPs, verify the decoded length
        let hex_value = sip_auth.unwrap().as_str().unwrap();
        let raw_bytes = codec::hex::decode(hex_value).unwrap();
        assert_eq!(raw_bytes.len(), 30, "RAND(16) + AUTS(14) = 30 bytes");
        assert_eq!(&raw_bytes[..16], &[0xABu8; 16]);
        assert_eq!(&raw_bytes[16..], &[0xCDu8; 14]);
    }
}
