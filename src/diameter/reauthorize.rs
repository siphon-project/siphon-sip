//! Server-initiated reauthorization (RAR) on an existing serving connection.
//!
//! A node serving an application (credit control, Gx, Rx) learns which client
//! sits behind which inbound connection from the requests that client sends.
//! Each connection loop that owns an inbound connection holds a
//! [`ServingConnection`]: it records a request's Origin-Host in the shared
//! registry the first time that host is seen on the connection, and removes
//! exactly its own entries when the connection loop ends. Requests relayed by
//! an agent carry the originating client's Origin-Host, so one connection can
//! serve several hosts. Nothing here runs per request beyond a lookup in the
//! connection's own set.
use super::{codec, dictionary, peer::DiameterPeer};
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Weak};

/// (tenant, configured peer name, client Origin-Host).
type ConnectionKey = (String, String, String);
static CONNECTIONS: LazyLock<DashMap<ConnectionKey, Weak<DiameterPeer>>> =
    LazyLock::new(DashMap::new);

/// The registry entries one inbound serving connection owns. Owned by the
/// connection loop; dropping it (the loop ends) removes its entries, unless a
/// newer connection has since claimed the same key.
pub(crate) struct ServingConnection {
    tenant: String,
    name: String,
    peer: Weak<DiameterPeer>,
    hosts: HashSet<String>,
}

impl ServingConnection {
    pub(crate) fn new(tenant: &str, name: &str, peer: &Arc<DiameterPeer>) -> Self {
        Self {
            tenant: tenant.to_owned(),
            name: name.to_owned(),
            peer: Arc::downgrade(peer),
            hosts: HashSet::new(),
        }
    }

    /// Record the Origin-Host of a decoded inbound request. Returns whether
    /// the shared registry was written, which happens only for a host not yet
    /// seen on this connection.
    pub(crate) fn observe(&mut self, avps: &serde_json::Value) -> bool {
        let Some(host) = avps.get("Origin-Host").and_then(serde_json::Value::as_str) else {
            return false;
        };
        if host.is_empty() || self.hosts.contains(host) {
            return false;
        }
        CONNECTIONS.insert(
            (self.tenant.clone(), self.name.clone(), host.to_owned()),
            Weak::clone(&self.peer),
        );
        self.hosts.insert(host.to_owned());
        true
    }
}

impl Drop for ServingConnection {
    fn drop(&mut self) {
        for host in self.hosts.drain() {
            CONNECTIONS.remove_if(
                &(self.tenant.clone(), self.name.clone(), host),
                |_, registered| Weak::ptr_eq(registered, &self.peer),
            );
        }
    }
}

/// The open connection that last carried a request from `host` for the
/// configured peer `name` in `tenant`.
pub(crate) fn connection(tenant: &str, name: &str, host: &str) -> Option<Arc<DiameterPeer>> {
    CONNECTIONS
        .get(&(tenant.into(), name.into(), host.into()))
        .and_then(|peer| peer.upgrade())
        .filter(|peer| peer.is_open())
}

/// AVPs the RAR builder sets itself; a caller cannot supply them again.
pub(crate) const FIXED_AVPS: [u32; 7] = [
    dictionary::avp::SESSION_ID,
    dictionary::avp::ORIGIN_HOST,
    dictionary::avp::ORIGIN_REALM,
    dictionary::avp::DESTINATION_HOST,
    dictionary::avp::DESTINATION_REALM,
    AUTH_APPLICATION_ID,
    RE_AUTH_REQUEST_TYPE,
];
const AUTH_APPLICATION_ID: u32 = 258;
const RE_AUTH_REQUEST_TYPE: u32 = 285;
const RE_AUTH_REQUEST: u32 = 258;
/// Re-Auth-Request-Type AUTHORIZE_ONLY (RFC 6733 section 8.12).
const AUTHORIZE_ONLY: u32 = 0;

/// The Re-Auth-Request for `application_id`. Session-Id comes first (RFC 6733
/// section 3); the application id goes in the header and in Auth-Application-Id,
/// as the RAR ABNF of RFC 8506, TS 29.212 and TS 29.214 have it. `extra` holds
/// already-encoded application AVPs, appended after the fixed ones.
pub(crate) fn wire(
    peer: &DiameterPeer,
    session: &str,
    host: &str,
    realm: &str,
    application_id: u32,
    extra: &[u8],
) -> Vec<u8> {
    let mut avps = Vec::with_capacity(160 + extra.len());
    for (code, value) in [
        (dictionary::avp::SESSION_ID, session),
        (
            dictionary::avp::ORIGIN_HOST,
            peer.config().origin_host.as_str(),
        ),
        (
            dictionary::avp::ORIGIN_REALM,
            peer.config().origin_realm.as_str(),
        ),
        (dictionary::avp::DESTINATION_HOST, host),
        (dictionary::avp::DESTINATION_REALM, realm),
    ] {
        avps.extend(codec::encode_avp_utf8(code, value));
    }
    avps.extend(codec::encode_avp_u32(AUTH_APPLICATION_ID, application_id));
    avps.extend(codec::encode_avp_u32(RE_AUTH_REQUEST_TYPE, AUTHORIZE_ONLY));
    avps.extend_from_slice(extra);
    codec::encode_diameter_message(
        codec::FLAG_REQUEST | codec::FLAG_PROXIABLE,
        RE_AUTH_REQUEST,
        application_id,
        peer.next_hbh(),
        peer.next_e2e(),
        &avps,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::diameter::peer::{PeerConfig, PeerState};
    use serde_json::json;

    pub(crate) fn open_peer() -> Arc<DiameterPeer> {
        let (sender, _) = tokio::sync::mpsc::channel(1);
        let peer = Arc::new(DiameterPeer::new_for_test(
            PeerConfig {
                host: "192.0.2.1".into(),
                port: 3868,
                origin_host: "chf.example".into(),
                origin_realm: "example".into(),
                destination_host: Some("smf.example".into()),
                destination_realm: "example".into(),
                local_ip: "192.0.2.2".parse().unwrap(),
                application_ids: vec![(0, 4)],
                watchdog_interval: 30,
                reconnect_delay: 5,
                product_name: "test-peer".into(),
                firmware_revision: 1,
            },
            sender,
        ));
        peer.set_state_for_test(PeerState::Open);
        peer
    }

    fn request_from(host: &str) -> serde_json::Value {
        json!({ "Origin-Host": host, "Session-Id": "s;1" })
    }

    fn registered(tenant: &str, name: &str, host: &str) -> Option<Weak<DiameterPeer>> {
        CONNECTIONS
            .get(&(tenant.into(), name.into(), host.into()))
            .map(|entry| Weak::clone(&entry))
    }

    #[test]
    fn absent_serving_connection_is_not_routed_to_an_unrelated_peer() {
        assert!(connection("test-tenant", "test-peer", "ims.example").is_none());
    }

    #[test]
    fn a_new_host_registers_once() {
        let peer = open_peer();
        let mut serving = ServingConnection::new("t-new", "p", &peer);
        assert!(serving.observe(&request_from("a.example")));
        assert!(!serving.observe(&request_from("a.example")));
        assert!(serving.observe(&request_from("b.example")));
        assert!(connection("t-new", "p", "a.example").is_some());
        assert!(connection("t-new", "p", "b.example").is_some());
    }

    #[test]
    fn a_request_without_origin_host_registers_nothing() {
        let peer = open_peer();
        let mut serving = ServingConnection::new("t-none", "p", &peer);
        assert!(!serving.observe(&json!({ "Session-Id": "s;1" })));
        assert!(!serving.observe(&request_from("")));
    }

    #[test]
    fn a_repeated_host_does_not_touch_the_registry() {
        let first = open_peer();
        let other = open_peer();
        let mut serving = ServingConnection::new("t-repeat", "p", &first);
        assert!(serving.observe(&request_from("a.example")));
        // Overwrite the entry behind the guard's back: a repeat sighting must
        // leave it as it is.
        CONNECTIONS.insert(
            ("t-repeat".into(), "p".into(), "a.example".into()),
            Arc::downgrade(&other),
        );
        assert!(!serving.observe(&request_from("a.example")));
        let entry = registered("t-repeat", "p", "a.example").unwrap();
        assert!(Weak::ptr_eq(&entry, &Arc::downgrade(&other)));
    }

    #[test]
    fn dropping_the_connection_removes_its_own_entries() {
        let peer = open_peer();
        let mut serving = ServingConnection::new("t-drop", "p", &peer);
        serving.observe(&request_from("a.example"));
        serving.observe(&request_from("b.example"));
        drop(serving);
        assert!(registered("t-drop", "p", "a.example").is_none());
        assert!(registered("t-drop", "p", "b.example").is_none());
    }

    #[test]
    fn dropping_an_old_connection_keeps_a_newer_connections_entry() {
        let old = open_peer();
        let newer = open_peer();
        let mut old_serving = ServingConnection::new("t-reconnect", "p", &old);
        old_serving.observe(&request_from("a.example"));
        old_serving.observe(&request_from("b.example"));
        let mut newer_serving = ServingConnection::new("t-reconnect", "p", &newer);
        newer_serving.observe(&request_from("a.example"));
        drop(old_serving);
        let kept = connection("t-reconnect", "p", "a.example").unwrap();
        assert!(Arc::ptr_eq(&kept, &newer));
        assert!(registered("t-reconnect", "p", "b.example").is_none());
        drop(newer_serving);
        assert!(registered("t-reconnect", "p", "a.example").is_none());
    }

    #[test]
    fn scoped_connection_closes_without_routing_to_another_tenant() {
        let peer = open_peer();
        let mut serving = ServingConnection::new("tenant-a", "local-ims", &peer);
        serving.observe(&request_from("ims.example"));
        assert!(connection("tenant-a", "local-ims", "ims.example").is_some());
        assert!(connection("tenant-b", "local-ims", "ims.example").is_none());
        assert!(connection("tenant-a", "other-peer", "ims.example").is_none());
        assert!(connection("tenant-a", "local-ims", "other.example").is_none());
        peer.set_state_for_test(PeerState::Closed);
        assert!(connection("tenant-a", "local-ims", "ims.example").is_none());
    }

    #[test]
    fn a_dropped_peer_is_not_returned() {
        let peer = open_peer();
        let mut serving = ServingConnection::new("t-gone", "p", &peer);
        serving.observe(&request_from("a.example"));
        drop(peer);
        assert!(connection("t-gone", "p", "a.example").is_none());
    }

    fn decoded(application_id: u32, extra: &[u8]) -> codec::DiameterMsg {
        let peer = open_peer();
        let wire = wire(
            &peer,
            "chf.example;1;2",
            "smf.example",
            "example",
            application_id,
            extra,
        );
        codec::DiameterMsg::from_wire(&wire).unwrap()
    }

    #[test]
    fn an_ro_rar_names_credit_control_in_header_and_body() {
        let message = decoded(dictionary::RO_APP_ID, &[]);
        assert_eq!(message.command_code, 258);
        assert!(message.is_request());
        assert!(message.is_proxiable());
        assert_eq!(message.application_id, 4);
        assert_eq!(message.avps[0].code, dictionary::avp::SESSION_ID);
        assert_eq!(message.get_str(263).as_deref(), Some("chf.example;1;2"));
        assert_eq!(message.get_str(264).as_deref(), Some("chf.example"));
        assert_eq!(message.get_str(296).as_deref(), Some("example"));
        assert_eq!(message.get_str(293).as_deref(), Some("smf.example"));
        assert_eq!(message.get_str(283).as_deref(), Some("example"));
        assert_eq!(message.find(258, 0).and_then(|avp| avp.as_u32()), Some(4));
        assert_eq!(message.find(285, 0).and_then(|avp| avp.as_u32()), Some(0));
    }

    #[test]
    fn a_gx_rar_names_gx_in_header_and_body() {
        let message = decoded(dictionary::GX_APP_ID, &[]);
        assert_eq!(message.application_id, 16_777_238);
        assert_eq!(
            message.find(258, 0).and_then(|avp| avp.as_u32()),
            Some(16_777_238)
        );
    }

    #[test]
    fn extra_avps_follow_the_fixed_ones() {
        let extra = codec::encode_avp_u32_3gpp(dictionary::avp::EVENT_TRIGGER, 2);
        let message = decoded(dictionary::GX_APP_ID, &extra);
        let last = message.avps.last().unwrap();
        assert_eq!(
            (last.code, last.vendor),
            (dictionary::avp::EVENT_TRIGGER, 10415)
        );
        assert_eq!(last.as_u32(), Some(2));
    }
}
