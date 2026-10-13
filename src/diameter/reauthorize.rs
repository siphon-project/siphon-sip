//! Server-initiated credit reauthorization on an existing serving connection.
use super::{codec, peer::DiameterPeer};
use dashmap::DashMap;
use std::sync::{Arc, LazyLock, Weak};

type ConnectionKey = (String, String, String);
static CONNECTIONS: LazyLock<DashMap<ConnectionKey, Weak<DiameterPeer>>> =
    LazyLock::new(DashMap::new);

pub(crate) fn register(tenant: &str, name: &str, host: &str, peer: &Arc<DiameterPeer>) {
    CONNECTIONS.retain(|_, connection| connection.strong_count() > 0);
    CONNECTIONS.insert(
        (tenant.into(), name.into(), host.into()),
        Arc::downgrade(peer),
    );
}

pub(crate) fn connection(tenant: &str, name: &str, host: &str) -> Option<Arc<DiameterPeer>> {
    CONNECTIONS
        .get(&(tenant.into(), name.into(), host.into()))
        .and_then(|peer| peer.upgrade())
        .filter(|peer| peer.is_open())
}

pub(crate) fn wire(peer: &DiameterPeer, session: &str, host: &str, realm: &str) -> Vec<u8> {
    let mut avps = Vec::new();
    for (code, value) in [
        (263, session),
        (264, peer.config().origin_host.as_str()),
        (296, peer.config().origin_realm.as_str()),
        (293, host),
        (283, realm),
    ] {
        avps.extend(codec::encode_avp_utf8(code, value));
    }
    avps.extend(codec::encode_avp_u32(258, 4));
    avps.extend(codec::encode_avp_u32(285, 0));
    codec::encode_diameter_message(
        codec::FLAG_REQUEST | codec::FLAG_PROXIABLE,
        258,
        4,
        peer.next_hbh(),
        peer.next_e2e(),
        &avps,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_serving_connection_is_not_routed_to_an_unrelated_peer() {
        assert!(connection("test-tenant", "test-peer", "ims.example").is_none());
    }
    #[test]
    fn scoped_connection_closes_without_routing_to_another_tenant() {
        use crate::diameter::peer::{PeerConfig, PeerState};
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let peer = Arc::new(DiameterPeer::new_for_test(
            PeerConfig {
                host: "192.0.2.1".into(),
                port: 3868,
                origin_host: "chf.example".into(),
                origin_realm: "example".into(),
                destination_host: Some("ims.example".into()),
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
        register("tenant-a", "local-ims", "ims.example", &peer);
        assert!(connection("tenant-a", "local-ims", "ims.example").is_some());
        assert!(connection("tenant-b", "local-ims", "ims.example").is_none());
        assert!(connection("tenant-a", "local-ims", "other.example").is_none());
        peer.set_state_for_test(PeerState::Closed);
        assert!(connection("tenant-a", "local-ims", "ims.example").is_none());
    }
}
