//! The directly connected peers of a Diameter server, by the Origin-Host each
//! gave in its capabilities exchange.
//!
//! A relay forwards a request whose Destination-Host is a directly connected
//! peer to that peer (RFC 6733 section 6.1.6), whichever side opened the
//! connection: a backend this node dialled (`servers`, `connect_to`) or a
//! client that dialled in (`clients`). The connection loop that owns a
//! connection holds its [`Listing`] for as long as the connection lives;
//! dropping it removes the entry, unless a newer connection of the same peer
//! has replaced it. Lookups never return a connection that is not open.
//!
//! DiameterIdentity is an FQDN (RFC 6733 section 4.3.1), so hosts compare
//! without regard to case.
use super::peer::DiameterPeer;
use dashmap::DashMap;
use std::sync::{Arc, LazyLock, Weak};

/// Tenant and lower-case Origin-Host.
type Key = (String, String);

struct Entry {
    name: String,
    peer: Weak<DiameterPeer>,
}

static PEERS: LazyLock<DashMap<Key, Entry>> = LazyLock::new(DashMap::new);

/// One connection's entry, owned by its connection loop.
pub(crate) struct Listing {
    key: Key,
    peer: Weak<DiameterPeer>,
}

/// List `peer`, the connection of the configured peer `name` in `tenant`, by
/// the Origin-Host it gave in its CER or CEA. None when it gave none.
pub(crate) fn list(tenant: &str, name: &str, peer: &Arc<DiameterPeer>) -> Option<Listing> {
    let host = peer.remote_origin_host().filter(|host| !host.is_empty())?;
    let key = (tenant.to_owned(), host.to_ascii_lowercase());
    let weak = Arc::downgrade(peer);
    PEERS.insert(
        key.clone(),
        Entry {
            name: name.to_owned(),
            peer: Weak::clone(&weak),
        },
    );
    Some(Listing { key, peer: weak })
}

impl Drop for Listing {
    fn drop(&mut self) {
        PEERS.remove_if(&self.key, |_, entry| Weak::ptr_eq(&entry.peer, &self.peer));
    }
}

/// The open connection to the peer whose Origin-Host is `host` in `tenant`,
/// with the name of the configured peer it belongs to.
pub(crate) fn find(tenant: &str, host: &str) -> Option<(String, Arc<DiameterPeer>)> {
    let key = (tenant.to_owned(), host.to_ascii_lowercase());
    let entry = PEERS.get(&key)?;
    let peer = entry.peer.upgrade().filter(|peer| peer.is_open())?;
    Some((entry.name.clone(), peer))
}

/// Entries listed for `tenant`, for the drain test.
#[cfg(test)]
fn listed_in(tenant: &str) -> usize {
    PEERS.iter().filter(|entry| entry.key().0 == tenant).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::{PeerConfig, PeerState};
    use tokio::sync::mpsc;

    fn connected(origin_host: Option<&str>) -> Arc<DiameterPeer> {
        let config = PeerConfig {
            host: "192.0.2.10".to_string(),
            port: 3868,
            origin_host: "dra.example.net".to_string(),
            origin_realm: "example.net".to_string(),
            destination_host: None,
            destination_realm: "example.net".to_string(),
            local_ip: "192.0.2.1".parse().expect("a literal address"),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            source_address: None,
            lifecycle: Default::default(),
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        };
        let (write_tx, _write_rx) = mpsc::channel(1);
        let peer = Arc::new(DiameterPeer::new_for_test(config, write_tx));
        if let Some(host) = origin_host {
            peer.set_remote_identity(host, "example.net");
        }
        peer
    }

    #[test]
    fn a_listed_peer_is_found_by_its_origin_host_in_any_case() {
        let peer = connected(Some("mme-1.example.net"));
        let _listing = list("t-find", "mme", &peer).expect("the peer gave an Origin-Host");
        let (name, found) = find("t-find", "MME-1.Example.NET").expect("listed");
        assert_eq!(name, "mme");
        assert!(Arc::ptr_eq(&found, &peer));
    }

    #[test]
    fn a_peer_is_found_only_in_its_own_tenant() {
        let peer = connected(Some("hss.example.net"));
        let _listing = list("t-own", "hss", &peer).expect("listed");
        assert!(find("t-other", "hss.example.net").is_none());
    }

    #[test]
    fn a_peer_without_an_origin_host_is_not_listed() {
        assert!(list("t-anonymous", "p", &connected(None)).is_none());
        assert!(list("t-anonymous", "p", &connected(Some(""))).is_none());
    }

    #[test]
    fn a_closed_connection_is_not_found() {
        let peer = connected(Some("scscf-2.example.net"));
        let _listing = list("t-closed", "scscf", &peer).expect("listed");
        peer.set_state_for_test(PeerState::Closed);
        assert!(find("t-closed", "scscf-2.example.net").is_none());
    }

    #[test]
    fn dropping_the_listing_removes_the_peer() {
        let peer = connected(Some("smsc.example.net"));
        let listing = list("t-drop", "smsc", &peer).expect("listed");
        drop(listing);
        assert!(find("t-drop", "smsc.example.net").is_none());
    }

    #[test]
    fn a_reconnected_peer_replaces_the_old_connection_and_survives_its_drop() {
        let old = connected(Some("udm-0.example.net"));
        let old_listing = list("t-reconnect", "udm", &old).expect("listed");
        let newer = connected(Some("udm-0.example.net"));
        let _newer_listing = list("t-reconnect", "udm", &newer).expect("listed");
        drop(old_listing);
        let (_, found) = find("t-reconnect", "udm-0.example.net").expect("the newer stays");
        assert!(Arc::ptr_eq(&found, &newer));
    }

    #[test]
    fn a_dropped_peer_is_not_found_even_before_its_listing_goes() {
        let peer = connected(Some("gone.example.net"));
        let _listing = list("t-gone", "gone", &peer).expect("listed");
        drop(peer);
        assert!(find("t-gone", "gone.example.net").is_none());
    }

    #[test]
    fn the_directory_drains_back_to_empty_after_many_connections() {
        let listings: Vec<_> = (0..500)
            .map(|index| {
                let peer = connected(Some(&format!("peer-{index}.example.net")));
                let listing = list("t-drain", "p", &peer).expect("listed");
                (peer, listing)
            })
            .collect();
        assert_eq!(listed_in("t-drain"), 500);
        drop(listings);
        assert_eq!(
            listed_in("t-drain"),
            0,
            "every closed connection leaves the directory"
        );
    }
}
