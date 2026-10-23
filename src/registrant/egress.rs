//! Where a request a UE sends over its security association goes.

use std::net::{IpAddr, SocketAddr};

use super::RegistrantManager;

/// The addresses of a request sent over a UE's established SA set (TS 33.203
/// clause 7.1): from the UE's protected client port to the P-CSCF's protected
/// server port, naming the UE's protected server port in its Via, which is
/// where the P-CSCF sends the responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UeEgress {
    /// The UE's protected client port on `ue_ip`: the source.
    pub local: SocketAddr,
    /// The P-CSCF's protected server port: the destination.
    pub destination: SocketAddr,
    /// The UE's protected server port on `ue_ip`: the Via sent-by.
    pub sent_by: SocketAddr,
}

impl RegistrantManager {
    /// The egress of a request `aor` sends over its established SA set, from
    /// `ue_ip`, siphon's own address on the SA. `None` until a set is
    /// established, and after the entry is removed.
    ///
    /// Read for every request, not once: a re-registration replaces the set,
    /// and with it the client port the requests leave from.
    pub fn ue_egress(&self, aor: &str, ue_ip: IpAddr) -> Option<UeEgress> {
        let entry = self.entries.get(aor)?;
        let (ue_port_c, pcscf_port_s) = Self::established_ports(&entry)?;
        let ue_port_s = entry.ue_ipsec.as_ref()?.ue_port_s;
        Some(UeEgress {
            local: SocketAddr::new(ue_ip, ue_port_c),
            destination: SocketAddr::new(entry.destination.ip(), pcscf_port_s),
            sent_by: SocketAddr::new(ue_ip, ue_port_s),
        })
    }

    /// Where a UDP response leaving a UE's protected server port `local` for
    /// the P-CSCF at `destination` goes instead: `(destination, local)` from
    /// the UE's protected client port to the P-CSCF's protected server port.
    ///
    /// TS 33.203 clause 7.1, UDP case: the UE "sends requests and responses
    /// protected with ESP on the port port_uc" and the P-CSCF "receives
    /// requests and responses protected with ESP from any UE on the port
    /// port_ps". A request the P-CSCF sends arrives on (port_pc -> port_us),
    /// so answering it back to its source would use the pair the UE only
    /// receives on. The mirror of the P-CSCF's own rule (`IpsecManager::
    /// udp_flow_to_ue`). `None` when `local` is no IPsec entry's protected
    /// server port, or the entry has no established set.
    pub fn ue_udp_response_egress(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
    ) -> Option<(SocketAddr, SocketAddr)> {
        self.entries.iter().find_map(|entry| {
            let ipsec = entry.ue_ipsec.as_ref()?;
            let own_address = entry.local_addr.is_none_or(|own| own == local.ip());
            if ipsec.ue_port_s != local.port()
                || !own_address
                || entry.destination.ip() != destination.ip()
            {
                return None;
            }
            let (ue_port_c, pcscf_port_s) = Self::established_ports(&entry)?;
            Some((
                SocketAddr::new(destination.ip(), pcscf_port_s),
                SocketAddr::new(local.ip(), ue_port_c),
            ))
        })
    }
}

/// A UE of the shared fixtures, registered over an established SA set from
/// `ue_ip`: what a request over its SA needs. Returns its AoR.
#[cfg(test)]
pub(crate) fn established_ue(manager: &RegistrantManager, index: u32, ue_ip: IpAddr) -> String {
    use super::test_support;
    let aor = test_support::impu(index);
    manager.add(test_support::ue(index, Some(ue_ip)));
    rotate_sa_set(manager, &aor);
    aor
}

/// Run the authentication of a re-registration of `aor` to its end, which
/// replaces its established SA set with a new one.
#[cfg(test)]
pub(crate) fn rotate_sa_set(manager: &RegistrantManager, aor: &str) {
    // The REGISTER that starts it offers a client port no held set uses.
    let listen = std::collections::HashMap::from([(
        crate::transport::Transport::Udp,
        "192.0.2.1:5060".parse().expect("an address"),
    )]);
    let defaults =
        super::EgressDefaults::new("192.0.2.1:5060".parse().expect("an address"), &listen);
    manager
        .build_register(aor, defaults, 600000)
        .expect("a REGISTER");
    let server = crate::ipsec::parse_security_client(super::test_support::SECURITY_SERVER)
        .expect("the fixture's Security-Server parses");
    manager.store_security_server(aor, &server, super::test_support::SECURITY_SERVER);
    manager
        .begin_authentication(aor, "Digest username=\"ue\"")
        .expect("an SA set to authenticate");
    manager
        .conclude_ipsec_exchange(aor)
        .expect("the exchange concludes");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_egress_runs_from_the_client_port_to_the_pcscf_server_port() {
        let manager = super::super::test_support::manager();
        let ue_ip: IpAddr = "192.0.2.77".parse().unwrap();
        let aor = super::super::test_support::impu(1);
        manager.add(super::super::test_support::ue(1, Some(ue_ip)));
        assert_eq!(manager.ue_egress(&aor, ue_ip), None, "no SA set yet");

        rotate_sa_set(&manager, &aor);
        let egress = manager.ue_egress(&aor, ue_ip).expect("an established set");
        assert_eq!(egress.destination, "198.51.100.10:5066".parse().unwrap());
        assert_eq!(egress.sent_by, "192.0.2.77:6101".parse().unwrap());
        assert_eq!(egress.local.ip(), ue_ip);
        assert_ne!(
            egress.local.port(),
            6101,
            "a client port, not the server port"
        );

        // A re-registration replaces the set, and its client port with it.
        rotate_sa_set(&manager, &aor);
        let rotated = manager.ue_egress(&aor, ue_ip).expect("the new set");
        assert_ne!(rotated.local, egress.local);
        assert_eq!(rotated.sent_by, egress.sent_by);

        manager.remove(&aor);
        assert_eq!(manager.ue_egress(&aor, ue_ip), None);
    }

    #[test]
    fn a_response_from_the_protected_server_port_leaves_from_the_client_port() {
        let manager = super::super::test_support::manager();
        let ue_ip: IpAddr = "192.0.2.77".parse().unwrap();
        let ue_server: SocketAddr = "192.0.2.77:6101".parse().unwrap();
        let pcscf_client: SocketAddr = "198.51.100.10:5064".parse().unwrap();
        let aor = super::super::test_support::impu(1);
        manager.add(super::super::test_support::ue(1, Some(ue_ip)));
        assert_eq!(
            manager.ue_udp_response_egress(ue_server, pcscf_client),
            None,
            "no SA set yet"
        );

        rotate_sa_set(&manager, &aor);
        let egress = manager.ue_egress(&aor, ue_ip).unwrap();
        assert_eq!(
            manager.ue_udp_response_egress(ue_server, pcscf_client),
            Some((egress.destination, egress.local))
        );
        // Another UE's address, another peer, or another port: untouched.
        for (local, destination) in [
            ("192.0.2.78:6101", "198.51.100.10:5064"),
            ("192.0.2.77:6101", "198.51.100.11:5064"),
            ("192.0.2.77:5060", "198.51.100.10:5064"),
        ] {
            assert_eq!(
                manager
                    .ue_udp_response_egress(local.parse().unwrap(), destination.parse().unwrap()),
                None,
                "{local} -> {destination}"
            );
        }
    }
}
