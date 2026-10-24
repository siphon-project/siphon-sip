//! Per-entry addresses: one process registering many IMS UEs, each from an
//! address of its own.
//!
//! An entry's `local_addr` is the UE's address. It is the Via and Contact host
//! of every REGISTER the entry sends, the UDP source of the unprotected
//! REGISTER, the retry and the de-REGISTER, and with IPsec sec-agree the UE
//! side of the four SAs (TS 33.203 §7.1), the protected REGISTER leaving from
//! `local_addr:ue_port_c`. The protected ports may repeat across entries, as
//! they do across real handsets: the SAs are told apart by address.
//!
//! The address is supplied, never derived: a script or `siphon.yaml` names it,
//! and [`RegistrantManager::set_local_addr`] moves it when the address the UE
//! holds changes. An entry without one registers from the process's address,
//! exactly as before.
//!
//! UDP and TCP. Over TCP the entry listens on its address (its protected
//! server port with IPsec, else its plain port) for the connection the P-CSCF
//! opens to it, and its own connection to the P-CSCF leaves from its address
//! (its protected client port, or the plain port for the unprotected initial
//! REGISTER); see [`RegistrantManager::ue_stream_plan`]. TLS is refused: the
//! UE side has no client certificate or TLS listener of its own.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use tracing::info;

use super::{RegistrantEntry, RegistrantEvent, RegistrantManager, RegistrantState};
use crate::transport::ue_streams::UeTcpPlan;
use crate::transport::Transport;

/// What [`RegistrantManager::find_by_local`] matches: an address alone, or an
/// address and the port a message arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAddrQuery {
    /// Any entry on this address.
    Ip(IpAddr),
    /// The entry on this address owning this port: its plain port, or with
    /// IPsec its protected client or server port.
    Socket(SocketAddr),
}

impl LocalAddrQuery {
    /// Parse `"192.0.2.10"`, `"192.0.2.10:6101"`, `"2001:db8::1"` or
    /// `"[2001:db8::1]:6101"`.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if let Ok(socket) = value.parse::<SocketAddr>() {
            return Ok(Self::Socket(socket));
        }
        let bare = value
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(value);
        bare.parse::<IpAddr>()
            .map(Self::Ip)
            .map_err(|_| format!("'{value}' is not an IP address or IP:port"))
    }
}

/// The identity two entries may not share: an address and the UE protected
/// ports (none without IPsec). Two IPsec entries on one address with disjoint
/// protected ports (its three client ports and server port, see
/// [`super::protected`]) are two UEs; two sharing a port would install
/// colliding SAs, and two plain entries would be indistinguishable to an MT
/// request.
fn address_key(entry: &RegistrantEntry) -> Option<(IpAddr, Vec<u16>)> {
    entry
        .local_addr
        .map(|ip| (ip, RegistrantManager::protected_ports(entry)))
}

/// Whether two address keys collide: the same address, and both plain or
/// sharing a protected port.
fn keys_collide(ours: &(IpAddr, Vec<u16>), theirs: &(IpAddr, Vec<u16>)) -> bool {
    ours.0 == theirs.0
        && (ours.1.is_empty() && theirs.1.is_empty()
            || ours.1.iter().any(|port| theirs.1.contains(port)))
}

impl RegistrantManager {
    /// Add an entry, refusing one whose `local_addr` cannot be used: it is
    /// neither UDP nor TCP, or another entry (not one with the same AoR, which this replaces)
    /// already registers from the same address and protected client port.
    ///
    /// An entry that requires an address and has none starts in
    /// [`RegistrantState::AwaitingAddress`].
    pub fn try_add(&self, mut entry: RegistrantEntry) -> Result<(), String> {
        let _guard = self
            .address_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        check_transport(&entry, entry.local_addr)?;
        if let Some(ipsec) = entry.ue_ipsec.as_ref() {
            if let Some(problem) =
                super::protected::protected_ports_problem(ipsec.ue_port_c, ipsec.ue_port_s)
            {
                return Err(format!("{}: {problem}", entry.aor));
            }
        }
        if let Some(key) = address_key(&entry) {
            self.refuse_taken(&entry.aor, &key)?;
        }
        if entry.require_local_addr && entry.local_addr.is_none() {
            entry.state = RegistrantState::AwaitingAddress;
        }
        info!(
            aor = %entry.aor,
            registrar = %entry.registrar_uri,
            local_addr = ?entry.local_addr,
            "registrant added"
        );
        let awaiting = entry.state == RegistrantState::AwaitingAddress;
        let aor = entry.aor.clone();
        if let Some(replaced) = self.entries.insert(aor.clone(), entry) {
            // The replacement starts a fresh handshake; the old one's SAs go.
            self.retire_sa_sets(&replaced, None);
        }
        if awaiting {
            self.emit_event(RegistrantEvent::AwaitingAddress { aor });
        }
        Ok(())
    }

    /// `Err` when an entry other than `aor` holds `key`.
    fn refuse_taken(&self, aor: &str, key: &(IpAddr, Vec<u16>)) -> Result<(), String> {
        let holder = self
            .entries
            .iter()
            .find(|other| {
                other.aor != aor
                    && address_key(other).is_some_and(|theirs| keys_collide(key, &theirs))
            })
            .map(|other| other.aor.clone());
        match holder {
            Some(holder) if key.1.is_empty() => {
                Err(format!("local_addr {} is already used by {holder}", key.0))
            }
            Some(holder) => Err(format!(
                "local_addr {} with protected ports {:?} overlaps the ports {holder} uses there",
                key.0, key.1
            )),
            None => Ok(()),
        }
    }

    /// The address `aor` registers from, when it has one of its own.
    pub fn ue_addr(&self, aor: &str) -> Option<IpAddr> {
        self.entries.get(aor).and_then(|entry| entry.local_addr)
    }

    /// Move `aor` to `local_addr`, or take its address away with `None`.
    ///
    /// Idempotent: the address it already has changes nothing, so a script can
    /// restate every UE's current address on a timer. A real move:
    ///
    /// - queues the SA pair on the old address for deletion (the loop holds
    ///   the IPsec manager), and clears the handshake state, so the next
    ///   REGISTER is a fresh initial one with a new Security-Client;
    /// - clears the captured Service-Route / P-Associated-URI / Path, and the
    ///   grant;
    /// - with an address, leaves the entry `Unregistered` and due now;
    ///   without one, `AwaitingAddress` (never due) when the entry requires an
    ///   address, which every entry that ever had one does, else `Unregistered`
    ///   on the process's address.
    ///
    /// The old binding is not de-registered: its address is usually already
    /// gone, so no de-REGISTER could leave from it. A registrar that keys
    /// bindings on the `+sip.instance` (RFC 5626 §6, which an `imei` adds)
    /// replaces it with the new one; otherwise it lapses at its `Expires`.
    ///
    /// `Ok(false)` when there is no such entry. `Err` for an address another
    /// entry holds, or an entry on a transport other than UDP or TCP.
    pub fn set_local_addr(&self, aor: &str, local_addr: Option<IpAddr>) -> Result<bool, String> {
        let _guard = self
            .address_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((current, transport, ports)) = self.entries.get(aor).map(|entry| {
            (
                entry.local_addr,
                entry.transport,
                RegistrantManager::protected_ports(&entry),
            )
        }) else {
            return Ok(false);
        };
        if current == local_addr {
            return Ok(true);
        }
        if local_addr.is_some() && !own_address_transport(transport) {
            return Err(transport_error(aor, transport));
        }
        if let Some(ip) = local_addr {
            self.refuse_taken(aor, &(ip, ports))?;
        }

        let Some(mut entry) = self.entries.get_mut(aor) else {
            return Ok(false);
        };
        // Every SA set on the old address goes: the UE deletes its SAs when its
        // address changes and registers afresh (TS 33.203 7.5).
        if let Some(ipsec) = entry.ue_ipsec.as_ref() {
            self.queue_sa_deletions(ipsec.sa_sets.keys().into_iter().map(|key| {
                super::SaDeletion {
                    address: current,
                    key,
                }
            }));
        }
        reset_for_new_address(&mut entry, local_addr);
        let awaiting = entry.state == RegistrantState::AwaitingAddress;
        info!(aor = %aor, from = ?current, to = ?local_addr, "registrant address changed");
        drop(entry);
        if awaiting {
            self.emit_event(RegistrantEvent::AwaitingAddress {
                aor: aor.to_string(),
            });
        }
        Ok(true)
    }

    /// The AoR registering from `query`: the first entry on that address, or
    /// with a port the one owning that port (plain, or protected client or
    /// server). A linear scan: for routing an MT request by the address it
    /// arrived on (`call.flow.local_addr`), not a per-packet path.
    pub fn find_by_local(&self, query: LocalAddrQuery) -> Option<String> {
        let plain_port = self
            .egress
            .get()
            .map_or(5060, |egress| egress.defaults().plain_port());
        self.entries
            .iter()
            .find(|entry| match (query, entry.local_addr) {
                (LocalAddrQuery::Ip(ip), Some(own)) => own == ip,
                (LocalAddrQuery::Socket(socket), Some(own)) => {
                    own == socket.ip()
                        && (socket.port() == plain_port
                            || RegistrantManager::protected_ports(entry).contains(&socket.port()))
                }
                (_, None) => false,
            })
            .map(|entry| entry.aor.clone())
    }

    /// How many entries are in each state, every state present (zero when
    /// none), keyed by its name.
    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts: BTreeMap<&'static str, usize> = ALL_STATES
            .iter()
            .map(|state| (state_name(*state), 0))
            .collect();
        for entry in self.entries.iter() {
            *counts.entry(state_name(entry.state)).or_insert(0) += 1;
        }
        counts
    }

    /// Every socket the entries need opened at run time, per AoR: for an
    /// entry with an address of its own, the plain port there; with IPsec, its
    /// protected client ports (all three it rotates through, TS 33.203 7.4.0)
    /// and server port (TS 33.203 7.1), on its own address or else on the
    /// process's UE address `process_ue_ip`. A port a configured `listen.udp`
    /// listener serves is left to it by [`UeSockets`](crate::transport::ue_sockets::UeSockets).
    /// An entry with a `local_addr` over TCP opens none: it listens and
    /// connects through [`ue_stream_plan`](Self::ue_stream_plan).
    pub(super) fn ue_socket_plan(
        &self,
        plain_port: u16,
        process_ue_ip: IpAddr,
    ) -> Vec<(String, Vec<SocketAddr>)> {
        self.entries
            .iter()
            .filter_map(|entry| {
                if entry.local_addr.is_some() && entry.transport == Transport::Tcp {
                    return None;
                }
                let protected = RegistrantManager::protected_ports(&entry);
                let ip = match entry.local_addr {
                    Some(ip) => ip,
                    // An entry waiting for an address of its own opens none.
                    None if !protected.is_empty()
                        && !entry.require_local_addr
                        && !process_ue_ip.is_unspecified() =>
                    {
                        process_ue_ip
                    }
                    None => return None,
                };
                let mut addrs: Vec<SocketAddr> = entry
                    .local_addr
                    .map(|own| SocketAddr::new(own, plain_port))
                    .into_iter()
                    .collect();
                addrs.extend(protected.into_iter().map(|port| SocketAddr::new(ip, port)));
                Some((entry.aor.clone(), addrs))
            })
            .collect()
    }
}

impl RegistrantManager {
    /// What the per-UE TCP side must hold for every TCP entry with an address
    /// of its own ([`UeTcpPlan`]), and each such AoR's listener, so a listener
    /// that will not bind is laid at its owner's door.
    ///
    /// - With IPsec the entry listens on its protected server port, where the
    ///   P-CSCF opens its connection "from the P-CSCF's protected client port
    ///   ... to the UE's protected server port" (TS 24.229 5.2.2.2 1A b). Its
    ///   own connection leaves "from the UE's protected client port and the
    ///   UE's IP address to the P-CSCF's protected server port" (5.1.1.2.2 1
    ///   b), so the three client ports it rotates through are sources, and the
    ///   plain port for the unprotected initial REGISTER. A connection is kept
    ///   from the client port of every SA set it holds, and from the plain port
    ///   until a set is established; any other closes (a re-authentication
    ///   moves to a new client port, TS 33.203 7.4).
    /// - Without IPsec it listens on its plain port, its Contact port, and
    ///   connects from it.
    ///
    /// A removed entry's sets awaiting the answer to its de-REGISTER keep their
    /// connections: the answer comes back on them.
    pub(super) fn ue_stream_plan(&self, plain_port: u16) -> (UeTcpPlan, Vec<(String, SocketAddr)>) {
        let mut plan = UeTcpPlan::default();
        let mut owners = Vec::new();
        for entry in self.entries.iter() {
            let Some(ip) = entry
                .local_addr
                .filter(|_| entry.transport == Transport::Tcp)
            else {
                continue;
            };
            let plain = SocketAddr::new(ip, plain_port);
            plan.sources.insert(plain);
            let listener = match entry.ue_ipsec.as_ref() {
                Some(ipsec) => {
                    let on_address = |port: u16| SocketAddr::new(ip, port);
                    plan.sources
                        .extend(ipsec.client_ports.iter().copied().map(on_address));
                    plan.keep.extend(
                        ipsec
                            .sa_sets
                            .keys()
                            .into_iter()
                            .map(|key| on_address(key.ue_port_c)),
                    );
                    if ipsec.sa_sets.usable().is_none() {
                        plan.keep.insert(plain);
                    }
                    on_address(ipsec.ue_port_s)
                }
                None => {
                    plan.keep.insert(plain);
                    plain
                }
            };
            plan.listeners.insert(listener);
            owners.push((entry.aor.clone(), listener));
        }
        for source in self.teardown_client_sources() {
            plan.sources.insert(source);
            plan.keep.insert(source);
        }
        (plan, owners)
    }
}

/// Every registration state, for [`RegistrantManager::counts`].
const ALL_STATES: [RegistrantState; 6] = [
    RegistrantState::Unregistered,
    RegistrantState::Registering,
    RegistrantState::Challenging,
    RegistrantState::Registered,
    RegistrantState::Failed,
    RegistrantState::AwaitingAddress,
];

fn state_name(state: RegistrantState) -> &'static str {
    match state {
        RegistrantState::Unregistered => "unregistered",
        RegistrantState::Registering => "registering",
        RegistrantState::Challenging => "challenging",
        RegistrantState::Registered => "registered",
        RegistrantState::Failed => "failed",
        RegistrantState::AwaitingAddress => "awaiting_address",
    }
}

/// Whether an entry on `transport` can register from an address of its own.
fn own_address_transport(transport: Transport) -> bool {
    matches!(transport, Transport::Udp | Transport::Tcp)
}

fn transport_error(aor: &str, transport: Transport) -> String {
    format!(
        "{aor}: local_addr needs transport udp or tcp, not {transport}: the UE side has no \
         TLS client identity or TLS listener of its own"
    )
}

fn check_transport(entry: &RegistrantEntry, local_addr: Option<IpAddr>) -> Result<(), String> {
    if local_addr.is_some() && !own_address_transport(entry.transport) {
        return Err(transport_error(&entry.aor, entry.transport));
    }
    Ok(())
}

/// Start `entry` over on `local_addr`; see [`RegistrantManager::set_local_addr`].
fn reset_for_new_address(entry: &mut RegistrantEntry, local_addr: Option<IpAddr>) {
    if local_addr.is_some() {
        entry.require_local_addr = true;
    }
    entry.local_addr = local_addr;
    entry.state = if local_addr.is_none() && entry.require_local_addr {
        RegistrantState::AwaitingAddress
    } else {
        RegistrantState::Unregistered
    };
    entry.next_attempt = Instant::now();
    entry.expires_at = None;
    entry.last_sent_at = None;
    entry.failure_count = 0;
    entry.last_failure_status = None;
    entry.backoff = std::time::Duration::from_secs(5);
    entry.service_route.clear();
    entry.associated_uris.clear();
    entry.path.clear();
    if let Some(ipsec) = entry.ue_ipsec.as_mut() {
        ipsec.reset_handshake();
    }
}

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;
