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
//! v1 is UDP only: a `local_addr` on a TCP or TLS entry is refused, because
//! the outbound connection pool opens stream connections from an ephemeral
//! source the entry's address would not name.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use tracing::info;

use super::{RegistrantEntry, RegistrantEvent, RegistrantManager, RegistrantState};
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
/// client port (`None` without IPsec). Two IPsec entries on one address with
/// distinct ports are two UEs; two with the same port would install colliding
/// SAs, and two plain entries would be indistinguishable to an MT request.
fn address_key(entry: &RegistrantEntry) -> Option<(IpAddr, Option<u16>)> {
    entry
        .local_addr
        .map(|ip| (ip, entry.ue_ipsec.as_ref().map(|ipsec| ipsec.ue_port_c)))
}

impl RegistrantManager {
    /// Add an entry, refusing one whose `local_addr` cannot be used: it is not
    /// UDP, or another entry (not one with the same AoR, which this replaces)
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
        if let Some(key) = address_key(&entry) {
            self.refuse_taken(&entry.aor, key)?;
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
        self.entries.insert(aor.clone(), entry);
        if awaiting {
            self.emit_event(RegistrantEvent::AwaitingAddress { aor });
        }
        Ok(())
    }

    /// `Err` when an entry other than `aor` holds `key`.
    fn refuse_taken(&self, aor: &str, key: (IpAddr, Option<u16>)) -> Result<(), String> {
        let holder = self
            .entries
            .iter()
            .find(|other| other.aor != aor && address_key(other) == Some(key))
            .map(|other| other.aor.clone());
        match holder {
            Some(holder) => Err(match key.1 {
                Some(port) => format!(
                    "local_addr {} with ue_port_c {port} is already used by {holder}",
                    key.0
                ),
                None => format!("local_addr {} is already used by {holder}", key.0),
            }),
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
    /// entry holds, or a non-UDP entry.
    pub fn set_local_addr(&self, aor: &str, local_addr: Option<IpAddr>) -> Result<bool, String> {
        let _guard = self
            .address_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((current, transport, ue_port_c)) = self.entries.get(aor).map(|entry| {
            (
                entry.local_addr,
                entry.transport,
                entry.ue_ipsec.as_ref().map(|ipsec| ipsec.ue_port_c),
            )
        }) else {
            return Ok(false);
        };
        if current == local_addr {
            return Ok(true);
        }
        if local_addr.is_some() && transport != Transport::Udp {
            return Err(non_udp_error(aor, transport));
        }
        if let Some(ip) = local_addr {
            self.refuse_taken(aor, (ip, ue_port_c))?;
        }

        let Some(mut entry) = self.entries.get_mut(aor) else {
            return Ok(false);
        };
        if let Some(port) = ue_port_c {
            let mut pending = self
                .pending_sa_deletions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.push((current, port));
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

    /// Take the SA pairs [`set_local_addr`](Self::set_local_addr) queued.
    pub(super) fn take_pending_sa_deletions(&self) -> Vec<(Option<IpAddr>, u16)> {
        let mut pending = self
            .pending_sa_deletions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *pending)
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
                            || entry.ue_ipsec.as_ref().is_some_and(|ipsec| {
                                socket.port() == ipsec.ue_port_c || socket.port() == ipsec.ue_port_s
                            }))
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

    /// Every socket the entries with an address of their own need, per AoR:
    /// the plain port on that address and, with IPsec, the protected client
    /// and server ports (TS 33.203 §7.1).
    pub(super) fn ue_socket_plan(&self, plain_port: u16) -> Vec<(String, Vec<SocketAddr>)> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let ip = entry.local_addr?;
                let mut addrs = vec![SocketAddr::new(ip, plain_port)];
                if let Some(ipsec) = entry.ue_ipsec.as_ref() {
                    addrs.push(SocketAddr::new(ip, ipsec.ue_port_c));
                    addrs.push(SocketAddr::new(ip, ipsec.ue_port_s));
                }
                Some((entry.aor.clone(), addrs))
            })
            .collect()
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

fn non_udp_error(aor: &str, transport: Transport) -> String {
    format!(
        "{aor}: local_addr needs transport udp, not {transport}: a TCP or TLS registration \
         leaves over a pooled connection from an ephemeral source, which the address would \
         not name"
    )
}

fn check_transport(entry: &RegistrantEntry, local_addr: Option<IpAddr>) -> Result<(), String> {
    if local_addr.is_some() && entry.transport != Transport::Udp {
        return Err(non_udp_error(&entry.aor, entry.transport));
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
