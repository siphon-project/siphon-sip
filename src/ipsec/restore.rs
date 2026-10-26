//! Registrations restored without their security associations.
//!
//! A P-CSCF's IPsec security associations live and die with the process that
//! negotiated them (3GPP TS 33.203 clause 7): the keys never leave it, so a
//! restart cannot bring them back. The registrar bindings can come back, from a
//! persistence backend, and one that was protected names a UE that still holds
//! its side of the SAs. Restored as live, that binding is worse than none:
//! refreshes from the UE are dropped in the kernel, and anything sent to the
//! UE's protected ports (a terminating request, a liveness probe, a reg-event
//! NOTIFY) leaves unprotected, because without the SAs the P-CSCF has no
//! outbound policy for those ports either.
//!
//! So a restored binding that was protected and whose SA pair this manager does
//! not hold is dropped at startup
//! ([`IpsecManager::drop_restored_bindings_without_sa`]), and every UE endpoint
//! it named is remembered until the binding would have expired: a request to
//! one of them while no SA pair covers it is refused at egress
//! ([`IpsecManager::refuses_unprotected_send`]) instead of going out in clear.
//!
//! Recovery is the specified one. The UE's next protected request goes
//! unanswered, and it performs an initial registration (TS 24.229 clause
//! 5.1.1.4.1): fresh AKA, new SAs, a new binding. A network that wants that
//! sooner uses P-CSCF restoration (TS 23.380 clause 5).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{error, warn};

use super::retire::SA_RETIRE_GRACE;
use super::IpsecManager;
use crate::registrar::{Contact, ContactKind, Registrar};
use crate::transport::OutboundMessage;

/// UE endpoints whose security associations died with a previous process,
/// each until the binding that named it would have expired.
#[derive(Default)]
pub(super) struct OrphanedFlows {
    pub(super) endpoints: DashMap<SocketAddr, Instant>,
}

impl IpsecManager {
    /// Drop every binding of `registrar` that was protected, accepted on one
    /// of `pcscf_ports_c` or on `pcscf_port_s`, and whose SA pair this manager does
    /// not hold. Returns how many were dropped.
    ///
    /// Run once at startup, after the backend restore and before any traffic.
    /// Each dropped binding is logged and counted
    /// (`siphon_registrar_restored_without_sa_total`), leaves the backend
    /// through the registrar's de-registration bookkeeping
    /// ([`Registrar::evict_restored`]), and has its UE endpoints barred from
    /// unprotected requests until it would have expired. A kernel SA a previous
    /// process left behind does not count as held: this manager can neither
    /// send over it nor keep it alive.
    pub fn drop_restored_bindings_without_sa(
        &self,
        registrar: &Registrar,
        pcscf_ports_c: &[u16],
        pcscf_port_s: u16,
    ) -> usize {
        let evicted = registrar.evict_restored(|contact| {
            contact.kind == ContactKind::Ue
                && contact.inbound_local_addr.is_some_and(|local| {
                    pcscf_ports_c.contains(&local.port()) || local.port() == pcscf_port_s
                })
                && !self.holds_pair_for(contact)
        });
        for binding in &evicted {
            let contact = &binding.contact;
            let endpoints = protected_endpoints(contact);
            warn!(
                aor = %binding.aor.escape_debug(),
                ue = ?contact.source_addr,
                ue_ports = ?endpoints.iter().map(SocketAddr::port).collect::<Vec<_>>(),
                local_port = ?contact.inbound_local_addr.map(|local| local.port()),
                owned_elsewhere = binding.owned_elsewhere,
                "IPsec: restored binding was protected but its security associations did not \
                 survive the restart; dropped, the UE re-registers (TS 24.229 clause 5.1.1.4.1)"
            );
            crate::metrics::ipsec::record_restored_without_sa();
            let until =
                Instant::now() + Duration::from_secs(contact.remaining_seconds()) + SA_RETIRE_GRACE;
            for endpoint in endpoints {
                self.orphaned_flows
                    .endpoints
                    .entry(endpoint)
                    .and_modify(|held| *held = (*held).max(until))
                    .or_insert(until);
            }
        }
        evicted.len()
    }

    /// Whether `message` must not leave: a request to a UE endpoint whose
    /// security associations died with a previous process, or to a UE port of
    /// a pair this manager deleted ([`super::deleted_flows`], logged at WARN),
    /// while no SA pair of this manager covers it. Logged at ERROR and counted
    /// (`siphon_ipsec_unprotected_sends_refused_total`) when refused.
    ///
    /// Only requests are refused. A response goes back to where its request
    /// came from, and a UE that sent one unprotected (the initial REGISTER of
    /// its recovery) is answered unprotected, as TS 33.203 has it. An endpoint
    /// that a new SA pair covers again, or whose binding would have expired by
    /// now, is forgotten.
    pub fn refuses_unprotected_send(&self, message: &OutboundMessage) -> bool {
        if self.refuses_send_to_deleted_flow(message) {
            return true;
        }
        let endpoints = &self.orphaned_flows.endpoints;
        if endpoints.is_empty() {
            return false;
        }
        let destination = message.destination;
        let Some(until) = endpoints.get(&destination).map(|held| *held) else {
            return false;
        };
        if until <= Instant::now()
            || self
                .find_sa_by_ue(&destination.ip(), destination.port())
                .is_some()
        {
            endpoints.remove(&destination);
            return false;
        }
        if message
            .frames()
            .all(|frame| crate::transport::response_route::is_response(frame))
        {
            return false;
        }
        error!(
            %destination,
            transport = message.transport.as_scheme(),
            "IPsec: refusing to send a request in clear to a UE protected port whose security \
             associations did not survive a restart; the UE has to re-register"
        );
        crate::metrics::ipsec::record_unprotected_send_refused();
        true
    }

    /// Whether `destination` is a UE protected port whose pair is gone (deleted
    /// here, or lost with a previous process) and that no pair covers again: a
    /// request to it is refused at egress ([`refuses_unprotected_send`]), so
    /// nothing is opened toward it either. Read only; the egress check forgets
    /// what is over.
    ///
    /// [`refuses_unprotected_send`]: Self::refuses_unprotected_send
    pub(crate) fn is_barred_flow(&self, destination: SocketAddr) -> bool {
        let now = Instant::now();
        let barred = self.deleted_flows.bars(destination, now)
            || self
                .orphaned_flows
                .endpoints
                .get(&destination)
                .is_some_and(|until| *until > now);
        barred
            && self
                .find_sa_by_ue(&destination.ip(), destination.port())
                .is_none()
    }

    /// Forget the barred endpoints whose binding would have expired by now.
    /// Called from the periodic sweep, so the set drains on its own.
    pub fn prune_orphaned_flows(&self) {
        let now = Instant::now();
        self.orphaned_flows
            .endpoints
            .retain(|_, until| *until > now);
        self.deleted_flows.prune(now);
    }

    /// How many UE endpoints are barred from unprotected requests.
    pub fn orphaned_flow_count(&self) -> usize {
        self.orphaned_flows.endpoints.len()
    }

    /// Whether this manager holds an SA pair for the flow `contact` was
    /// registered over: its source address, on the UE's protected client or
    /// server port.
    fn holds_pair_for(&self, contact: &Contact) -> bool {
        contact.source_addr.is_some_and(|source| {
            self.get_sa(&source.ip(), source.port()).is_some()
                || self.find_sa_by_ue(&source.ip(), source.port()).is_some()
        })
    }
}

/// The process-wide manager, for the egress check in
/// [`crate::transport::OutboundRouter::send`]. `None` when no P-CSCF IPsec role
/// is configured.
pub fn egress_guard() -> Option<&'static IpsecManager> {
    super::GLOBAL_MANAGER.get().map(AsRef::as_ref)
}

/// The UE endpoints a protected binding names: the address it registered from
/// (the UE's protected client port) and its Contact address (the protected
/// server port, where terminating requests go).
fn protected_endpoints(contact: &Contact) -> Vec<SocketAddr> {
    let mut endpoints = Vec::with_capacity(2);
    if let Some(source) = contact.source_addr {
        endpoints.push(source);
    }
    let host = contact
        .uri
        .host
        .trim_start_matches('[')
        .trim_end_matches(']');
    if let (Ok(address), Some(port)) = (host.parse::<IpAddr>(), contact.uri.port) {
        let target = SocketAddr::new(address, port);
        if !endpoints.contains(&target) {
            endpoints.push(target);
        }
    }
    endpoints
}
