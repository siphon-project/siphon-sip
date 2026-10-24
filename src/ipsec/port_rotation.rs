//! A P-CSCF protected client port per authentication (3GPP TS 33.203 clause
//! 7.4.0): "When security associations are changed in an authenticated
//! re-registration then the protected server ports at the UE (port_us) and the
//! P-CSCF (port_ps) shall remain unchanged, while the protected client ports at
//! the UE (port_uc) and the P-CSCF (port_pc) shall change."
//!
//! With `ipsec.pcscf_port_c` listing several ports, each new pair of a UE takes
//! one no other live pair of that UE holds (clause 7.1, rule 3: the P-CSCF
//! checks "that the pair (UE_IP_address, UE_protected_client_port) ... has not
//! yet been associated with entries in the SA_table"; another UE may hold the
//! same port). The old and the new set then have selectors of their own, and
//! nothing in the kernel is shared, so the P-CSCF can follow clause 7.4.2a as
//! written: the challenge (SM6) goes over the old set, the 2xx (SM12) over the
//! new one, and requests to the UE stay on the old set until "a further SIP
//! message protected with a new inbound SA is successfully received from the
//! UE", after which "the P-CSCF starts to use the new SAs for outbound
//! messages" and "the old SAs are then deleted as soon as all pending SIP
//! transactions have been completed, or have timed out" (64*T1). "When the old
//! SAs expire without a further SIP message protected by the new SAs, the new
//! SAs are taken into use for outbound messages."
//!
//! With a single port, old and new share it and the one outbound policy of SA
//! #3 (see [`kernel_objects`](super::kernel_objects)); that path is unchanged.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tracing::info;

use super::retire::{pair_spis, Pending, RetireCondition, SA_RETIRE_GRACE};
use super::{IpsecManager, SaRole, SecurityAssociationPair};

/// Whether `other` is another set of `pair`'s UE on the same UE protected
/// server port: the one requests to the UE could go over instead.
fn same_server_port(pair: &SecurityAssociationPair, other: &SecurityAssociationPair) -> bool {
    other.role == SaRole::PCscf
        && other.ue_addr == pair.ue_addr
        && other.ue_port_s == pair.ue_port_s
        && other.ue_port_c != pair.ue_port_c
}

impl IpsecManager {
    /// The protected client port a new pair of the UE at `ue_addr` takes, out
    /// of `ports` (`ipsec.pcscf_port_c`, in the order configured): the first
    /// no live or pending pair of that UE holds. With every port held (a pool
    /// smaller than the pairs the UE has), one no pair in use holds, else the
    /// oldest pair's; the shared-policy handling covers two sets on one port.
    /// A single port is always that port; `None` only for no port at all.
    pub fn pick_pcscf_port_c(&self, ue_addr: &IpAddr, ports: &[u16]) -> Option<u16> {
        let first = ports.first().copied()?;
        if ports.len() == 1 {
            return Some(first);
        }
        let held: Vec<(u16, bool, std::time::Instant)> = self
            .associations
            .iter()
            .filter(|entry| entry.value().ue_addr == *ue_addr)
            .map(|entry| {
                let pair = entry.value();
                (pair.pcscf_port_c, self.is_in_use(pair), pair.created_at)
            })
            .collect();
        if let Some(free) = ports
            .iter()
            .find(|port| !held.iter().any(|(held_port, ..)| held_port == *port))
        {
            return Some(*free);
        }
        if let Some(unused) = ports.iter().find(|port| {
            held.iter()
                .filter(|(held_port, ..)| held_port == *port)
                .all(|(_, in_use, _)| !in_use)
        }) {
            return Some(*unused);
        }
        Some(
            held.iter()
                .filter(|(held_port, ..)| ports.contains(held_port))
                .min_by_key(|(_, _, created_at)| *created_at)
                .map_or(first, |(port, ..)| *port),
        )
    }

    /// Whether `sa`, about to be installed, has a protected client port of its
    /// own beside a set in use on the UE's protected server port, so it is
    /// pending until taken into use ([`Pending::Challenged`]).
    pub(super) fn beside_a_set_in_use(&self, sa: &SecurityAssociationPair) -> bool {
        sa.role == SaRole::PCscf
            && self.associations.iter().any(|entry| {
                let other = entry.value();
                same_server_port(sa, other)
                    && other.pcscf_port_c != sa.pcscf_port_c
                    && self.is_in_use(other)
            })
    }

    /// How the pair at `(ue_addr, ue_port_c)` waits to be taken into use, or
    /// `None` when it is in use (or there is none).
    pub fn pending_how(&self, ue_addr: &IpAddr, ue_port_c: u16) -> Option<Pending> {
        let key = Self::contact_key(ue_addr, ue_port_c);
        let spis = self
            .associations
            .get(&key)
            .map(|entry| pair_spis(entry.value()))?;
        self.lifecycle.pending_how(&key, spis)
    }

    /// The pair requests to `pair`'s UE go over instead of `pair`: of the sets
    /// on the same UE protected server port, the newest in use and not being
    /// retired. While `pair` is pending that is the set in use, which the UE
    /// still holds and expects them on (TS 33.203 clause 7.4.2a: "If SM1 was
    /// protected, the old SAs are used to protect messages other than those in
    /// the authentication"); once a newer set is taken into use and `pair` is
    /// the old one kept for its pending transactions, that newer set ("the
    /// P-CSCF starts to use the new SAs for outbound messages"). `pair` itself
    /// when it is the one, or nothing better is left. Two map lookups for a
    /// pair in use that is not being retired.
    pub fn request_pair(&self, pair: SecurityAssociationPair) -> SecurityAssociationPair {
        let preferred = |candidate: &SecurityAssociationPair| {
            self.is_in_use(candidate) && !self.is_retiring(candidate)
        };
        if pair.role != SaRole::PCscf || preferred(&pair) {
            return pair;
        }
        let candidates: Vec<SecurityAssociationPair> = self
            .associations
            .iter()
            .filter(|entry| same_server_port(&pair, entry.value()))
            .map(|entry| entry.value().clone())
            .collect();
        let newest = |keep: &dyn Fn(&SecurityAssociationPair) -> bool| {
            candidates
                .iter()
                .filter(|candidate| keep(candidate))
                .max_by_key(|candidate| candidate.created_at)
                .cloned()
        };
        newest(&preferred)
            .or_else(|| {
                if self.is_in_use(&pair) {
                    None
                } else {
                    newest(&|candidate| self.is_in_use(candidate))
                }
            })
            .unwrap_or(pair)
    }

    /// The 2xx to the REGISTER that came over the pending pair at `(ue_addr,
    /// ue_port_c)`, with a protected client port of its own, has left over it
    /// (SM12): it waits for a further message over it from now on
    /// ([`Pending::Registered`]), or is taken into use at once when no set in
    /// use is left beside it. Returns whether the pair was
    /// [`Pending::Challenged`].
    pub fn confirm_registration(self: &Arc<Self>, ue_addr: &IpAddr, ue_port_c: u16) -> bool {
        let key = Self::contact_key(ue_addr, ue_port_c);
        let Some(pair) = self.get_sa(ue_addr, ue_port_c) else {
            return false;
        };
        let spis = pair_spis(&pair);
        if self.lifecycle.pending_how(&key, spis) != Some(Pending::Challenged) {
            return false;
        }
        if self.beside_a_set_in_use(&pair) {
            self.lifecycle
                .set_pending(&key, spis, Some(Pending::Registered));
            info!(
                ue = %pair.ue_addr,
                ue_port_c = pair.ue_port_c,
                pcscf_port_c = pair.pcscf_port_c,
                "IPsec: new SA pair registered; requests stay on the old set until one arrives \
                 over the new"
            );
        } else {
            self.promote(&pair, "no set in use is left beside it");
        }
        true
    }

    /// A message from `remote` arrived on the protected local port
    /// `local_port`. When it came over a pair waiting for one
    /// ([`Pending::Registered`]), take that pair into use: "When ... a
    /// further SIP message protected with a new inbound SA is successfully
    /// received from the UE, the P-CSCF starts to use the new SAs for outbound
    /// messages" (TS 33.203 clause 7.4.2a). One atomic load while no pair
    /// waits.
    pub fn note_protected_inbound(self: &Arc<Self>, remote: SocketAddr, local_port: u16) {
        if !self.lifecycle.any_registered_pending() {
            return;
        }
        // SA #1 (port_uc -> port_ps) names the pair by the UE's client port;
        // SA #4 (port_us -> port_pc) by the P-CSCF's client port.
        let over = self
            .get_sa(&remote.ip(), remote.port())
            .filter(|pair| pair.pcscf_port_s == local_port)
            .or_else(|| {
                self.associations
                    .iter()
                    .find(|entry| {
                        let pair = entry.value();
                        pair.ue_addr == remote.ip()
                            && pair.ue_port_s == remote.port()
                            && pair.pcscf_port_c == local_port
                    })
                    .map(|entry| entry.value().clone())
            });
        let Some(pair) = over else {
            return;
        };
        let key = Self::contact_key(&pair.ue_addr, pair.ue_port_c);
        if self.lifecycle.pending_how(&key, pair_spis(&pair)) == Some(Pending::Registered) {
            self.promote(&pair, "a message arrived over it");
        }
    }

    /// Take `pair`, with a protected client port of its own, into use, and
    /// shorten every set in use on the same UE protected server port to 64*T1:
    /// "The old SAs are then deleted as soon as all pending SIP transactions
    /// have been completed, or have timed out" (TS 33.203 clause 7.4.2a).
    pub(super) fn promote(self: &Arc<Self>, pair: &SecurityAssociationPair, why: &'static str) {
        let key = Self::contact_key(&pair.ue_addr, pair.ue_port_c);
        if !self.lifecycle.take_pending(&key, pair_spis(pair)) {
            return;
        }
        let old: Vec<SecurityAssociationPair> = self
            .associations
            .iter()
            .filter(|entry| same_server_port(pair, entry.value()) && self.is_in_use(entry.value()))
            .map(|entry| entry.value().clone())
            .collect();
        info!(
            ue = %pair.ue_addr,
            ue_port_c = pair.ue_port_c,
            pcscf_port_c = pair.pcscf_port_c,
            old_sets = old.len(),
            why,
            "IPsec: SA pair taken into use"
        );
        for old in old {
            self.retire_pair(
                old.ue_addr,
                old.ue_port_c,
                SA_RETIRE_GRACE,
                RetireCondition::Always,
                "old set: the new set was taken into use",
            );
        }
    }

    /// `went`, a set in use, has been deleted: a pair beside it that has its
    /// own protected client port and whose 2xx has left is taken into use,
    /// "When the old SAs expire without a further SIP message protected by the
    /// new SAs, the new SAs are taken into use for outbound messages" (TS
    /// 33.203 clause 7.4.2a).
    pub(super) fn set_in_use_went(&self, went: &SecurityAssociationPair) {
        if went.role != SaRole::PCscf || !self.lifecycle.any_registered_pending() {
            return;
        }
        let waiting: Vec<SecurityAssociationPair> = self
            .associations
            .iter()
            .filter(|entry| same_server_port(went, entry.value()))
            .map(|entry| entry.value().clone())
            .collect();
        for pair in waiting {
            let key = Self::contact_key(&pair.ue_addr, pair.ue_port_c);
            let spis = pair_spis(&pair);
            if self.lifecycle.pending_how(&key, spis) == Some(Pending::Registered)
                && self.lifecycle.take_pending(&key, spis)
            {
                info!(
                    ue = %pair.ue_addr,
                    ue_port_c = pair.ue_port_c,
                    pcscf_port_c = pair.pcscf_port_c,
                    "IPsec: SA pair taken into use, the set in use went"
                );
            }
        }
    }
}
