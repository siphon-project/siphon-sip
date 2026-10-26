//! When a UE's security associations go (3GPP TS 33.203 clause 7.4.2a, TS
//! 24.229 clauses 5.2.5.1 and 5.2.5.2).
//!
//! A pair is installed at the 401 and taken into use at the 200 of the
//! REGISTER that authenticated it. What ends it:
//!
//! - **The UE de-registers.** Once all the public user identities the UE
//!   registered over it are de-registered, "the P-CSCF shall delete any
//!   security associations ... towards the UE, after the server transaction
//!   ... pertaining to this deregistration terminates" (TS 24.229 clause
//!   5.2.5.1), so the 200 still leaves protected. The dispatcher schedules
//!   that when it relays a 2xx to a de-REGISTER ([`IpsecManager::retire_pair`]
//!   with [`RetireCondition::Unregistered`]), or sends one the script answered.
//! - **The network ends the registration, or it expires.** The P-CSCF "shall
//!   shorten any security associations ... towards the UE" to what lets the
//!   NOTIFY with the de-registration reach it (TS 24.229 clause 5.2.5.2, NOTE
//!   2). The P-CSCF learns of it as the binding leaving the registrar (the
//!   script removing it on the reg-event NOTIFY, the expiry sweep), so a pair a
//!   registrar binding was seen on and that no live binding holds any more is
//!   retired ([`IpsecManager::reconcile_registrations`], each sweep).
//! - **A re-registration replaces it.** After the new pair is taken into use,
//!   the old one the REGISTER arrived over stays "as soon as all pending SIP
//!   transactions have been completed, or have timed out", and any other old
//!   one goes at once (TS 33.203 clause 7.4.2a,
//!   [`IpsecManager::supersede_pairs_for_ue`]).
//! - **The script says so** (`ipsec.delete()`).
//!
//! Retiring a pair also ends the stream connections between the protected
//! ports and the UE's: they are carried by the associations and useless
//! without them, and a connection siphon opened would otherwise retransmit
//! into a deleted association toward an address the access network may give
//! to another UE.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::time::Instant;
use tracing::{debug, info};

use super::{IpsecManager, SecurityAssociationPair};

/// How long a superseded or shortened pair is kept: 64*T1 with the default T1,
/// the time a transaction started over it can take to complete or time out
/// (RFC 3261 Timers F and J, TS 33.203 clause 7.4.2a), and enough for the
/// NOTIFY a network-initiated de-registration sends the UE (TS 24.229 clause
/// 5.2.5.2 NOTE 2).
pub const SA_RETIRE_GRACE: Duration = Duration::from_secs(32);

/// How long a retirement waits for the connections it closed to finish
/// closing before it deletes the pair under them.
const CONNECTION_CLOSE_BOUND: Duration = Duration::from_millis(500);

/// What must still hold when a scheduled retirement comes due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireCondition {
    /// Retire it whatever the registrar holds.
    Always,
    /// Retire it only if no live registrar binding was registered over it any
    /// more: another public user identity of the UE still registered keeps
    /// the associations (TS 33.203 clause 7.4.2a, TS 24.229 clause 5.2.5.1).
    Unregistered,
}

/// The local inbound SPIs of a pair, which name that installation of it: a
/// pair re-created under the same UE address and port has others.
pub(super) type PairSpis = (u32, u32);

fn spis_of(sa: &SecurityAssociationPair) -> PairSpis {
    (sa.spi_pc, sa.spi_ps)
}

#[derive(Debug, Clone, Copy)]
struct Retirement {
    spis: PairSpis,
    deadline: Instant,
    condition: RetireCondition,
    reason: &'static str,
    generation: u64,
}

/// What the manager knows of each pair's registration, beside the pair.
#[derive(Default)]
pub(super) struct Lifecycle {
    /// Pairs a live registrar binding was registered over, by contact key.
    registered: DashMap<String, PairSpis>,
    /// For a pair set up by a REGISTER that arrived protected, the pair that
    /// protected it, by the new pair's contact key: its UE client port and
    /// SPIs.
    predecessors: DashMap<String, (u16, PairSpis)>,
    /// Scheduled retirements, by contact key. Each is removed by its own task
    /// when it comes due.
    retiring: DashMap<String, Retirement>,
    /// Pairs installed beside a set of the UE that is in use and not yet taken
    /// into use themselves (TS 24.229 clause 5.2.2.2, the temporary set), by
    /// contact key, with how each gets there ([`Pending`]).
    pending: DashMap<String, (PairSpis, Pending)>,
    /// How many entries `pending` holds, and how many of them are
    /// [`Pending::Registered`], so the checks a request to a UE and every
    /// message arriving on a protected port make are one load while none is.
    pending_count: AtomicUsize,
    registered_pending: AtomicUsize,
    generation: AtomicU64,
}

/// Why a pair is not in use yet, and what takes it into use (TS 33.203 clause
/// 7.4.2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    /// It has the P-CSCF's protected client port of the set in use (a
    /// single-port `ipsec.pcscf_port_c`), so the kernel holds one outbound
    /// policy of SA #3 for both, naming the set in use (see
    /// [`kernel_objects`](super::kernel_objects)). Taken into use, by moving
    /// that policy, as the 2xx to the REGISTER that came over it leaves
    /// ([`IpsecManager::take_into_use`]).
    SharedPolicy,
    /// It has a protected client port of its own, beside the set in use on
    /// the UE's protected server port; the challenge is out, the 2xx not yet.
    /// Responses over it go over it; requests to the UE go over the set in
    /// use.
    Challenged,
    /// As `Challenged`, and the 2xx to the REGISTER that came over it has
    /// left over it (SM12). Taken into use when "a further SIP message
    /// protected with a new inbound SA is successfully received from the UE",
    /// or when the set in use goes ([`IpsecManager::note_protected_inbound`]).
    Registered,
}

impl Lifecycle {
    #[cfg(test)]
    pub(super) fn sizes(&self) -> (usize, usize, usize) {
        (
            self.registered.len(),
            self.predecessors.len(),
            self.retiring.len(),
        )
    }

    #[cfg(test)]
    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// How many pending pairs wait for a message over them.
    #[cfg(test)]
    pub(super) fn registered_pending_len(&self) -> usize {
        self.registered_pending.load(Ordering::Relaxed)
    }

    /// Mark the pair `spis` at `key` as not yet taken into use, `how`, or as
    /// in use (`None`).
    pub(super) fn set_pending(&self, key: &str, spis: PairSpis, how: Option<Pending>) {
        let replaced = match how {
            Some(how) => {
                self.count_added(how);
                self.pending.insert(key.to_string(), (spis, how))
            }
            None => self.pending.remove(key).map(|(_, value)| value),
        };
        self.count_removed(replaced);
    }

    /// Keep the counters in step with an entry put into `pending`.
    fn count_added(&self, how: Pending) {
        self.pending_count.fetch_add(1, Ordering::Relaxed);
        if how == Pending::Registered {
            self.registered_pending.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Keep the counters in step with an entry that left `pending`.
    fn count_removed(&self, removed: Option<(PairSpis, Pending)>) {
        let Some((_, how)) = removed else {
            return;
        };
        self.pending_count.fetch_sub(1, Ordering::Relaxed);
        if how == Pending::Registered {
            self.registered_pending.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Whether the pair `spis` at `key` is not yet taken into use.
    pub(super) fn is_pending(&self, key: &str, spis: PairSpis) -> bool {
        self.pending_how(key, spis).is_some()
    }

    /// How the pair `spis` at `key` waits to be taken into use, if it does.
    pub(super) fn pending_how(&self, key: &str, spis: PairSpis) -> Option<Pending> {
        self.pending
            .get(key)
            .and_then(|entry| (entry.value().0 == spis).then_some(entry.value().1))
    }

    /// Whether any pending pair waits for a message over it: one load.
    pub(super) fn any_registered_pending(&self) -> bool {
        self.registered_pending.load(Ordering::Relaxed) > 0
    }

    /// Whether no pair is pending at all: one load.
    pub(super) fn none_pending(&self) -> bool {
        self.pending_count.load(Ordering::Relaxed) == 0
    }

    /// Take the pair `spis` at `key` into use. Returns whether it was pending.
    pub(super) fn take_pending(&self, key: &str, spis: PairSpis) -> bool {
        let removed = self
            .pending
            .remove_if(key, |_, (pending, _)| *pending == spis)
            .map(|(_, value)| value);
        let was = removed.is_some();
        self.count_removed(removed);
        was
    }

    /// Forget whatever is pending at `key`.
    fn forget_pending(&self, key: &str) {
        let removed = self.pending.remove(key).map(|(_, value)| value);
        self.count_removed(removed);
    }
}

/// The local inbound SPIs that name this installation of `sa`.
pub(super) fn pair_spis(sa: &SecurityAssociationPair) -> PairSpis {
    spis_of(sa)
}

/// Whether the process registrar holds a live binding registered from
/// `source`. No registrar, no binding.
fn registered_from(source: SocketAddr) -> bool {
    crate::script::api::registrar_arc()
        .is_some_and(|registrar| registrar.has_live_binding_from(source))
}

impl IpsecManager {
    /// Drop what the lifecycle holds for a pair that is gone. A scheduled
    /// retirement is left to its task, which finds nothing to do.
    pub(super) fn forget_lifecycle(&self, key: &str) {
        self.lifecycle.registered.remove(key);
        self.lifecycle.predecessors.remove(key);
        self.lifecycle.forget_pending(key);
        self.network_dereg.forget(key);
    }

    /// Whether `pair` is scheduled to be retired: an old set kept for its
    /// pending transactions, or one being shortened.
    pub(super) fn is_retiring(&self, pair: &SecurityAssociationPair) -> bool {
        let key = Self::contact_key(&pair.ue_addr, pair.ue_port_c);
        self.lifecycle
            .retiring
            .get(&key)
            .is_some_and(|entry| entry.value().spis == spis_of(pair))
    }

    /// Whether a new connection to the UE may be opened over `pair`: a
    /// P-CSCF pair in use (not one an authentication in progress set up and
    /// the UE may not hold yet) that is not being retired (an old set kept
    /// only for the transactions still pending on it, whose connections go
    /// with it), unless it is kept for the NOTIFY of a network
    /// de-registration, which the UE still holds it for (TS 24.229 clause
    /// 5.2.5.2 NOTE 2).
    pub(crate) fn opens_connections_over(&self, pair: &SecurityAssociationPair) -> bool {
        if pair.role != super::SaRole::PCscf || !self.is_in_use(pair) {
            return false;
        }
        !self.is_retiring(pair)
            || self
                .network_dereg
                .awaits(&Self::contact_key(&pair.ue_addr, pair.ue_port_c))
    }

    /// Note that a registrar binding was registered over the pair at
    /// `(ue_addr, ue_port_c)`, so it is retired once no live binding holds it
    /// ([`reconcile_registrations`](Self::reconcile_registrations)). Returns
    /// whether there is such a pair.
    pub fn note_registered(&self, ue_addr: &IpAddr, ue_port_c: u16) -> bool {
        let key = Self::contact_key(ue_addr, ue_port_c);
        let Some(spis) = self
            .associations
            .get(&key)
            .map(|entry| spis_of(entry.value()))
        else {
            return false;
        };
        self.lifecycle.registered.insert(key, spis);
        true
    }

    /// Record that the REGISTER which set up the pairs named by `new_keys`
    /// arrived over the pair at `(ue_addr, protected_by_port_c)`, so the
    /// re-registration keeps that one until its pending transactions are done
    /// ([`supersede_pairs_for_ue`](Self::supersede_pairs_for_ue)).
    pub(crate) fn record_predecessor(
        &self,
        ue_addr: &IpAddr,
        protected_by_port_c: u16,
        new_keys: &[String],
    ) {
        let old_key = Self::contact_key(ue_addr, protected_by_port_c);
        let Some(old_spis) = self
            .associations
            .get(&old_key)
            .map(|entry| spis_of(entry.value()))
        else {
            return;
        };
        for new_key in new_keys.iter().filter(|new_key| **new_key != old_key) {
            self.lifecycle
                .predecessors
                .insert(new_key.clone(), (protected_by_port_c, old_spis));
        }
    }

    /// Schedule the pair at `(ue_addr, ue_port_c)` to be retired after
    /// `delay`, if `condition` still holds then. Returns whether this call
    /// scheduled it: `false` when there is no such pair, or an earlier
    /// retirement of it at least as strong is already due first.
    ///
    /// The pair is named by its SPIs as of now, so a pair re-created under the
    /// same key in the meantime is never taken.
    pub fn retire_pair(
        self: &Arc<Self>,
        ue_addr: IpAddr,
        ue_port_c: u16,
        delay: Duration,
        condition: RetireCondition,
        reason: &'static str,
    ) -> bool {
        let key = Self::contact_key(&ue_addr, ue_port_c);
        let Some(spis) = self
            .associations
            .get(&key)
            .map(|entry| spis_of(entry.value()))
        else {
            return false;
        };
        let deadline = Instant::now() + delay;
        let generation = self.lifecycle.generation.fetch_add(1, Ordering::Relaxed);
        let retirement = Retirement {
            spis,
            deadline,
            condition,
            reason,
            generation,
        };
        match self.lifecycle.retiring.entry(key.clone()) {
            Entry::Occupied(mut scheduled) => {
                let earlier = scheduled.get();
                let at_least_as_strong = earlier.condition == RetireCondition::Always
                    || condition == RetireCondition::Unregistered;
                if earlier.spis == spis && earlier.deadline <= deadline && at_least_as_strong {
                    return false;
                }
                scheduled.insert(retirement);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(retirement);
            }
        }
        debug!(
            ue = %ue_addr,
            ue_port_c,
            delay = ?delay,
            ?condition,
            reason,
            "IPsec: SA pair scheduled for deletion"
        );
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            manager.retire_when_due(&key, generation).await;
        });
        true
    }

    /// [`retire_pair`](Self::retire_pair) for every pair of `ue_addr`, or the
    /// one at `ue_port_c`. Returns how many were scheduled.
    pub fn retire_ue(
        self: &Arc<Self>,
        ue_addr: IpAddr,
        ue_port_c: Option<u16>,
        delay: Duration,
        condition: RetireCondition,
        reason: &'static str,
    ) -> usize {
        self.ue_ports_c(&ue_addr, ue_port_c)
            .into_iter()
            .filter(|port_c| self.retire_pair(ue_addr, *port_c, delay, condition, reason))
            .count()
    }

    /// Retire every pair of `ue_addr`, or the one at `ue_port_c`, now. Returns
    /// how many were deleted.
    pub async fn retire_ue_now(
        &self,
        ue_addr: IpAddr,
        ue_port_c: Option<u16>,
        reason: &'static str,
    ) -> usize {
        let mut deleted = 0;
        for port_c in self.ue_ports_c(&ue_addr, ue_port_c) {
            let pair = self.get_sa(&ue_addr, port_c);
            if let Some(pair) = pair {
                self.retire_now(&pair, reason).await;
                deleted += 1;
            }
        }
        deleted
    }

    fn ue_ports_c(&self, ue_addr: &IpAddr, ue_port_c: Option<u16>) -> Vec<u16> {
        self.associations
            .iter()
            .map(|entry| (entry.value().ue_addr, entry.value().ue_port_c))
            .filter(|(addr, port_c)| {
                addr == ue_addr && ue_port_c.is_none_or(|only| only == *port_c)
            })
            .map(|(_, port_c)| port_c)
            .collect()
    }

    async fn retire_when_due(&self, key: &str, generation: u64) {
        let Some((_, retirement)) = self
            .lifecycle
            .retiring
            .remove_if(key, |_, scheduled| scheduled.generation == generation)
        else {
            // Replaced by a later schedule, whose own task carries it out.
            return;
        };
        let Some(pair) = self
            .associations
            .get(key)
            .map(|entry| entry.value().clone())
        else {
            return;
        };
        if spis_of(&pair) != retirement.spis {
            debug!(ue = %pair.ue_addr, ue_port_c = pair.ue_port_c,
                "IPsec: SA pair re-created since its deletion was scheduled, kept");
            return;
        }
        if retirement.condition == RetireCondition::Unregistered
            && registered_from(SocketAddr::new(pair.ue_addr, pair.ue_port_c))
        {
            debug!(ue = %pair.ue_addr, ue_port_c = pair.ue_port_c, reason = retirement.reason,
                "IPsec: SA pair still carries a registration, kept");
            return;
        }
        self.retire_now(&pair, retirement.reason).await;
    }

    /// Signal every stream connection with `pair`'s UE at one of `ports` to
    /// close, and wait (bounded) until they have, so what they send the UE on
    /// the way out (the FIN, a reset) still leaves in the pair. A port another
    /// pair of the UE also uses (the protected server port stays across a
    /// re-registration, TS 33.203 clause 7.4.0) carries that pair's
    /// connections now and is left alone, except for the connection the
    /// P-CSCF opened to it from this pair's own protected client port when no
    /// other pair there has that port (clause 7.4.0 changes port_pc too).
    /// Returns how many were signalled.
    pub(super) async fn close_unshared_connections(
        &self,
        pair: &SecurityAssociationPair,
        ports: &[u16],
        reason: &'static str,
    ) -> usize {
        let others: Vec<(u16, u16, u16)> = self
            .associations
            .iter()
            .filter(|entry| {
                let other = entry.value();
                other.ue_addr == pair.ue_addr && other.ue_port_c != pair.ue_port_c
            })
            .map(|entry| {
                let other = entry.value();
                (other.ue_port_c, other.ue_port_s, other.pcscf_port_c)
            })
            .collect();
        let shared = |port: u16| {
            others
                .iter()
                .any(|(port_c, port_s, _)| *port_c == port || *port_s == port)
        };
        let own_client_port = pair.role == super::SaRole::PCscf
            && !others.iter().any(|(_, port_s, pcscf_port_c)| {
                *port_s == pair.ue_port_s && *pcscf_port_c == pair.pcscf_port_c
            });
        let mut closed = 0;
        let mut closing = Vec::new();
        for port in ports {
            let peer = SocketAddr::new(pair.ue_addr, *port);
            if !shared(*port) {
                let signalled = crate::transport::disconnect::close_peer(peer, reason);
                if signalled > 0 {
                    closing.push((peer, None));
                }
                closed += signalled;
            } else if *port == pair.ue_port_s && own_client_port {
                let signalled =
                    crate::transport::disconnect::close_peer_from(peer, pair.pcscf_port_c, reason);
                if signalled > 0 {
                    closing.push((peer, Some(pair.pcscf_port_c)));
                }
                closed += signalled;
            }
        }
        // The connections close in their own tasks: wait for them.
        for (peer, local_port) in closing {
            let closed_in_time = match local_port {
                None => {
                    crate::transport::disconnect::peer_closed_within(peer, CONNECTION_CLOSE_BOUND)
                        .await
                }
                Some(local_port) => {
                    crate::transport::disconnect::peer_closed_from_within(
                        peer,
                        local_port,
                        CONNECTION_CLOSE_BOUND,
                    )
                    .await
                }
            };
            if !closed_in_time {
                debug!(ue = %pair.ue_addr, port = peer.port(),
                    "IPsec: a connection still closing as its SA pair goes");
            }
        }
        closed
    }

    /// End the connections the pair carried, wait (bounded) until they are
    /// closed, then delete it.
    async fn retire_now(&self, pair: &SecurityAssociationPair, reason: &'static str) {
        let closed = self
            .close_unshared_connections(pair, &[pair.ue_port_c, pair.ue_port_s], reason)
            .await;
        // As this installation: the connections closing is a wait, and a pair
        // re-created on the port meanwhile is not the one retired.
        if !self.delete_installation(pair).await {
            debug!(ue = %pair.ue_addr, ue_port_c = pair.ue_port_c,
                "IPsec: SA pair replaced while retiring, the new one kept");
            return;
        }
        info!(
            ue = %pair.ue_addr,
            ue_port_c = pair.ue_port_c,
            ue_port_s = pair.ue_port_s,
            connections_closed = closed,
            reason,
            "IPsec: SA pair retired"
        );
    }

    /// Retire every pair a registrar binding was registered over and that no
    /// live binding holds any more, after `delay`, and note the pairs one now
    /// holds. Run from the periodic sweep: it is how the end of a registration
    /// the P-CSCF did not see a de-REGISTER for (the script removing the
    /// binding on a reg-event NOTIFY, TS 24.229 clause 5.2.5.2; the expiry
    /// sweep) reaches the associations. Returns how many were scheduled.
    ///
    /// A pair no binding was ever seen on is left alone: it is pending (the 401
    /// is out, the 200 not yet in), or the deployment keeps no registrar.
    pub fn reconcile_registrations(self: &Arc<Self>, delay: Duration) -> usize {
        let Some(registrar) = crate::script::api::registrar_arc() else {
            return 0;
        };
        let pairs: Vec<(String, IpAddr, u16, PairSpis)> = self
            .associations
            .iter()
            .map(|entry| {
                let pair = entry.value();
                (
                    entry.key().clone(),
                    pair.ue_addr,
                    pair.ue_port_c,
                    spis_of(pair),
                )
            })
            .collect();
        let mut scheduled = 0;
        for (key, ue_addr, ue_port_c, spis) in pairs {
            if registrar.has_live_binding_from(SocketAddr::new(ue_addr, ue_port_c)) {
                self.lifecycle.registered.insert(key, spis);
                continue;
            }
            let was_registered = self
                .lifecycle
                .registered
                .get(&key)
                .is_some_and(|entry| *entry.value() == spis);
            if was_registered
                && self.retire_pair(
                    ue_addr,
                    ue_port_c,
                    delay,
                    RetireCondition::Unregistered,
                    "registration ended",
                )
            {
                scheduled += 1;
            }
        }
        scheduled
    }

    /// The pair at `(ue_addr, keep_port_c)` has been taken into use (the 200
    /// to the REGISTER that authenticated it): the UE's other pairs go (TS
    /// 33.203 clause 7.4.2a). The one the REGISTER arrived over is retired
    /// after `delay`, so the transactions pending on it can complete or time
    /// out; every other one is deleted now.
    ///
    /// Replaces deleting all of them at once, which cut every transaction the
    /// UE had in flight over the old pair (an INVITE sent before the
    /// re-registration got its responses unprotected, and the UE drops those).
    pub async fn supersede_pairs_for_ue(
        self: &Arc<Self>,
        ue_addr: &IpAddr,
        keep_port_c: u16,
        delay: Duration,
    ) {
        let keep_key = Self::contact_key(ue_addr, keep_port_c);
        let predecessor = self
            .lifecycle
            .predecessors
            .remove(&keep_key)
            .map(|(_, predecessor)| predecessor);
        let victims: Vec<SecurityAssociationPair> = self
            .associations
            .iter()
            .filter(|entry| {
                entry.value().ue_addr == *ue_addr && entry.value().ue_port_c != keep_port_c
            })
            .map(|entry| entry.value().clone())
            .collect();
        for victim in victims {
            let protected_the_register = predecessor.is_some_and(|(port_c, spis)| {
                port_c == victim.ue_port_c && spis == spis_of(&victim)
            });
            if protected_the_register {
                self.retire_pair(
                    victim.ue_addr,
                    victim.ue_port_c,
                    delay,
                    RetireCondition::Always,
                    "superseded by a re-registration",
                );
            } else {
                self.retire_now(&victim, "superseded by a registration")
                    .await;
            }
        }
    }
}
