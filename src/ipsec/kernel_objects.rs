//! The eight kernel objects of a pair (four SA states, four policies):
//! installing them, re-pinning their lifetimes, and taking them down without
//! taking one another pair of the UE shares. A P-CSCF that keeps its protected
//! ports fixed (siphon's own with a single `ipsec.pcscf_port_c`; with a list
//! each pair has its own, see [`port_rotation`](super::port_rotation)) and a
//! UE that keeps its protected server port across an authenticated
//! re-registration (3GPP TS 33.203 clause 7.4.0) make an old and a new pair
//! hold the policies of SA #3 and #4 under one kernel key.
//!
//! At the P-CSCF the kernel's outbound policy of that key names one set, the
//! one in use. A set installed beside it for a re-authentication is pending:
//! the challenge still goes over the old set (TS 24.229 clause 5.2.2.2: "send
//! the 401 (Unauthorized) response to the UE using the security association
//! with which the associated REGISTER request was protected"; TS 33.203 clause
//! 7.4.2a: SM6 "shall be protected with the old outbound SA"), since the UE
//! derives the new set's keys from that very challenge. The new set is taken
//! into use ([`IpsecManager::take_into_use`]) when the 2xx to the REGISTER that
//! came over it leaves, which goes over the new set (clause 5.2.2.2: "protect
//! the 200 (OK) response ... within the same security association to that in
//! which the REGISTER request was protected"; clause 7.4.2a: SM12 "shall be
//! protected using the new outbound SA").

use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, info, warn};

use super::retire::{pair_spis, Pending, RetireCondition, SA_RETIRE_GRACE};
use super::{
    netlink, IpsecError, IpsecManager, PolicyDir, SaProtocol, SaRole, SecurityAssociationPair,
    XfrmBackend,
};

/// One of the eight kernel objects of a pair, with what it takes to install it
/// again. Compared by [`KernelObject::same_kernel_key`], the key the kernel
/// itself holds it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KernelObject {
    /// An SA state, keyed by the kernel on `(destination, spi)`.
    State {
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        spi: u32,
    },
    /// A policy, keyed by the kernel on its selector and direction; the SPI is
    /// only in its template.
    Policy {
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        direction: PolicyDir,
        protocol: SaProtocol,
        spi: u32,
    },
}

impl KernelObject {
    /// Whether the kernel holds `self` and `other` under one key, so only one
    /// of them can be installed at a time.
    pub(super) fn same_kernel_key(&self, other: &KernelObject) -> bool {
        match (self, other) {
            (
                KernelObject::State {
                    destination: ours,
                    spi: our_spi,
                    ..
                },
                KernelObject::State {
                    destination: theirs,
                    spi: their_spi,
                    ..
                },
            ) => ours == theirs && our_spi == their_spi,
            (
                KernelObject::Policy {
                    source,
                    source_port,
                    destination,
                    destination_port,
                    direction,
                    protocol,
                    ..
                },
                KernelObject::Policy {
                    source: their_source,
                    source_port: their_source_port,
                    destination: their_destination,
                    destination_port: their_destination_port,
                    direction: their_direction,
                    protocol: their_protocol,
                    ..
                },
            ) => {
                source == their_source
                    && source_port == their_source_port
                    && destination == their_destination
                    && destination_port == their_destination_port
                    && direction == their_direction
                    && protocol == their_protocol
            }
            _ => false,
        }
    }
}

/// The netlink message deleting `object`, keyed as the kernel keys it.
fn delete_message(object: &KernelObject) -> Vec<u8> {
    match *object {
        KernelObject::State {
            destination, spi, ..
        } => netlink::del_sa_message(&destination, spi),
        KernelObject::Policy {
            source,
            source_port,
            destination,
            destination_port,
            direction,
            protocol,
            ..
        } => netlink::del_policy_message(
            &source,
            source_port,
            &destination,
            destination_port,
            direction.into(),
            protocol.as_u8(),
        ),
    }
}

/// The four states and four policies `create_sa_pair` installs for `sa`.
///
/// A policy's template names the SA it applies, except on the policies of SA
/// #3 and #4 (`port_pc` <-> `port_us`) that a UE installs, and on the inbound
/// one of them (SA #4) a P-CSCF installs: their template names SPI 0, any SA of
/// the selector. With a P-CSCF that keeps `port_pc`, an old and a new set have
/// one selector there and the kernel one policy for both, so a template naming
/// one set's SPI would drop what the peer still sends over the other while
/// both are held (TS 24.229 clause 5.1.1.5.1: the UE deletes the old set only
/// once something arrives over the new one; TS 33.203 clauses 7.4.1a and
/// 7.4.2a). The states still tell the sets apart: only an SA the receiver
/// holds decrypts. Outbound, the UE's kernel picks the newest SA of the
/// selector; the P-CSCF's outbound policy of SA #3 names the set in use (see
/// the module). Against a P-CSCF that changes `port_pc` (clause 7.4.0) the
/// selectors differ and nothing is shared.
pub(super) fn kernel_objects(sa: &SecurityAssociationPair) -> [KernelObject; 8] {
    let role = sa.role;
    let state = |source, source_port, destination, destination_port, spi| KernelObject::State {
        source,
        source_port,
        destination,
        destination_port,
        spi,
    };
    let policy = |source, source_port, destination, destination_port, ue_sourced, spi| {
        KernelObject::Policy {
            source,
            source_port,
            destination,
            destination_port,
            direction: role.policy_dir(ue_sourced),
            protocol: sa.protocol,
            spi,
        }
    };
    [
        state(
            sa.ue_addr,
            sa.ue_port_c,
            sa.pcscf_addr,
            sa.pcscf_port_s,
            sa.spi_ps,
        ),
        state(
            sa.pcscf_addr,
            sa.pcscf_port_s,
            sa.ue_addr,
            sa.ue_port_c,
            sa.spi_uc,
        ),
        state(
            sa.pcscf_addr,
            sa.pcscf_port_c,
            sa.ue_addr,
            sa.ue_port_s,
            sa.spi_us,
        ),
        state(
            sa.ue_addr,
            sa.ue_port_s,
            sa.pcscf_addr,
            sa.pcscf_port_c,
            sa.spi_pc,
        ),
        policy(
            sa.ue_addr,
            sa.ue_port_c,
            sa.pcscf_addr,
            sa.pcscf_port_s,
            true,
            sa.spi_ps,
        ),
        policy(
            sa.pcscf_addr,
            sa.pcscf_port_s,
            sa.ue_addr,
            sa.ue_port_c,
            false,
            sa.spi_uc,
        ),
        policy(
            sa.pcscf_addr,
            sa.pcscf_port_c,
            sa.ue_addr,
            sa.ue_port_s,
            false,
            shared_template_spi(role, role.policy_dir(false), sa.spi_us),
        ),
        policy(
            sa.ue_addr,
            sa.ue_port_s,
            sa.pcscf_addr,
            sa.pcscf_port_c,
            true,
            shared_template_spi(role, role.policy_dir(true), sa.spi_pc),
        ),
    ]
}

/// What is left of `holder`'s lifetime, for a kernel object installed for it
/// now: a fresh object counts from now, the holder's ends where it always did.
fn remaining_lifetime(holder: &SecurityAssociationPair) -> Option<u64> {
    holder.hard_lifetime_secs.map(|secs| {
        secs.saturating_sub(holder.created_at.elapsed().as_secs())
            .max(1)
    })
}

/// The template SPI of a policy whose selector an old and a new set may
/// share: open (0) at the UE and on the P-CSCF's inbound one, `spi` on the
/// P-CSCF's outbound one, which names the set in use.
fn shared_template_spi(role: SaRole, direction: PolicyDir, spi: u32) -> u32 {
    match (role, direction) {
        (SaRole::PCscf, PolicyDir::Out) => spi,
        _ => 0,
    }
}

/// Whether `object` is one of `pair`'s kernel keys.
fn shares_key(pair: &SecurityAssociationPair, object: &KernelObject) -> bool {
    kernel_objects(pair)
        .iter()
        .any(|theirs| theirs.same_kernel_key(object))
}

/// Whether `a` and `b` are one installation of a pair.
fn same_pair(a: &SecurityAssociationPair, b: &SecurityAssociationPair) -> bool {
    a.ue_addr == b.ue_addr && a.ue_port_c == b.ue_port_c && pair_spis(a) == pair_spis(b)
}

/// A live pair and whether it is in use (not pending).
type Candidate = (SecurityAssociationPair, bool);

/// Of `candidates`, the one whose version of `object`'s kernel key the kernel
/// holds: the newest in use, or the newest when none is.
fn holder_of<'a>(candidates: &'a [Candidate], object: &KernelObject) -> Option<&'a Candidate> {
    candidates
        .iter()
        .filter(|(pair, _)| shares_key(pair, object))
        .max_by_key(|(pair, in_use)| (*in_use, pair.created_at))
}

impl IpsecManager {
    /// Best-effort teardown of the four XFRM states + four policies for `sa`
    /// (ignores `ENOENT`), all but `kept`. Used to clear a colliding orphan
    /// before install and to roll back a partial install; [`delete_sa_pair`]
    /// goes through [`teardown_unshared`](Self::teardown_unshared) instead.
    /// Every delete is independent — one failure never skips the rest, so a
    /// single missing key can't strand the other seven (the latent leak in the
    /// old `?`-chained `delete_sa_pair`). Keys on exactly the kernel's own key,
    /// so it removes a colliding orphan regardless of which registration
    /// created it.
    pub(super) async fn teardown_sa_kernel_except(
        &self,
        sa: &SecurityAssociationPair,
        kept: &[KernelObject],
    ) {
        let doomed: Vec<KernelObject> = kernel_objects(sa)
            .into_iter()
            .filter(|object| !kept.contains(object))
            .collect();
        self.delete_kernel_objects(&doomed).await;
    }

    /// Delete `objects`, best-effort, each on its own as
    /// [`delete_kernel_object`](Self::delete_kernel_object) does. On netlink
    /// they go as one datagram of one message each: the kernel handles and
    /// acks every message of it in order, one failing (`ENOENT`) never
    /// skipping the next, so the kernel ends where the deletes one by one
    /// left it, for one round trip instead of eight.
    pub(super) async fn delete_kernel_objects(&self, objects: &[KernelObject]) {
        #[cfg(test)]
        let one_by_one = self.kernel_mock.is_some() || self.backend == XfrmBackend::IpCommand;
        #[cfg(not(test))]
        let one_by_one = self.backend == XfrmBackend::IpCommand;
        if one_by_one {
            for object in objects {
                self.delete_kernel_object(object).await;
            }
            return;
        }
        let messages = objects.iter().map(delete_message).collect();
        // ENOENT is an object already gone, the usual case; anything else is
        // logged and the rest still deleted, as one by one.
        match self.xfrm().acknowledge(messages).await {
            Ok(results) => {
                for (object, result) in objects.iter().zip(results) {
                    if let Err(error) = result {
                        if !error.to_string().contains("No such file or directory") {
                            debug!(?object, %error, "IPsec: kernel object delete failed");
                        }
                    }
                }
            }
            Err(error) => warn!(%error, "IPsec: kernel object deletes not sent"),
        }
    }

    /// Install the four states and four policies of `sa` (all `EXCL`), all
    /// but `kept`. Returns on the first failure with partial state installed;
    /// the caller ([`create_sa_pair`]) rolls it back.
    pub(super) async fn install_sa_kernel(
        &self,
        sa: &SecurityAssociationPair,
        kept: &[KernelObject],
    ) -> Result<(), IpsecError> {
        // Policies get the same hard lifetime as the states, so they reap on
        // the same deadline (3GPP TS 33.203 clause 7.4); `None` = permanent.
        for object in kernel_objects(sa) {
            if !kept.contains(&object) {
                self.install_kernel_object(sa, &object, sa.hard_lifetime_secs, false)
                    .await?;
            }
        }
        Ok(())
    }

    /// The kernel objects of `sa` that `create_sa_pair` leaves to another
    /// live pair of the same UE, and whether `sa` is pending. Left alone: an
    /// object a sibling holds in exactly this form (a shared policy with an
    /// open template), and one a sibling in use holds in its own version (the
    /// P-CSCF's outbound policy of SA #3), which keeps naming that sibling
    /// until `sa` is taken into use ([`take_into_use`](Self::take_into_use)).
    pub(super) fn objects_left_to_siblings(
        &self,
        sa: &SecurityAssociationPair,
    ) -> (Vec<KernelObject>, bool) {
        let siblings = self.siblings_with_use(sa);
        let mut pending = false;
        let left = kernel_objects(sa)
            .into_iter()
            .filter(|object| {
                let sharers = || siblings.iter().filter(|(pair, _)| shares_key(pair, object));
                if sharers().any(|(pair, _)| kernel_objects(pair).contains(object)) {
                    return true;
                }
                let held_in_use = sharers().any(|(_, in_use)| *in_use);
                pending |= held_in_use;
                held_in_use
            })
            .collect();
        (left, pending)
    }

    /// The other live pairs of `sa`'s UE address (another client port), with
    /// whether each is in use.
    fn siblings_with_use(&self, sa: &SecurityAssociationPair) -> Vec<Candidate> {
        self.associations
            .iter()
            .filter(|entry| {
                let other = entry.value();
                other.ue_addr == sa.ue_addr && other.ue_port_c != sa.ue_port_c
            })
            .map(|entry| {
                let pair = entry.value().clone();
                let in_use = self.is_in_use(&pair);
                (pair, in_use)
            })
            .collect()
    }

    /// Whether `sa` is in use: not installed beside a set in use and waiting
    /// to be taken into use.
    pub(super) fn is_in_use(&self, sa: &SecurityAssociationPair) -> bool {
        let key = Self::contact_key(&sa.ue_addr, sa.ue_port_c);
        !self.lifecycle.is_pending(&key, pair_spis(sa))
    }

    /// Whether the pair at `(ue_addr, ue_port_c)` is pending: installed
    /// beside a set of the UE in use, which the kernel still sends over, and
    /// not yet taken into use.
    pub fn is_pending(&self, ue_addr: &IpAddr, ue_port_c: u16) -> bool {
        self.associations
            .get(&Self::contact_key(ue_addr, ue_port_c))
            .is_some_and(|entry| !self.is_in_use(entry.value()))
    }

    /// Take the pending pair at `(ue_addr, ue_port_c)` into use: the kernel's
    /// policies it shares with the UE's set in use name it from now on, and
    /// that set, now old, goes after 64*T1 (TS 24.229 clause 5.2.2.2: "reduce
    /// the SIP level lifetime of the old set of security associations towards
    /// the same UE to 64*T1 (if currently longer than 64*T1); and use the newly
    /// established set of security associations for further messages sent
    /// towards the UE"). Run as the 2xx to the REGISTER that came over it
    /// leaves, so that 2xx goes over it.
    ///
    /// Returns whether it was pending. A pair in use, or none, is left as is.
    /// On a failed policy update the pair stays pending, and the old set in
    /// use.
    pub async fn take_into_use(
        self: &Arc<Self>,
        ue_addr: &IpAddr,
        ue_port_c: u16,
    ) -> Result<bool, IpsecError> {
        let key = Self::contact_key(ue_addr, ue_port_c);
        let Some(sa) = self
            .associations
            .get(&key)
            .map(|entry| entry.value().clone())
        else {
            return Ok(false);
        };
        match self.lifecycle.pending_how(&key, pair_spis(&sa)) {
            None => return Ok(false),
            // Its own protected client port: nothing in the kernel to move.
            Some(Pending::Challenged | Pending::Registered) => {
                self.promote(&sa, "taken into use");
                return Ok(true);
            }
            Some(Pending::SharedPolicy) => {}
        }
        if !self.lifecycle.take_pending(&key, pair_spis(&sa)) {
            return Ok(false);
        }
        let siblings = self.siblings_with_use(&sa);
        let mut candidates = siblings.clone();
        candidates.push((sa.clone(), true));
        for object in kernel_objects(&sa) {
            let shared = siblings.iter().any(|(pair, _)| shares_key(pair, &object));
            let held_identically = siblings
                .iter()
                .any(|(pair, _)| kernel_objects(pair).contains(&object));
            let ours =
                holder_of(&candidates, &object).is_some_and(|(pair, _)| same_pair(pair, &sa));
            if !matches!(object, KernelObject::Policy { .. })
                || !shared
                || held_identically
                || !ours
            {
                continue;
            }
            if let Err(error) = self
                .install_kernel_object(&sa, &object, remaining_lifetime(&sa), true)
                .await
            {
                self.lifecycle
                    .set_pending(&key, pair_spis(&sa), Some(Pending::SharedPolicy));
                return Err(error);
            }
        }
        info!(
            ue = %sa.ue_addr,
            ue_port_c = sa.ue_port_c,
            spi_us = sa.spi_us,
            "IPsec: SA pair taken into use"
        );
        for (old, _) in siblings.iter().filter(|(pair, _)| {
            kernel_objects(&sa)
                .iter()
                .any(|object| shares_key(pair, object))
        }) {
            self.retire_pair(
                old.ue_addr,
                old.ue_port_c,
                SA_RETIRE_GRACE,
                RetireCondition::Always,
                "old set: the new set was taken into use",
            );
        }
        Ok(true)
    }

    /// Re-pin the lifetime of `sa`'s kernel objects: the four states to
    /// `state_lifetime` (anchored on the install, which `XFRM_MSG_UPDSA`
    /// keeps), and the policies it holds to `policy_lifetime` (from now: an
    /// updated policy counts from the update). A policy the kernel holds in
    /// another pair's version (a newer pair's, or, for a pending pair, the
    /// set in use's) is that pair's to re-pin, with its own template.
    pub(super) async fn repin_kernel_lifetimes(
        &self,
        sa: &SecurityAssociationPair,
        state_lifetime: Option<u64>,
        policy_lifetime: Option<u64>,
    ) -> Result<(), IpsecError> {
        let mut candidates = self.siblings_with_use(sa);
        candidates.push((sa.clone(), self.is_in_use(sa)));
        for object in kernel_objects(sa) {
            match object {
                KernelObject::State {
                    source,
                    source_port,
                    destination,
                    destination_port,
                    spi,
                } => {
                    self.update_sa_only(
                        &source,
                        source_port,
                        &destination,
                        destination_port,
                        spi,
                        &sa.ealg,
                        &sa.aalg,
                        &sa.encryption_key,
                        &sa.integrity_key,
                        sa.protocol,
                        state_lifetime,
                    )
                    .await?;
                }
                KernelObject::Policy { .. } => {
                    let ours = holder_of(&candidates, &object)
                        .is_some_and(|(holder, _)| same_pair(holder, sa));
                    if ours {
                        self.install_kernel_object(sa, &object, policy_lifetime, true)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Delete one kernel object, best-effort.
    pub(super) async fn delete_kernel_object(&self, object: &KernelObject) {
        match *object {
            // States are keyed on (dst, spi); src is ignored by the kernel del.
            KernelObject::State {
                source,
                destination,
                spi,
                ..
            } => {
                self.del_sa(&source, &destination, spi).await.ok();
            }
            KernelObject::Policy {
                source,
                source_port,
                destination,
                destination_port,
                direction,
                protocol,
                ..
            } => {
                self.del_policy(
                    &source,
                    source_port,
                    &destination,
                    destination_port,
                    direction,
                    protocol,
                )
                .await
                .ok();
            }
        }
    }

    /// Install `holder`'s version of `object` again, for the rest of
    /// `holder`'s lifetime.
    pub(super) async fn reinstall_kernel_object(
        &self,
        holder: &SecurityAssociationPair,
        object: &KernelObject,
    ) -> Result<(), IpsecError> {
        self.install_kernel_object(holder, object, remaining_lifetime(holder), false)
            .await
    }

    /// Install `object` with `holder`'s keys and transform, for `lifetime`
    /// seconds from now. A policy with `replace` is added or replaced in one
    /// step (`XFRM_MSG_UPDPOLICY`), never missing in between.
    async fn install_kernel_object(
        &self,
        holder: &SecurityAssociationPair,
        object: &KernelObject,
        lifetime: Option<u64>,
        replace: bool,
    ) -> Result<(), IpsecError> {
        match *object {
            KernelObject::State {
                source,
                source_port,
                destination,
                destination_port,
                spi,
            } => {
                self.add_sa(
                    &source,
                    source_port,
                    &destination,
                    destination_port,
                    spi,
                    &holder.ealg,
                    &holder.aalg,
                    &holder.encryption_key,
                    &holder.integrity_key,
                    holder.protocol,
                    lifetime,
                )
                .await
            }
            KernelObject::Policy {
                source,
                source_port,
                destination,
                destination_port,
                direction,
                protocol,
                spi,
            } => {
                self.add_policy(
                    &source,
                    source_port,
                    &destination,
                    destination_port,
                    direction,
                    spi,
                    protocol,
                    lifetime,
                    replace,
                )
                .await
            }
        }
    }

    /// Tear down `sa`, which has already left `associations` and was in use
    /// or not as `sa_in_use` says, without taking a kernel object another
    /// live pair of the same UE holds.
    ///
    /// Two pairs of one UE can share kernel keys. The P-CSCF's protected ports
    /// are fixed, and 3GPP TS 33.203 clause 7.4.0 keeps the UE's protected
    /// server port across an authenticated re-registration, so the policies of
    /// SA #3 and #4 (`port_pc` <-> `port_us`) have one selector in the old pair
    /// and the new: the kernel holds one policy for both, in the version of
    /// the newest pair in use (see [`holder_of`]). Deleting a pair whose
    /// version the kernel does not hold (the old one once the new is in use,
    /// clause 7.4.2a; a pending one whose authentication failed, "the P-CSCF
    /// shall delete the new SAs") leaves the policy alone. Deleting the one
    /// whose version it holds hands the policy, in place, to the pair that
    /// holds it next; a pending one handed it is taken into use ("When the old
    /// SAs expire without a further SIP message protected by the new SAs, the
    /// new SAs are taken into use for outbound messages").
    pub(super) async fn teardown_unshared(&self, sa: &SecurityAssociationPair, sa_in_use: bool) {
        let siblings: Vec<Candidate> = self
            .associations
            .iter()
            .filter(|entry| entry.value().ue_addr == sa.ue_addr)
            .map(|entry| {
                let pair = entry.value().clone();
                let in_use = self.is_in_use(&pair);
                (pair, in_use)
            })
            .collect();
        let mut candidates = siblings.clone();
        candidates.push((sa.clone(), sa_in_use));
        for object in kernel_objects(sa) {
            let Some((next, next_in_use)) = holder_of(&siblings, &object) else {
                self.delete_kernel_object(&object).await;
                continue;
            };
            let ours =
                holder_of(&candidates, &object).is_some_and(|(holder, _)| same_pair(holder, sa));
            if !ours {
                debug!(
                    ue = %sa.ue_addr,
                    ue_port_c = sa.ue_port_c,
                    object = ?object,
                    "IPsec: kernel object held in another pair's version of the UE, left in place"
                );
                continue;
            }
            if !next_in_use {
                let key = Self::contact_key(&next.ue_addr, next.ue_port_c);
                if self.lifecycle.take_pending(&key, pair_spis(next)) {
                    info!(
                        ue = %next.ue_addr,
                        ue_port_c = next.ue_port_c,
                        "IPsec: SA pair taken into use, the set in use went"
                    );
                }
            }
            let Some(theirs) = kernel_objects(next)
                .into_iter()
                .find(|theirs| theirs.same_kernel_key(&object))
            else {
                continue;
            };
            let handed_over = match theirs {
                // In place, never missing: a policy is replaced in one step.
                KernelObject::Policy { .. } => {
                    self.install_kernel_object(next, &theirs, remaining_lifetime(next), true)
                        .await
                }
                KernelObject::State { .. } => {
                    self.delete_kernel_object(&object).await;
                    self.reinstall_kernel_object(next, &theirs).await
                }
            };
            if let Err(error) = handed_over {
                warn!(
                    ue = %sa.ue_addr,
                    holder_port_c = next.ue_port_c,
                    %error,
                    "IPsec: could not hand a shared kernel object to another pair of the UE"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an IP literal")
    }

    /// A pair on the UE's protected server port 6101 and the P-CSCF's fixed
    /// ports 5064/5066, client port `ue_port_c`, SPIs from `spi_base`.
    fn pair(role: SaRole, ue_port_c: u16, spi_base: u32) -> SecurityAssociationPair {
        SecurityAssociationPair {
            ue_addr: ip("192.0.2.77"),
            pcscf_addr: ip("198.51.100.10"),
            ue_port_c,
            ue_port_s: 6101,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: spi_base,
            spi_us: spi_base + 1,
            spi_pc: spi_base + 2,
            spi_ps: spi_base + 3,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "00".repeat(20),
            hard_lifetime_secs: Some(240),
            protocol: SaProtocol::Any,
            expires_at: Instant::now(),
            created_at: Instant::now(),
            role,
            impi: None,
            security_server: None,
        }
    }

    fn template_spis(sa: &SecurityAssociationPair) -> Vec<u32> {
        kernel_objects(sa)
            .into_iter()
            .filter_map(|object| match object {
                KernelObject::Policy { spi, .. } => Some(spi),
                KernelObject::State { .. } => None,
            })
            .collect()
    }

    fn socket(text: &str) -> SocketAddr {
        text.parse().expect("a socket address")
    }

    #[test]
    fn a_ue_leaves_the_shared_selectors_template_open_and_a_pcscf_pins_its_outbound_one() {
        let ue = pair(SaRole::Ue, 6100, 70_000);
        // SA #1, #2 pinned; SA #3 (port_pc -> port_us), #4 (port_us -> port_pc) open.
        assert_eq!(template_spis(&ue), vec![70_003, 70_000, 0, 0]);
        // At the P-CSCF only the inbound one of them (SA #4) is open.
        let pcscf = pair(SaRole::PCscf, 6100, 70_000);
        assert_eq!(template_spis(&pcscf), vec![70_003, 70_000, 70_001, 0]);
    }

    /// Make-before-break at the UE against a P-CSCF with a fixed `port_pc`:
    /// the new set installs beside the old without touching the shared
    /// policies, so a request over either set's SA #3 is accepted; deleting
    /// the old one leaves them to the new.
    #[tokio::test]
    async fn a_ue_overlap_accepts_both_sets_and_never_drops_the_shared_policy() {
        let manager = IpsecManager::with_test_kernel();
        let old = pair(SaRole::Ue, 6100, 70_000);
        let new = pair(SaRole::Ue, 6102, 71_000);
        manager.create_ue_sa_pair(old.clone()).await.expect("old");
        let ops_before = manager.test_kernel_ops().len();
        manager.create_ue_sa_pair(new.clone()).await.expect("new");

        let shared_in = "policy:198.51.100.10:5064->192.0.2.77:6101:in";
        let shared_out = "policy:192.0.2.77:6101->198.51.100.10:5064:out";
        let later = &manager.test_kernel_ops()[ops_before..];
        for key in [shared_in, shared_out] {
            assert!(
                !later.iter().any(|op| op.ends_with(key)),
                "the shared policy is neither deleted nor re-added: {later:?}"
            );
            assert_eq!(manager.test_kernel_policy_template(key), Some(0));
        }
        let (from, to) = (socket("198.51.100.10:5064"), socket("192.0.2.77:6101"));
        assert!(manager.test_kernel_accepts_inbound(from, to, old.spi_us));
        assert!(manager.test_kernel_accepts_inbound(from, to, new.spi_us));

        // Re-pinning the older set leaves the shared policies to the newer;
        // re-pinning the newer moves all four of its policies.
        manager
            .update_sa_pair_lifetime(&old.ue_addr, 6100, Some(500))
            .await
            .expect("re-pinned");
        let updated: Vec<String> = manager
            .test_kernel_policy_updates()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(updated.len(), 2, "only the old set's own two: {updated:?}");
        assert!(!updated
            .iter()
            .any(|key| key == shared_in || key == shared_out));
        manager
            .update_sa_pair_lifetime(&new.ue_addr, 6102, Some(630))
            .await
            .expect("re-pinned");
        let updates = manager.test_kernel_policy_updates();
        assert_eq!(updates.len(), 6);
        assert!(updates[2..]
            .iter()
            .all(|(_, lifetime)| *lifetime == Some(630)));

        manager
            .delete_sa_pair(&old.ue_addr, 6100)
            .await
            .expect("deleted");
        assert!(manager.test_kernel_accepts_inbound(from, to, new.spi_us));
        assert!(!manager.test_kernel_accepts_inbound(from, to, old.spi_us));
        assert_eq!(manager.test_kernel_live_count(), 8, "the new set's eight");
        manager
            .delete_sa_pair(&new.ue_addr, 6102)
            .await
            .expect("deleted");
        assert_eq!(manager.test_kernel_live_count(), 0);
        assert_eq!(manager.test_spi_owner_count(), 0);
    }

    /// The P-CSCF's policies of SA #3 (outbound) and SA #4 (inbound), shared
    /// by every set of the UE on server port 6101.
    const PCSCF_OUT: &str = "policy:198.51.100.10:5064->192.0.2.77:6101:out";
    const PCSCF_IN: &str = "policy:192.0.2.77:6101->198.51.100.10:5064:in";

    fn shared_inbound() -> (SocketAddr, SocketAddr) {
        (socket("192.0.2.77:6101"), socket("198.51.100.10:5064"))
    }

    fn ops_on(manager: &IpsecManager, from: usize, key: &str) -> Vec<String> {
        manager.test_kernel_ops()[from..]
            .iter()
            .filter(|op| op.ends_with(key))
            .cloned()
            .collect()
    }

    /// A P-CSCF re-authentication: the set the challenge sets up is installed
    /// pending. The outbound policy of SA #3 keeps naming the set in use, so
    /// the 401 goes over the SA the UE holds (TS 24.229 clause 5.2.2.2, TS
    /// 33.203 clause 7.4.2a); the inbound one of SA #4 is open, so a response
    /// over either set is accepted.
    ///
    /// Before: the new set's install replaced the outbound policy with its own
    /// template, the 401 went over an SA the UE could only derive from that
    /// 401, and the UE dropped it.
    #[tokio::test]
    async fn a_pcscf_re_authentication_leaves_the_challenge_on_the_set_in_use() {
        let manager = IpsecManager::with_test_kernel();
        let old = pair(SaRole::PCscf, 6100, 70_000);
        let new = pair(SaRole::PCscf, 6102, 71_000);
        manager.create_sa_pair(old.clone()).await.expect("old");
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(old.spi_us)
        );
        assert_eq!(manager.test_kernel_policy_template(PCSCF_IN), Some(0));
        assert!(
            !manager.is_pending(&old.ue_addr, 6100),
            "nothing to wait for"
        );

        let ops_before = manager.test_kernel_ops().len();
        manager.create_sa_pair(new.clone()).await.expect("new");
        for key in [PCSCF_OUT, PCSCF_IN] {
            assert!(
                ops_on(&manager, ops_before, key).is_empty(),
                "{key} is neither deleted nor re-added"
            );
        }
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(old.spi_us)
        );
        assert_eq!(manager.test_kernel_policy_template(PCSCF_IN), Some(0));
        assert!(manager.is_pending(&new.ue_addr, 6102));
        assert!(!manager.is_pending(&old.ue_addr, 6100));
        let (from, to) = shared_inbound();
        assert!(manager.test_kernel_accepts_inbound(from, to, old.spi_pc));
        assert!(manager.test_kernel_accepts_inbound(from, to, new.spi_pc));
        // Old eight, plus the new set's four states and two own policies.
        assert_eq!(manager.test_kernel_live_count(), 14);
    }

    /// Taking the new set into use (the 2xx to the REGISTER that came over
    /// it) moves the outbound policy to it in one update, and the old set goes
    /// after 64*T1 (TS 24.229 clause 5.2.2.2).
    #[tokio::test(start_paused = true)]
    async fn taking_the_new_set_into_use_moves_the_outbound_policy_and_shortens_the_old_set() {
        let manager = Arc::new(IpsecManager::with_test_kernel());
        let old = pair(SaRole::PCscf, 6100, 70_000);
        let new = pair(SaRole::PCscf, 6102, 71_000);
        manager.create_sa_pair(old.clone()).await.expect("old");
        manager.create_sa_pair(new.clone()).await.expect("new");
        let ops_before = manager.test_kernel_ops().len();

        assert!(manager
            .take_into_use(&new.ue_addr, 6102)
            .await
            .expect("taken"));
        assert_eq!(
            ops_on(&manager, ops_before, PCSCF_OUT),
            vec![format!("update_policy {PCSCF_OUT}")],
            "replaced in place, never missing"
        );
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(new.spi_us)
        );
        assert!(!manager.is_pending(&new.ue_addr, 6102));
        assert_eq!(manager.lifecycle.sizes().2, 1, "the old set is shortened");
        assert!(
            !manager
                .take_into_use(&new.ue_addr, 6102)
                .await
                .expect("idempotent"),
            "already in use"
        );
        assert!(!manager
            .take_into_use(&old.ue_addr, 6100)
            .await
            .expect("in use"));
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(new.spi_us)
        );

        tokio::time::sleep(crate::ipsec::retire::SA_RETIRE_GRACE / 2).await;
        assert!(
            manager.has_sa(&old.ue_addr, 6100),
            "kept for its pending transactions"
        );
        tokio::time::sleep(crate::ipsec::retire::SA_RETIRE_GRACE).await;
        assert!(!manager.has_sa(&old.ue_addr, 6100));
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(new.spi_us)
        );
        assert_eq!(manager.test_kernel_live_count(), 8, "the new set's eight");
        let (from, to) = shared_inbound();
        assert!(manager.test_kernel_accepts_inbound(from, to, new.spi_pc));
        assert!(!manager.test_kernel_accepts_inbound(from, to, old.spi_pc));
    }

    /// An authentication that failed: the pending set is deleted ("the P-CSCF
    /// shall delete the new SAs", TS 33.203 clause 7.4.2a) and the outbound
    /// policy never left the set in use.
    #[tokio::test]
    async fn an_abandoned_pending_set_leaves_the_outbound_policy_on_the_set_in_use() {
        let manager = IpsecManager::with_test_kernel();
        let old = pair(SaRole::PCscf, 6100, 70_000);
        let new = pair(SaRole::PCscf, 6102, 71_000);
        manager.create_sa_pair(old.clone()).await.expect("old");
        manager.create_sa_pair(new.clone()).await.expect("new");
        let ops_before = manager.test_kernel_ops().len();

        manager
            .delete_sa_pair(&new.ue_addr, 6102)
            .await
            .expect("deleted");
        for key in [PCSCF_OUT, PCSCF_IN] {
            assert!(
                ops_on(&manager, ops_before, key).is_empty(),
                "{key} stays with the set in use"
            );
        }
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(old.spi_us)
        );
        assert_eq!(manager.test_kernel_live_count(), 8, "the old set's eight");
        assert_eq!(manager.lifecycle.pending_len(), 0);
        let (from, to) = shared_inbound();
        assert!(manager.test_kernel_accepts_inbound(from, to, old.spi_pc));
        assert!(!manager.test_kernel_accepts_inbound(from, to, new.spi_pc));
    }

    /// The old set going first (its lifetime ran out) takes the pending one
    /// into use: "When the old SAs expire without a further SIP message
    /// protected by the new SAs, the new SAs are taken into use for outbound
    /// messages" (TS 33.203 clause 7.4.2a).
    #[tokio::test]
    async fn the_set_in_use_going_first_takes_the_pending_one_into_use() {
        let manager = IpsecManager::with_test_kernel();
        let old = pair(SaRole::PCscf, 6100, 70_000);
        let new = pair(SaRole::PCscf, 6102, 71_000);
        manager.create_sa_pair(old.clone()).await.expect("old");
        manager.create_sa_pair(new.clone()).await.expect("new");

        manager
            .delete_sa_pair(&old.ue_addr, 6100)
            .await
            .expect("deleted");
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(new.spi_us)
        );
        assert_eq!(manager.test_kernel_policy_template(PCSCF_IN), Some(0));
        assert!(!manager.is_pending(&new.ue_addr, 6102));
        assert_eq!(manager.test_kernel_live_count(), 8, "the new set's eight");
    }

    /// Re-pinning a pending set's lifetime leaves the outbound policy to the
    /// set in use; re-pinning that one keeps it on itself.
    #[tokio::test]
    async fn repinning_a_pending_set_leaves_the_outbound_policy_to_the_set_in_use() {
        let manager = IpsecManager::with_test_kernel();
        let old = pair(SaRole::PCscf, 6100, 70_000);
        let new = pair(SaRole::PCscf, 6102, 71_000);
        manager.create_sa_pair(old.clone()).await.expect("old");
        manager.create_sa_pair(new.clone()).await.expect("new");

        manager
            .update_sa_pair_lifetime(&new.ue_addr, 6102, Some(500))
            .await
            .expect("re-pinned");
        let updated: Vec<String> = manager
            .test_kernel_policy_updates()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert!(!updated.iter().any(|key| key == PCSCF_OUT), "{updated:?}");
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(old.spi_us)
        );
        manager
            .update_sa_pair_lifetime(&old.ue_addr, 6100, Some(500))
            .await
            .expect("re-pinned");
        assert_eq!(
            manager.test_kernel_policy_template(PCSCF_OUT),
            Some(old.spi_us)
        );
    }

    /// Leak gate: re-authentication after re-authentication, each new set
    /// taken into use and the old one retired, leaves one set's eight kernel
    /// objects, and nothing once the last goes.
    #[tokio::test(start_paused = true)]
    async fn repeated_re_authentications_leave_one_set_and_drain() {
        let manager = Arc::new(IpsecManager::with_test_kernel());
        let first = pair(SaRole::PCscf, 6100, 70_000);
        manager.create_sa_pair(first).await.expect("first");
        let mut in_use = 6100;
        for cycle in 1..=20u16 {
            let port_c = 6100 + 2 * cycle;
            let next = pair(SaRole::PCscf, port_c, 70_000 + 10 * u32::from(cycle));
            manager.create_sa_pair(next.clone()).await.expect("next");
            assert!(manager
                .take_into_use(&next.ue_addr, port_c)
                .await
                .expect("taken"));
            assert_eq!(
                manager.test_kernel_policy_template(PCSCF_OUT),
                Some(next.spi_us)
            );
            tokio::time::sleep(crate::ipsec::retire::SA_RETIRE_GRACE * 2).await;
            assert!(!manager.has_sa(&next.ue_addr, in_use), "cycle {cycle}");
            assert_eq!(manager.active_count(), 1);
            assert_eq!(manager.test_kernel_live_count(), 8);
            in_use = port_c;
        }
        manager
            .delete_sa_pair(&ip("192.0.2.77"), in_use)
            .await
            .expect("deleted");
        assert_eq!(manager.test_kernel_live_count(), 0);
        assert_eq!(manager.test_spi_owner_count(), 0);
        assert_eq!(manager.lifecycle.sizes(), (0, 0, 0));
        assert_eq!(manager.lifecycle.pending_len(), 0);
    }
}
