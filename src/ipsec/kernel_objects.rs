//! The eight kernel objects of a pair (four SA states, four policies):
//! installing them, re-pinning their lifetimes, and taking them down without
//! taking one another pair of the UE shares. A P-CSCF that keeps its protected
//! ports fixed (siphon's own does) and a UE that keeps its protected server
//! port across an authenticated re-registration (3GPP TS 33.203 clause 7.4.0)
//! make an old and a new pair hold the policies of SA #3 and #4 under one
//! kernel key.

use std::net::IpAddr;

use tracing::debug;

use super::{IpsecError, IpsecManager, PolicyDir, SaProtocol, SaRole, SecurityAssociationPair};

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

/// The four states and four policies `create_sa_pair` installs for `sa`.
///
/// A policy's template names the SA it applies, except on the UE's policies
/// of SA #3 and #4 (`port_pc` <-> `port_us`), whose template names SPI 0: any
/// SA of the selector. Against a P-CSCF that keeps `port_pc`, an old and a new
/// set have one selector there and the kernel one policy for both, so a
/// template naming the new set's SPI would drop a request the P-CSCF still
/// sends over the old set while the UE holds both (TS 24.229 clause 5.1.1.5.1:
/// the old set is deleted only once something arrives over the new one; TS
/// 33.203 clause 7.4.1a). The states still tell the sets apart: only an SA the
/// UE holds decrypts. Outbound, the kernel picks the newest SA of the
/// selector, the set a P-CSCF that pins its own template to its newest set
/// accepts. Against a P-CSCF that changes `port_pc` (clause 7.4.0) the
/// selectors differ and nothing is shared. The P-CSCF role keeps every
/// template pinned.
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
            shared_template_spi(role, sa.spi_us),
        ),
        policy(
            sa.ue_addr,
            sa.ue_port_s,
            sa.pcscf_addr,
            sa.pcscf_port_c,
            true,
            shared_template_spi(role, sa.spi_pc),
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
/// share: open (0) at the UE, `spi` at the P-CSCF.
fn shared_template_spi(role: SaRole, spi: u32) -> u32 {
    match role {
        SaRole::Ue => 0,
        SaRole::PCscf => spi,
    }
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
        for object in kernel_objects(sa) {
            if !kept.contains(&object) {
                self.delete_kernel_object(&object).await;
            }
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

    /// The kernel objects of `sa` another live pair of the same UE already
    /// holds in exactly this form (same key, same template): a UE's shared
    /// policy of SA #3 or #4, see [`kernel_objects`].
    pub(super) fn objects_held_identically(
        &self,
        sa: &SecurityAssociationPair,
    ) -> Vec<KernelObject> {
        let siblings = self.siblings_of(sa);
        kernel_objects(sa)
            .into_iter()
            .filter(|object| {
                siblings
                    .iter()
                    .any(|sibling| kernel_objects(sibling).contains(object))
            })
            .collect()
    }

    /// The other live pairs of `sa`'s UE address.
    fn siblings_of(&self, sa: &SecurityAssociationPair) -> Vec<SecurityAssociationPair> {
        self.associations
            .iter()
            .filter(|entry| {
                let other = entry.value();
                other.ue_addr == sa.ue_addr && other.ue_port_c != sa.ue_port_c
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Re-pin the lifetime of `sa`'s kernel objects: the four states to
    /// `state_lifetime` (anchored on the install, which `XFRM_MSG_UPDSA`
    /// keeps), and the policies it holds to `policy_lifetime` (from now: an
    /// updated policy counts from the update). A policy a newer pair of the
    /// UE holds is that pair's to re-pin, with its own template.
    pub(super) async fn repin_kernel_lifetimes(
        &self,
        sa: &SecurityAssociationPair,
        state_lifetime: Option<u64>,
        policy_lifetime: Option<u64>,
    ) -> Result<(), IpsecError> {
        let siblings = self.siblings_of(sa);
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
                    let held_by_newer = siblings.iter().any(|sibling| {
                        sibling.created_at > sa.created_at
                            && kernel_objects(sibling)
                                .iter()
                                .any(|theirs| theirs.same_kernel_key(&object))
                    });
                    if !held_by_newer {
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

    /// Tear down `sa`, which has already left `associations`, without taking a
    /// kernel object another live pair of the same UE holds.
    ///
    /// Two pairs of one UE can share kernel keys. The P-CSCF's protected ports
    /// are fixed, and 3GPP TS 33.203 clause 7.4.0 keeps the UE's protected
    /// server port across an authenticated re-registration, so the policies of
    /// SA #3 and #4 (`port_pc` <-> `port_us`) have one selector in the old pair
    /// and the new: the kernel holds one policy for both, the one installed
    /// last. Deleting the old pair while the new one is in use (clause 7.4.2a
    /// retires it after the new one is taken into use) must leave that policy
    /// alone, and deleting the new one while the old one stays (an
    /// authentication that failed, clause 7.4.2a: "the P-CSCF shall delete the
    /// new SAs", the old ones still protect) must put the old one's back.
    pub(super) async fn teardown_unshared(&self, sa: &SecurityAssociationPair) {
        let siblings: Vec<SecurityAssociationPair> = self
            .associations
            .iter()
            .filter(|entry| entry.value().ue_addr == sa.ue_addr)
            .map(|entry| entry.value().clone())
            .collect();
        for object in kernel_objects(sa) {
            // The kernel holds the version of the sibling installed last, or
            // this pair's when it came after every sibling.
            let holder = siblings
                .iter()
                .filter(|sibling| {
                    kernel_objects(sibling)
                        .iter()
                        .any(|theirs| theirs.same_kernel_key(&object))
                })
                .max_by_key(|sibling| sibling.created_at);
            match holder {
                None => self.delete_kernel_object(&object).await,
                Some(holder) if holder.created_at >= sa.created_at => {
                    debug!(
                        ue = %sa.ue_addr,
                        ue_port_c = sa.ue_port_c,
                        holder_port_c = holder.ue_port_c,
                        object = ?object,
                        "IPsec: kernel object held by a newer pair of the UE, left in place"
                    );
                }
                Some(holder) => {
                    let theirs = kernel_objects(holder)
                        .into_iter()
                        .find(|theirs| theirs.same_kernel_key(&object));
                    // The same policy (a UE's open template): handed back in
                    // place, with the holder's lifetime, never missing.
                    if theirs == Some(object) {
                        if let Err(error) = self
                            .install_kernel_object(
                                holder,
                                &object,
                                remaining_lifetime(holder),
                                true,
                            )
                            .await
                        {
                            tracing::warn!(
                                ue = %sa.ue_addr,
                                holder_port_c = holder.ue_port_c,
                                %error,
                                "IPsec: could not hand a shared policy back to the older pair of the UE"
                            );
                        }
                        continue;
                    }
                    self.delete_kernel_object(&object).await;
                    if let Some(theirs) = theirs {
                        if let Err(error) = self.reinstall_kernel_object(holder, &theirs).await {
                            tracing::warn!(
                                ue = %sa.ue_addr,
                                holder_port_c = holder.ue_port_c,
                                %error,
                                "IPsec: could not give a kernel object back to the older pair of the UE"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};
    use std::net::SocketAddr;
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
    fn a_ue_leaves_the_shared_selectors_template_open_and_a_pcscf_pins_all() {
        let ue = pair(SaRole::Ue, 6100, 70_000);
        // SA #1, #2 pinned; SA #3 (port_pc -> port_us), #4 (port_us -> port_pc) open.
        assert_eq!(template_spis(&ue), vec![70_003, 70_000, 0, 0]);
        let pcscf = pair(SaRole::PCscf, 6100, 70_000);
        assert_eq!(template_spis(&pcscf), vec![70_003, 70_000, 70_001, 70_002]);
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

    /// The P-CSCF role is as it was: the newer pair's install replaces the
    /// shared policy with its own pinned template.
    #[tokio::test]
    async fn a_pcscf_overlap_still_pins_the_newest_set() {
        let manager = IpsecManager::with_test_kernel();
        let old = pair(SaRole::PCscf, 6100, 70_000);
        let new = pair(SaRole::PCscf, 6102, 71_000);
        manager.create_sa_pair(old).await.expect("old");
        manager.create_sa_pair(new.clone()).await.expect("new");
        assert_eq!(
            manager.test_kernel_policy_template("policy:192.0.2.77:6101->198.51.100.10:5064:in"),
            Some(new.spi_pc)
        );
        assert_eq!(
            manager.test_kernel_policy_template("policy:198.51.100.10:5064->192.0.2.77:6101:out"),
            Some(new.spi_us)
        );
    }
}
