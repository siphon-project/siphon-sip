//! The eight kernel objects of a pair (four SA states, four policies) and
//! taking them down without taking one another pair of the UE shares: the
//! P-CSCF's protected ports are fixed and the UE keeps its protected server
//! port across an authenticated re-registration (3GPP TS 33.203 clause
//! 7.4.0), so an old and a new pair hold the policies of SA #3 and #4 under
//! one kernel key.

use std::net::IpAddr;

use tracing::debug;

use super::{IpsecError, IpsecManager, PolicyDir, SaProtocol, SecurityAssociationPair};

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
            sa.spi_us,
        ),
        policy(
            sa.ue_addr,
            sa.ue_port_s,
            sa.pcscf_addr,
            sa.pcscf_port_c,
            true,
            sa.spi_pc,
        ),
    ]
}

impl IpsecManager {
    /// Best-effort teardown of the four XFRM states + four policies for `sa`
    /// (ignores `ENOENT`). Used to clear a colliding orphan before install and
    /// to roll back a partial install; [`delete_sa_pair`] goes through
    /// [`teardown_unshared`](Self::teardown_unshared) instead. Every delete is
    /// independent — one failure never skips the rest, so a single missing key
    /// can't strand the other seven (the latent leak in the old `?`-chained
    /// `delete_sa_pair`). Keys on exactly the kernel's own key, so it removes a
    /// colliding orphan regardless of which registration created it.
    pub(super) async fn teardown_sa_kernel(&self, sa: &SecurityAssociationPair) {
        for object in kernel_objects(sa) {
            self.delete_kernel_object(&object).await;
        }
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
        // A fresh kernel object counts its lifetime from now; the holder's ends
        // where it always did.
        let remaining = holder.hard_lifetime_secs.map(|secs| {
            secs.saturating_sub(holder.created_at.elapsed().as_secs())
                .max(1)
        });
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
                    remaining,
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
                    remaining,
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
                    self.delete_kernel_object(&object).await;
                    let theirs = kernel_objects(holder)
                        .into_iter()
                        .find(|theirs| theirs.same_kernel_key(&object));
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
