//! A pair named by its installation: its four SPIs, not the UE's address and
//! protected client port alone.
//!
//! The manager holds one pair per `(UE address, client port)`. A UE that
//! retransmits an unanswered initial REGISTER gets a second challenge, and a
//! second pair on the same client port that replaces the first in the manager
//! and in the kernel ([`create_sa_pair`](IpsecManager::create_sa_pair)). What
//! still names the first, the `PendingSA` the script stashed for it, names a
//! pair that is gone: deleting or re-pinning "the pair at that port" would act
//! on the second, in use by the time the first one's stash entry expires, and
//! leave the UE with no security associations while it stays registered.
//! 3GPP TS 33.203 clause 7.4: a new set replaces the old one only once it is
//! used, and an unused set is removed by its own SPIs, never touching a set in
//! use. So a caller that holds a particular installation acts on it by
//! [`delete_installation`](IpsecManager::delete_installation) and
//! [`holds_installation`](IpsecManager::holds_installation).

use std::sync::Arc;

use tracing::{debug, warn};

use super::retire::SA_RETIRE_GRACE;
use super::{IpsecManager, SecurityAssociationPair};

/// Whether `a` and `b` are one installation of a pair: the same UE address and
/// client port, and the same four SPIs (a re-key keeps them, a new challenge
/// allocates the P-CSCF's two afresh).
pub(super) fn same_installation(a: &SecurityAssociationPair, b: &SecurityAssociationPair) -> bool {
    a.ue_addr == b.ue_addr
        && a.ue_port_c == b.ue_port_c
        && (a.spi_pc, a.spi_ps, a.spi_uc, a.spi_us) == (b.spi_pc, b.spi_ps, b.spi_uc, b.spi_us)
}

impl IpsecManager {
    /// Whether the pair held at `sa`'s UE address and client port is still
    /// this installation of it, not a newer pair that replaced it.
    pub fn holds_installation(&self, sa: &SecurityAssociationPair) -> bool {
        self.associations
            .get(&Self::contact_key(&sa.ue_addr, sa.ue_port_c))
            .is_some_and(|held| same_installation(held.value(), sa))
    }

    /// Whether another installation is held at `sa`'s UE address and client
    /// port: a newer challenge replaced `sa` there.
    pub fn is_replaced(&self, sa: &SecurityAssociationPair) -> bool {
        self.associations
            .get(&Self::contact_key(&sa.ue_addr, sa.ue_port_c))
            .is_some_and(|held| !same_installation(held.value(), sa))
    }

    /// Delete the installation `sa` names and nothing else: when a newer pair
    /// has replaced it on the same client port (whose replacement already
    /// took the old states, see `retire_replaced_pair`), or it is gone, this
    /// is a no-op. Returns whether it deleted it.
    pub async fn delete_installation(&self, sa: &SecurityAssociationPair) -> bool {
        let key = Self::contact_key(&sa.ue_addr, sa.ue_port_c);
        let Some((key, held)) = self
            .associations
            .remove_if(&key, |_, held| same_installation(held, sa))
        else {
            debug!(
                ue = %sa.ue_addr,
                ue_port_c = sa.ue_port_c,
                spi_pc = sa.spi_pc,
                spi_ps = sa.spi_ps,
                "IPsec: SA pair already replaced or deleted, nothing to delete"
            );
            return false;
        };
        self.tear_down_removed(&key, held).await;
        true
    }

    /// What activating the `PendingSA` of `sa` does in the kernel, on the
    /// 200 OK to the REGISTER it authenticated: re-pin its lifetime to the
    /// grant (when given), and supersede the UE's other pairs (TS 33.203
    /// clause 7.4.2a). Both fire-and-forget. Nothing when `sa` is no longer
    /// the pair held at its client port: a newer challenge replaced it, and
    /// acting on its port would act on that newer pair.
    pub fn activate_installation(
        self: &Arc<Self>,
        sa: &SecurityAssociationPair,
        hard_lifetime_secs: Option<u64>,
    ) {
        if !self.holds_installation(sa) {
            warn!(
                ue = %sa.ue_addr,
                ue_port_c = sa.ue_port_c,
                spi_pc = sa.spi_pc,
                spi_ps = sa.spi_ps,
                "ipsec.PendingSA: activated after a newer pair replaced it; the newer pair is left as it is"
            );
            return;
        }
        let (ue_addr, ue_port_c) = (sa.ue_addr, sa.ue_port_c);
        if let Some(secs) = hard_lifetime_secs {
            let manager = Arc::clone(self);
            let installation = sa.clone();
            tokio::spawn(async move {
                if !manager.holds_installation(&installation) {
                    return;
                }
                if let Err(error) = manager
                    .update_sa_pair_lifetime(&ue_addr, ue_port_c, Some(secs))
                    .await
                {
                    warn!(
                        %error,
                        ue = %ue_addr,
                        ue_port_c,
                        hard_lifetime_secs = secs,
                        "ipsec.PendingSA.activate: kernel hard-lifetime repin failed"
                    );
                }
            });
        }
        // The UE's other pairs go now that this one is in use. The UE picks a
        // fresh port_uc on every REGISTER, so a re-REGISTER installs under a
        // new contact key and the previous pair's policies would otherwise
        // stay in the kernel. The pair the REGISTER arrived over is kept
        // until the transactions pending on it can be done; any other is
        // deleted at once.
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager
                .supersede_pairs_for_ue(&ue_addr, ue_port_c, SA_RETIRE_GRACE)
                .await;
        });
    }
}
