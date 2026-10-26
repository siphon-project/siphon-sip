//! A UE's pair kept through a network-initiated de-registration, so the
//! NOTIFY that reports it reaches the UE.
//!
//! 3GPP TS 24.229 clause 5.2.5.2: "when all public user identities of the UE
//! have been deregistered, the P-CSCF shall shorten any security associations
//! or TLS sessions towards the UE", with NOTE 2: "The security association
//! between the P-CSCF and the UE is shortened to a value that will allow the
//! NOTIFY request containing the deregistration event to reach the UE."
//!
//! When the P-CSCF de-registers a UE itself (registrar liveness gave up on
//! it) the S-CSCF answers with exactly that NOTIFY, for the UE's own reg-event
//! subscription. Deleting the pair at once sent it in clear, from a plaintext
//! listener. The pair is now kept for a grace instead, its kernel lifetime cut
//! to match, and goes as soon as a final response to a NOTIFY comes back from
//! the UE, or when the grace is over, whichever is first. Nothing waits: the
//! grace is a scheduled retirement ([`IpsecManager::retire_pair`]).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tracing::{debug, info, warn};

use super::retire::RetireCondition;
use super::IpsecManager;

/// Pairs waiting for their de-registration NOTIFY, by contact key: the UE's
/// address and its protected client and server ports.
#[derive(Default)]
pub(super) struct AwaitingNotify {
    pairs: DashMap<String, (IpAddr, u16, u16)>,
}

impl AwaitingNotify {
    pub(super) fn forget(&self, key: &str) {
        self.pairs.remove(key);
    }

    /// Whether the pair at contact key `key` is kept for the NOTIFY reporting
    /// its network de-registration.
    pub(super) fn awaits(&self, key: &str) -> bool {
        self.pairs.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.pairs.len()
    }
}

impl IpsecManager {
    /// The UE at `(ue_addr, ue_port_c)` has been de-registered by the network:
    /// keep its pair for `grace` so the NOTIFY reporting it rides the pair,
    /// then delete it, sooner once [`notify_answered`](Self::notify_answered)
    /// sees the UE answer. Returns whether there was a pair to keep.
    pub fn shorten_for_network_dereg(
        self: &Arc<Self>,
        ue_addr: IpAddr,
        ue_port_c: u16,
        grace: Duration,
    ) -> bool {
        let Some(pair) = self.get_sa(&ue_addr, ue_port_c) else {
            return false;
        };
        let key = Self::contact_key(&ue_addr, ue_port_c);
        self.network_dereg
            .pairs
            .insert(key, (ue_addr, ue_port_c, pair.ue_port_s));
        self.retire_pair(
            ue_addr,
            ue_port_c,
            grace,
            RetireCondition::Always,
            "network de-registration: the grace for its NOTIFY is over",
        );
        // The kernel's own lifetime follows, so the pair cannot outlive the
        // grace there either if the retirement were lost.
        let lifetime = grace.as_secs() + 1;
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = manager
                .update_sa_pair_lifetime(&ue_addr, ue_port_c, Some(lifetime))
                .await
            {
                warn!(ue = %ue_addr, ue_port_c, %error,
                    "IPsec: could not shorten the SA pair of a de-registered UE in the kernel");
            }
        });
        info!(
            ue = %ue_addr,
            ue_port_c,
            ue_port_s = pair.ue_port_s,
            grace = ?grace,
            "IPsec: SA pair shortened for the network de-registration's NOTIFY \
             (TS 24.229 clause 5.2.5.2)"
        );
        true
    }

    /// A final response to a NOTIFY came from `source`. When it is a UE whose
    /// pair is kept for its de-registration NOTIFY, the pair goes now: the
    /// NOTIFY's transaction is over. Returns whether one was.
    pub fn notify_answered(self: &Arc<Self>, source: SocketAddr) -> bool {
        let pairs = &self.network_dereg.pairs;
        if pairs.is_empty() {
            return false;
        }
        let found = pairs
            .iter()
            .find(|entry| {
                let (ue_addr, port_c, port_s) = *entry.value();
                ue_addr == source.ip() && (source.port() == port_c || source.port() == port_s)
            })
            .map(|entry| entry.key().clone());
        let Some((_, (ue_addr, ue_port_c, _))) = found.and_then(|key| pairs.remove(&key)) else {
            return false;
        };
        debug!(ue = %ue_addr, ue_port_c, "IPsec: the de-registered UE answered its NOTIFY");
        self.retire_pair(
            ue_addr,
            ue_port_c,
            Duration::ZERO,
            RetireCondition::Always,
            "network de-registration: its NOTIFY was answered",
        );
        true
    }
}
