//! The protected ports of UEs whose security association pair is gone.
//!
//! A pair is deleted while traffic toward the UE can still be on its way: an
//! in-dialog request routed by a Contact or a Record-Route that names the UE's
//! protected server port, a NOTIFY for the UE's own reg-event subscription
//! after a network-initiated de-registration. Without the pair the P-CSCF has
//! no outbound policy for those ports, so the request would leave in clear,
//! from a plaintext listener, to a port the UE only ever reads over the
//! security association (3GPP TS 33.203 clause 7.1). Each deleted pair's UE
//! ports are remembered here, until the registration it carried would have
//! ended, and a request to one of them while no pair covers it is refused at
//! egress ([`IpsecManager::refuses_unprotected_send`]).
//!
//! Bounded ([`MAX_DELETED_FLOWS`]) and pruned by the periodic sweep
//! ([`IpsecManager::prune_orphaned_flows`]), so it drains.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, warn};

use super::retire::SA_RETIRE_GRACE;
use super::{IpsecManager, SaRole, SecurityAssociationPair};
use crate::transport::OutboundMessage;

/// At most this many UE ports are remembered; past it a deleted pair's ports
/// are not, which only loses the refusal for that pair.
pub(super) const MAX_DELETED_FLOWS: usize = 65_536;

/// Remembered at least this long, past the pair's own expiry.
const LONGEST_BAR: Duration = Duration::from_secs(24 * 60 * 60);

/// A UE port whose pair is gone.
#[derive(Clone, Debug)]
pub(super) struct DeletedFlow {
    until: Instant,
    /// The private identity the pair was set up for, when known.
    impi: Option<String>,
    ue_port_c: u16,
    ue_port_s: u16,
}

/// UE ports of deleted pairs, by `(UE address, port)`.
#[derive(Default)]
pub(super) struct DeletedFlows {
    ports: DashMap<SocketAddr, DeletedFlow>,
}

impl DeletedFlows {
    pub(super) fn len(&self) -> usize {
        self.ports.len()
    }

    pub(super) fn prune(&self, now: Instant) {
        self.ports.retain(|_, flow| flow.until > now);
    }
}

impl IpsecManager {
    /// Remember the UE ports of `sa`, a P-CSCF pair just deleted, until its
    /// registration would have ended.
    pub(super) fn bar_deleted_pair(&self, sa: &SecurityAssociationPair) {
        if sa.role != SaRole::PCscf {
            return;
        }
        let now = Instant::now();
        let until = sa
            .expires_at
            .max(now + SA_RETIRE_GRACE)
            .min(now + LONGEST_BAR);
        let ports = &self.deleted_flows.ports;
        if ports.len() >= MAX_DELETED_FLOWS {
            self.deleted_flows.prune(now);
            if ports.len() >= MAX_DELETED_FLOWS {
                debug!(ue = %sa.ue_addr, "IPsec: too many deleted pairs remembered; this one is not");
                return;
            }
        }
        let flow = DeletedFlow {
            until,
            impi: sa.impi.clone(),
            ue_port_c: sa.ue_port_c,
            ue_port_s: sa.ue_port_s,
        };
        for port in [sa.ue_port_c, sa.ue_port_s] {
            ports.insert(SocketAddr::new(sa.ue_addr, port), flow.clone());
        }
    }

    /// Whether `message` is a request to a UE port of a deleted pair that no
    /// live pair covers. Logged at WARN and counted when it is.
    pub(super) fn refuses_send_to_deleted_flow(&self, message: &OutboundMessage) -> bool {
        let ports = &self.deleted_flows.ports;
        if ports.is_empty() {
            return false;
        }
        let destination = message.destination;
        let Some(flow) = ports.get(&destination).map(|flow| flow.clone()) else {
            return false;
        };
        if flow.until <= Instant::now()
            || self
                .find_sa_by_ue(&destination.ip(), destination.port())
                .is_some()
        {
            ports.remove(&destination);
            return false;
        }
        if message
            .frames()
            .all(|frame| crate::transport::response_route::is_response(frame))
        {
            return false;
        }
        warn!(
            %destination,
            impi = flow.impi.as_deref().unwrap_or("-"),
            ue = %destination.ip(),
            ue_port_c = flow.ue_port_c,
            ue_port_s = flow.ue_port_s,
            transport = message.transport.as_scheme(),
            "IPsec: refusing to send a request in clear to a UE protected port whose security \
             association pair is gone (TS 33.203 clause 7.1)"
        );
        crate::metrics::ipsec::record_unprotected_send_refused();
        true
    }

    /// How many UE ports of deleted pairs are remembered.
    pub fn deleted_flow_count(&self) -> usize {
        self.deleted_flows.len()
    }
}
