//! The RFC 3261 §18.1.1 size threshold, shared by every sender that may move a
//! UDP request to TCP: the dispatcher's relay and B-leg paths and the
//! registrant's REGISTER over an IMS UE's security associations.

/// RFC 3261 §18.1.1: a UDP request whose serialised length exceeds `mtu - 200`
/// bytes must be sent over a congestion-controlled transport (TCP). The 200
/// bytes is headroom for the Via siphon adds plus additions by downstream hops.
pub fn over_mtu(len: usize, mtu: u16) -> bool {
    len > mtu.saturating_sub(200) as usize
}
