//! Messages to a UE held while a pending pair of its is taken into use.
//!
//! The 2xx to a REGISTER that came over a pending pair goes over that pair
//! (TS 24.229 clause 5.2.2.2, TS 33.203 clause 7.4.2a SM12), so it must not
//! leave before the kernel policy update that takes the pair into use. Waiting
//! for the update on the thread that answers the REGISTER (an executor worker,
//! a tokio worker) blocked that thread on a netlink round trip run on the
//! blocking pool, and a thread blocked like that while attached to Python
//! holds up every free-threaded stop-the-world, which is how the whole
//! process wedged. Instead the update runs on its own task, and what is sent
//! to the UE in the meantime waits here, in order, at the one point every
//! outbound message passes through ([`crate::transport::OutboundRouter`]),
//! to be sent once the update is over.
//!
//! Keyed by the UE's address, not the full socket: the egress rewrite moves a
//! response between the UE's protected ports ([`super::egress`]), and holding
//! everything for that UE for the length of one policy update keeps it all in
//! order whichever port it goes to.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::transport::OutboundMessage;

/// A UE whose sends are held: how many switches hold them, and what has been
/// held, in send order.
#[derive(Default)]
struct Held {
    holders: usize,
    messages: Vec<OutboundMessage>,
}

static HELD: LazyLock<DashMap<IpAddr, Held>> = LazyLock::new(DashMap::new);

/// How many UEs are held, so a send with none held costs one atomic load.
static HOLDING: AtomicUsize = AtomicUsize::new(0);

/// Hold every message to `ue` until this switch and any other holding them
/// have each called [`unhold`], and [`release`] has handed out what was held.
pub(crate) fn hold(ue: IpAddr) {
    let mut held = HELD.entry(ue).or_insert_with(|| {
        HOLDING.fetch_add(1, Ordering::AcqRel);
        Held::default()
    });
    held.holders += 1;
}

/// This switch is over; the last one over sends what was held ([`release`]).
pub(crate) fn unhold(ue: IpAddr) {
    if let Some(mut held) = HELD.get_mut(&ue) {
        held.holders = held.holders.saturating_sub(1);
    }
}

/// `message`, to send now, or `None` when it was held for its UE.
pub(crate) fn hold_or_pass(message: OutboundMessage) -> Option<OutboundMessage> {
    if HOLDING.load(Ordering::Acquire) == 0 {
        return Some(message);
    }
    match HELD.get_mut(&message.destination.ip()) {
        Some(mut held) => {
            held.messages.push(message);
            None
        }
        None => Some(message),
    }
}

/// The next batch held for `ue`, oldest first, to send in that order; `None`
/// once nothing is left, when `ue` is no longer held unless another switch
/// still holds it (whose own release then sends what follows). Called until
/// `None`, so what is held while a batch goes out follows it rather than
/// overtaking it. The batch is taken under the map's lock and sent once that
/// is let go: a send comes back through [`hold_or_pass`], which takes the same
/// lock.
pub(crate) fn release(ue: IpAddr) -> Option<Vec<OutboundMessage>> {
    match HELD.entry(ue) {
        Entry::Occupied(mut held) if !held.get().messages.is_empty() => {
            Some(std::mem::take(&mut held.get_mut().messages))
        }
        Entry::Occupied(held) if held.get().holders == 0 => {
            held.remove();
            HOLDING.fetch_sub(1, Ordering::AcqRel);
            None
        }
        _ => None,
    }
}

/// Whether sends to `ue` are held.
#[cfg(test)]
pub(crate) fn is_held(ue: IpAddr) -> bool {
    HELD.contains_key(&ue)
}
