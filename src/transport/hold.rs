//! Holds that keep a connection open while a transaction is pending on it.
//!
//! How long a connection lives is this implementation's choice (RFC 3261 §18),
//! and the outbound pool closes one that has been silent for its idle timeout.
//! Silence is not the same as nothing pending, though: an INVITE whose callee
//! is still ringing has said all it will say until the final response, and
//! that response is owed on the connection the request left on (§18.2.2).
//! Closing the connection under it leaves the answer with nowhere to go.
//!
//! A client transaction therefore takes a [`ConnectionHold`] on the connection
//! its request went out on and keeps it for as long as it lives. The pool asks
//! [`ConnectionHolds::is_held`] when its idle timer fires and lets a held
//! connection be. The hold is released by dropping it, so it ends with the
//! transaction whatever ends that: a final response, a timer, a removal.
//!
//! A hold suspends the idle timer and nothing else. A held connection still
//! goes the moment the peer closes it or a read or write fails.

use std::sync::Arc;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::transport::ConnectionId;

/// The number of pending transactions per connection, for the connections
/// that have any.
#[derive(Debug, Clone, Default)]
pub struct ConnectionHolds {
    counts: Arc<DashMap<ConnectionId, usize>>,
}

impl ConnectionHolds {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep `connection_id` from being closed for idleness until the returned
    /// hold is dropped. Holds on one connection add up: it is free to idle out
    /// again once the last of them is gone.
    pub fn hold(&self, connection_id: ConnectionId) -> ConnectionHold {
        *self.counts.entry(connection_id).or_insert(0) += 1;
        ConnectionHold {
            counts: Arc::clone(&self.counts),
            connection_id,
        }
    }

    /// Whether anything still holds `connection_id`.
    pub fn is_held(&self, connection_id: ConnectionId) -> bool {
        self.counts.contains_key(&connection_id)
    }

    /// Connections with at least one hold, for the drains-to-baseline tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.counts.len()
    }
}

/// One pending transaction's claim on a connection. Dropping it releases the
/// claim.
#[derive(Debug)]
pub struct ConnectionHold {
    counts: Arc<DashMap<ConnectionId, usize>>,
    connection_id: ConnectionId,
}

impl ConnectionHold {
    /// The connection this hold keeps open.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }
}

impl Drop for ConnectionHold {
    fn drop(&mut self) {
        if let Entry::Occupied(mut entry) = self.counts.entry(self.connection_id) {
            let remaining = entry.get().saturating_sub(1);
            if remaining == 0 {
                entry.remove();
            } else {
                *entry.get_mut() = remaining;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_is_held_until_its_last_hold_is_dropped() {
        let holds = ConnectionHolds::new();
        let connection = ConnectionId(7);
        assert!(!holds.is_held(connection));

        let first = holds.hold(connection);
        let second = holds.hold(connection);
        assert_eq!(first.connection_id(), connection);
        assert!(holds.is_held(connection));

        drop(first);
        assert!(
            holds.is_held(connection),
            "one of two transactions ending released the connection"
        );
        drop(second);
        assert!(!holds.is_held(connection));
    }

    #[test]
    fn a_hold_names_one_connection() {
        let holds = ConnectionHolds::new();
        let _hold = holds.hold(ConnectionId(7));
        assert!(!holds.is_held(ConnectionId(8)));
    }

    #[test]
    fn the_hold_table_drains_to_its_starting_len() {
        let holds = ConnectionHolds::new();
        let baseline = holds.len();
        let taken: Vec<ConnectionHold> = (0..500)
            .map(|index| holds.hold(ConnectionId(index % 50)))
            .collect();
        assert_eq!(holds.len(), baseline + 50);
        drop(taken);
        assert_eq!(holds.len(), baseline);
    }
}
