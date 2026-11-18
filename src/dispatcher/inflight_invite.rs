//! INVITEs a worker has taken in and not yet turned into a call, and the
//! CANCELs that overtake them.
//!
//! Requests are handed to a pool of workers in the order they arrive, but a
//! worker that has taken an INVITE still has to admit it, answer `100 Trying`
//! and create the call before anything can be matched to it, while the worker
//! that took the caller's CANCEL a moment later goes straight to the lookup. A
//! caller that cancels within a few milliseconds of its INVITE (the early
//! CANCEL of RFC 3261 §9.1) therefore finds no call, is answered `481`, and the
//! INVITE then goes on to ring the callee for a call the caller has already
//! abandoned.
//!
//! RFC 3261 §9.2 matches a CANCEL to the INVITE's *server transaction*, which
//! exists from the INVITE's arrival and not from the moment siphon has built
//! its call. This is that transaction's stand-in for the time between the two:
//! an INVITE registers here as soon as it is parsed, a CANCEL that matches
//! nothing else but finds it is held, and whoever creates the call runs the
//! held CANCEL as though it had arrived then. An INVITE that ends without a
//! call (refused, rejected, passed to the proxy path) replays it when its
//! worker is done, so a held CANCEL is always answered.

use super::*;

/// How many CANCELs one INVITE holds. A caller retransmits its CANCEL on Timer
/// E, so a handful is every legitimate case; one past that is answered as if
/// the INVITE were not here (`481`) and not kept.
const HELD_CANCELS_PER_INVITE: usize = 8;

/// A CANCEL held for an INVITE whose call does not exist yet.
pub(super) struct HeldCancel {
    pub(super) inbound: InboundMessage,
    pub(super) message: SipMessage,
}

struct InflightInvite {
    /// The call exists: a CANCEL finds it by its own lookup, and holding one
    /// here would strand it.
    call_exists: bool,
    held: Vec<HeldCancel>,
}

/// INVITEs between their arrival and their call, keyed by the INVITE's server
/// transaction (top Via branch and sent-by).
#[derive(Default)]
pub struct InflightInvites {
    entries: DashMap<TransactionKey, InflightInvite>,
}

/// The INVITE server transaction key `message` is, or the one a CANCEL of it
/// names (RFC 3261 §9.1: same branch and sent-by). `None` for a message whose
/// top Via carries no branch.
pub(super) fn invite_transaction_key(message: &SipMessage) -> Option<TransactionKey> {
    let top_via = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())?;
    let branch = top_via.branch.clone()?;
    Some(TransactionKey::new(
        branch,
        Method::Invite,
        TransactionKey::format_sent_by(&top_via.host, top_via.port),
    ))
}

impl InflightInvites {
    /// Register the INVITE `message`, if it is an initial one, for as long as
    /// the returned guard lives. `None` when it is not an initial INVITE, has no
    /// branch, or is a copy of one already registered (a retransmission on
    /// another worker, which must not end the original's entry early).
    pub(super) fn begin(
        &self,
        message: &SipMessage,
        state: &Arc<DispatcherState>,
    ) -> Option<InflightInviteGuard> {
        if message.method() != Some(&Method::Invite) || to_has_tag(message) {
            return None;
        }
        let key = invite_transaction_key(message)?;
        match self.entries.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => return None,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(InflightInvite {
                    call_exists: false,
                    held: Vec::new(),
                });
            }
        }
        Some(InflightInviteGuard {
            key,
            state: Arc::clone(state),
        })
    }

    /// Hold `cancel` for the INVITE it cancels, if that INVITE is between its
    /// arrival and its call. Handed back when it is not, for the caller to
    /// answer.
    pub(super) fn hold_cancel(
        &self,
        key: &TransactionKey,
        cancel: HeldCancel,
    ) -> Result<(), Box<HeldCancel>> {
        match self.entries.get_mut(key) {
            Some(mut entry) if !entry.call_exists && entry.held.len() < HELD_CANCELS_PER_INVITE => {
                entry.held.push(cancel);
                Ok(())
            }
            _ => Err(Box::new(cancel)),
        }
    }

    /// The call of the INVITE `key` now exists: take the CANCELs held for it,
    /// and stop holding any (a later one finds the call itself).
    pub(super) fn call_created(&self, key: &TransactionKey) -> Vec<HeldCancel> {
        match self.entries.get_mut(key) {
            Some(mut entry) => {
                entry.call_exists = true;
                std::mem::take(&mut entry.held)
            }
            None => Vec::new(),
        }
    }

    /// Number of INVITEs still registered (leak-test accessor): back to zero
    /// once every INVITE's worker has finished.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// An INVITE's registration, ended with its worker.
pub(super) struct InflightInviteGuard {
    key: TransactionKey,
    state: Arc<DispatcherState>,
}

impl Drop for InflightInviteGuard {
    fn drop(&mut self) {
        let held = self
            .state
            .inflight_invites
            .entries
            .remove(&self.key)
            .map(|(_, entry)| entry.held)
            .unwrap_or_default();
        // The entry is gone first, so a replayed CANCEL that still matches
        // nothing is answered and not held again.
        for cancel in held {
            replay_cancel(cancel, &self.state);
        }
    }
}

/// The call of the INVITE `message` now exists and its handler window is open:
/// run the CANCELs that overtook it on another worker before it existed.
///
/// Run with the window open so each takes the path of a CANCEL arriving while
/// `@b2bua.on_invite` runs: `200` to it, `487` to the INVITE, `on_cancel` once
/// the handler is done.
pub(super) fn release_held_cancels(message: &Mutex<SipMessage>, state: &DispatcherState) {
    let key = message
        .lock()
        .ok()
        .and_then(|message| invite_transaction_key(&message));
    let Some(key) = key else {
        return;
    };
    for held in state.inflight_invites.call_created(&key) {
        replay_cancel(held, state);
    }
}

/// Run a held CANCEL through the CANCEL path as though it had just arrived.
pub(super) fn replay_cancel(cancel: HeldCancel, state: &DispatcherState) {
    let Some(key) = invite_transaction_key(&cancel.message) else {
        return;
    };
    debug!(
        server_key = %key,
        "running a CANCEL held for its INVITE's call (RFC 3261 §9.2)"
    );
    handle_cancel(
        cancel.inbound,
        cancel.message,
        Some(&key.branch),
        &key.sent_by,
        state,
    );
}

/// Test synchronisation: park the worker of one INVITE just before its call is
/// created, so a test can deliver the CANCEL in exactly that window.
#[cfg(test)]
pub(super) mod pause {
    use std::collections::HashMap;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::Mutex;

    type Gate = (Sender<()>, Receiver<()>);

    static GATES: Mutex<Option<HashMap<String, Gate>>> = Mutex::new(None);

    /// Arm `sip_call_id`: its INVITE's worker signals `reached` and then waits
    /// for `release` at the checkpoint.
    pub(in crate::dispatcher) fn arm(sip_call_id: &str) -> (Receiver<()>, Sender<()>) {
        let (reached_sender, reached) = channel();
        let (release, release_receiver) = channel();
        if let Ok(mut gates) = GATES.lock() {
            gates
                .get_or_insert_with(HashMap::new)
                .insert(sip_call_id.to_string(), (reached_sender, release_receiver));
        }
        (reached, release)
    }

    pub(in crate::dispatcher) fn checkpoint(sip_call_id: &str) {
        let gate = GATES
            .lock()
            .ok()
            .and_then(|mut gates| gates.as_mut().and_then(|map| map.remove(sip_call_id)));
        if let Some((reached, release)) = gate {
            let _ = reached.send(());
            let _ = release.recv_timeout(std::time::Duration::from_secs(10));
        }
    }
}
