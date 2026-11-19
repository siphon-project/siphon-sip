//! The dispatcher's half of [`crate::b2bua::inflight`]: registering an INVITE
//! in the dispatch loop, and running the CANCELs that were held for it.
//!
//! See that module for why. Here: the guard that ends an INVITE's registration
//! with its worker (replaying what it still holds, so a held CANCEL is always
//! answered, whether the INVITE became a call, was refused, shed, or never
//! parsed), and the step that runs the held CANCELs once the call exists.

use super::*;
use crate::b2bua::inflight::{initial_invite_key, InflightInvites};

/// A CANCEL held for an INVITE whose call does not exist yet.
pub struct HeldCancel {
    pub(super) inbound: InboundMessage,
    pub(super) message: SipMessage,
}

/// The INVITEs this dispatcher has taken in and not finished with.
pub type InflightInviteStore = InflightInvites<HeldCancel>;

/// The INVITE server transaction key a CANCEL names (RFC 3261 §9.1: the
/// INVITE's branch and sent-by).
fn cancel_target_key(message: &SipMessage) -> Option<TransactionKey> {
    let top_via = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())?;
    Some(TransactionKey::new(
        top_via.branch.clone()?,
        Method::Invite,
        TransactionKey::format_sent_by(&top_via.host, top_via.port),
    ))
}

/// Register `inbound` if it is an initial INVITE, for as long as the returned
/// guard lives. Called by the dispatch loop for every message, before the
/// message is handed to a worker; a message that is not an INVITE costs one
/// prefix comparison.
pub(super) fn register_inbound(
    inbound: &InboundMessage,
    state: &Arc<DispatcherState>,
) -> Option<InflightInviteGuard> {
    let key = initial_invite_key(&inbound.data)?;
    if !state.inflight_invites.register(key.clone()) {
        return None;
    }
    Some(InflightInviteGuard {
        key,
        state: Arc::clone(state),
    })
}

/// An INVITE's registration, ended with its worker.
pub(super) struct InflightInviteGuard {
    key: TransactionKey,
    state: Arc<DispatcherState>,
}

impl Drop for InflightInviteGuard {
    fn drop(&mut self) {
        // The entry is gone first, so a replayed CANCEL that still matches
        // nothing is answered and not held again.
        for held in self.state.inflight_invites.release(&self.key) {
            replay_cancel(held, &self.state);
        }
    }
}

/// Hold `inbound` (a CANCEL that matched no call) for its INVITE, if that INVITE
/// is registered and has no call yet. Handed back when it is not.
pub(super) fn hold_cancel(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) -> Option<(InboundMessage, SipMessage)> {
    let Some(key) = cancel_target_key(&message) else {
        return Some((inbound, message));
    };
    match state
        .inflight_invites
        .hold(&key, HeldCancel { inbound, message })
    {
        Ok(()) => {
            debug!(server_key = %key, "CANCEL for an INVITE whose call is not created yet: held until it is (RFC 3261 §9.2)");
            None
        }
        Err(held) => Some((held.inbound, held.message)),
    }
}

/// Open the handler window of the call just created for the INVITE `message`
/// and run the CANCELs that overtook it before the call existed. `None` when the
/// call is already gone: a CANCEL took it down in the moment since it was
/// created and has answered both parties, so `@b2bua.on_invite` must not run
/// for it.
///
/// The window is open when the held CANCELs run, so each takes the path of a
/// CANCEL arriving while `@b2bua.on_invite` runs: `200` to it, `487` to the
/// INVITE, `on_cancel` once the handler is done.
pub(super) fn begin_invite_window(
    message: &Mutex<SipMessage>,
    call_id: &str,
    state: &DispatcherState,
) -> Option<Arc<std::sync::atomic::AtomicBool>> {
    #[cfg(test)]
    pause::checkpoint(
        "created",
        message
            .lock()
            .ok()
            .and_then(|message| message.headers.call_id().cloned())
            .as_deref()
            .unwrap_or_default(),
    );
    let cancelled = state.call_actors.begin_invite_handler(call_id)?;
    let key = message
        .lock()
        .ok()
        .and_then(|message| cancel_target_key(&message));
    if let Some(key) = key {
        for held in state.inflight_invites.call_created(&key) {
            replay_cancel(held, state);
        }
    }
    Some(cancelled)
}

/// Run a held CANCEL through the CANCEL path as though it had just arrived.
fn replay_cancel(held: HeldCancel, state: &DispatcherState) {
    let Some(key) = cancel_target_key(&held.message) else {
        return;
    };
    handle_cancel(
        held.inbound,
        held.message,
        Some(&key.branch),
        &key.sent_by,
        state,
    );
}

/// Test synchronisation: park the worker of one INVITE at a named stage, so a
/// test can deliver the CANCEL in exactly that window.
#[cfg(test)]
pub(super) mod pause {
    use std::collections::HashMap;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::Mutex;

    type Gate = (Sender<()>, Receiver<()>);

    static GATES: Mutex<Option<HashMap<String, Gate>>> = Mutex::new(None);

    /// Arm `stage` for the INVITE with `sip_call_id`: its worker signals
    /// `reached` and then waits for `release` there. Stages: `start` (the
    /// worker has the INVITE and has done nothing with it), `create` (just
    /// before the call is created), `created` (just after, before the handler
    /// window opens).
    pub(in crate::dispatcher) fn arm(stage: &str, sip_call_id: &str) -> (Receiver<()>, Sender<()>) {
        let (reached_sender, reached) = channel();
        let (release, release_receiver) = channel();
        if let Ok(mut gates) = GATES.lock() {
            gates.get_or_insert_with(HashMap::new).insert(
                format!("{stage}:{sip_call_id}"),
                (reached_sender, release_receiver),
            );
        }
        (reached, release)
    }

    pub(in crate::dispatcher) fn checkpoint(stage: &str, sip_call_id: &str) {
        let gate = GATES.lock().ok().and_then(|mut gates| {
            gates
                .as_mut()
                .and_then(|map| map.remove(&format!("{stage}:{sip_call_id}")))
        });
        if let Some((reached, release)) = gate {
            let _ = reached.send(());
            let _ = release.recv_timeout(std::time::Duration::from_secs(10));
        }
    }

    /// [`checkpoint`] for the raw bytes of an INVITE, before anything has read
    /// its Call-ID.
    pub(in crate::dispatcher) fn checkpoint_raw(stage: &str, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw);
        let armed: Vec<String> = GATES
            .lock()
            .ok()
            .and_then(|gates| {
                gates.as_ref().map(|map| {
                    map.keys()
                        .filter_map(|key| key.strip_prefix(&format!("{stage}:")))
                        .map(str::to_string)
                        .collect()
                })
            })
            .unwrap_or_default();
        for id in armed {
            if text.contains(&format!("Call-ID: {id}")) {
                checkpoint(stage, &id);
            }
        }
    }
}
