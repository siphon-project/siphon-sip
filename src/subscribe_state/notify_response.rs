//! What the end of a NOTIFY transaction does to the subscription it was sent
//! in, for a subscription this node is the notifier of (RFC 6665 §4.2.2).

use std::sync::Arc;

use tokio::sync::oneshot;
use tracing::info;

use super::{SubscribeDialog, SubscribeStore};
use crate::uac::UacResult;

impl SubscribeStore {
    /// The NOTIFY sent in dialog `id` ended: `Some(status)` is its final
    /// response, `None` means none came before Timer F.  `generation` is the
    /// dialog's when the NOTIFY was built.
    ///
    /// RFC 6665 §4.2.2: a NOTIFY that times out, or is answered 404, 405, 410,
    /// 416, 480-485, 489, 501 or 604, removes the subscription; a 408 counts
    /// as the timeout (RFC 5057 §5.1).  [`crate::presence::notify_failure`]
    /// holds that list.  Any other response leaves the subscription as it is.
    ///
    /// A SUBSCRIBE refresh that landed while the NOTIFY was out proves the
    /// subscriber still holds the dialog, so the failure of the older NOTIFY
    /// leaves the refreshed subscription alone.  Returns whether the
    /// subscription was removed.
    pub fn notify_ended(&self, id: &str, generation: u64, outcome: Option<u16>) -> bool {
        if outcome.is_some_and(|status| (200..300).contains(&status)) {
            return false;
        }
        crate::metrics::subscribe_notify::record_failure(outcome);
        let Some(failure) = crate::presence::notify_failure(outcome) else {
            return false;
        };
        let Some((_, dialog)) = self.dialogs.remove_if(id, |_, dialog| {
            !dialog.is_outbound && dialog.generation == generation
        }) else {
            return false;
        };
        self.delete_cached(id);
        info!(
            id,
            call_id = %dialog.call_id,
            event = %dialog.event,
            status = ?outcome,
            reason = failure.label(),
            "subscribe_state: NOTIFY failed, subscription removed (RFC 6665 §4.2.2)"
        );
        true
    }
}

/// Wait for the end of the NOTIFY transaction `answered` reports, sent in
/// `dialog`, and apply it to the subscription.
///
/// Pure Rust on a tokio worker: nothing here attaches to Python, and the
/// script's `await handle.notify()` does not wait for it.  It ends when the
/// transaction does, on its final response or when the UAC sweep expires it
/// at Timer F, so it holds nothing past the transaction.
pub fn watch_notify(
    store: Arc<SubscribeStore>,
    dialog: &SubscribeDialog,
    answered: oneshot::Receiver<UacResult>,
) -> tokio::task::JoinHandle<()> {
    let id = dialog.id.clone();
    let generation = dialog.generation;
    tokio::spawn(async move {
        let outcome = match answered.await {
            Ok(UacResult::Response(response)) => response.status_code(),
            Ok(UacResult::Timeout) => None,
            // The UAC went away with the transaction still open, which is
            // this node shutting down and says nothing about the subscriber.
            Err(_) => return,
        };
        store.notify_ended(&id, generation, outcome);
    })
}
