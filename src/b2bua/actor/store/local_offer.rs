//! The engine's offer held on a call until the caller's ACK answers it.

use super::*;

impl CallActorStore {
    /// Hold the engine's offer a 2xx carried for a caller that sent none, until
    /// its ACK answers it.
    pub fn set_pending_local_offer(&self, call_id: &str, pending: PendingLocalOffer) {
        if let Some(mut call) = self.get_call_mut(call_id) {
            call.pending_local_offer = Some(pending);
        }
    }

    /// Claim the offer awaiting the caller's answer, once: a retransmitted ACK
    /// finds it claimed and completes nothing again. The offer stays on the call
    /// until [`Self::finish_pending_local_offer`], so a verb that arrives while
    /// the answer is with the engine still waits for it.
    pub fn claim_pending_local_offer(&self, call_id: &str) -> Option<PendingLocalOffer> {
        let mut call = self.get_call_mut(call_id)?;
        let pending = call.pending_local_offer.as_mut()?;
        if pending.claimed {
            return None;
        }
        pending.claimed = true;
        Some(pending.clone())
    }

    /// The answer has been applied or refused: drop the offer, which wakes
    /// everything waiting on it.
    pub fn finish_pending_local_offer(&self, call_id: &str) {
        if let Some(mut call) = self.get_call_mut(call_id) {
            call.pending_local_offer = None;
        }
    }

    /// Something to wait on while the call's offer has no answer yet, or `None`
    /// when it has none pending. Resolves (`changed()` is an error) once the
    /// offer is finished or the call is gone.
    pub fn pending_local_offer_wait(
        &self,
        call_id: &str,
    ) -> Option<tokio::sync::watch::Receiver<()>> {
        self.get_call(call_id)?
            .pending_local_offer
            .as_ref()
            .map(|pending| pending.completion.subscribe())
    }

    /// How many calls hold an offer still waiting for its answer.
    pub fn pending_local_offer_count(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| call.pending_local_offer.is_some())
            .count()
    }
}
