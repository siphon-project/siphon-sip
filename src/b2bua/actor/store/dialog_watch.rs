//! The call store's half of RFC 4235 dialog-state reporting: every change is
//! made under the call's lock and published after it is released.

use super::*;

impl CallActorStore {
    /// Start watching a leg of `call_id` and report the state it starts in.
    /// Nothing happens when the call is gone or the leg is already watched.
    pub fn watch_dialog(&self, call_id: &str, watch: DialogWatch) {
        let report = self
            .calls
            .get_mut(call_id)
            .and_then(|mut call| call.watch_dialog(watch));
        publish_dialog_states(report.into_iter().collect());
    }

    /// Move the watched leg `leg_id` of `call_id` to `state`.
    pub fn advance_dialog(
        &self,
        call_id: &str,
        leg_id: &str,
        state: DialogState,
        observed_tag: Option<&str>,
    ) {
        let report = self
            .calls
            .get_mut(call_id)
            .and_then(|mut call| call.advance_dialog(leg_id, state, observed_tag));
        publish_dialog_states(report.into_iter().collect());
    }

    /// Move the watched B-leg whose INVITE rides Via `via_branch` to `state`.
    pub fn advance_dialog_by_via(
        &self,
        call_id: &str,
        via_branch: &str,
        state: DialogState,
        observed_tag: Option<&str>,
    ) {
        let report = self
            .calls
            .get_mut(call_id)
            .and_then(|mut call| call.advance_dialog_by_via(via_branch, state, observed_tag));
        publish_dialog_states(report.into_iter().collect());
    }

    /// End the watches of `legs`, which siphon CANCELled or otherwise gave up
    /// on while the call goes on.
    pub fn end_dialogs_of_legs(&self, call_id: &str, legs: &[Leg]) {
        let reports: Vec<DialogWatch> = match self.calls.get_mut(call_id) {
            Some(mut call) if !call.dialog_watches.is_empty() => legs
                .iter()
                .filter_map(|leg| call.advance_dialog(&leg.id.0, DialogState::Terminated, None))
                .collect(),
            _ => Vec::new(),
        };
        publish_dialog_states(reports);
    }

    /// Record a response siphon sent the caller of `call_id`. See
    /// [`CallActor::note_caller_response`].
    pub fn note_caller_response(&self, call_id: &str, status_code: u16, has_to_tag: bool) {
        let report = self
            .calls
            .get_mut(call_id)
            .and_then(|mut call| call.note_caller_response(status_code, has_to_tag));
        publish_dialog_states(report.into_iter().collect());
    }

    /// The watches of `call_id`, for a test to read the state it is in.
    #[cfg(test)]
    pub fn dialog_watches(&self, call_id: &str) -> Vec<DialogWatch> {
        self.calls
            .get(call_id)
            .map(|call| call.dialog_watches.clone())
            .unwrap_or_default()
    }
}
