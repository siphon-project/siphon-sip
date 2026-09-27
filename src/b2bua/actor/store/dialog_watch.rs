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

    /// End every watch whose binding `binding_live` no longer knows — the phone
    /// de-registered, its binding expired, or registrar liveness reaped it —
    /// and publish the reports. The call itself is left alone: it ends on its
    /// own teardown, session timer or duration cap.
    pub fn end_dialogs_without_binding(&self, binding_live: &dyn Fn(&str, &str) -> bool) {
        // Candidates under read locks first; a write lock only on a call that has
        // a watch to end.
        let candidates: Vec<String> = self
            .calls
            .iter()
            .filter(|entry| {
                entry.dialog_watches.iter().any(|watch| {
                    watch.state != DialogState::Terminated
                        && watch
                            .contact
                            .as_deref()
                            .is_some_and(|contact| !binding_live(&watch.aor, contact))
                })
            })
            .map(|entry| entry.key().clone())
            .collect();
        let mut reports = Vec::new();
        for call_id in candidates {
            let Some(mut call) = self.calls.get_mut(&call_id) else {
                continue;
            };
            for watch in &mut call.dialog_watches {
                let gone = watch
                    .contact
                    .as_deref()
                    .is_some_and(|contact| !binding_live(&watch.aor, contact));
                if gone && watch.advance(DialogState::Terminated, None) {
                    reports.push(watch.clone());
                }
            }
        }
        publish_dialog_states(reports);
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
