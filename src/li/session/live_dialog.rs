//! Session decisions for live dialogs when a warrant starts mid-call.

use std::sync::Arc;

use super::{CallOwner, DialogMedia, Identities, LiManager, MessageFacts, SessionView};

impl LiManager {
    /// Decide, now, the session of a dialog that opened before a warrant that
    /// covers it was activated, as its dialog-forming INVITE would have been
    /// decided had the warrant been there.
    ///
    /// The identities are the INVITE's own, so the `From` is the caller and
    /// the parties are oriented as on that INVITE. `owner` is the B2BUA call
    /// the dialog is the caller leg of, and `media` what the media path holds
    /// for it (a call whose media moved to an engine call siphon minted is on
    /// that one). `answered` marks the session established, so a failure that
    /// follows is a re-INVITE's and ends nothing.
    ///
    /// Records no message, and so emits no X2: that resumes at the call's next
    /// message, which finds the decision made and carries on from it.
    pub fn decide_live_dialog(
        &self,
        dialog: &super::super::live_dialogs::LiveDialog,
        owner: Option<CallOwner>,
        media: Option<DialogMedia>,
        answered: bool,
        other_legs: &[String],
    ) -> SessionView {
        let owner_of_legs = owner.clone();
        let facts = MessageFacts {
            request: true,
            method: "INVITE",
            status_code: None,
            to_tagged: false,
            branch: None,
        };
        let identities = Identities {
            request_uri: Some(&dialog.request_uri),
            from_uri: Some(&dialog.from),
            to_uri: Some(&dialog.to),
            source_ip: dialog.source_ip,
        };
        let view = self.resolve_session_inner(
            &dialog.call_id,
            &facts,
            &identities,
            || owner,
            || media,
            true,
        );
        if view.matches.is_empty() {
            // Nothing covers it. Not remembered as unwarranted either: no
            // message follows to release that, as one does for a dialog that
            // ends in front of this node.
            self.forget_session(&view.session_id);
            return view;
        }
        if let Some(mut decision) = self.decisions.get_mut(&*view.session_id) {
            // A dialog-forming INVITE opened it, as it would have.
            decision.invite_session = true;
            decision.established |= answered;
        }
        // The call's other legs were decided too while it was set up, as
        // unwarranted when no warrant covered it. Those decisions are stale
        // now: retired here, in the step that makes the call's own, and each
        // leg resolved to the call's session, so no later message of the leg
        // finds the stale one and releases what it knew of the call.
        for leg in other_legs {
            if self.aliases.contains_key(leg.as_str()) {
                continue;
            }
            if let Some((_, stale)) = self
                .decisions
                .remove_if(leg.as_str(), |_, decision| decision.matched.is_empty())
            {
                self.release_engine_calls(leg, &stale.engine_calls);
            }
            self.alias(leg, &view.session_id);
            if owner_of_legs
                .as_ref()
                .is_some_and(|owner| owner.dialled_for_called_party(leg))
            {
                self.note_called_party_leg(&view.session_id, leg);
            }
        }
        view
    }

    /// `call_id` is a leg the session's call dialled for its called party.
    pub(super) fn note_called_party_leg(&self, session_id: &Arc<str>, call_id: &str) {
        if let Some(mut decision) = self.decisions.get_mut(&**session_id) {
            if !decision
                .called_party_legs
                .iter()
                .any(|leg| &**leg == call_id)
            {
                decision.called_party_legs.push(Arc::from(call_id));
            }
        }
    }

    /// Forget a session's decision and every leg resolved to it.
    ///
    /// For an unwarranted session, as its dialog ends: the map would otherwise
    /// grow with every call the node ever handles and rely on the cap to save
    /// it. A warranted one ends through [`note_message`](Self::note_message) and
    /// is released by [`sweep_sessions`](Self::sweep_sessions) after its grace.
    pub fn forget_session(&self, session_id: &str) {
        if let Some((_, decision)) = self.decisions.remove(session_id) {
            self.release_warranted_count(&decision);
            for leg in &decision.legs {
                self.aliases.remove(&**leg);
            }
            // The engine call's content record goes with its session. Asked
            // whatever the session matches now: a warrant deactivated since
            // may have left one.
            self.forget_x3_call_of(&decision.primary_call_id, session_id);
            for (seat, _) in &decision.seats {
                self.forget_x3_call_of(&seat.record(), session_id);
            }
            self.release_engine_calls(session_id, &decision.engine_calls);
        }
    }
}
