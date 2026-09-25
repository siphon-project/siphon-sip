//! The RFC 4235 dialog state of registered AoRs, as siphon observed it.
//!
//! A controller serving the `dialog` event package (busy-lamp field) needs to
//! know, per registered phone, whether it is ringing, talking or idle. A B2BUA
//! is a party to every dialog it carries, so it can answer that from the wire
//! alone: the INVITE it received from the phone or sent to it, the responses on
//! that leg, and the teardown. Each such leg gets a [`DialogWatch`], created
//! when siphon can tell which registered AoR the leg belongs to, advanced as the
//! leg's responses arrive, and ended on every path that ends the leg. A state
//! only ever moves forward (`trying` → `proceeding` → `early` → `confirmed` →
//! `terminated`, RFC 4235 §3.7.1), and `terminated` is reported exactly once.
//!
//! Everything a report carries is from the AoR's point of view, as dialog-info
//! renders it: `local_tag` is the phone's own tag, `remote_tag` the other end's
//! (siphon's, on this leg), `remote_identity` the party the phone is talking to
//! as siphon presented it on this leg.

use super::*;

/// The application-level event class a controller subscribes to.
pub const DIALOG_EVENT_CLASS: &str = "dialog";

/// The event name every report goes out under.
pub const DIALOG_STATE_EVENT: &str = "DialogStateChanged";

/// RFC 4235 §3.7.1 dialog states, in the only order a dialog moves through
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DialogState {
    /// The INVITE was sent or received and nothing has answered it.
    Trying,
    /// A provisional without a To-tag answered it.
    Proceeding,
    /// A provisional with a To-tag answered it: an early dialog (ringing).
    Early,
    /// A 2xx answered it: the dialog is established.
    Confirmed,
    /// The dialog, or the attempt to set it up, is over.
    Terminated,
}

impl DialogState {
    /// The dialog-info `<state>` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trying => "trying",
            Self::Proceeding => "proceeding",
            Self::Early => "early",
            Self::Confirmed => "confirmed",
            Self::Terminated => "terminated",
        }
    }

    /// The state a provisional response moves an INVITE's dialog to: early
    /// when it carries a To-tag (RFC 3261 §12.1), proceeding when it does not.
    pub fn of_provisional(has_to_tag: bool) -> Self {
        if has_to_tag {
            Self::Early
        } else {
            Self::Proceeding
        }
    }
}

/// Which end of the dialog the AoR is (RFC 4235 §4.1.1 `direction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogDirection {
    /// The AoR sent the INVITE: a call the phone placed.
    Initiator,
    /// The AoR received the INVITE: a call ringing the phone.
    Recipient,
}

impl DialogDirection {
    /// The dialog-info `direction` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Recipient => "recipient",
        }
    }
}

/// One leg of a call that belongs to a registered AoR, and the state it has
/// been reported in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogWatch {
    /// The leg's [`LegId`]: stable for the dialog's life (a 401/407 or 422
    /// retry of the leg keeps it) and unique, so it serves as the dialog-info
    /// `id`. For a branch of a controller's `dial` it is the `leg_id` the
    /// branch's `DialBranch` event named.
    pub leg_id: String,
    /// The registered AoR the leg belongs to.
    pub aor: String,
    pub direction: DialogDirection,
    /// The SIP Call-ID of the phone's own dialog: the one on this leg.
    pub call_id: String,
    /// The phone's tag, once known: its From-tag when it placed the call, its
    /// To-tag once it answered one siphon placed with a tagged response.
    pub local_tag: Option<String>,
    /// The other end's tag, once known: siphon's To-tag on a call the phone
    /// placed, from siphon's first tagged response; siphon's From-tag on a call
    /// siphon placed to the phone.
    pub remote_tag: Option<String>,
    /// The party the phone is talking to, as presented on this leg.
    pub remote_uri: String,
    /// That party's display name, when the header carried one.
    pub remote_display_name: Option<String>,
    /// The state last reported.
    pub state: DialogState,
    /// The Contact of the registrar binding that tied this leg to `aor`: the
    /// binding that vouched for a call the phone placed, or the one a call to
    /// the phone was sent to. When it is gone the phone is no longer reachable
    /// through siphon and the dialog is reported ended. `None` when no single
    /// binding applies. Never reported.
    pub contact: Option<String>,
}

impl DialogWatch {
    /// The `DialogStateChanged` payload for the state this watch is in.
    pub fn payload(&self) -> serde_json::Value {
        serde_json::json!({
            "aor": self.aor,
            "state": self.state.as_str(),
            "direction": self.direction.as_str(),
            "leg_id": self.leg_id,
            "call_id": self.call_id,
            "local_tag": self.local_tag,
            "remote_tag": self.remote_tag,
            "remote_identity": {
                "uri": self.remote_uri,
                "display_name": self.remote_display_name,
            },
        })
    }

    /// Move to `state` if it is ahead of the state reported, learning the tag
    /// the observation carried. Returns whether the state moved, so a report
    /// goes out once per step and never for a step backwards: a provisional
    /// reordered behind its 2xx, or a straggler after the teardown.
    pub fn advance(&mut self, state: DialogState, observed_tag: Option<&str>) -> bool {
        if state <= self.state {
            return false;
        }
        if let Some(tag) = observed_tag.filter(|tag| !tag.is_empty()) {
            // The tag an observation carries is the far side of siphon's own
            // leg: on a call siphon placed that is the phone's To-tag, on one the
            // phone placed it is siphon's To-tag, i.e. the phone's remote tag.
            let slot = match self.direction {
                DialogDirection::Recipient => &mut self.local_tag,
                DialogDirection::Initiator => &mut self.remote_tag,
            };
            if slot.is_none() {
                *slot = Some(tag.to_string());
            }
        }
        self.state = state;
        true
    }
}

/// Publish each report to the apps that subscribed to `dialog` events.
pub fn publish_dialog_states(reports: Vec<DialogWatch>) {
    for report in reports {
        crate::control::notify_app_event(DIALOG_EVENT_CLASS, DIALOG_STATE_EVENT, report.payload());
    }
}

impl CallActor {
    /// Start watching a leg of this call, returning the report of the state it
    /// starts in. `None` when the leg is already watched: a leg belongs to one
    /// AoR for its whole life.
    pub fn watch_dialog(&mut self, watch: DialogWatch) -> Option<DialogWatch> {
        if self
            .dialog_watches
            .iter()
            .any(|existing| existing.leg_id == watch.leg_id)
        {
            return None;
        }
        self.dialog_watches.push(watch.clone());
        Some(watch)
    }

    /// Move the watched leg `leg_id` to `state`, returning the report when it
    /// moved. See [`DialogWatch::advance`].
    pub fn advance_dialog(
        &mut self,
        leg_id: &str,
        state: DialogState,
        observed_tag: Option<&str>,
    ) -> Option<DialogWatch> {
        let watch = self
            .dialog_watches
            .iter_mut()
            .find(|watch| watch.leg_id == leg_id)?;
        watch.advance(state, observed_tag).then(|| watch.clone())
    }

    /// [`Self::advance_dialog`] for the B-leg whose INVITE rides Via
    /// `via_branch`, which is what a response matches on.
    pub fn advance_dialog_by_via(
        &mut self,
        via_branch: &str,
        state: DialogState,
        observed_tag: Option<&str>,
    ) -> Option<DialogWatch> {
        if self.dialog_watches.is_empty() {
            return None;
        }
        let leg_id = self.find_b_leg_by_branch(via_branch)?.1.id.0.clone();
        self.advance_dialog(&leg_id, state, observed_tag)
    }

    /// Record a response siphon sent the caller for its INVITE, and move the
    /// caller's watch with it: a provisional carrying siphon's To-tag makes the
    /// caller's dialog early, a 2xx confirms it. A final failure is left to the
    /// teardown that follows it (or, for a controller's `dial`, to the caller
    /// staying unanswered, which it does).
    pub fn note_caller_response(
        &mut self,
        status_code: u16,
        has_to_tag: bool,
    ) -> Option<DialogWatch> {
        let state = match status_code {
            101..=199 if has_to_tag => DialogState::Early,
            200..=299 => DialogState::Confirmed,
            _ => return None,
        };
        if state > self.caller_dialog_state {
            self.caller_dialog_state = state;
        }
        let leg_id = self.a_leg.id.0.clone();
        let tag = self.a_leg.dialog.local_tag.clone();
        self.advance_dialog(&leg_id, state, Some(&tag))
    }

    /// End every watch whose leg has left this call — a CANCELled or removed
    /// branch, a transfer's referrer, a dialog `Replaces` took over — returning
    /// the reports. Run after anything that takes legs off the call, so no
    /// watch outlives its leg in `early` or `confirmed`.
    pub fn end_orphaned_dialogs(&mut self) -> Vec<DialogWatch> {
        if self.dialog_watches.is_empty() {
            return Vec::new();
        }
        let a_leg_id = self.a_leg.id.0.clone();
        let live: Vec<String> = self.b_legs.iter().map(|leg| leg.id.0.clone()).collect();
        self.dialog_watches
            .iter_mut()
            .filter(|watch| watch.leg_id != a_leg_id && !live.contains(&watch.leg_id))
            .filter_map(|watch| {
                watch
                    .advance(DialogState::Terminated, None)
                    .then(|| watch.clone())
            })
            .collect()
    }

    /// End every watch on this call, returning the reports: the call is over.
    pub fn end_all_dialogs(&mut self) -> Vec<DialogWatch> {
        self.dialog_watches
            .iter_mut()
            .filter_map(|watch| {
                watch
                    .advance(DialogState::Terminated, None)
                    .then(|| watch.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ConnectionId;

    fn transport(address: &str) -> TransportInfo {
        TransportInfo {
            remote_addr: address.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: crate::transport::Transport::Udp,
            local_addr: None,
        }
    }

    fn call() -> CallActor {
        CallActor::new(Leg::new_a_leg(
            "a-leg@192.0.2.21".to_string(),
            "phone-tag".to_string(),
            "z9hG4bK-a".to_string(),
            transport("192.0.2.21:5060"),
        ))
    }

    fn b_leg(via_branch: &str) -> Leg {
        Leg::new_b_leg(
            format!("{via_branch}@siphon"),
            format!("siphon-{via_branch}"),
            "sip:202@198.51.100.22".to_string(),
            via_branch.to_string(),
            transport("198.51.100.22:5060"),
        )
    }

    fn recipient(leg: &Leg) -> DialogWatch {
        DialogWatch {
            leg_id: leg.id.0.clone(),
            aor: "sip:202@example.com".to_string(),
            direction: DialogDirection::Recipient,
            call_id: leg.dialog.call_id.clone(),
            local_tag: None,
            remote_tag: Some(leg.dialog.local_tag.clone()),
            remote_uri: "sip:201@example.com".to_string(),
            remote_display_name: Some("Front Desk".to_string()),
            state: DialogState::Trying,
            contact: None,
        }
    }

    fn states(reports: &[DialogWatch]) -> Vec<&'static str> {
        reports.iter().map(|report| report.state.as_str()).collect()
    }

    #[test]
    fn states_only_move_forward_and_terminate_once() {
        let mut call = call();
        let leg = b_leg("z9hG4bK-b1");
        call.add_b_leg(leg.clone());
        let mut reports = vec![call.watch_dialog(recipient(&leg)).expect("watched")];
        reports.extend(call.advance_dialog_by_via("z9hG4bK-b1", DialogState::Proceeding, None));
        reports.extend(call.advance_dialog_by_via(
            "z9hG4bK-b1",
            DialogState::Early,
            Some("phone-to-tag"),
        ));
        // A 180 retransmission and a 100 reordered behind it move nothing.
        reports.extend(call.advance_dialog_by_via("z9hG4bK-b1", DialogState::Early, None));
        reports.extend(call.advance_dialog_by_via("z9hG4bK-b1", DialogState::Proceeding, None));
        reports.extend(call.advance_dialog_by_via("z9hG4bK-b1", DialogState::Confirmed, None));
        reports.extend(call.end_all_dialogs());
        reports.extend(call.end_all_dialogs());
        reports.extend(call.advance_dialog_by_via("z9hG4bK-b1", DialogState::Confirmed, None));
        assert_eq!(
            states(&reports),
            ["trying", "proceeding", "early", "confirmed", "terminated"]
        );
        let last = reports.last().expect("a report");
        assert_eq!(last.local_tag.as_deref(), Some("phone-to-tag"));
        assert_eq!(last.remote_tag.as_deref(), Some("siphon-z9hG4bK-b1"));
    }

    #[test]
    fn a_leg_is_watched_once() {
        let mut call = call();
        let leg = b_leg("z9hG4bK-b1");
        call.add_b_leg(leg.clone());
        assert!(call.watch_dialog(recipient(&leg)).is_some());
        assert!(call.watch_dialog(recipient(&leg)).is_none());
        assert_eq!(call.dialog_watches.len(), 1);
    }

    #[test]
    fn nothing_moves_without_a_watch() {
        let mut call = call();
        call.add_b_leg(b_leg("z9hG4bK-b1"));
        assert!(call
            .advance_dialog_by_via("z9hG4bK-b1", DialogState::Early, Some("t"))
            .is_none());
        assert!(call.end_all_dialogs().is_empty());
        assert!(call.end_orphaned_dialogs().is_empty());
    }

    #[test]
    fn the_callers_responses_move_its_watch_and_are_remembered() {
        let mut call = call();
        // Recorded with no watch yet: a watch that starts later starts here.
        assert!(call.note_caller_response(183, true).is_none());
        assert_eq!(call.caller_dialog_state, DialogState::Early);

        let watch = DialogWatch {
            leg_id: call.a_leg.id.0.clone(),
            aor: "sip:201@example.com".to_string(),
            direction: DialogDirection::Initiator,
            call_id: call.a_leg.dialog.call_id.clone(),
            local_tag: Some("phone-tag".to_string()),
            remote_tag: None,
            remote_uri: "sip:15550100077@example.com".to_string(),
            remote_display_name: None,
            state: DialogState::Trying,
            contact: None,
        };
        assert!(call.watch_dialog(watch).is_some());
        // A 100 and an untagged 180 do not make the caller's dialog early.
        assert!(call.note_caller_response(100, false).is_none());
        assert!(call.note_caller_response(180, false).is_none());
        let early = call.note_caller_response(180, true).expect("early");
        assert_eq!(early.state, DialogState::Early);
        assert_eq!(
            early.remote_tag.as_deref(),
            Some(call.a_leg.dialog.local_tag.as_str()),
            "the phone's remote tag is siphon's To-tag"
        );
        assert_eq!(early.local_tag.as_deref(), Some("phone-tag"));
        let confirmed = call.note_caller_response(200, true).expect("confirmed");
        assert_eq!(confirmed.state, DialogState::Confirmed);
        assert_eq!(call.caller_dialog_state, DialogState::Confirmed);
        // A failure after an answer is not the caller's teardown.
        assert!(call.note_caller_response(487, true).is_none());
    }

    #[test]
    fn a_leg_leaving_the_call_ends_its_watch_and_only_its() {
        let mut call = call();
        let staying = b_leg("z9hG4bK-b1");
        let leaving = b_leg("z9hG4bK-b2");
        call.add_b_leg(staying.clone());
        call.add_b_leg(leaving.clone());
        let _ = call.watch_dialog(recipient(&staying));
        let _ = call.watch_dialog(recipient(&leaving));
        assert!(call.remove_b_leg(1).is_some());
        let ended = call.end_orphaned_dialogs();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].leg_id, leaving.id.0);
        assert_eq!(ended[0].state, DialogState::Terminated);
        assert!(call.end_orphaned_dialogs().is_empty());
        assert_eq!(states(&call.end_all_dialogs()), ["terminated"]);
    }

    #[test]
    fn the_payload_is_dialog_info_shaped() {
        let leg = b_leg("z9hG4bK-b1");
        let mut watch = recipient(&leg);
        assert!(watch.advance(DialogState::Early, Some("phone-to-tag")));
        assert_eq!(
            watch.payload(),
            serde_json::json!({
                "aor": "sip:202@example.com",
                "state": "early",
                "direction": "recipient",
                "leg_id": leg.id.0,
                "call_id": "z9hG4bK-b1@siphon",
                "local_tag": "phone-to-tag",
                "remote_tag": "siphon-z9hG4bK-b1",
                "remote_identity": {
                    "uri": "sip:201@example.com",
                    "display_name": "Front Desk",
                },
            })
        );
    }

    #[test]
    fn tokens_are_the_rfc_4235_ones() {
        assert_eq!(DialogState::Trying.as_str(), "trying");
        assert_eq!(DialogState::Proceeding.as_str(), "proceeding");
        assert_eq!(DialogState::Early.as_str(), "early");
        assert_eq!(DialogState::Confirmed.as_str(), "confirmed");
        assert_eq!(DialogState::Terminated.as_str(), "terminated");
        assert_eq!(DialogDirection::Initiator.as_str(), "initiator");
        assert_eq!(DialogDirection::Recipient.as_str(), "recipient");
        assert_eq!(DialogState::of_provisional(true), DialogState::Early);
        assert_eq!(DialogState::of_provisional(false), DialogState::Proceeding);
    }
}
