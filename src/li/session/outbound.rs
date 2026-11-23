//! The messages siphon itself sends to a target, and which leg a target is on.
//!
//! X2 carries every SIP message to and from the target's user agent. What siphon
//! receives is intercepted as it arrives ([`LiManager::resolve_session`]); what
//! siphon generates (a local answer, a teardown, the copy a B2BUA builds for the
//! far leg) never arrives anywhere, so it is looked up here at the point it
//! leaves, against the session the leg already belongs to.
//!
//! Nothing is decided here: a Call-ID no inbound message has resolved is not a
//! warranted session, and the lookup says so. And nothing here drives the
//! session's lifecycle (`note_message`): a BYE or a 487 siphon sends does not
//! end the session, the inbound one that follows it does.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::{
    CallOwner, Identities, LiManager, MatchedParty, MessageFacts, MessageOn, PayloadDirection,
    Sender, SessionDecision, SessionMatch,
};
use crate::li::x1::store::TaskMatch;
use crate::li::x1::types::XId;

/// The warranted session a frame siphon sends belongs to, and the warrants
/// the frame goes to the target of.
#[derive(Debug, Clone)]
pub struct OutboundSession {
    /// What the session is correlated on.
    pub session_id: Arc<str>,
    /// The warrants whose target the frame is addressed to, each with
    /// [`PayloadDirection::SentToTarget`]. Empty when the frame is to the
    /// session's other party only.
    pub matches: Vec<TaskMatch>,
}

impl SessionMatch {
    /// Whether a frame siphon sends, with `sender`'s tags, is addressed to the
    /// target of this match.
    ///
    /// The recipient is the end of the dialog the sender is not. Which end that
    /// is comes from the tags, in the order they are known:
    ///
    /// - a tag the target is known to send under, as the recipient's;
    /// - the anchor tag, which an endpoint owns, as the recipient's (siphon
    ///   answers or tears down towards it) or as the sender's (siphon
    ///   speaks as that end on a proxied dialog, so the recipient is the other);
    /// - the leg a B2BUA dialled for its called party, which only that party is
    ///   on;
    /// - who the frame itself is addressed to, when the warrant names that
    ///   identity.
    ///
    /// Anything else is not known to be to the target, and is not reported as
    /// such: a frame to the session's other party is not to or from the target.
    fn is_addressed_to_target(&self, sender: &Sender<'_>, on: &MessageOn<'_>) -> bool {
        let recipient_tag = match sender.request {
            true => sender.to_tag,
            false => sender.from_tag,
        };
        if recipient_tag.is_some_and(|tag| self.target_tags.iter().any(|known| &**known == tag)) {
            return true;
        }
        if let Some(anchor_tag) = self.anchor_tag.as_deref() {
            if recipient_tag == Some(anchor_tag) {
                return self.target_owns_anchor;
            }
            if sender.tag() == Some(anchor_tag) {
                return !self.target_owns_anchor;
            }
        }
        if on.called_party_leg {
            return self.party == MatchedParty::Terminating;
        }
        on.names(self.x_id, on.recipient_identity(sender))
    }
}

impl LiManager {
    /// Whether any remembered session names a warrant. One relaxed load: the
    /// gate in front of everything the outbound tap does, so a node with no
    /// intercepted call pays nothing else per frame it sends.
    pub fn any_warranted_session(&self) -> bool {
        self.warranted_sessions.load(Ordering::Relaxed) > 0
    }

    /// Count a decision about to be inserted, when it names a warrant.
    pub(super) fn count_warranted(&self, matched: &[SessionMatch]) -> bool {
        let counted = !matched.is_empty();
        if counted {
            self.warranted_sessions.fetch_add(1, Ordering::Relaxed);
        }
        counted
    }

    /// Forget every decision, and the count that went with them.
    pub(super) fn clear_decisions(&self) {
        self.decisions.clear();
        self.warranted_sessions.store(0, Ordering::Relaxed);
    }

    /// Give back the count a removed decision held.
    pub(super) fn release_warranted_count(&self, decision: &SessionDecision) {
        if decision.counted {
            // Saturating by construction: a clear resets the count to zero
            // and removes the decisions it counted, so a removal never finds
            // more to release than was added.
            let mut held = self.warranted_sessions.load(Ordering::Relaxed);
            while held > 0 {
                match self.warranted_sessions.compare_exchange_weak(
                    held,
                    held - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => held = current,
                }
            }
        }
    }

    /// The warranted session the leg `call_id` is on, when it is on one: the
    /// cheap half of [`outbound_session`](Self::outbound_session), which needs
    /// no parsed frame. For a leg no message has resolved yet (the first frame
    /// siphon sends on a leg it dialled itself) `owner` names the B2BUA call it
    /// is a leg of, and the leg joins that call's session.
    pub fn outbound_leg(
        &self,
        call_id: &str,
        owner: impl FnOnce() -> Option<CallOwner>,
    ) -> Option<Arc<str>> {
        if let Some(session_id) = self.session_id_of(call_id) {
            return Some(session_id);
        }
        let owner = owner()?;
        let session_id = self.warranted_session_of(&owner)?;
        self.alias(call_id, &session_id);
        if owner.dialled_for_called_party(call_id) {
            self.note_called_party_leg(&session_id, call_id);
        }
        Some(session_id)
    }

    /// The warranted session the frame siphon sends on `call_id` belongs to,
    /// and the warrants it goes to the target of. `None` when `call_id` is on
    /// no warranted session.
    ///
    /// `facts` and `identities` describe the frame as `resolve_session` is
    /// given a received message. `owner` is asked as for
    /// [`outbound_leg`](Self::outbound_leg).
    pub fn outbound_session(
        &self,
        call_id: &str,
        facts: &MessageFacts<'_>,
        identities: &Identities<'_>,
        owner: impl FnOnce() -> Option<CallOwner>,
    ) -> Option<OutboundSession> {
        let session_id = self.outbound_leg(call_id, owner)?;
        self.outbound_matches(session_id, call_id, facts, identities)
    }

    /// The warrants the frame on `call_id` goes to the target of, in the
    /// session [`outbound_leg`](Self::outbound_leg) found for it.
    pub fn outbound_matches(
        &self,
        session_id: Arc<str>,
        call_id: &str,
        facts: &MessageFacts<'_>,
        identities: &Identities<'_>,
    ) -> Option<OutboundSession> {
        let sender = Sender::of(facts, identities);
        let decision = self.decisions.get(&*session_id)?;
        let on = MessageOn {
            manager: self,
            identities,
            called_party_leg: decision
                .called_party_legs
                .iter()
                .any(|leg| &**leg == call_id),
        };
        let matches: Vec<TaskMatch> = decision
            .matched
            .iter()
            .filter(|known| known.is_addressed_to_target(&sender, &on))
            .filter_map(|known| known.task_match_of_no_message(self))
            .map(|matched| TaskMatch {
                direction: PayloadDirection::SentToTarget,
                ..matched
            })
            .collect();
        drop(decision);
        Some(OutboundSession {
            session_id,
            matches,
        })
    }

    /// Whether a message received on `call_id` is on a leg the target of the
    /// warrant `x_id` is on, so that it is to or from the target.
    ///
    /// A B2BUA call has a dialog per party. What the far leg's party sends and
    /// receives is not to or from the target, and what siphon relays there is
    /// not either: the target's leg has its own messages, and those are
    /// recorded. Only what is known is excluded: the caller's leg for a warrant
    /// on the called party, the dialled leg for a warrant on the caller. A leg
    /// dialled for somebody new (a transfer target), a proxied dialog, and a
    /// session that is no B2BUA call's stay as they were.
    pub fn is_on_target_leg(&self, session_id: &str, call_id: &str, x_id: XId) -> bool {
        let Some(decision) = self.decisions.get(session_id) else {
            return true;
        };
        if !decision.bound_to_call {
            return true;
        }
        let Some(known) = decision.matched.iter().find(|known| known.x_id == x_id) else {
            return true;
        };
        if decision
            .called_party_legs
            .iter()
            .any(|leg| &**leg == call_id)
        {
            return known.party == MatchedParty::Terminating;
        }
        if &*decision.primary_call_id == call_id {
            return known.target_owns_anchor;
        }
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::target::MatchedParty;
    use crate::li::tests::{manager, provision, provision_targets};
    use crate::li::x1::types::{DeliveryType, TargetIdentifier};
    use std::time::Instant;

    const CALLER_LEG: &str = "caller-leg@example.com";
    const CALLEE_LEG: &str = "callee-leg@example.com";
    const DIALOG: &str = "proxied-dialog@example.com";

    fn facts(
        request: bool,
        method: &'static str,
        code: Option<u16>,
        tagged: bool,
    ) -> MessageFacts<'static> {
        MessageFacts {
            request,
            method,
            status_code: code,
            to_tagged: tagged,
            branch: Some("z9hG4bK-test"),
        }
    }

    fn invite() -> MessageFacts<'static> {
        facts(true, "INVITE", None, false)
    }

    fn caller_invite() -> Identities<'static> {
        Identities {
            request_uri: Some("sip:bob@example.com"),
            from_uri: Some("<sip:alice@example.com>;tag=a"),
            to_uri: Some("<sip:bob@example.com>"),
            source_ip: None,
        }
    }

    /// Siphon's answer on the caller's leg: headers of the request, its own tag.
    fn answer_on_caller_leg() -> Identities<'static> {
        Identities {
            request_uri: None,
            from_uri: Some("<sip:alice@example.com>;tag=a"),
            to_uri: Some("<sip:bob@example.com>;tag=siphon-a"),
            source_ip: None,
        }
    }

    /// Siphon's INVITE on the leg it dials for the called party.
    fn invite_on_callee_leg() -> Identities<'static> {
        Identities {
            request_uri: Some("sip:15550100042@198.51.100.77"),
            from_uri: Some("<sip:15550100001@192.0.2.1>;tag=siphon-b"),
            to_uri: Some("<sip:15550100042@198.51.100.77>"),
            source_ip: None,
        }
    }

    /// Siphon's BYE towards the caller on its leg.
    fn bye_to_caller() -> Identities<'static> {
        Identities {
            request_uri: Some("sip:alice@192.0.2.10"),
            from_uri: Some("<sip:bob@example.com>;tag=siphon-a"),
            to_uri: Some("<sip:alice@example.com>;tag=a"),
            source_ip: None,
        }
    }

    fn owner(internal_id: &str) -> CallOwner {
        CallOwner {
            internal_id: internal_id.to_string(),
            a_leg_call_id: CALLER_LEG.to_string(),
            replacement_target: false,
        }
    }

    fn warranted_call(manager: &LiManager, identities: &Identities<'_>) -> String {
        let opening = manager.resolve_session(CALLER_LEG, &invite(), identities, || None);
        assert_eq!(opening.matches.len(), 1);
        manager
            .reserved_session_id(CALLER_LEG)
            .expect("a warranted INVITE reserves the call's id")
    }

    fn bob() -> Vec<TargetIdentifier> {
        vec![TargetIdentifier::SipUri("sip:bob@example.com".to_string())]
    }

    #[test]
    fn an_answer_siphon_sends_to_a_calling_target_is_to_the_target() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        warranted_call(&manager, &caller_invite());

        let sent = manager
            .outbound_session(
                CALLER_LEG,
                &facts(false, "INVITE", Some(200), true),
                &answer_on_caller_leg(),
                || panic!("a resolved leg must not need its call"),
            )
            .expect("the leg is on a warranted session");
        assert_eq!(sent.matches.len(), 1);
        assert_eq!(sent.matches[0].direction, PayloadDirection::SentToTarget);
    }

    #[test]
    fn a_100_trying_has_no_to_tag_and_is_still_to_the_calling_target() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        warranted_call(&manager, &caller_invite());
        let trying = Identities {
            to_uri: Some("<sip:bob@example.com>"),
            ..answer_on_caller_leg()
        };
        let sent = manager
            .outbound_session(
                CALLER_LEG,
                &facts(false, "INVITE", Some(100), false),
                &trying,
                || None,
            )
            .expect("warranted");
        assert_eq!(sent.matches.len(), 1);
    }

    #[test]
    fn what_siphon_sends_to_the_far_leg_is_not_to_a_calling_target() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager, &caller_invite());

        let sent = manager
            .outbound_session(CALLEE_LEG, &invite(), &invite_on_callee_leg(), || {
                Some(owner(&internal_id))
            })
            .expect("the dialled leg joins the warranted session");
        assert!(sent.matches.is_empty(), "the far leg is not the target's");
    }

    #[test]
    fn what_siphon_sends_to_the_dialled_leg_is_to_a_called_target() {
        let (manager, _iri, _audit) = manager();
        provision_targets(&manager, DeliveryType::X2Only, None, bob());
        let internal_id = warranted_call(&manager, &caller_invite());

        let sent = manager
            .outbound_session(CALLEE_LEG, &invite(), &invite_on_callee_leg(), || {
                Some(owner(&internal_id))
            })
            .expect("warranted");
        assert_eq!(sent.matches.len(), 1);
        assert_eq!(sent.matches[0].party, MatchedParty::Terminating);
        assert_eq!(sent.matches[0].direction, PayloadDirection::SentToTarget);
        let ack = manager
            .outbound_session(
                CALLEE_LEG,
                &facts(true, "ACK", None, true),
                &invite_on_callee_leg(),
                || panic!("an aliased leg must not need its call"),
            )
            .expect("warranted");
        assert_eq!(ack.matches.len(), 1);
    }

    #[test]
    fn what_siphon_sends_to_the_caller_is_not_to_a_called_target() {
        let (manager, _iri, _audit) = manager();
        provision_targets(&manager, DeliveryType::X2Only, None, bob());
        warranted_call(&manager, &caller_invite());

        let teardown = manager
            .outbound_session(
                CALLER_LEG,
                &facts(true, "BYE", None, true),
                &bye_to_caller(),
                || None,
            )
            .expect("warranted");
        assert!(teardown.matches.is_empty());
        let answer = manager
            .outbound_session(
                CALLER_LEG,
                &facts(false, "INVITE", Some(180), true),
                &answer_on_caller_leg(),
                || None,
            )
            .expect("warranted");
        assert!(answer.matches.is_empty());
    }

    #[test]
    fn a_leg_no_message_resolved_and_no_call_owns_is_no_session() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        assert!(manager
            .outbound_session("stranger@example.com", &invite(), &caller_invite(), || None)
            .is_none());
    }

    #[test]
    fn an_unwarranted_call_has_no_outbound_matches() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let nobody = Identities {
            request_uri: Some("sip:carol@example.com"),
            from_uri: Some("<sip:dave@example.com>;tag=d"),
            to_uri: Some("<sip:carol@example.com>"),
            source_ip: None,
        };
        manager.resolve_session(DIALOG, &invite(), &nobody, || None);
        let reply = Identities {
            to_uri: Some("<sip:carol@example.com>;tag=s"),
            ..nobody
        };
        let sent = manager
            .outbound_session(
                DIALOG,
                &facts(false, "INVITE", Some(200), true),
                &reply,
                || None,
            )
            .expect("a decided session");
        assert!(sent.matches.is_empty());
    }

    #[test]
    fn on_a_proxied_dialog_a_local_reply_is_to_the_caller_only() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        manager.resolve_session(DIALOG, &invite(), &caller_invite(), || None);
        let to_caller = manager
            .outbound_session(
                DIALOG,
                &facts(false, "INVITE", Some(487), true),
                &answer_on_caller_leg(),
                || None,
            )
            .expect("warranted");
        assert_eq!(to_caller.matches.len(), 1, "alice is the caller");

        let (manager, _iri, _audit) = crate::li::tests::manager();
        provision_targets(&manager, DeliveryType::X2Only, None, bob());
        manager.resolve_session(DIALOG, &invite(), &caller_invite(), || None);
        let to_caller = manager
            .outbound_session(
                DIALOG,
                &facts(false, "INVITE", Some(100), false),
                &answer_on_caller_leg(),
                || None,
            )
            .expect("warranted");
        assert!(
            to_caller.matches.is_empty(),
            "bob is the callee, the caller is not the target"
        );
    }

    #[test]
    fn the_target_leg_decides_which_inbound_messages_are_recorded() {
        let (manager, _iri, _audit) = manager();
        let calling = provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager, &caller_invite());
        manager.outbound_session(CALLEE_LEG, &invite(), &invite_on_callee_leg(), || {
            Some(owner(&internal_id))
        });
        assert!(manager.is_on_target_leg(&internal_id, CALLER_LEG, calling));
        assert!(!manager.is_on_target_leg(&internal_id, CALLEE_LEG, calling));
        assert!(manager.is_on_target_leg(&internal_id, "other-leg", calling));
    }

    #[test]
    fn a_proxied_session_has_one_dialog_and_all_of_it_is_the_targets() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);
        manager.resolve_session(DIALOG, &invite(), &caller_invite(), || None);
        assert!(manager.is_on_target_leg(DIALOG, DIALOG, x_id));
    }

    #[test]
    fn the_warranted_session_count_follows_the_sessions() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        assert!(!manager.any_warranted_session());
        let nobody = Identities {
            request_uri: Some("sip:carol@example.com"),
            from_uri: Some("<sip:dave@example.com>;tag=d"),
            to_uri: Some("<sip:carol@example.com>"),
            source_ip: None,
        };
        for index in 0..100 {
            let completed = format!("completed-{index}@example.com");
            let failed = format!("failed-{index}@example.com");
            let first = manager.resolve_session(&completed, &invite(), &caller_invite(), || None);
            manager.note_message(&first, &invite());
            manager.note_message(&first, &facts(true, "BYE", None, true));
            let second = manager.resolve_session(&failed, &invite(), &caller_invite(), || None);
            manager.note_message(&second, &facts(false, "INVITE", Some(486), true));
            manager.resolve_session(
                &format!("none-{index}@example.com"),
                &invite(),
                &nobody,
                || None,
            );
        }
        assert!(manager.any_warranted_session());
        assert_eq!(manager.warranted_sessions.load(Ordering::Relaxed), 200);
        manager.sweep_sessions(Instant::now() + super::super::SESSION_GRACE, |_| false);
        // Only the unwarranted ones, which nothing ends here, remain.
        assert_eq!(manager.remembered_session_count(), 100);
        assert!(!manager.any_warranted_session());
        assert_eq!(manager.warranted_sessions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_forgotten_session_releases_its_count_once() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let view = manager.resolve_session(DIALOG, &invite(), &caller_invite(), || None);
        assert_eq!(manager.warranted_sessions.load(Ordering::Relaxed), 1);
        manager.forget_session(&view.session_id);
        manager.forget_session(&view.session_id);
        assert_eq!(manager.warranted_sessions.load(Ordering::Relaxed), 0);
    }
}
