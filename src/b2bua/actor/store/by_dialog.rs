//! Finding a call by the dialog a SIP message names.
//!
//! A SIP Call-ID is unique to a call until an INVITE this node dialled is
//! routed back to it (RFC 3261 §16.3, a spiral) and served as a new call. The
//! Call-ID is then the callee dialog of the call that dialled it and the
//! caller dialog of the call that received it. Everything arriving on it is
//! for one of the two, and the tags say which.

use super::*;

fn from_tag_of(message: &SipMessage) -> Option<String> {
    message
        .typed_from()
        .ok()
        .flatten()
        .and_then(|from| from.tag)
}

impl CallActorStore {
    /// Drop the mappings of `sip_call_id` to calls that are no longer in the
    /// store, before a new one is added.
    ///
    /// A call taken apart for a `Replaces` adoption leaves its mapping behind
    /// on purpose (`detach_a_leg_for_adoption`). The registration that follows
    /// replaces it; kept beside the new one, it would be what the Call-ID
    /// resolves to.
    pub(super) fn forget_ended_owners(&self, sip_call_id: &str) {
        for owner in self.registry.lookup_call_ids(sip_call_id) {
            if !self.calls.contains_key(&owner) {
                self.registry.remove_call_id(sip_call_id, &owner);
            }
        }
    }

    /// Look up the call a dialog belongs to: its SIP Call-ID, the tag siphon
    /// put on it and the peer's tag (RFC 3261 §12: "A dialog is identified at
    /// each UA with a dialog ID, which consists of a Call-ID value, a local
    /// tag and a remote tag").
    ///
    /// The Call-ID alone is enough while one call has it, which is nearly
    /// always, and the tags are then not looked at: a request with a tag the
    /// call does not know is still that call's to answer. They decide when an
    /// INVITE this node dialled was routed back to it and taken as a new call
    /// (RFC 3261 §16.3, a spiral). The two calls then share the Call-ID and
    /// the same two tags, mirrored: the tag that is local to the dialog one
    /// call dialled is the remote tag of the dialog the other answers. A
    /// request names the dialog it is for by the tag in its To, which is the
    /// local tag of exactly one of them.
    ///
    /// With no local tag to go by (a CANCEL, which copies the To of the INVITE
    /// it cancels), the peer's tag picks the caller dialog it opened. Failing
    /// both, the answer is that of [`Self::find_by_sip_call_id`].
    ///
    /// Reads the candidate calls, so never call it with a call held.
    pub fn find_by_dialog(
        &self,
        sip_call_id: &str,
        local_tag: Option<&str>,
        remote_tag: Option<&str>,
    ) -> Option<String> {
        let mut candidates = self.registry.lookup_call_ids(sip_call_id);
        if candidates.len() < 2 {
            return candidates.pop();
        }
        let matching = |matches: &dyn Fn(&CallActor) -> bool| {
            candidates
                .iter()
                .find(|id| {
                    self.calls
                        .get(id.as_str())
                        .is_some_and(|call| matches(&call))
                })
                .cloned()
        };
        local_tag
            .and_then(|local_tag| {
                matching(&|call| {
                    std::iter::once(&call.a_leg)
                        .chain(call.b_legs.iter())
                        // Not the pseudo-leg that tracks a request relayed
                        // across the call: it is filed under the identifiers
                        // of the request, the sender's tag among them.
                        .filter(|leg| !leg.is_tracking_leg())
                        .any(|leg| {
                            leg.dialog.call_id == sip_call_id && leg.dialog.local_tag == local_tag
                        })
                })
            })
            .or_else(|| {
                let remote_tag = remote_tag?;
                matching(&|call| call.is_caller_dialog(sip_call_id, remote_tag))
            })
            .or_else(|| candidates.first().cloned())
    }

    /// The call a SIP message belongs to, by its Call-ID and tags.
    ///
    /// For a request siphon received, and for a response siphon sends to one,
    /// which carries the same From and To: the To tag is siphon's and the From
    /// tag the peer's. See [`Self::find_by_dialog`], and
    /// [`Self::find_by_own_request`] for the other direction.
    pub fn find_by_message(&self, message: &SipMessage) -> Option<String> {
        let sip_call_id = message.headers.call_id()?;
        let to_tag = extract_to_tag(message);
        let from_tag = from_tag_of(message);
        self.find_by_dialog(sip_call_id, to_tag.as_deref(), from_tag.as_deref())
    }

    /// The call a request siphon sent belongs to, read off the request or a
    /// response to it: there the From tag is siphon's and the To tag the peer's.
    pub fn find_by_own_request(&self, message: &SipMessage) -> Option<String> {
        let sip_call_id = message.headers.call_id()?;
        let to_tag = extract_to_tag(message);
        let from_tag = from_tag_of(message);
        self.find_by_dialog(sip_call_id, from_tag.as_deref(), to_tag.as_deref())
    }

    /// The call whose caller sent an INVITE with this Call-ID and From tag and
    /// no To tag: the call a retransmission of that INVITE, or a copy of it
    /// that arrived over another path, belongs to.
    ///
    /// RFC 3261 §17.2.3 matches a request to a server transaction by its top
    /// Via branch, and the Call-ID is no part of that. An INVITE whose Call-ID
    /// this node knows only as a dialog it dialled itself is a new request
    /// that was routed back here, not a copy of one it received, so it matches
    /// no call here and is served as a new one.
    pub fn find_by_caller_dialog(&self, sip_call_id: &str, from_tag: &str) -> Option<String> {
        self.registry
            .lookup_call_ids(sip_call_id)
            .into_iter()
            .find(|id| {
                self.calls
                    .get(id.as_str())
                    .is_some_and(|call| call.is_caller_dialog(sip_call_id, from_tag))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ConnectionId, Transport};
    use std::net::SocketAddr;

    const DIALLED: &str = "b2b-dialled@192.0.2.1";

    fn transport() -> TransportInfo {
        TransportInfo {
            remote_addr: "192.0.2.50:5060"
                .parse::<SocketAddr>()
                .expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        }
    }

    fn caller_leg(sip_call_id: &str, from_tag: &str, branch: &str) -> Leg {
        Leg::new_a_leg(
            sip_call_id.to_string(),
            from_tag.to_string(),
            branch.to_string(),
            transport(),
        )
    }

    /// A call that dialled [`DIALLED`] with the From tag `dialler-tag`, and the
    /// call that received that INVITE back and answers it. Returns
    /// `(store, first, second, the second call's To tag)`.
    fn spiral() -> (CallActorStore, String, String, String) {
        let store = CallActorStore::new();
        let first = store.create_call(caller_leg(
            "first@192.0.2.10",
            "caller-tag",
            "z9hG4bK-caller",
        ));
        assert!(store.add_b_leg(
            &first,
            Leg::new_b_leg(
                DIALLED.to_string(),
                "dialler-tag".to_string(),
                "sip:next@192.0.2.50".to_string(),
                "z9hG4bK-dialled".to_string(),
                transport(),
            ),
        ));
        let second = store.create_call(caller_leg(DIALLED, "dialler-tag", "z9hG4bK-proxy"));
        let answering_tag = store
            .get_call(&second)
            .map(|call| call.a_leg.dialog.local_tag.clone())
            .expect("the second call exists");
        (store, first, second, answering_tag)
    }

    /// One call has the Call-ID: it is the answer whatever the tags say, as it
    /// was before two calls could share one.
    #[test]
    fn a_call_id_only_one_call_has_resolves_without_its_tags() {
        let store = CallActorStore::new();
        let call = store.create_call(caller_leg("only@192.0.2.10", "caller-tag", "z9hG4bK-1"));
        assert_eq!(
            store.find_by_dialog("only@192.0.2.10", Some("not-a-tag-of-it"), Some("nor-this")),
            Some(call.clone())
        );
        assert_eq!(
            store.find_by_dialog("only@192.0.2.10", None, None),
            Some(call)
        );
        assert_eq!(store.find_by_dialog("unknown@192.0.2.10", None, None), None);
    }

    /// RFC 3261 §12: the dialog is the Call-ID with a local and a remote tag.
    /// The To tag of a request is the local tag of the dialog it is for: the
    /// second call's on a request the first call sent, the first call's on one
    /// the second sent.
    #[test]
    fn a_shared_call_id_resolves_by_the_local_tag() {
        let (store, first, second, answering_tag) = spiral();
        assert_eq!(
            store.find_by_dialog(DIALLED, Some(&answering_tag), Some("dialler-tag")),
            Some(second.clone())
        );
        assert_eq!(
            store.find_by_dialog(DIALLED, Some("dialler-tag"), Some(&answering_tag)),
            Some(first)
        );
        // Named by the Call-ID alone, it is the call that answers it.
        assert_eq!(store.find_by_sip_call_id(DIALLED), Some(second));
    }

    /// A CANCEL has no To tag. Its From tag is the remote tag of the caller's
    /// dialog of the call that received the INVITE it cancels.
    #[test]
    fn a_shared_call_id_without_a_local_tag_resolves_to_the_caller_dialog() {
        let (store, _, second, _) = spiral();
        assert_eq!(
            store.find_by_dialog(DIALLED, None, Some("dialler-tag")),
            Some(second)
        );
    }

    /// RFC 3261 §17.2.3: the INVITE a call dialled is not a retransmission of
    /// one it received. Only the call whose caller sent it owns it.
    #[test]
    fn an_invite_is_owned_by_the_call_whose_caller_sent_it() {
        let store = CallActorStore::new();
        let first = store.create_call(caller_leg(
            "first@192.0.2.10",
            "caller-tag",
            "z9hG4bK-caller",
        ));
        assert!(store.add_b_leg(
            &first,
            Leg::new_b_leg(
                DIALLED.to_string(),
                "dialler-tag".to_string(),
                "sip:next@192.0.2.50".to_string(),
                "z9hG4bK-dialled".to_string(),
                transport(),
            ),
        ));
        assert_eq!(
            store.find_by_caller_dialog("first@192.0.2.10", "caller-tag"),
            Some(first.clone())
        );
        assert_eq!(store.find_by_caller_dialog(DIALLED, "dialler-tag"), None);
        assert_eq!(
            store.find_by_caller_dialog("first@192.0.2.10", "another-caller"),
            None
        );

        let second = store.create_call(caller_leg(DIALLED, "dialler-tag", "z9hG4bK-proxy"));
        assert_eq!(
            store.find_by_caller_dialog(DIALLED, "dialler-tag"),
            Some(second)
        );
    }

    /// Once the call that dialled the shared Call-ID has ended, a request the
    /// other one sent toward it has no dialog to arrive on. The Call-ID still
    /// resolves, to the sender, which does not take its own request for one
    /// from its caller: the handler answers 481.
    #[test]
    fn a_calls_own_request_is_not_taken_for_its_peers() {
        let (store, first, second, answering_tag) = spiral();
        store.remove_call(&first);
        assert_eq!(
            store.find_by_dialog(DIALLED, Some("dialler-tag"), Some(&answering_tag)),
            Some(second.clone())
        );
        let call = store.get_call(&second).expect("the second call exists");
        assert_eq!(call.request_direction(DIALLED, Some(&answering_tag)), None);
        assert_eq!(
            call.request_direction(DIALLED, Some("dialler-tag")),
            Some(LegSide::A)
        );
    }

    /// Each call takes only its own mapping with it: the other still resolves,
    /// in either order, and the Call-ID is free once both are gone.
    #[test]
    fn a_call_that_ends_leaves_the_other_calls_mapping() {
        let (store, first, second, _) = spiral();
        store.remove_call(&first);
        assert_eq!(store.find_by_sip_call_id(DIALLED), Some(second.clone()));
        store.remove_call(&second);
        assert_eq!(store.find_by_sip_call_id(DIALLED), None);

        let (store, first, second, _) = spiral();
        store.remove_call(&second);
        assert_eq!(store.find_by_sip_call_id(DIALLED), Some(first.clone()));
        store.remove_call(&first);
        assert_eq!(store.find_by_sip_call_id(DIALLED), None);
    }
}
