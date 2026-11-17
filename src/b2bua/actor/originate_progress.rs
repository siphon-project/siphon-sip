//! What a call siphon placed keeps of its provisional responses: who is told
//! of them, and what a reliable one settled of the session before the 2xx.
//! Its accessors live with the other by-leg ones on the call store.

/// The provisional-response state of a call siphon placed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginateProgress {
    /// True for a call placed through the in-process `b2bua.originate()`
    /// surface: its provisional responses run `@b2bua.on_originate_progress`.
    /// False for a call the control plane placed, whose progress is reported
    /// as channel events.
    pub script_originated: bool,
    /// The early dialog (its To-tag) whose offer, made in a reliable
    /// provisional to an offerless INVITE, siphon's PRACK answered, and that
    /// answer (RFC 3262 §5). The 2xx of that dialog is then ACKed without one.
    /// `None` until a PRACK answers an offer. Claimed with an empty answer
    /// while the engine is asked, so one early dialog holds the call's media.
    pub prack_answer: Option<(String, String)>,
    /// The early dialogs whose reliable provisional answered the offer in
    /// siphon's INVITE, each with that answer's SDP: its 2xx need not repeat
    /// it (RFC 3261 §13.2.1). One per early dialog (a downstream fork opens
    /// several), empty until a reliable provisional answers.
    pub callee_answers: Vec<(String, Vec<u8>)>,
}

impl OriginateProgress {
    /// Forget what the reliable provisionals of an INVITE settled, when that
    /// INVITE ends without an answer and another replaces it. Returns whether
    /// a PRACK had answered an offer, which the media engine still holds.
    pub fn forget_session(&mut self) -> bool {
        self.callee_answers.clear();
        self.prack_answer.take().is_some()
    }

    /// Keep `answer` as the one early dialog `to_tag` gave, over an earlier
    /// one of the same dialog.
    pub fn keep_callee_answer(&mut self, to_tag: &str, answer: Vec<u8>) {
        self.callee_answers.retain(|(tag, _)| tag != to_tag);
        self.callee_answers.push((to_tag.to_string(), answer));
    }

    /// The answer early dialog `to_tag` gave in a reliable provisional.
    pub fn callee_answer(&self, to_tag: &str) -> Option<&[u8]> {
        self.callee_answers
            .iter()
            .find(|(tag, _)| tag == to_tag)
            .map(|(_, answer)| answer.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_starts_as_nobodys_and_with_nothing_answered() {
        let progress = OriginateProgress::default();
        assert!(!progress.script_originated);
        assert_eq!(progress.prack_answer, None);
        assert!(progress.callee_answers.is_empty());
    }

    #[test]
    fn each_early_dialog_keeps_its_own_answer() {
        let mut progress = OriginateProgress::default();
        progress.keep_callee_answer("first", b"one".to_vec());
        progress.keep_callee_answer("second", b"two".to_vec());
        progress.keep_callee_answer("first", b"one again".to_vec());
        assert_eq!(progress.callee_answer("first"), Some(&b"one again"[..]));
        assert_eq!(progress.callee_answer("second"), Some(&b"two"[..]));
        assert_eq!(progress.callee_answer("third"), None);
        assert_eq!(progress.callee_answers.len(), 2);
    }

    #[test]
    fn forgetting_the_session_keeps_who_placed_the_call() {
        let mut progress = OriginateProgress {
            script_originated: true,
            prack_answer: Some(("tag".to_string(), "v=0".to_string())),
            callee_answers: vec![("tag".to_string(), b"v=0".to_vec())],
        };
        assert!(progress.forget_session(), "an answered offer holds media");
        assert!(progress.script_originated);
        assert_eq!(progress.prack_answer, None);
        assert!(progress.callee_answers.is_empty());
        assert!(!progress.forget_session());
    }
}
