//! The answer a native handler returns.

use crate::diameter::codec::{Avp, DiameterMsg};
use crate::diameter::dictionary::avp;
use crate::diameter::forward;

/// An answer to an inbound request: the same message `request.answer()`
/// gives a script, with the same rules for setting AVPs on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAnswer {
    message: DiameterMsg,
    /// The (code, vendor) of the AVPs copied from the request and not
    /// touched since. Setting one replaces the copy.
    copied_from_request: Vec<(u32, u32)>,
}

impl NativeAnswer {
    /// An answer a handler fills in, `copied` naming the AVPs it took from
    /// the request ([`forward::build_handler_answer`]).
    pub(super) fn for_handler(message: DiameterMsg, copied: Vec<(u32, u32)>) -> Self {
        Self {
            message,
            copied_from_request: copied,
        }
    }

    /// Wrap a complete answer: one received from a backend, or built by
    /// hand. It must carry the Hop-by-Hop and End-to-End Identifiers of the
    /// request it answers.
    pub fn from_message(message: DiameterMsg) -> Self {
        Self {
            message,
            copied_from_request: Vec::new(),
        }
    }

    /// The answer as a message tree.
    pub fn message(&self) -> &DiameterMsg {
        &self.message
    }

    /// The answer as a message tree, to change in place.
    pub fn message_mut(&mut self) -> &mut DiameterMsg {
        &mut self.message
    }

    pub fn into_message(self) -> DiameterMsg {
        self.message
    }

    /// The Result-Code, None when the answer carries an Experimental-Result
    /// instead.
    pub fn result_code(&self) -> Option<u32> {
        self.message.answer_result_codes().0
    }

    /// The Experimental-Result-Code inside Experimental-Result (RFC 6733
    /// section 7.6).
    pub fn experimental_result_code(&self) -> Option<u32> {
        self.message.answer_result_codes().1
    }

    /// Whether the header E bit is set.
    pub fn is_error(&self) -> bool {
        self.message.is_error()
    }

    /// The first top-level AVP with `code` and `vendor`.
    pub fn avp(&self, code: u32, vendor: u32) -> Option<&Avp> {
        self.message.find(code, vendor)
    }

    /// Put `avp` in the answer in place of every AVP of its code and vendor.
    pub fn set_avp(&mut self, mut avp: Avp) -> &mut Self {
        forward::answer_avp_flags(&mut avp);
        self.take_copied(avp.code, avp.vendor);
        self.message.remove(avp.code, avp.vendor);
        self.message.avps.push(avp);
        self
    }

    /// Append `avp`, keeping the ones already there with its code and
    /// vendor: once per occurrence for an AVP the answer carries more than
    /// once. The first insert of an AVP that was copied from the request
    /// (Vendor-Specific-Application-Id, Auth-Session-State) replaces that
    /// copy.
    pub fn insert_avp(&mut self, avp: Avp) -> &mut Self {
        if self.take_copied(avp.code, avp.vendor) {
            self.message.remove(avp.code, avp.vendor);
        }
        self.message.avps.push(avp);
        self
    }

    /// [`set_avp`](Self::set_avp), by value.
    pub fn with_avp(mut self, avp: Avp) -> Self {
        self.set_avp(avp);
        self
    }

    /// Remove every top-level AVP with `code` and `vendor`; returns how many.
    pub fn remove_avp(&mut self, code: u32, vendor: u32) -> usize {
        self.take_copied(code, vendor);
        self.message.remove(code, vendor)
    }

    /// Carry Experimental-Result { Vendor-Id, Experimental-Result-Code } in
    /// the place of the Result-Code (RFC 6733 section 7.6): an answer has one
    /// or the other.
    pub fn set_experimental_result(&mut self, vendor_id: u32, code: u32) -> &mut Self {
        let group = Avp::grouped(
            avp::EXPERIMENTAL_RESULT,
            0,
            vec![
                Avp::u32(avp::VENDOR_ID, 0, vendor_id),
                Avp::u32(avp::EXPERIMENTAL_RESULT_CODE, 0, code),
            ],
        );
        self.message.remove(avp::EXPERIMENTAL_RESULT, 0);
        let position = self
            .message
            .avps
            .iter()
            .position(|existing| existing.code == avp::RESULT_CODE && existing.vendor == 0);
        match position {
            Some(position) => self.message.avps[position] = group,
            None => self.message.avps.push(group),
        }
        self.message.remove(avp::RESULT_CODE, 0);
        self
    }

    /// The answer on the wire.
    pub fn to_wire(&self) -> Vec<u8> {
        self.message.to_wire()
    }

    /// Forget that `(code, vendor)` was copied from the request, because the
    /// handler is now setting it. Returns whether it was.
    fn take_copied(&mut self, code: u32, vendor: u32) -> bool {
        let before = self.copied_from_request.len();
        self.copied_from_request
            .retain(|entry| *entry != (code, vendor));
        self.copied_from_request.len() != before
    }
}
