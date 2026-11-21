//! Attaching X3 content delivery when a call is offered.
//!
//! An engine that lists `x3_attach_at_offer` in `node_info.features` accepts
//! `attach_x3` on a call that is offered but not answered yet, and puts the
//! taps on at the first answer. It lists the feature only when it is
//! provisioned to deliver X3 at all, so the one name answers both questions.
//! What the connected engine listed is kept per connection.
//!
//! Also here: the observer a controller registers to be told of each engine
//! call siphon creates (an `offer`, the moment such an attach is made) and of
//! each one it ends (a `delete`, or an `offer` replacing a call), which is the
//! one way a call's content delivery ends that is not a fault.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use siphon_rtp_proto::{CmdResult, Command};

use super::per_call::scoped_key;
use super::scope::CallScope;
use super::{result_kind, SiphonRtpClient, SiphonRtpClientSet};
use crate::rtpengine::error::RtpEngineError;

/// What an engine that takes `attach_x3` on an offered, unanswered call
/// lists in `node_info.features`.
const X3_AT_OFFER_FEATURE: &str = "x3_attach_at_offer";

const NOT_ASKED: u8 = 0;
const NOT_LISTED: u8 = 1;
const LISTED: u8 = 2;

/// Whether the connected engine listed [`X3_AT_OFFER_FEATURE`], or nothing
/// yet.
///
/// Per connection: an engine upgraded or provisioned in place answers on a
/// new connection, so the value is dropped when one is established and
/// learned again.
#[derive(Debug, Default)]
pub(super) struct X3AtOffer(AtomicU8);

impl X3AtOffer {
    /// Keep what a `node_info` answer's `features` say.
    pub(super) fn record(&self, features: &[String]) {
        let listed = features
            .iter()
            .any(|feature| feature == X3_AT_OFFER_FEATURE);
        self.0
            .store(if listed { LISTED } else { NOT_LISTED }, Ordering::Release);
    }

    /// A connection was established: whatever the last one's engine said no
    /// longer holds.
    pub(super) fn forget(&self) {
        self.0.store(NOT_ASKED, Ordering::Release);
    }

    /// Whether the engine listed the feature; `None` while it has not been
    /// asked on this connection.
    pub(super) fn listed(&self) -> Option<bool> {
        match self.0.load(Ordering::Acquire) {
            NOT_ASKED => None,
            state => Some(state == LISTED),
        }
    }
}

/// What siphon is doing to an engine call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineCallChange {
    /// siphon is about to end the engine call under this id, if there is one:
    /// a `delete`, or an `offer`, which replaces a call already there. Told
    /// before the frame is written, so before the engine can answer or report
    /// anything of the call ending.
    Ending,
    /// An `offer` has just created the engine call.
    Offered,
}

/// One engine call siphon is ending or has just created.
#[derive(Debug, Clone, Copy)]
pub struct EngineCall<'a> {
    /// The call-id the engine knows the call by.
    pub call_id: &'a str,
    /// The offerer's tag; empty on a `delete` of a whole call by id.
    pub from_tag: &'a str,
    /// The per-call scope the leg is anchored under; `None` for the node's.
    pub scope: Option<&'a CallScope>,
    pub change: EngineCallChange,
}

/// What is told of every engine call siphon creates or ends. It runs inside
/// the verb, so it must not wait on anything: it spawns what takes time.
pub type EngineCallObserver = Box<dyn Fn(&EngineCall<'_>) + Send + Sync>;

/// The one observer of a set's engine calls.
#[derive(Default)]
pub(super) struct CallWatch(OnceLock<EngineCallObserver>);

impl CallWatch {
    /// Register `observer`. The first registered stays.
    pub(super) fn set(&self, observer: EngineCallObserver) {
        let _ = self.0.set(observer);
    }

    /// Tell the observer, if there is one, of `change` to the leg of
    /// `call_id` under `scope`.
    pub(super) fn notify(
        &self,
        change: EngineCallChange,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
    ) {
        if let Some(observer) = self.0.get() {
            observer(&EngineCall {
                call_id,
                from_tag,
                scope,
                change,
            });
        }
    }
}

impl SiphonRtpClient {
    /// Whether this instance's engine accepts `attach_x3` on a call that is
    /// offered but not answered (`x3_attach_at_offer`); `None` while it has
    /// not been asked on this connection.
    pub fn x3_attach_at_offer(&self) -> Option<bool> {
        self.x3_at_offer.listed()
    }

    /// [`Self::x3_attach_at_offer`], asking the engine when it has not been
    /// asked yet. One `node_info` per connection.
    pub async fn learn_x3_attach_at_offer(&self) -> Result<bool, RtpEngineError> {
        if let Some(listed) = self.x3_attach_at_offer() {
            return Ok(listed);
        }
        // `request_in` records the features of every `node_info` it sees.
        match self.request_in(None, Command::NodeInfo).await? {
            CmdResult::NodeInfo { node } => Ok(node
                .features
                .iter()
                .any(|feature| feature == X3_AT_OFFER_FEATURE)),
            CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
                "node_info refused while checking for {X3_AT_OFFER_FEATURE}: {reason}"
            ))),
            other => Err(RtpEngineError::Protocol(format!(
                "unexpected '{}' response for node_info",
                result_kind(&other)
            ))),
        }
    }
}

impl SiphonRtpClientSet {
    /// Register the observer of every engine call this set creates or ends.
    pub fn observe_calls(&self, observer: EngineCallObserver) {
        self.calls.set(observer);
    }

    /// Whether the instance holding the leg of `call_id` under `scope` accepts
    /// `attach_x3` before the answer; `None` while it has not been asked.
    pub fn x3_attach_at_offer(&self, call_id: &str, scope: Option<&CallScope>) -> Option<bool> {
        self.select_key(&scoped_key(call_id, scope))
            .x3_attach_at_offer()
    }

    /// [`Self::x3_attach_at_offer`], asking that instance when it has not
    /// been asked.
    pub async fn learn_x3_attach_at_offer(
        &self,
        call_id: &str,
        scope: Option<&CallScope>,
    ) -> Result<bool, RtpEngineError> {
        self.select_key(&scoped_key(call_id, scope))
            .learn_x3_attach_at_offer()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn the_feature_is_read_off_node_info_features() {
        let engine = X3AtOffer::default();
        assert_eq!(engine.listed(), None, "not asked yet");
        engine.record(&features(&["relay", "scope"]));
        assert_eq!(engine.listed(), Some(false));
        engine.record(&features(&["relay", "x3_attach_at_offer"]));
        assert_eq!(engine.listed(), Some(true));
        engine.record(&features(&["x3_attach_at_offer_v2", "x3"]));
        assert_eq!(engine.listed(), Some(false), "the exact name only");
    }

    #[test]
    fn a_new_connection_forgets_what_the_last_engine_listed() {
        let engine = X3AtOffer::default();
        engine.record(&features(&["x3_attach_at_offer"]));
        engine.forget();
        assert_eq!(engine.listed(), None);
    }
}
