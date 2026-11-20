//! Attaching X3 content delivery when a call is offered, and what else the
//! connected engine says it can intercept.
//!
//! An engine that lists `x3_attach_at_offer` in `node_info.features` accepts
//! `attach_x3` on a call that is offered but not answered yet, and puts the
//! taps on at the first answer. One that lists `x3_conference_seat` accepts it
//! on a seat that joined a conference room, named by the room and the seat's
//! tag, and carries a call's interception into a room with its leg. One that
//! lists `x3_single_leg` accepts it on a call it answered itself
//! (`answer_local`). It lists each only when it is provisioned to deliver X3
//! at all, so a name answers both questions. What the connected engine listed
//! is kept per connection.
//!
//! Also here: the observer a controller registers to be told of each engine
//! call siphon creates (an `offer`, an `answer_local`, a seat joining a room:
//! the moment such an attach is made) and of each one it ends (a `delete`, an
//! `offer` replacing a call, a joined seat leaving its room), which is the one
//! way a call's content delivery ends that is not a fault.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use siphon_rtp_proto::{CmdResult, Command};

use super::per_call::scoped_key;
use super::scope::CallScope;
use super::{result_kind, SiphonRtpClient, SiphonRtpClientSet};
use crate::rtpengine::error::RtpEngineError;

/// What an engine may say it can intercept, by the name it lists in
/// `node_info.features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X3Feature {
    /// `attach_x3` on a call that is offered and not answered yet.
    AttachAtOffer,
    /// `attach_x3` on a seat that joined a conference room, and a call's
    /// interception following its leg into one.
    ConferenceSeat,
    /// `attach_x3` on a call the engine answered itself.
    SingleLeg,
}

impl X3Feature {
    /// The name the engine lists the feature under.
    pub fn name(self) -> &'static str {
        match self {
            Self::AttachAtOffer => "x3_attach_at_offer",
            Self::ConferenceSeat => "x3_conference_seat",
            Self::SingleLeg => "x3_single_leg",
        }
    }

    fn bit(self) -> u8 {
        match self {
            Self::AttachAtOffer => 1,
            Self::ConferenceSeat => 2,
            Self::SingleLeg => 4,
        }
    }

    const ALL: [X3Feature; 3] = [Self::AttachAtOffer, Self::ConferenceSeat, Self::SingleLeg];
}

/// Set once the engine has been asked on this connection.
const ASKED: u8 = 0x80;

/// Which [`X3Feature`]s the connected engine listed, or nothing yet.
///
/// Per connection: an engine upgraded or provisioned in place answers on a
/// new connection, so the value is dropped when one is established and
/// learned again.
#[derive(Debug, Default)]
pub(super) struct X3Features(AtomicU8);

impl X3Features {
    /// Keep what a `node_info` answer's `features` say.
    pub(super) fn record(&self, features: &[String]) {
        let listed = X3Feature::ALL
            .into_iter()
            .filter(|feature| features.iter().any(|name| name == feature.name()))
            .fold(ASKED, |listed, feature| listed | feature.bit());
        self.0.store(listed, Ordering::Release);
    }

    /// A connection was established: whatever the last one's engine said no
    /// longer holds.
    pub(super) fn forget(&self) {
        self.0.store(0, Ordering::Release);
    }

    /// Whether the engine listed `feature`; `None` while it has not been
    /// asked on this connection.
    pub(super) fn listed(&self, feature: X3Feature) -> Option<bool> {
        let state = self.0.load(Ordering::Acquire);
        (state & ASKED != 0).then_some(state & feature.bit() != 0)
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
    /// An `answer_local` has just been answered: the engine holds the call
    /// with itself as the far side. A re-answer of the same dialog is told
    /// again, and keeps the call.
    AnsweredLocally,
    /// A participant has just been seated in a conference room
    /// (`conference_join`, or the answer to a `conference_offer`). No engine
    /// call is behind the seat: `call_id` is the room and `from_tag` the
    /// seat's tag.
    SeatJoined,
    /// siphon is about to take a joined seat out of its room
    /// (`conference_leave`), which stops the room with its last seat. Told
    /// before the frame is written. Named as [`Self::SeatJoined`] names it.
    SeatLeaving,
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
    /// The SIP Call-ID of the call a seat seats, on a seat's change.
    pub sip_call_id: Option<&'a str>,
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
                sip_call_id: None,
                change,
            });
        }
    }

    /// Tell the observer of `change` to the seat `from_tag` of the room
    /// `conference_id`, which seats the call `sip_call_id`.
    pub(super) fn notify_seat(
        &self,
        change: EngineCallChange,
        conference_id: &str,
        from_tag: &str,
        sip_call_id: &str,
    ) {
        if let Some(observer) = self.0.get() {
            observer(&EngineCall {
                call_id: conference_id,
                from_tag,
                scope: None,
                sip_call_id: Some(sip_call_id),
                change,
            });
        }
    }
}

impl SiphonRtpClient {
    /// Whether this instance's engine listed `feature`; `None` while it has
    /// not been asked on this connection.
    pub fn x3_feature(&self, feature: X3Feature) -> Option<bool> {
        self.x3_features.listed(feature)
    }

    /// [`Self::x3_feature`], asking the engine when it has not been asked
    /// yet. One `node_info` per connection.
    pub async fn learn_x3_feature(&self, feature: X3Feature) -> Result<bool, RtpEngineError> {
        if let Some(listed) = self.x3_feature(feature) {
            return Ok(listed);
        }
        // `request_in` records the features of every `node_info` it sees.
        match self.request_in(None, Command::NodeInfo).await? {
            CmdResult::NodeInfo { node } => {
                Ok(node.features.iter().any(|name| name == feature.name()))
            }
            CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
                "node_info refused while checking for {}: {reason}",
                feature.name()
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

    /// Whether the instance holding the leg of `call_id` under `scope` listed
    /// `feature`; `None` while it has not been asked.
    pub fn x3_feature(
        &self,
        feature: X3Feature,
        call_id: &str,
        scope: Option<&CallScope>,
    ) -> Option<bool> {
        self.select_key(&scoped_key(call_id, scope))
            .x3_feature(feature)
    }

    /// [`Self::x3_feature`], asking that instance when it has not been asked.
    pub async fn learn_x3_feature(
        &self,
        feature: X3Feature,
        call_id: &str,
        scope: Option<&CallScope>,
    ) -> Result<bool, RtpEngineError> {
        self.select_key(&scoped_key(call_id, scope))
            .learn_x3_feature(feature)
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
        let engine = X3Features::default();
        let at_offer = X3Feature::AttachAtOffer;
        assert_eq!(engine.listed(at_offer), None, "not asked yet");
        engine.record(&features(&["relay", "scope"]));
        assert_eq!(engine.listed(at_offer), Some(false));
        engine.record(&features(&["relay", "x3_attach_at_offer"]));
        assert_eq!(engine.listed(at_offer), Some(true));
        engine.record(&features(&["x3_attach_at_offer_v2", "x3"]));
        assert_eq!(engine.listed(at_offer), Some(false), "the exact name only");
    }

    #[test]
    fn each_feature_is_listed_on_its_own() {
        let engine = X3Features::default();
        engine.record(&features(&["x3_attach_at_offer", "x3_single_leg"]));
        assert_eq!(engine.listed(X3Feature::AttachAtOffer), Some(true));
        assert_eq!(engine.listed(X3Feature::SingleLeg), Some(true));
        assert_eq!(
            engine.listed(X3Feature::ConferenceSeat),
            Some(false),
            "an engine before the room taps lists the others without it"
        );
        engine.record(&features(&["x3_conference_seat"]));
        assert_eq!(engine.listed(X3Feature::ConferenceSeat), Some(true));
        assert_eq!(engine.listed(X3Feature::SingleLeg), Some(false));
    }

    #[test]
    fn a_new_connection_forgets_what_the_last_engine_listed() {
        let engine = X3Features::default();
        engine.record(&features(&["x3_attach_at_offer", "x3_conference_seat"]));
        engine.forget();
        for feature in X3Feature::ALL {
            assert_eq!(engine.listed(feature), None);
        }
    }
}
