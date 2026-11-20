//! Which X3 content deliveries exist, per engine call.
//!
//! Keyed on what the media engine keys them on: the engine call-id and the
//! leg's per-call scope. Not on the SIP session: a call routed again after its
//! media was released is the same session and a new engine call, and the
//! interception died with the old one.
//!
//! Three rules hold the record together.
//!
//! **An attachment is recorded before the engine is asked for it.** The record
//! is what stops a second request for the same `(leg, warrant, destination)`,
//! from an offer or from an ACK, and what an end or a loss the engine reports
//! is attributed to. Recorded after the engine answered, a report that beat
//! the answer found nothing, raised nothing, and the late record then stayed
//! for good.
//!
//! **siphon ending an engine call ends that call's attempt, at once.** siphon
//! is told before the `delete` (or the `offer` that replaces the call) is
//! written. The leg's attachments move to a queue of attempts siphon ended
//! and the leg's attempt number moves on, so the next offer of the leg attaches
//! afresh without waiting for the engine to report anything.
//!
//! **The engine's report of a delivery ending is matched oldest first.** The
//! engine ends one delivery per engine call, in the order the calls ended. A
//! report for a leg with an attempt siphon ended belongs to the oldest of
//! those, and is the call ending as siphon asked. A report for a leg with none
//! belongs to the live attempt, which nothing of siphon's ended.
//!
//! A call's entry stays until its lawful-intercept session is released
//! ([`LiManager::forget_x3_call`]), so that an attach still in flight compares
//! its attempt number against the leg's and not against a fresh zero.

use std::collections::VecDeque;

use super::x1::types::{DId, XId};
use super::{ActiveIntercept, LiManager};
use crate::rtpengine::events::X3EndedEvent;
use crate::rtpengine::CallScope;

/// One leg of an engine call: the call's own media (`None`) or the leg
/// anchored under a per-call scope.
#[derive(Debug, Default)]
struct Leg {
    scope: Option<CallScope>,
    /// How many engine calls siphon has ended on this leg: the number of the
    /// attempt in progress.
    attempt: u64,
    /// The deliveries siphon ended, is ending or detached, whose end the
    /// engine has not reported yet, oldest first.
    ended: VecDeque<Ended>,
    /// The `(warrant, destination)` pairs the engine refused for good on the
    /// attempt in progress. They are not asked for again on this engine call:
    /// the answer would be the same, and so would the report. A new attempt
    /// is a new engine call, and starts with none.
    refused: Vec<(XId, DId)>,
    /// The `(warrant, destination, Correlation ID)` a second session on the
    /// engine call asked for and the engine cannot deliver beside the first,
    /// each reported once.
    undeliverable: Vec<(XId, DId, u64)>,
}

/// Whether siphon ended the engine call a delivery was on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineCallEnd {
    /// It did not: the delivery was only detached.
    No,
    /// It has asked the engine to, and the engine has not answered. An end
    /// the engine reports meanwhile is this one's.
    Asked,
    /// It did.
    Yes,
}

/// The attachments of one attempt whose delivery is over as far as siphon is
/// concerned, kept until the engine reports it ended: that report is what
/// says whether anything was dropped, and it needs a warrant to be reported
/// against.
#[derive(Debug)]
struct Ended {
    /// The attempt the attachments were asked under.
    attempt: u64,
    /// siphon detached them (`detach_x3`), rather than ending their call.
    detached: bool,
    engine_call: EngineCallEnd,
    attachments: Vec<ActiveIntercept>,
    /// The engine's report of this delivery ending, when it arrived while the
    /// end siphon asked for was still unanswered. Whether that end is clean
    /// depends on the answer, so the report waits for it. One per attempt.
    held: Option<X3EndedEvent>,
    /// The pairs the engine had refused for good on the attempt, put back
    /// when the end siphon asked for fails and the attempt goes on.
    refused: Vec<(XId, DId)>,
}

/// An engine's report of a delivery ending that waited for the answer to the
/// end siphon had asked for, with the delivery it belongs to.
#[derive(Debug)]
pub struct HeldEnd {
    pub ended: X3EndedEvent,
    pub delivery: EndedDelivery,
}

/// What asking to record an attachment came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X3Registration {
    /// Recorded: ask the engine for it.
    Recorded,
    /// Nothing to ask: it is on record already, the engine refused it for
    /// good on this engine call, or the attempt it was decided in is over.
    Known,
    /// The same warrant and destination is on record on this engine call
    /// under another session's Correlation ID (`held`): two calls bridged
    /// onto one engine call, both of the same target. Told once per pair.
    OtherCorrelation {
        /// The Correlation ID the engine call's delivery carries.
        held: u64,
    },
}

/// The content deliveries of one engine call-id.
#[derive(Debug, Default)]
pub(super) struct CallContent {
    /// The attachments of every leg's attempt in progress, asked for or live.
    attachments: Vec<ActiveIntercept>,
    legs: Vec<Leg>,
}

impl CallContent {
    fn leg(&mut self, scope: Option<&CallScope>) -> &mut Leg {
        let position = self
            .legs
            .iter()
            .position(|leg| leg.scope.as_ref() == scope)
            .unwrap_or_else(|| {
                self.legs.push(Leg {
                    scope: scope.cloned(),
                    ..Leg::default()
                });
                self.legs.len() - 1
            });
        &mut self.legs[position]
    }

    fn take_leg(&mut self, scope: Option<&CallScope>) -> Vec<ActiveIntercept> {
        let (leg, others) = std::mem::take(&mut self.attachments)
            .into_iter()
            .partition(|attachment| attachment.scope.as_ref() == scope);
        self.attachments = others;
        leg
    }

    /// Whether a delivery is asked for, live, or ended by siphon and not yet
    /// reported ended.
    fn delivering(&self) -> bool {
        !self.attachments.is_empty()
            || self
                .legs
                .iter()
                .flat_map(|leg| &leg.ended)
                .any(|ended| !ended.attachments.is_empty())
    }
}

/// What the content delivery of a seat that joined a conference room is
/// recorded under.
///
/// The engine holds no call behind such a seat and keys its interception on
/// the room and the seat's tag, so the record is keyed on the pair. Joined by
/// U+001F, which no SIP Call-ID holds (RFC 3261 §25.1) and the engine refuses
/// in a call-id, so the key is never an engine call's.
pub fn seat_record(conference_id: &str, tag: &str) -> String {
    format!("{conference_id}\u{1f}{tag}")
}

/// What a failed attach was an attach of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedAttach {
    /// The attempt in progress: warranted content is not being delivered.
    Live,
    /// An attempt siphon has ended since: the engine call was going away.
    EndedBySiphon,
}

/// The delivery an engine's end report belongs to.
#[derive(Debug)]
pub struct EndedDelivery {
    /// Whether siphon ended the engine call the delivery was on.
    pub by_siphon: bool,
    /// The attachments that delivery served, to report a fault against.
    pub attachments: Vec<ActiveIntercept>,
}

impl EndedDelivery {
    /// The delivery of an end nothing is on record for.
    pub fn unknown() -> Self {
        Self {
            by_siphon: false,
            attachments: Vec::new(),
        }
    }
}

impl LiManager {
    /// The number of the attempt in progress on a leg of an engine call. An
    /// attach is asked for under it, and is not made once it has moved on.
    pub fn x3_attempt(&self, call_id: &str, scope: Option<&CallScope>) -> u64 {
        self.x3_attachments
            .entry(call_id.to_string())
            .or_default()
            .leg(scope)
            .attempt
    }

    /// Whether `attempt` is still the attempt in progress on a leg of an
    /// engine call: siphon has not ended that engine call since, and the
    /// call's record has not been released. Looks, and records nothing.
    pub fn x3_attempt_in_progress(
        &self,
        call_id: &str,
        scope: Option<&CallScope>,
        attempt: u64,
    ) -> bool {
        self.x3_attachments.get(call_id).is_some_and(|content| {
            content
                .legs
                .iter()
                .find(|leg| leg.scope.as_ref() == scope)
                .map_or(0, |leg| leg.attempt)
                == attempt
        })
    }

    /// Record an attachment that is about to be asked of the engine, under the
    /// `attempt` it was decided in. `false`, and nothing recorded, when the
    /// same `(leg, warrant, destination)` is already recorded or siphon has
    /// ended that attempt's engine call since.
    pub fn register_x3_attachment(
        &self,
        call_id: &str,
        attachment: ActiveIntercept,
        attempt: u64,
    ) -> bool {
        self.x3_register(call_id, attachment, attempt) == X3Registration::Recorded
    }

    /// [`Self::register_x3_attachment`], saying why nothing was recorded.
    ///
    /// An attachment is one warrant delivering to one destination from one leg
    /// *under one session's Correlation ID*. Two calls of one target bridged
    /// onto one engine call are two sessions with a Correlation ID each, and
    /// each is owed its content under its own.
    pub fn x3_register(
        &self,
        call_id: &str,
        attachment: ActiveIntercept,
        attempt: u64,
    ) -> X3Registration {
        let mut content = self.x3_attachments.entry(call_id.to_string()).or_default();
        let scope = attachment.scope.clone();
        let pair = (attachment.x_id, attachment.d_id);
        let leg = content.leg(scope.as_ref());
        if leg.refused.contains(&pair) || leg.attempt != attempt {
            return X3Registration::Known;
        }
        let other = content
            .attachments
            .iter()
            .find(|known| (known.x_id, known.d_id) == pair && known.scope == scope)
            .map(|known| known.correlation_id);
        match other {
            None => {
                content.attachments.push(attachment);
                X3Registration::Recorded
            }
            Some(held) if held == attachment.correlation_id => X3Registration::Known,
            Some(held) => {
                let told = (pair.0, pair.1, attachment.correlation_id);
                let leg = content.leg(scope.as_ref());
                if leg.undeliverable.contains(&told) {
                    return X3Registration::Known;
                }
                leg.undeliverable.push(told);
                X3Registration::OtherCorrelation { held }
            }
        }
    }

    /// Record that content delivery started for a call, on the attempt in
    /// progress.
    pub fn record_x3_attachment(&self, call_id: &str, attachment: ActiveIntercept) {
        let attempt = self.x3_attempt(call_id, attachment.scope.as_ref());
        self.register_x3_attachment(call_id, attachment, attempt);
    }

    /// siphon is ending the engine call of one leg (a `delete`, or an `offer`
    /// replacing it) and the engine has taken the command: its attempt is
    /// over, and its attachments wait for the engine's report of their
    /// delivery ending. Nothing for a call with no record, which is every call
    /// no content warrant covers.
    ///
    /// [`Self::x3_media_ending`] and [`Self::x3_media_end_committed`] in one,
    /// for an end that cannot fail.
    pub fn x3_media_ended_by_siphon(&self, call_id: &str, scope: Option<&CallScope>) {
        self.x3_media_ending(call_id, scope);
        self.x3_media_end_committed(call_id, scope);
    }

    /// siphon is about to ask the engine to end the engine call of one leg.
    /// Told before the command is written, so that the record is there before
    /// the engine can report anything of the call ending: from here on an end
    /// the engine reports on the leg is this one's, and the next offer of the
    /// leg attaches afresh. The command's outcome follows
    /// ([`Self::x3_media_end_committed`], [`Self::x3_media_end_failed`]).
    pub fn x3_media_ending(&self, call_id: &str, scope: Option<&CallScope>) {
        let Some(mut content) = self.x3_attachments.get_mut(call_id) else {
            return;
        };
        let attachments = content.take_leg(scope);
        let leg = content.leg(scope);
        // A delivery siphon detached and the engine has not reported ended
        // goes with the call as well, whichever of the two the engine saw
        // first.
        for ended in &mut leg.ended {
            if ended.engine_call == EngineCallEnd::No {
                ended.engine_call = EngineCallEnd::Asked;
            }
        }
        let refused = std::mem::take(&mut leg.refused);
        leg.undeliverable.clear();
        leg.ended.push_back(Ended {
            attempt: leg.attempt,
            detached: false,
            engine_call: EngineCallEnd::Asked,
            attachments,
            held: None,
            refused,
        });
        leg.attempt += 1;
    }

    /// The engine took the end siphon asked for: the engine call is gone, by
    /// siphon's doing. Returns the end reports that waited for this answer,
    /// each with its delivery, now known to be of an engine call siphon ended.
    pub fn x3_media_end_committed(&self, call_id: &str, scope: Option<&CallScope>) -> Vec<HeldEnd> {
        let Some(mut content) = self.x3_attachments.get_mut(call_id) else {
            return Vec::new();
        };
        let mut released = Vec::new();
        let leg = content.leg(scope);
        for ended in &mut leg.ended {
            if ended.engine_call != EngineCallEnd::Asked {
                continue;
            }
            ended.engine_call = EngineCallEnd::Yes;
            if let Some(report) = ended.held.take() {
                released.push(HeldEnd {
                    ended: report,
                    delivery: EndedDelivery {
                        by_siphon: true,
                        attachments: std::mem::take(&mut ended.attachments),
                    },
                });
            }
        }
        leg.ended.retain(|ended| !ended.attachments.is_empty());
        released
    }

    /// The engine refused the end siphon asked for, or the command failed: the
    /// engine call is still there as far as siphon made it so, and its
    /// delivery with it. The attempt that was put aside is the one in progress
    /// again, with its attachments and what the engine had refused on it. An
    /// end the engine reports from here on is one siphon did not bring about.
    ///
    /// Returns the end reports that arrived while the command was out. They
    /// waited because the command's answer decides them, and it has: siphon
    /// ended nothing, so each is the engine ending a delivery on its own.
    pub fn x3_media_end_failed(&self, call_id: &str, scope: Option<&CallScope>) -> Vec<HeldEnd> {
        let Some(mut content) = self.x3_attachments.get_mut(call_id) else {
            return Vec::new();
        };
        let mut restored = Vec::new();
        let mut released = Vec::new();
        let leg = content.leg(scope);
        let current = leg.attempt;
        let mut reopened = None;
        leg.ended.retain_mut(|ended| {
            if ended.engine_call != EngineCallEnd::Asked {
                return true;
            }
            ended.engine_call = EngineCallEnd::No;
            // The attempt the failed command put aside: nothing was started
            // after it, since the engine call it would have made room for
            // never went away.
            let put_aside = !ended.detached && ended.attempt + 1 == current;
            if put_aside {
                reopened = Some((ended.attempt, std::mem::take(&mut ended.refused)));
            }
            if let Some(report) = ended.held.take() {
                released.push(HeldEnd {
                    ended: report,
                    delivery: EndedDelivery {
                        by_siphon: false,
                        attachments: std::mem::take(&mut ended.attachments),
                    },
                });
                return false;
            }
            if put_aside {
                restored.append(&mut ended.attachments);
                return false;
            }
            !ended.attachments.is_empty()
        });
        if let Some((attempt, refused)) = reopened {
            leg.attempt = attempt;
            leg.refused = refused;
        }
        content.attachments.append(&mut restored);
        released
    }

    /// siphon is detaching every delivery of a call's attempts in progress
    /// (`detach_x3`): they stop being live, and stay on record until the
    /// engine reports each ended. A detach that dropped content, or lost the
    /// race to a transport failure, is then still reported against its
    /// warrant. Returns what to detach.
    pub fn x3_detaching(&self, call_id: &str) -> Vec<ActiveIntercept> {
        let Some(mut content) = self.x3_attachments.get_mut(call_id) else {
            return Vec::new();
        };
        let detached = std::mem::take(&mut content.attachments);
        let mut scopes: Vec<Option<CallScope>> = Vec::new();
        for attachment in &detached {
            if !scopes.contains(&attachment.scope) {
                scopes.push(attachment.scope.clone());
            }
        }
        for scope in scopes {
            let attachments = detached
                .iter()
                .filter(|attachment| attachment.scope == scope)
                .cloned()
                .collect();
            let leg = content.leg(scope.as_ref());
            leg.ended.push_back(Ended {
                attempt: leg.attempt,
                detached: true,
                engine_call: EngineCallEnd::No,
                attachments,
                held: None,
                refused: Vec::new(),
            });
        }
        detached
    }

    /// The engine refused or failed an attach asked under `attempt`, for
    /// good: drop its record, and say whether that attempt is still the one
    /// in progress. If it is, the pair is not asked for again on this engine
    /// call.
    ///
    /// Only the record of that attempt goes. The same warrant and destination
    /// on another attempt of the leg, ended and waiting for the engine's
    /// report, is a delivery of its own.
    pub fn x3_attach_failed(
        &self,
        call_id: &str,
        scope: Option<&CallScope>,
        x_id: XId,
        d_id: DId,
        attempt: u64,
    ) -> FailedAttach {
        let Some(mut content) = self.x3_attachments.get_mut(call_id) else {
            return FailedAttach::Live;
        };
        let same = |known: &ActiveIntercept| known.x_id == x_id && known.d_id == d_id;
        let live = content.leg(scope).attempt == attempt;
        if live {
            content
                .attachments
                .retain(|known| !(same(known) && known.scope.as_ref() == scope));
        }
        let leg = content.leg(scope);
        // Never attached, so the engine will report no end for it.
        for ended in &mut leg.ended {
            if ended.attempt == attempt {
                ended.attachments.retain(|known| !same(known));
            }
        }
        leg.ended.retain(|ended| {
            !ended.attachments.is_empty() || ended.engine_call == EngineCallEnd::Asked
        });
        if !live {
            return FailedAttach::EndedBySiphon;
        }
        if !leg.refused.contains(&(x_id, d_id)) {
            leg.refused.push((x_id, d_id));
        }
        FailedAttach::Live
    }

    /// The engine reported a delivery ended on a leg: the delivery it belongs
    /// to, as [`Self::x3_delivery_ended`] finds it, or `None` when that
    /// delivery's engine call is one siphon has asked the engine to end and
    /// the engine has not answered. Whether such an end is siphon's doing is
    /// what the answer says, so the report is kept with the delivery and
    /// handed back with the answer ([`Self::x3_media_end_committed`],
    /// [`Self::x3_media_end_failed`]). A delivery holds one report; a further
    /// one is the next delivery's.
    pub fn x3_delivery_end_reported(
        &self,
        call_id: &str,
        scope: Option<&CallScope>,
        ended: &X3EndedEvent,
    ) -> Option<EndedDelivery> {
        {
            let mut content = self.x3_attachments.get_mut(call_id)?;
            let oldest = content
                .leg(scope)
                .ended
                .iter_mut()
                .find(|delivery| !delivery.attachments.is_empty() && delivery.held.is_none());
            if let Some(delivery) = oldest {
                if delivery.engine_call == EngineCallEnd::Asked {
                    delivery.held = Some(ended.clone());
                    return None;
                }
            }
        }
        Some(self.x3_delivery_ended(call_id, scope))
    }

    /// The delivery an end the engine reported on a leg belongs to, dropped
    /// from the record: the oldest one siphon ended, is ending or detached,
    /// else the attempt in progress.
    pub fn x3_delivery_ended(&self, call_id: &str, scope: Option<&CallScope>) -> EndedDelivery {
        let Some(mut content) = self.x3_attachments.get_mut(call_id) else {
            return EndedDelivery {
                by_siphon: false,
                attachments: Vec::new(),
            };
        };
        let leg = content.leg(scope);
        let oldest = leg
            .ended
            .iter()
            .position(|ended| !ended.attachments.is_empty() && ended.held.is_none());
        match oldest {
            Some(index) => {
                let ended = &mut leg.ended[index];
                let delivery = EndedDelivery {
                    by_siphon: ended.engine_call != EngineCallEnd::No,
                    attachments: std::mem::take(&mut ended.attachments),
                };
                // An end still being asked for keeps its place, for the
                // command's outcome to find.
                if ended.engine_call != EngineCallEnd::Asked {
                    leg.ended.remove(index);
                }
                delivery
            }
            None => EndedDelivery {
                by_siphon: false,
                attachments: content.take_leg(scope),
            },
        }
    }

    /// The record an engine event naming `call_id` and `from_tag` belongs to:
    /// that of the seat that joined the room `call_id` as `from_tag` when one
    /// is on record, else the engine call's.
    pub fn x3_record_of_event<'a>(
        &self,
        call_id: &'a str,
        from_tag: &str,
    ) -> std::borrow::Cow<'a, str> {
        let seat = seat_record(call_id, from_tag);
        match self.x3_attachments.contains_key(&seat) {
            true => seat.into(),
            false => call_id.into(),
        }
    }

    /// Every interception of a call's attempts in progress, asked for or live.
    pub fn x3_attachments_for(&self, call_id: &str) -> Vec<ActiveIntercept> {
        self.x3_attachments
            .get(call_id)
            .map(|content| content.attachments.clone())
            .unwrap_or_default()
    }

    /// The interceptions on one leg of a call: its own media (`None`) or the
    /// leg anchored under a per-call `scope`.
    pub fn x3_attachments_for_leg(
        &self,
        call_id: &str,
        scope: Option<&CallScope>,
    ) -> Vec<ActiveIntercept> {
        self.x3_attachments_for(call_id)
            .into_iter()
            .filter(|attachment| attachment.scope.as_ref() == scope)
            .collect()
    }

    /// Drop and return one leg's interceptions; the call's other legs keep
    /// theirs.
    pub fn take_x3_attachments_for_leg(
        &self,
        call_id: &str,
        scope: Option<&CallScope>,
    ) -> Vec<ActiveIntercept> {
        self.x3_attachments
            .get_mut(call_id)
            .map(|mut content| content.take_leg(scope))
            .unwrap_or_default()
    }

    /// Drop and return a call's interceptions, to detach them at teardown.
    pub fn take_x3_attachments(&self, call_id: &str) -> Vec<ActiveIntercept> {
        self.x3_attachments
            .get_mut(call_id)
            .map(|mut content| std::mem::take(&mut content.attachments))
            .unwrap_or_default()
    }

    /// How many calls have a content delivery asked for, live, or ended by
    /// siphon and not yet reported ended.
    ///
    /// Used by the per-module leak guard: this must drain to zero as calls end.
    pub fn x3_attachment_count(&self) -> usize {
        self.x3_attachments
            .iter()
            .filter(|content| content.delivering())
            .count()
    }

    /// How many engine calls have a record at all. Drains to zero as their
    /// lawful-intercept sessions are released; exposed for the leak tests.
    pub fn x3_call_count(&self) -> usize {
        self.x3_attachments.len()
    }

    /// Release the record of an engine call, with its session.
    pub(super) fn forget_x3_call(&self, call_id: &str) {
        self.x3_attachments.remove(call_id);
    }

    /// Release every record no delivery hangs on: when the sessions they
    /// belonged to are all released at once.
    pub(super) fn forget_idle_x3_calls(&self) {
        self.x3_attachments
            .retain(|_, content| content.delivering());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::tests::manager;

    const CALL: &str = "call@example.com";

    /// The one warrant of these tests.
    fn x_id() -> XId {
        static X_ID: std::sync::OnceLock<XId> = std::sync::OnceLock::new();
        *X_ID.get_or_init(XId::generate)
    }

    fn ended_report(reason: &str) -> X3EndedEvent {
        X3EndedEvent {
            call_id: CALL.to_string(),
            from_tag: "caller-tag".to_string(),
            reason: reason.to_string(),
            orderly: reason == "Detached",
            delivered: 10,
            dropped: 0,
        }
    }

    fn attachment(d_id: DId, scope: Option<&str>) -> ActiveIntercept {
        ActiveIntercept {
            x_id: x_id(),
            d_id,
            from_tag: "caller-tag".to_string(),
            correlation_id: 9,
            scope: scope.map(|scope| CallScope::per_call(scope).expect("a scope")),
        }
    }

    #[test]
    fn an_attachment_is_recorded_once_per_leg_warrant_and_destination() {
        let (manager, _iri, _audit) = manager();
        let d_id = DId::generate();
        let attempt = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), attempt));
        assert!(
            !manager.register_x3_attachment(CALL, attachment(d_id, None), attempt),
            "asked once, by the offer or by the ACK"
        );
        let orig = attachment(d_id, Some("orig"));
        let orig_attempt = manager.x3_attempt(CALL, orig.scope.as_ref());
        assert!(
            manager.register_x3_attachment(CALL, orig, orig_attempt),
            "another leg is its own attachment"
        );
        assert!(
            manager.register_x3_attachment(CALL, attachment(DId::generate(), None), attempt),
            "and so is another destination"
        );
        assert_eq!(manager.x3_attachments_for(CALL).len(), 3);
    }

    #[test]
    fn siphon_ending_the_engine_call_frees_the_leg_for_the_next_attempt_at_once() {
        let (manager, _iri, _audit) = manager();
        let d_id = DId::generate();
        let first = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), first));

        manager.x3_media_ended_by_siphon(CALL, None);
        assert!(manager.x3_attachments_for(CALL).is_empty());
        assert!(
            !manager.register_x3_attachment(CALL, attachment(d_id, None), first),
            "an attach decided before the delete is not made after it"
        );
        let second = manager.x3_attempt(CALL, None);
        assert!(
            manager.register_x3_attachment(CALL, attachment(d_id, None), second),
            "the new offer attaches without waiting for the engine's report"
        );

        // The old delivery's end is the old attempt's, and leaves the new one.
        let ended = manager.x3_delivery_ended(CALL, None);
        assert!(ended.by_siphon);
        assert_eq!(ended.attachments.len(), 1);
        assert_eq!(manager.x3_attachments_for(CALL).len(), 1);

        // The next end is the live attempt's, which siphon did not end.
        let ended = manager.x3_delivery_ended(CALL, None);
        assert!(!ended.by_siphon);
        assert_eq!(ended.attachments.len(), 1);
        assert_eq!(manager.x3_attachment_count(), 0);
    }

    #[test]
    fn a_failed_attach_is_told_from_one_whose_call_siphon_ended() {
        let (manager, _iri, _audit) = manager();
        let d_id = DId::generate();
        let x_id = x_id();
        let attempt = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), attempt));
        assert_eq!(
            manager.x3_attach_failed(CALL, None, x_id, d_id, attempt),
            FailedAttach::Live
        );
        assert!(
            manager.x3_attachments_for(CALL).is_empty(),
            "not left behind"
        );

        assert!(
            !manager.register_x3_attachment(CALL, attachment(d_id, None), attempt),
            "refused for good on this engine call: not asked again"
        );
        let d_id = DId::generate();
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), attempt));
        manager.x3_media_ended_by_siphon(CALL, None);
        assert_eq!(
            manager.x3_attach_failed(CALL, None, x_id, d_id, attempt),
            FailedAttach::EndedBySiphon
        );
        assert_eq!(
            manager.x3_attachment_count(),
            0,
            "an attach that never took has no end to wait for"
        );
        assert!(!manager.x3_delivery_ended(CALL, None).by_siphon);
    }

    #[test]
    fn an_attempt_is_in_progress_until_siphon_ends_its_engine_call() {
        let (manager, _iri, _audit) = manager();
        assert!(
            !manager.x3_attempt_in_progress(CALL, None, 0),
            "a call with no record has nothing in progress"
        );
        assert_eq!(manager.x3_call_count(), 0, "and asking recorded nothing");
        let attempt = manager.x3_attempt(CALL, None);
        manager.register_x3_attachment(CALL, attachment(DId::generate(), None), attempt);
        assert!(manager.x3_attempt_in_progress(CALL, None, attempt));
        manager.x3_media_ended_by_siphon(CALL, None);
        assert!(!manager.x3_attempt_in_progress(CALL, None, attempt));
        assert!(manager.x3_attempt_in_progress(CALL, None, attempt + 1));
        manager.forget_x3_call(CALL);
        assert!(!manager.x3_attempt_in_progress(CALL, None, attempt + 1));
    }

    #[test]
    fn a_call_with_no_record_is_left_without_one() {
        let (manager, _iri, _audit) = manager();
        manager.x3_media_ended_by_siphon(CALL, None);
        assert!(!manager.x3_delivery_ended(CALL, None).by_siphon);
        assert!(manager.take_x3_attachments(CALL).is_empty());
        assert_eq!(manager.x3_call_count(), 0);
    }

    #[test]
    fn records_are_released_with_their_calls() {
        let (manager, _iri, _audit) = manager();
        for index in 0..100 {
            let call = format!("call-{index}@example.com");
            let attempt = manager.x3_attempt(&call, None);
            manager.register_x3_attachment(&call, attachment(DId::generate(), None), attempt);
            manager.x3_media_ended_by_siphon(&call, None);
            manager.x3_delivery_ended(&call, None);
        }
        assert_eq!(manager.x3_attachment_count(), 0);
        assert_eq!(manager.x3_call_count(), 100, "kept for attaches in flight");
        manager.forget_idle_x3_calls();
        assert_eq!(manager.x3_call_count(), 0);

        let attempt = manager.x3_attempt(CALL, None);
        manager.register_x3_attachment(CALL, attachment(DId::generate(), None), attempt);
        manager.forget_idle_x3_calls();
        assert_eq!(
            manager.x3_call_count(),
            1,
            "a live delivery keeps its record"
        );
        manager.forget_x3_call(CALL);
        assert_eq!(manager.x3_call_count(), 0);
    }

    /// A seat that joined a room is recorded under the room and its tag, so
    /// two seats of one room are two records, and an engine event naming the
    /// pair finds the seat's while one naming a call finds the call's.
    #[test]
    fn a_joined_seat_has_a_record_of_its_own() {
        let (manager, _iri, _audit) = manager();
        let (first, second) = (seat_record("room", "tag-1"), seat_record("room", "tag-2"));
        assert_ne!(first, second);
        for record in [&first, &second] {
            let attempt = manager.x3_attempt(record, None);
            assert!(manager.register_x3_attachment(
                record,
                attachment(DId::generate(), None),
                attempt
            ));
        }
        assert_eq!(manager.x3_record_of_event("room", "tag-1"), first);
        assert_eq!(manager.x3_record_of_event("room", "tag-2"), second);
        assert_eq!(
            manager.x3_record_of_event("room", "caller-tag"),
            "room",
            "no seat on record under that tag: an engine call's event"
        );
        assert_eq!(manager.x3_record_of_event(CALL, "caller-tag"), CALL);

        // One seat leaving ends its own delivery and not the other's.
        manager.x3_media_ended_by_siphon(&first, None);
        assert!(manager.x3_delivery_ended(&first, None).by_siphon);
        assert_eq!(manager.x3_attachments_for(&second).len(), 1);
        assert!(!manager.x3_delivery_ended(&second, None).by_siphon);
        assert_eq!(manager.x3_attachment_count(), 0);
    }

    /// A leg's attempt A was attached and siphon ended its engine call; the
    /// next attempt B of the same warrant and destination is refused, late.
    /// The refusal is B's. A's delivery is still owed its end report, and an
    /// unclean one is reported against A's warrant.
    #[test]
    fn a_late_refusal_leaves_the_record_of_another_attempt() {
        let (manager, _iri, _audit) = manager();
        let (x_id, d_id) = (x_id(), DId::generate());
        let first = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), first));
        manager.x3_media_ended_by_siphon(CALL, None);
        let second = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), second));
        manager.x3_media_ended_by_siphon(CALL, None);

        assert_eq!(
            manager.x3_attach_failed(CALL, None, x_id, d_id, second),
            FailedAttach::EndedBySiphon
        );
        let ended = manager.x3_delivery_ended(CALL, None);
        assert!(ended.by_siphon);
        assert_eq!(
            ended.attachments.len(),
            1,
            "the first attempt's is still there"
        );
        assert_eq!(
            manager.x3_attachment_count(),
            0,
            "and the refused one is not"
        );
    }

    /// A pair the engine refused for good is not asked for again until siphon
    /// ends that engine call.
    #[test]
    fn a_refusal_for_good_holds_until_the_engine_call_changes() {
        let (manager, _iri, _audit) = manager();
        let (x_id, d_id) = (x_id(), DId::generate());
        let attempt = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), attempt));
        manager.x3_attach_failed(CALL, None, x_id, d_id, attempt);
        assert!(!manager.register_x3_attachment(CALL, attachment(d_id, None), attempt));
        assert!(
            manager.register_x3_attachment(CALL, attachment(DId::generate(), None), attempt),
            "another destination is asked for"
        );
        let scoped = attachment(d_id, Some("orig"));
        let scoped_attempt = manager.x3_attempt(CALL, scoped.scope.as_ref());
        assert!(
            manager.register_x3_attachment(CALL, scoped, scoped_attempt),
            "and so is another leg"
        );

        manager.x3_media_ended_by_siphon(CALL, None);
        let next = manager.x3_attempt(CALL, None);
        assert!(
            manager.register_x3_attachment(CALL, attachment(d_id, None), next),
            "a new engine call is asked afresh"
        );
    }

    /// A detached delivery stays on record until the engine reports it ended,
    /// so the report finds its warrant.
    #[test]
    fn a_detached_delivery_is_kept_until_the_engine_reports_it_ended() {
        let (manager, _iri, _audit) = manager();
        let attempt = manager.x3_attempt(CALL, None);
        manager.register_x3_attachment(CALL, attachment(DId::generate(), None), attempt);
        assert_eq!(manager.x3_detaching(CALL).len(), 1);
        assert!(
            manager.x3_attachments_for(CALL).is_empty(),
            "no longer live"
        );
        assert_eq!(manager.x3_attachment_count(), 1, "and still on record");

        let ended = manager.x3_delivery_ended(CALL, None);
        assert!(
            !ended.by_siphon,
            "siphon detached it, the call was not ended"
        );
        assert_eq!(ended.attachments.len(), 1);
        assert_eq!(manager.x3_attachment_count(), 0);

        // Detached and then deleted: the engine may report either first.
        manager.register_x3_attachment(CALL, attachment(DId::generate(), None), attempt);
        manager.x3_detaching(CALL);
        manager.x3_media_ending(CALL, None);
        let ended = manager.x3_delivery_ended(CALL, None);
        assert!(ended.by_siphon, "the call's end is siphon's");
        assert_eq!(ended.attachments.len(), 1);
        manager.x3_media_end_committed(CALL, None);
        assert_eq!(manager.x3_attachment_count(), 0);
    }

    /// An end siphon asked for counts while the engine has not answered, and
    /// is undone when the engine refuses it: the attempt is in progress
    /// again, and an end reported later is not siphon's.
    #[test]
    fn a_refused_end_puts_the_attempt_back_in_progress() {
        let (manager, _iri, _audit) = manager();
        let d_id = DId::generate();
        let attempt = manager.x3_attempt(CALL, None);
        manager.register_x3_attachment(CALL, attachment(d_id, None), attempt);

        manager.x3_media_ending(CALL, None);
        assert!(!manager.x3_attempt_in_progress(CALL, None, attempt));
        manager.x3_media_end_failed(CALL, None);
        assert!(manager.x3_attempt_in_progress(CALL, None, attempt));
        assert_eq!(manager.x3_attachments_for(CALL).len(), 1, "live again");
        assert!(
            !manager.register_x3_attachment(CALL, attachment(d_id, None), attempt),
            "and not asked for twice"
        );
        let ended = manager.x3_delivery_ended(CALL, None);
        assert!(
            !ended.by_siphon,
            "the engine ended a call siphon still holds"
        );
        assert_eq!(ended.attachments.len(), 1);

        // An end reported while the command is out waits for the command's
        // answer, which is what says whose doing it was. The engine refused:
        // siphon ended nothing, so the engine ended the delivery on its own.
        manager.register_x3_attachment(CALL, attachment(d_id, None), attempt);
        manager.x3_media_ending(CALL, None);
        let report = ended_report("CallEnded");
        assert!(
            manager
                .x3_delivery_end_reported(CALL, None, &report)
                .is_none(),
            "held, not judged"
        );
        assert_eq!(manager.x3_attachment_count(), 1, "and still on record");
        let released = manager.x3_media_end_failed(CALL, None);
        assert_eq!(released.len(), 1);
        assert!(!released[0].delivery.by_siphon);
        assert_eq!(released[0].delivery.attachments.len(), 1);
        assert_eq!(released[0].ended, report);
        assert!(manager.x3_attachments_for(CALL).is_empty(), "it did end");
        assert_eq!(manager.x3_attachment_count(), 0);
        assert!(manager.x3_attempt_in_progress(CALL, None, attempt));

        // The engine took the command: the same report is the command's.
        manager.register_x3_attachment(CALL, attachment(d_id, None), attempt);
        manager.x3_media_ending(CALL, None);
        assert!(manager
            .x3_delivery_end_reported(CALL, None, &report)
            .is_none());
        let released = manager.x3_media_end_committed(CALL, None);
        assert_eq!(released.len(), 1);
        assert!(released[0].delivery.by_siphon);
        assert_eq!(manager.x3_attachment_count(), 0);
        let attempt = manager.x3_attempt(CALL, None);

        // A call with nothing attached keeps its attempt number too.
        manager.x3_media_ending(CALL, None);
        manager.x3_media_end_failed(CALL, None);
        assert!(manager.x3_attempt_in_progress(CALL, None, attempt));
    }

    /// What the engine refused for good stays refused when an end siphon
    /// asked for fails: the engine call is the same one.
    #[test]
    fn a_failed_end_keeps_what_the_engine_refused() {
        let (manager, _iri, _audit) = manager();
        let (x_id, d_id) = (x_id(), DId::generate());
        let attempt = manager.x3_attempt(CALL, None);
        manager.register_x3_attachment(CALL, attachment(d_id, None), attempt);
        manager.x3_attach_failed(CALL, None, x_id, d_id, attempt);

        manager.x3_media_ending(CALL, None);
        manager.x3_media_end_failed(CALL, None);
        assert!(
            !manager.register_x3_attachment(CALL, attachment(d_id, None), attempt),
            "the same engine call: not asked again"
        );
        manager.x3_media_ending(CALL, None);
        manager.x3_media_end_committed(CALL, None);
        let next = manager.x3_attempt(CALL, None);
        assert!(manager.register_x3_attachment(CALL, attachment(d_id, None), next));
    }

    /// The same warrant and destination under another session's Correlation
    /// ID is another attachment. It is told apart, and told once.
    #[test]
    fn the_same_warrant_under_another_correlation_is_told_apart() {
        let (manager, _iri, _audit) = manager();
        let d_id = DId::generate();
        let attempt = manager.x3_attempt(CALL, None);
        let other = ActiveIntercept {
            correlation_id: 10,
            ..attachment(d_id, None)
        };
        assert_eq!(
            manager.x3_register(CALL, attachment(d_id, None), attempt),
            X3Registration::Recorded
        );
        assert_eq!(
            manager.x3_register(CALL, attachment(d_id, None), attempt),
            X3Registration::Known
        );
        assert_eq!(
            manager.x3_register(CALL, other.clone(), attempt),
            X3Registration::OtherCorrelation { held: 9 }
        );
        assert_eq!(
            manager.x3_register(CALL, other.clone(), attempt),
            X3Registration::Known,
            "reported once"
        );
        assert_eq!(manager.x3_attachments_for(CALL).len(), 1);
        manager.x3_media_ended_by_siphon(CALL, None);
        let next = manager.x3_attempt(CALL, None);
        assert_eq!(
            manager.x3_register(CALL, other, next),
            X3Registration::Recorded
        );
    }
}
