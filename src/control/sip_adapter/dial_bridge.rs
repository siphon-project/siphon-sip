//! `dial {on_answer: "bridge"}`: ring phones for a caller siphon has already
//! answered, and bridge the caller to the one that picks up.
//!
//! The flow every IVR ends in — greeting, menu, then "ring the department". The
//! caller is answered and anchored on the media engine, which is what let the
//! controller `play` to it, so a connecting `dial` (which answers the caller
//! with the phone's answer) is refused for it. This rings each phone as a call
//! siphon places itself (an originate group, each contact of an `{aor}` over
//! its own flow and Path), and once one answers, joins it to the caller with
//! the `bridge` verb's own path. The caller's own dialog is not touched until
//! the bridge re-INVITEs it.
//!
//! An answer is provisional until its bridge forms: the other phones ring on,
//! a phone answering meanwhile waits as a standby, and a bridge that fails
//! hangs its phone up and the dial carries on — the standbys in answer order,
//! then whatever still rings.
//!
//! On the caller's channel, in order:
//!
//! * `DialBranch` as each phone's INVITE goes out, and `DialBranchFailed` as
//!   each ends without being kept — the payloads a connecting dial reports,
//!   with cause `bridge_failed` for a phone whose bridge failed;
//! * `PlayStarted` with `origin: "ringback"` once a phone is alerting, unless
//!   the controller turned ringback off (and `PlayFinished` with the same
//!   origin when it ends);
//! * `BridgeFailed` for each bridge that failed;
//! * `DialAnswered` for the phone that was bridged, naming its branch and the
//!   `channel` it is now owned under — a channel siphon minted, registered to
//!   the same app and connection as the caller's, with the caller's
//!   control-loss policy — and then `ChannelBridged` on both channels;
//! * or `DialFailed`, with the ringback stopped first, the caller untouched.
//!
//! A phone's early media is not relayed to the caller in this version: the two
//! are not joined until one answers, and the ringback covers the wait.

use std::collections::HashMap;
use std::sync::Arc;

use crate::b2bua::actor::DialBranch;
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::{ChannelRef, ControlBus};
use crate::control::AdapterCommand;
use crate::dispatcher::{
    DialBridgeCaller, DialBridgeListener, DialBridgeRefusal, DialBridgeSender, DialBridgeSignal,
    DialBridgeStartError, DialError, DialShaping, DialTarget, DispatcherHandle,
    OriginateGroupFailure, OriginateGroupSink, OriginateGroupStrategy, OriginateGroupWinner,
    OriginateLegProgress,
};
use crate::rtpengine::client::PlayMediaSource;

use super::media::{play_accept, start_playback, PlayOptions};
use super::routing::OnAnswer;

/// The ringback a bridge dial plays when the controller names none.
pub(super) const DEFAULT_RINGBACK: &str = "ringback_eu";

/// Parse `args.ringback`: a tone preset or cadence (`"ringback_eu"`,
/// `"425/1000,0/4000*inf"`), `false` for none, or `true` / absent for
/// [`DEFAULT_RINGBACK`]. Only a bridge dial plays one — a connecting dial's
/// caller hears the phone's own ringing — so naming it on one is refused
/// rather than ignored.
pub(super) fn parse_ringback(
    value: Option<&serde_json::Value>,
    on_answer: OnAnswer,
) -> Result<Option<PlayMediaSource>, ControlResult> {
    let refusal = |reason: &str, message: String| {
        ControlResult::error_with_details(
            ControlErrorCode::BadRequest,
            message,
            serde_json::json!({
                "verb": "dial",
                "argument": "ringback",
                "reason": reason,
            }),
        )
    };
    let named = match value {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(true)) => Some(DEFAULT_RINGBACK.to_string()),
        Some(serde_json::Value::Bool(false)) => {
            if on_answer == OnAnswer::Connect {
                return Err(refusal(
                    "requires_bridge",
                    "dial args.ringback applies to on_answer \"bridge\" — a connecting dial's caller hears the phone's own ringing".to_string(),
                ));
            }
            return Ok(None);
        }
        Some(serde_json::Value::String(tone)) if !tone.trim().is_empty() => Some(tone.clone()),
        Some(_) => {
            return Err(refusal(
                "invalid_value",
                "dial args.ringback must be a tone preset or cadence string, or false for none"
                    .to_string(),
            ))
        }
    };
    match (on_answer, named) {
        (OnAnswer::Connect, None) => Ok(None),
        (OnAnswer::Connect, Some(_)) => Err(refusal(
            "requires_bridge",
            "dial args.ringback applies to on_answer \"bridge\" — a connecting dial's caller hears the phone's own ringing".to_string(),
        )),
        (OnAnswer::Bridge, named) => Ok(Some(PlayMediaSource::Tone(
            named.unwrap_or_else(|| DEFAULT_RINGBACK.to_string()),
        ))),
    }
}

/// A bridge dial, as the `dial` verb parsed it.
pub(super) struct BridgeDialRequest {
    pub(super) targets: Vec<DialTarget>,
    pub(super) shaping: DialShaping,
    pub(super) headers: Vec<(String, String)>,
    pub(super) strategy: String,
    pub(super) timeout_secs: u32,
    pub(super) ringback: Option<PlayMediaSource>,
}

/// Where a bridge dial runs: the bus that owns the caller's channel and the
/// dispatcher its phones are rung on. The running B2BUA's in production, a
/// test's own when it drives the verb end to end.
pub(super) fn rail(app: &str) -> Option<(Arc<ControlBus>, Arc<dyn DispatcherHandle>)> {
    #[cfg(test)]
    {
        if let Some(rail) = super::originate::staged::rail_for(app) {
            return Some((Arc::clone(&rail.bus), Arc::clone(&rail.dispatcher)));
        }
    }
    Some((ControlBus::global()?, dispatcher_for(app)))
}

/// The dispatcher an app's verbs act on: the running B2BUA in production, a
/// test's own when it drives the verb end to end.
pub(super) fn dispatcher_for(app: &str) -> Arc<dyn DispatcherHandle> {
    #[cfg(test)]
    {
        if let Some(rail) = super::originate::staged::rail_for(app) {
            return Arc::clone(&rail.dispatcher);
        }
    }
    let _ = app;
    Arc::new(crate::dispatcher::RunningDispatcher)
}

/// Ring the phones for an answered caller. The reply says the INVITEs are on
/// the wire; everything after arrives as events on the caller's channel.
pub(super) fn dial_bridge(
    channel: &ChannelRef,
    command: &AdapterCommand,
    request: BridgeDialRequest,
) -> ControlResult {
    let Some((bus, dispatcher)) = rail(&command.origin.app) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "control plane is not installed",
        );
    };
    let (Some(state), Some(runtime)) = (dispatcher.state(), dispatcher.runtime()) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "b2bua is not running — nothing to dial from",
        );
    };
    // The send path may spawn (TCP/TLS connect).
    let _enter = runtime.enter();

    let caller = match crate::dispatcher::dial_bridge_caller(state, &channel.sip_call_id) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let strategy = match request.strategy.to_ascii_lowercase().as_str() {
        // `single` is a sequential hunt of one, as for a connecting dial.
        "single" => OriginateGroupStrategy::Sequential,
        name => match OriginateGroupStrategy::parse(name) {
            Some(strategy) => strategy,
            None => {
                return ControlResult::error(
                    ControlErrorCode::UnsupportedVerb,
                    DialError::UnsupportedStrategy(request.strategy).to_string(),
                )
            }
        },
    };
    let total_timeout_secs = super::originate::default_total_timeout(
        strategy,
        request.timeout_secs,
        request.targets.len(),
    );
    let target_count = request.targets.len();
    let ring_timeout_secs = request.timeout_secs;
    let spec = match crate::dispatcher::dial_bridge_spec(
        &caller,
        crate::dispatcher::DialBridgePlan {
            targets: request.targets,
            shaping: request.shaping,
            headers: request.headers,
            strategy,
            ring_timeout_secs: request.timeout_secs,
            total_timeout_secs,
        },
    ) {
        Ok(spec) => spec,
        Err(error) => return ControlResult::error(ControlErrorCode::BadRequest, error.to_string()),
    };

    let (signals, receiver) = tokio::sync::mpsc::unbounded_channel();
    let sink = Arc::new(BridgeDialSink {
        bus: Arc::clone(&bus),
        caller_channel: channel.channel_id.clone(),
        signals: signals.clone(),
    });
    let ringback = request
        .ringback
        .as_ref()
        .map_or(serde_json::Value::Bool(false), |source| match source {
            PlayMediaSource::Tone(tone) => serde_json::Value::String(tone.clone()),
            _ => serde_json::Value::Bool(true),
        });
    runtime.spawn(
        Coordinator {
            listener: Arc::new(BridgedReporter {
                bus: Arc::clone(&bus),
                caller_channel: channel.channel_id.clone(),
            }),
            bus,
            dispatcher: Arc::clone(&dispatcher),
            caller_channel: channel.channel_id.clone(),
            caller: caller.clone(),
            ringback: request.ringback,
            phase: Ringback::Idle,
            signals: signals.downgrade(),
            bridging: None,
            standby: std::collections::VecDeque::new(),
            alerted: false,
        }
        .run(receiver),
    );
    match crate::dispatcher::dial_bridge_start(state, &caller, spec, sink, signals) {
        Ok((group_id, branches)) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "state": "dialing",
            "on_answer": OnAnswer::Bridge.as_str(),
            "group_id": group_id,
            "targets": target_count,
            "strategy": strategy.as_str(),
            "timeout": ring_timeout_secs,
            "total_timeout": total_timeout_secs,
            "ringback": ringback,
            "branches": branches
                .iter()
                .map(crate::dispatcher::dial_branch_identity)
                .collect::<Vec<_>>(),
        })),
        Err(DialBridgeStartError::Refused(refusal)) => refused(refusal),
        Err(DialBridgeStartError::Originate(error)) => super::originate::originate_error(error),
    }
}

/// A caller phones cannot be rung for: `invalid_state` naming why (the fix is
/// to answer it, anchor it, unbridge it or wait), `not_found` when it is gone.
fn refused(refusal: DialBridgeRefusal) -> ControlResult {
    let code = match refusal {
        DialBridgeRefusal::Gone => ControlErrorCode::NotFound,
        _ => ControlErrorCode::InvalidState,
    };
    let mut details = serde_json::json!({
        "verb": "dial",
        "on_answer": OnAnswer::Bridge.as_str(),
        "reason": refusal.reason(),
    });
    if let (DialBridgeRefusal::NotAnswered { call_state }, Some(fields)) =
        (&refusal, details.as_object_mut())
    {
        fields.insert("call_state".into(), call_state.clone().into());
    }
    ControlResult::error_with_details(code, refusal.to_string(), details)
}

/// `DialFailed`, in the shape a connecting dial reports it, with `cause`
/// saying how the group ended (`rejected`, `ring timeout`, `unsent`,
/// `caller_hangup`, ...).
fn dial_failed_payload(failure: &OriginateGroupFailure) -> serde_json::Value {
    serde_json::json!({
        "code": failure.code,
        "reason": failure.response,
        "cause": failure.reason,
        "timed_out": failure.reason == "ring timeout",
        "branches": failure
            .branches
            .iter()
            .map(crate::dispatcher::dial_branch_summary)
            .collect::<Vec<_>>(),
    })
}

/// Reports a bridge dial's phones on the caller's channel and hands what needs
/// the media engine or the bridge to the coordinator.
///
/// Called by the originate group outside its locks, in order, from whichever
/// thread moved the group. Its answers are confirmed ones: `answered` is
/// called for every phone that picks up, each provisional until bridged.
struct BridgeDialSink {
    bus: Arc<ControlBus>,
    caller_channel: String,
    signals: DialBridgeSender,
}

impl OriginateGroupSink for BridgeDialSink {
    fn branch_created(&self, _group_id: &str, branch: &DialBranch) {
        self.bus.publish_channel_event(
            &self.caller_channel,
            "DialBranch",
            crate::dispatcher::dial_branch_identity(branch),
        );
    }

    fn branch_progress(
        &self,
        _group_id: &str,
        _branch: &DialBranch,
        progress: &OriginateLegProgress,
    ) {
        // A phone alerting (RFC 3960 §2: 180, or early media in a 181-183)
        // is what the caller's ringback stands for.
        if (180..=183).contains(&progress.code) {
            let _ = self.signals.send(DialBridgeSignal::Alerting);
        }
    }

    fn branch_ended(&self, _group_id: &str, branch: &DialBranch) {
        self.bus.publish_channel_event(
            &self.caller_channel,
            "DialBranchFailed",
            crate::dispatcher::dial_branch_summary(branch),
        );
    }

    fn answered(&self, winner: &OriginateGroupWinner) {
        // Provisional: nothing is reported until the phone is bridged.
        let _ = self
            .signals
            .send(DialBridgeSignal::Answered(winner.clone()));
    }

    fn failed(&self, failure: &OriginateGroupFailure) {
        if failure.reason == crate::dispatcher::DIAL_BRIDGE_CALLER_GONE {
            // The caller is being torn down right now: no ringback to stop
            // (its media goes with it), and this is the last moment its
            // channel is there to hear why the phones stopped.
            self.bus.publish_channel_event(
                &self.caller_channel,
                "DialFailed",
                dial_failed_payload(failure),
            );
            return;
        }
        let _ = self.signals.send(DialBridgeSignal::Failed(failure.clone()));
    }
}

/// Reports the phone a bridge dial kept: told synchronously once it is
/// bridged, before the bridge's `ChannelBridged` goes out.
struct BridgedReporter {
    bus: Arc<ControlBus>,
    caller_channel: String,
}

impl DialBridgeListener for BridgedReporter {
    /// Register the phone under a channel of its own, owned exactly as the
    /// caller's is, and report it with `DialAnswered` — the one answer the dial
    /// kept. `channel` is `null` when the caller's channel had no live owner to
    /// register it to.
    fn bridged(&self, winner: &OriginateGroupWinner) {
        let channel = self
            .bus
            .channel_owner(&self.caller_channel)
            .map(|(connection, on_lost)| {
                let channel_id = format!("dial-{}", uuid::Uuid::new_v4().simple());
                self.bus.register_channel(
                    &channel_id,
                    &connection,
                    &winner.internal_call_id,
                    &winner.sip_call_id,
                    &on_lost,
                    HashMap::new(),
                );
                channel_id
            });
        let mut payload = crate::dispatcher::dial_answered_payload(&winner.branch);
        if let Some(fields) = payload.as_object_mut() {
            fields.insert(
                "channel".into(),
                channel.map_or(serde_json::Value::Null, serde_json::Value::String),
            );
        }
        self.bus
            .publish_channel_event(&self.caller_channel, "DialAnswered", payload);
    }
}

/// Where the caller's ringback stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ringback {
    /// Not playing: nothing is alerting yet, or a bridge stopped it.
    Idle,
    /// A phone is alerting, but the caller was still hearing a playback of the
    /// controller's; the ringback starts when that ends.
    Held,
    /// Playing, under this `play_id` when the engine named one.
    Playing { play_id: Option<u64> },
    /// Never wanted, refused by the engine, or the dial is over.
    Done,
}

/// Runs one bridge dial past its start: the ringback, the bridges, and the
/// events that need the engine or the bridge first. One task per dial,
/// handling its signals in order, so a ringback being started, a bridge being
/// put in motion and the dial failing can never cross.
///
/// Phones are bridged one at a time, in the order they answered. A phone that
/// answers while another's bridge is in motion waits as a standby: bridged
/// next when that bridge fails, released by the group when it forms.
struct Coordinator {
    bus: Arc<ControlBus>,
    dispatcher: Arc<dyn DispatcherHandle>,
    caller_channel: String,
    caller: DialBridgeCaller,
    ringback: Option<PlayMediaSource>,
    phase: Ringback,
    /// What a bridge's settlement is signalled on. Weak, so the dial's senders
    /// (the group's sink, the caller's entry, a bridge in motion) are what keep
    /// this task alive, never the task itself.
    signals: tokio::sync::mpsc::WeakUnboundedSender<DialBridgeSignal>,
    listener: Arc<BridgedReporter>,
    /// The phone whose bridge is in motion.
    bridging: Option<String>,
    /// Phones that answered meanwhile, in answer order.
    standby: std::collections::VecDeque<OriginateGroupWinner>,
    /// A phone has alerted, so the caller is owed ringback while any rings.
    alerted: bool,
}

impl Coordinator {
    async fn run(mut self, mut signals: tokio::sync::mpsc::UnboundedReceiver<DialBridgeSignal>) {
        // Ends on the dial's outcome, or when every sender is gone: the dial
        // never started, or the caller hung up and took it with it.
        while let Some(signal) = signals.recv().await {
            match signal {
                DialBridgeSignal::Alerting => {
                    self.alerted = true;
                    if self.bridging.is_none() {
                        self.start_ringback(Ringback::Idle).await;
                    }
                }
                DialBridgeSignal::PromptFinished => {
                    if self.bridging.is_none() {
                        self.start_ringback(Ringback::Held).await;
                    }
                }
                DialBridgeSignal::Answered(winner) => {
                    self.standby.push_back(winner);
                    if self.bridging.is_none() {
                        self.bridge_next().await;
                    }
                }
                DialBridgeSignal::BridgeFailed(winner) => {
                    if self.bridging.as_deref() == Some(winner.internal_call_id.as_str()) {
                        self.bridging = None;
                    }
                    self.bridge_next().await;
                }
                DialBridgeSignal::Bridged => {
                    // The group released every standby when it kept the answer.
                    self.standby.clear();
                    self.phase = Ringback::Done;
                    self.release();
                    break;
                }
                DialBridgeSignal::Failed(failure) => {
                    self.failed(&failure).await;
                    break;
                }
            }
        }
    }

    /// Bridge the next phone that answered, in answer order; a phone whose
    /// bridge cannot even start is released and the next one tried. With none
    /// left, the ringback resumes while phones still ring.
    async fn bridge_next(&mut self) {
        let dispatcher = Arc::clone(&self.dispatcher);
        let Some(state) = dispatcher.state() else {
            return;
        };
        while let Some(winner) = self.standby.pop_front() {
            let Some(signals) = self.signals.upgrade() else {
                return;
            };
            // The bridge re-points the caller's media; the ringback stops first,
            // so a bridge that fails early leaves nothing half-played.
            self.stop_ringback().await;
            self.phase = Ringback::Idle;
            self.bridging = Some(winner.internal_call_id.clone());
            let listener: Arc<dyn DialBridgeListener> = self.listener.clone();
            match crate::dispatcher::dial_bridge_join(
                state,
                &self.caller.sip_call_id,
                &winner,
                signals,
                listener,
            )
            .await
            {
                // In motion: its settlement is signalled.
                Ok(_) => return,
                Err(error) => {
                    tracing::warn!(
                        caller = %self.caller.sip_call_id,
                        phone = %winner.sip_call_id,
                        %error,
                        "control plane: dial — a phone answered but could not be bridged; releasing it"
                    );
                    self.bridging = None;
                    self.bus.publish_channel_event(
                        &self.caller_channel,
                        "BridgeFailed",
                        serde_json::json!({
                            "stage": "setup",
                            "reason": error.to_string(),
                            "peer_sip_call_id": winner.sip_call_id,
                        }),
                    );
                    crate::dispatcher::dial_bridge_refuse_phone(state, &winner, 500);
                }
            }
        }
        // Nobody left to bridge: the caller waits on the phones still ringing,
        // and hears ringback again once one has alerted.
        if self.alerted {
            self.start_ringback(Ringback::Idle).await;
        }
    }

    /// Start the ringback when it is wanted, the dial is still ringing, the
    /// phase is `from`, and the caller is not hearing anything else. A playback
    /// of the controller's is never talked over: the ringback is held until it
    /// ends.
    async fn start_ringback(&mut self, from: Ringback) {
        if self.phase != from {
            return;
        }
        let Some(source) = self.ringback.clone() else {
            self.phase = Ringback::Done;
            return;
        };
        let Some(state) = self.dispatcher.state() else {
            return;
        };
        // Only while phones still ring: not once the dial has concluded, even
        // before its outcome reaches this task.
        let ringing = state
            .dial_bridges
            .group_of(&self.caller.sip_call_id)
            .is_some_and(|group_id| state.originate_groups.contains(&group_id));
        if !ringing {
            return;
        }
        // The caller's session as the store has it now, not as it was when the
        // dial began: that is the one its audio is on.
        let Some((media_call_id, from_tag)) = self.caller_media(state.rtpengine_sessions.as_ref())
        else {
            tracing::info!(
                caller = %self.caller.sip_call_id,
                "control plane: dial — the caller has no media session any more (it is being torn down); no ringback"
            );
            self.phase = Ringback::Done;
            return;
        };
        if crate::rtpengine::MediaBackend::playback_started(&media_call_id, &from_tag) {
            self.phase = Ringback::Held;
            return;
        }
        let Some(backend) = state.rtpengine_set.clone() else {
            self.phase = Ringback::Done;
            return;
        };
        let result = start_playback(
            &backend,
            &media_call_id,
            &from_tag,
            &source,
            &PlayOptions::default(),
        )
        .await;
        let play_id = match &result {
            Ok(outcome) => outcome.play_id,
            Err(error) if error.is_call_not_found() => {
                // Not an engine fault: the session went away under the dial,
                // which only a teardown of the caller does.
                tracing::info!(
                    caller = %self.caller.sip_call_id,
                    %media_call_id,
                    %error,
                    "control plane: dial — the caller's media session is gone from the engine; no ringback"
                );
                self.phase = Ringback::Done;
                return;
            }
            Err(error) => {
                tracing::warn!(
                    caller = %self.caller.sip_call_id,
                    %media_call_id,
                    %error,
                    "control plane: dial — the media engine refused the ringback"
                );
                self.phase = Ringback::Done;
                return;
            }
        };
        self.phase = Ringback::Playing { play_id };
        if let Some(play_id) = play_id {
            state.dial_bridges.record_ringback(
                &self.caller.sip_call_id,
                &media_call_id,
                &from_tag,
                play_id,
            );
        }
        let (_, started) = play_accept(&self.caller_channel, &source, result);
        if let Some(mut payload) = started {
            if let Some(fields) = payload.as_object_mut() {
                fields.insert(
                    "origin".into(),
                    crate::dispatcher::DIAL_RINGBACK_ORIGIN.into(),
                );
            }
            self.bus
                .publish_channel_event(&self.caller_channel, "PlayStarted", payload);
        }
    }

    /// Stop the ringback, if it is playing — only it, when the engine named it.
    async fn stop_ringback(&mut self) {
        let Ringback::Playing { play_id } = self.phase else {
            return;
        };
        self.phase = Ringback::Done;
        let dispatcher = Arc::clone(&self.dispatcher);
        let Some(state) = dispatcher.state() else {
            return;
        };
        let (Some(backend), Some((media_call_id, from_tag))) = (
            state.rtpengine_set.clone(),
            self.caller_media(state.rtpengine_sessions.as_ref()),
        ) else {
            return;
        };
        if let Err(error) = backend.stop_media(&media_call_id, &from_tag, play_id).await {
            tracing::warn!(
                caller = %self.caller.sip_call_id,
                %error,
                "control plane: dial — the ringback could not be stopped"
            );
        }
    }

    /// The caller's media session as the store has it: its engine call-id and
    /// tag. `None` once the caller is being torn down.
    fn caller_media(
        &self,
        sessions: Option<&Arc<crate::rtpengine::MediaSessionStore>>,
    ) -> Option<(String, String)> {
        sessions
            .and_then(|sessions| sessions.get(&self.caller.sip_call_id))
            .map(|session| (session.rtpengine_id().to_string(), session.from_tag.clone()))
    }

    /// Nobody answered, or no answer could be bridged: the ringback stops
    /// before the controller hears so, so the prompt it plays next is not mixed
    /// with it. The caller is left answered and owned.
    async fn failed(&mut self, failure: &OriginateGroupFailure) {
        self.stop_ringback().await;
        self.phase = Ringback::Done;
        self.bus.publish_channel_event(
            &self.caller_channel,
            "DialFailed",
            dial_failed_payload(failure),
        );
        self.release();
    }

    /// The dial is over: the caller may dial again.
    fn release(&self) {
        if let Some(state) = self.dispatcher.state() {
            state.dial_bridges.release(&self.caller.sip_call_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b2bua::actor::{DialBranchCause, DialBranchOutcome};
    use crate::control::sip_adapter::routing::parse_on_answer;

    fn refusal_details(result: ControlResult) -> (ControlErrorCode, serde_json::Value) {
        match result {
            ControlResult::Error { code, details, .. } => (code, details.unwrap_or_default()),
            ControlResult::Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    #[test]
    fn on_answer_defaults_to_connect_and_names_only_two_values() {
        assert_eq!(parse_on_answer(None).ok(), Some(OnAnswer::Connect));
        assert_eq!(
            parse_on_answer(Some(&serde_json::Value::Null)).ok(),
            Some(OnAnswer::Connect)
        );
        assert_eq!(
            parse_on_answer(Some(&serde_json::json!("bridge"))).ok(),
            Some(OnAnswer::Bridge)
        );
        assert_eq!(
            parse_on_answer(Some(&serde_json::json!("connect"))).ok(),
            Some(OnAnswer::Connect)
        );
        for value in [serde_json::json!("Bridge"), serde_json::json!(true)] {
            let (code, details) = refusal_details(
                parse_on_answer(Some(&value)).expect_err("an unknown value is refused"),
            );
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert_eq!(details["argument"], "on_answer");
            assert_eq!(details["reason"], "unknown_value");
        }
    }

    #[test]
    fn a_bridge_dial_rings_back_with_the_default_unless_told_otherwise() {
        let tone = |value: Option<serde_json::Value>| match parse_ringback(
            value.as_ref(),
            OnAnswer::Bridge,
        )
        .expect("accepted")
        {
            None => None,
            Some(PlayMediaSource::Tone(tone)) => Some(tone),
            Some(other) => panic!("a ringback is a tone, got {other:?}"),
        };
        assert_eq!(tone(None).as_deref(), Some(DEFAULT_RINGBACK));
        assert_eq!(
            tone(Some(serde_json::json!(true))).as_deref(),
            Some(DEFAULT_RINGBACK)
        );
        assert_eq!(tone(Some(serde_json::json!(false))), None);
        assert_eq!(
            tone(Some(serde_json::json!("busy_na"))).as_deref(),
            Some("busy_na")
        );
        for value in [
            serde_json::json!(3),
            serde_json::json!(" "),
            serde_json::json!([]),
        ] {
            let (code, details) = refusal_details(
                parse_ringback(Some(&value), OnAnswer::Bridge).expect_err("refused"),
            );
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert_eq!(details["reason"], "invalid_value");
        }
    }

    #[test]
    fn a_connecting_dial_takes_no_ringback() {
        assert!(parse_ringback(None, OnAnswer::Connect)
            .expect("accepted")
            .is_none());
        for value in [serde_json::json!("ringback_eu"), serde_json::json!(false)] {
            let (code, details) = refusal_details(
                parse_ringback(Some(&value), OnAnswer::Connect).expect_err("refused"),
            );
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert_eq!(details["reason"], "requires_bridge");
        }
    }

    #[test]
    fn dial_failed_says_how_the_group_ended_and_lists_every_phone() {
        let branch = DialBranch {
            leg_id: "leg-1".to_string(),
            leg_sip_call_id: "leg-1@siphon".to_string(),
            target: "sip:201@198.51.100.7".to_string(),
            aor: None,
            outcome: Some(DialBranchOutcome::new(
                408,
                "Request Timeout",
                DialBranchCause::Timeout,
            )),
        };
        let payload = dial_failed_payload(&OriginateGroupFailure {
            group_id: "group".to_string(),
            reason: "ring timeout".to_string(),
            code: 408,
            response: "Request Timeout".to_string(),
            branches: vec![branch],
        });
        assert_eq!(payload["code"], 408);
        assert_eq!(payload["reason"], "Request Timeout");
        assert_eq!(payload["cause"], "ring timeout");
        assert_eq!(payload["timed_out"], true);
        assert_eq!(payload["branches"][0]["cause"], "timeout");
    }

    #[test]
    fn every_refusal_is_typed_with_the_verb_and_its_reason() {
        let (code, details) = refusal_details(refused(DialBridgeRefusal::Gone));
        assert_eq!(code, ControlErrorCode::NotFound);
        assert_eq!(details["reason"], "call_gone");
        let (code, details) = refusal_details(refused(DialBridgeRefusal::NotAnswered {
            call_state: "ringing".to_string(),
        }));
        assert_eq!(code, ControlErrorCode::InvalidState);
        assert_eq!(details["verb"], "dial");
        assert_eq!(details["on_answer"], "bridge");
        assert_eq!(details["call_state"], "ringing");
    }
}
