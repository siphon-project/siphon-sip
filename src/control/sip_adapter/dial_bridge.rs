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
//! On the caller's channel, in order:
//!
//! * `DialBranch` as each phone's INVITE goes out, and `DialBranchFailed` as
//!   each ends unanswered — the payloads a connecting dial reports;
//! * `PlayStarted` with `origin: "ringback"` once a phone is alerting, unless
//!   the controller turned ringback off (and `PlayFinished` with the same
//!   origin when it ends);
//! * `DialAnswered` naming the answered phone's branch and the `channel` it is
//!   now owned under — a channel siphon minted, registered to the same app and
//!   connection as the caller's, with the caller's control-loss policy; then
//!   `ChannelBridged` on both channels once the media meets, or `BridgeFailed`,
//!   after which the phone is hung up and the caller stays answered;
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
    DialBridgeCaller, DialBridgeRefusal, DialBridgeSender, DialBridgeSignal, DialBridgeStartError,
    DialError, DialShaping, DialTarget, DispatcherHandle, OriginateGroupFailure,
    OriginateGroupSink, OriginateGroupStrategy, OriginateGroupWinner, OriginateLegProgress,
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
fn rail(app: &str) -> Option<(Arc<ControlBus>, Arc<dyn DispatcherHandle>)> {
    #[cfg(test)]
    {
        if let Some(rail) = super::originate::staged::rail_for(app) {
            return Some((Arc::clone(&rail.bus), Arc::clone(&rail.dispatcher)));
        }
    }
    let _ = app;
    Some((
        ControlBus::global()?,
        Arc::new(crate::dispatcher::RunningDispatcher),
    ))
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
            bus,
            dispatcher: Arc::clone(&dispatcher),
            caller_channel: channel.channel_id.clone(),
            caller: caller.clone(),
            ringback: request.ringback,
            phase: Ringback::Idle,
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
/// thread moved the group; `answered` or `failed` exactly once and last.
struct BridgeDialSink {
    bus: Arc<ControlBus>,
    caller_channel: String,
    signals: DialBridgeSender,
}

impl BridgeDialSink {
    /// Register the phone that answered under a channel of its own, owned
    /// exactly as the caller's is. `None` when the caller's channel has no live
    /// owner — nobody would be there to drive the phone.
    fn register_winner(&self, winner: &OriginateGroupWinner) -> Option<String> {
        let (connection, on_lost) = self.bus.channel_owner(&self.caller_channel)?;
        let channel_id = format!("dial-{}", uuid::Uuid::new_v4().simple());
        self.bus.register_channel(
            &channel_id,
            &connection,
            &winner.internal_call_id,
            &winner.sip_call_id,
            &on_lost,
            HashMap::new(),
        );
        Some(channel_id)
    }
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
        // Registered here, before the phone's own answered state change is
        // published, so that event reaches the new channel.
        let channel = self.register_winner(winner);
        if let Some(channel_id) = &channel {
            let mut payload = crate::dispatcher::dial_answered_payload(&winner.branch);
            if let Some(fields) = payload.as_object_mut() {
                fields.insert("channel".into(), channel_id.clone().into());
            }
            self.bus
                .publish_channel_event(&self.caller_channel, "DialAnswered", payload);
        }
        let _ = self.signals.send(DialBridgeSignal::Answered {
            winner: winner.clone(),
            channel,
        });
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

/// Where the caller's ringback stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ringback {
    /// Nothing is alerting yet.
    Idle,
    /// A phone is alerting, but the caller was still hearing a playback of the
    /// controller's; the ringback starts when that ends.
    Held,
    /// Playing, under this `play_id` when the engine named one.
    Playing { play_id: Option<u64> },
    /// Stopped, never wanted, or refused by the engine.
    Done,
}

/// Runs one bridge dial past its start: the ringback, the bridge, and the two
/// events that need the engine first. One task per dial, handling its signals
/// in order, so a ringback being started and the dial failing can never cross.
struct Coordinator {
    bus: Arc<ControlBus>,
    dispatcher: Arc<dyn DispatcherHandle>,
    caller_channel: String,
    caller: DialBridgeCaller,
    ringback: Option<PlayMediaSource>,
    phase: Ringback,
}

impl Coordinator {
    async fn run(mut self, mut signals: tokio::sync::mpsc::UnboundedReceiver<DialBridgeSignal>) {
        // Ends on the dial's outcome, or when every sender is gone: the dial
        // never started, or the caller hung up and took it with it.
        while let Some(signal) = signals.recv().await {
            match signal {
                DialBridgeSignal::Alerting => self.start_ringback(Ringback::Idle).await,
                DialBridgeSignal::PromptFinished => self.start_ringback(Ringback::Held).await,
                DialBridgeSignal::Answered { winner, channel } => {
                    self.answered(&winner, channel).await;
                    break;
                }
                DialBridgeSignal::Failed(failure) => {
                    self.failed(&failure).await;
                    break;
                }
            }
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
        if !state.dial_bridges.is_ringing(&self.caller.sip_call_id) {
            return;
        }
        if crate::rtpengine::MediaBackend::playback_started(
            &self.caller.media_call_id,
            &self.caller.from_tag,
        ) {
            self.phase = Ringback::Held;
            return;
        }
        let Some(backend) = state.rtpengine_set.clone() else {
            self.phase = Ringback::Done;
            return;
        };
        let result = start_playback(
            &backend,
            &self.caller.media_call_id,
            &self.caller.from_tag,
            &source,
            &PlayOptions::default(),
        )
        .await;
        let play_id = match &result {
            Ok(outcome) => outcome.play_id,
            Err(error) => {
                tracing::warn!(
                    caller = %self.caller.sip_call_id,
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
                &self.caller.media_call_id,
                &self.caller.from_tag,
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
            self.phase = Ringback::Done;
            return;
        };
        self.phase = Ringback::Done;
        let Some(backend) = self
            .dispatcher
            .state()
            .and_then(|state| state.rtpengine_set.clone())
        else {
            return;
        };
        if let Err(error) = backend
            .stop_media(&self.caller.media_call_id, &self.caller.from_tag, play_id)
            .await
        {
            tracing::warn!(
                caller = %self.caller.sip_call_id,
                %error,
                "control plane: dial — the ringback could not be stopped"
            );
        }
    }

    /// Nobody answered: the ringback stops before the controller hears so, so
    /// the prompt it plays next is not mixed with it. The caller is left
    /// answered and owned.
    async fn failed(&mut self, failure: &OriginateGroupFailure) {
        self.stop_ringback().await;
        self.bus.publish_channel_event(
            &self.caller_channel,
            "DialFailed",
            dial_failed_payload(failure),
        );
        self.release();
    }

    /// A phone answered: bridge it to the caller. The bridge stops the ringback
    /// itself before it re-points the caller's media.
    async fn answered(&mut self, winner: &OriginateGroupWinner, channel: Option<String>) {
        let dispatcher = Arc::clone(&self.dispatcher);
        let Some(state) = dispatcher.state() else {
            return;
        };
        let Some(winner_channel) = channel else {
            // The caller's controller is gone: nobody could drive the phone.
            self.stop_ringback().await;
            crate::dispatcher::dial_bridge_release_phone(state, &winner.internal_call_id);
            self.release();
            return;
        };
        match crate::dispatcher::dial_bridge_join(state, &self.caller.sip_call_id, winner).await {
            Ok(_) => self.phase = Ringback::Done,
            Err(error) => {
                tracing::warn!(
                    caller = %self.caller.sip_call_id,
                    phone = %winner.sip_call_id,
                    %error,
                    "control plane: dial — the phone answered but could not be bridged; releasing it"
                );
                self.stop_ringback().await;
                let reason = error.to_string();
                self.bus.publish_channel_event(
                    &self.caller_channel,
                    "BridgeFailed",
                    serde_json::json!({
                        "stage": "setup",
                        "reason": reason,
                        "peer_sip_call_id": winner.sip_call_id,
                    }),
                );
                self.bus.publish_channel_event(
                    &winner_channel,
                    "BridgeFailed",
                    serde_json::json!({
                        "stage": "setup",
                        "reason": reason,
                        "peer_sip_call_id": self.caller.sip_call_id,
                    }),
                );
                crate::dispatcher::dial_bridge_release_phone(state, &winner.internal_call_id);
            }
        }
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
