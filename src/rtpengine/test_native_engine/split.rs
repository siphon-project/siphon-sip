//! What the test engine does with the split bridge, as siphon-rtp 0.29.0
//! does it ([`siphon_rtp_proto::ws_split`]): on an engine that lists
//! `ws_split`, an attach on a call it holds isolates the parties and answers
//! `ws_split_started`; a second attach on the call is refused
//! `ws-split-already-bridged`, an unserved rate `ws-split-sample-rate`; a
//! detach ends it `detached` and is idempotent; deleting the call ends it
//! `call_deleted`. An end the test asks for ([`SplitModel::end`]) leaves the
//! call isolated, as the engine does, until a detach.
//!
//! It sends no events itself. It keeps the ones the real engine would have
//! sent ([`SplitModel::take_events`]), and a test passes them on.

use std::collections::HashMap;
use std::sync::Mutex;

use siphon_rtp_proto::{resolve_ws_split_sample_rate, Command, WsSplitEndReason};

use super::Recorded;
use crate::rtpengine::events::{RtpEngineEvent, WsSplitEnded, WsSplitStarted};

/// What `node_info` lists when the engine serves the split bridge.
pub(crate) const NATIVE_ENGINE_WS_SPLIT: &str = "ws_split";

/// One live split: the stream the engine named it, and whether its end has
/// been reported (the call is then still isolated, waiting for a detach).
#[derive(Debug, Clone)]
struct HeldSplit {
    stream_id: String,
    from_tag: String,
    ended: bool,
}

/// The splits the engine holds, keyed `(scope, call_id)`.
#[derive(Default)]
pub(super) struct SplitModel {
    held: Mutex<HashMap<(Option<String>, String), HeldSplit>>,
    /// The `ws_split_started` / `ws_split_ended` the engine would have sent,
    /// oldest first.
    events: Mutex<Vec<RtpEngineEvent>>,
    /// Refusal tokens for the next attaches, one each.
    refuse_next: Mutex<Vec<String>>,
}

impl SplitModel {
    /// What the engine records of a split command.
    pub(super) fn record(command: &Command) -> Option<Recorded> {
        match command {
            Command::AttachWsSplit(attach) => Some(Recorded {
                detail: Some(attach.ws_uri.clone()),
                sample_rate: attach.sample_rate,
                // What the engine read of the offerer's uplink options.
                profile: attach.offerer_profile.as_deref().cloned(),
                ..Recorded::new("attach_ws_split", &attach.call_id, &attach.from_tag)
            }),
            Command::DetachWsSplit(detach) => Some(Recorded::new(
                "detach_ws_split",
                &detach.call_id,
                &detach.from_tag,
            )),
            _ => None,
        }
    }

    /// The engine's refusal of a split command.
    pub(super) fn refusal(&self, command: &Command, scope: &Option<String>) -> Option<String> {
        let Command::AttachWsSplit(attach) = command else {
            return None;
        };
        if let Ok(mut tokens) = self.refuse_next.lock() {
            if !tokens.is_empty() {
                let token = tokens.remove(0);
                return Some(format!("attach_ws_split: {token}: refused for the test"));
            }
        }
        if let Err(error) = resolve_ws_split_sample_rate(attach.sample_rate) {
            return Some(format!("attach_ws_split: ws-split-sample-rate: {error}"));
        }
        let key = (scope.clone(), attach.call_id.clone());
        let held = self.held.lock().is_ok_and(|held| held.contains_key(&key));
        held.then(|| {
            "attach_ws_split: ws-split-already-bridged: the call already has a WebSocket \
             takeover or a split"
                .to_string()
        })
    }

    /// Keep what an accepted command changed, and the events it caused.
    pub(super) fn accepted(&self, command: &Command, scope: &Option<String>) {
        let (Ok(mut held), Ok(mut events)) = (self.held.lock(), self.events.lock()) else {
            return;
        };
        match command {
            Command::AttachWsSplit(attach) => {
                let stream_id = format!("split-{}", attach.call_id);
                held.insert(
                    (scope.clone(), attach.call_id.clone()),
                    HeldSplit {
                        stream_id: stream_id.clone(),
                        from_tag: attach.from_tag.clone(),
                        ended: false,
                    },
                );
                events.push(RtpEngineEvent::WsSplitStarted(WsSplitStarted {
                    call_id: attach.call_id.clone(),
                    from_tag: attach.from_tag.clone(),
                    stream_id,
                    ws_uri: attach.ws_uri.clone(),
                    sample_rate: attach.sample_rate.unwrap_or(16_000),
                }));
            }
            Command::DetachWsSplit(detach) => {
                if let Some(split) = held.remove(&(scope.clone(), detach.call_id.clone())) {
                    // An end already reported is not reported twice.
                    if !split.ended {
                        events.push(ended(&detach.call_id, split, WsSplitEndReason::Detached));
                    }
                }
            }
            Command::Delete {
                call_id,
                to_tag: None,
                ..
            } => {
                if let Some(split) = held.remove(&(scope.clone(), call_id.clone())) {
                    if !split.ended {
                        events.push(ended(call_id, split, WsSplitEndReason::CallDeleted));
                    }
                }
            }
            _ => {}
        }
    }

    /// End the split on `call_id` for `reason` as the engine would on its own
    /// (the bot closed the socket, a failure): the end is reported once and
    /// the call stays isolated, held until a detach.
    pub(super) fn end(&self, scope: &Option<String>, call_id: &str, reason: WsSplitEndReason) {
        let (Ok(mut held), Ok(mut events)) = (self.held.lock(), self.events.lock()) else {
            return;
        };
        if let Some(split) = held.get_mut(&(scope.clone(), call_id.to_string())) {
            if !split.ended {
                split.ended = true;
                events.push(ended(call_id, split.clone(), reason));
            }
        }
    }

    /// The events the engine would have sent since this was last asked.
    pub(super) fn take_events(&self) -> Vec<RtpEngineEvent> {
        self.events
            .lock()
            .map(|mut events| std::mem::take(&mut *events))
            .unwrap_or_default()
    }

    /// Refuse the next attach with `token`.
    pub(super) fn refuse_next(&self, token: &str) {
        if let Ok(mut tokens) = self.refuse_next.lock() {
            tokens.push(token.to_string());
        }
    }

    /// How many calls the engine holds isolated: attached, or ended and
    /// waiting for a detach.
    pub(super) fn count(&self) -> usize {
        self.held.lock().map(|held| held.len()).unwrap_or(0)
    }
}

fn ended(call_id: &str, split: HeldSplit, reason: WsSplitEndReason) -> RtpEngineEvent {
    RtpEngineEvent::WsSplitEnded(WsSplitEnded {
        call_id: call_id.to_string(),
        from_tag: split.from_tag,
        stream_id: split.stream_id,
        reason: crate::rtpengine::siphon_rtp::ws_split_end_reason_name(reason),
    })
}
