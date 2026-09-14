//! Outbound REFER verdicts (`TransferProgress` / `TransferCompleted` /
//! `TransferFailed`), the inbound `TransferRequested` event, and the teardown
//! flush that keeps a transfer from being left pending.

use tracing::debug;

use crate::control::protocol::EventFrame;

use super::ControlBus;

/// Where a verdict on a **siphon-originated (outbound) REFER** came from — the
/// `stage` field of the `TransferProgress` / `TransferCompleted` /
/// `TransferFailed` payload, and what decides which of those three names the
/// event carries.
///
/// The split exists because RFC 3515 §2.4.4 separates two things an application
/// otherwise cannot tell apart: a `2xx` to the REFER means the referee accepted
/// it **for processing**, while the transfer's real outcome arrives later on the
/// implicit subscription as a `message/sipfrag` NOTIFY. Reporting that `2xx` as
/// success would call every failed transfer a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    /// The referee returned a `2xx` to the REFER: accepted for processing only
    /// (RFC 3515 §2.4.4). Not an outcome — non-terminal.
    Accepted,
    /// The referee challenged the REFER (`401`/`407`) and siphon answered it
    /// with the call's credentials; the credentialed retry is on the wire.
    /// Non-terminal, and the signal that distinguishes "the peer challenged and
    /// we answered" from "the peer refused".
    Challenged,
    /// A non-terminating sipfrag NOTIFY reported progress (e.g. `100`, `180`).
    /// Non-terminal.
    Notify,
    /// A terminating sipfrag NOTIFY reported a `2xx` — the transfer completed.
    Transferred,
    /// A terminating sipfrag NOTIFY reported a `3xx`+ status — the referee tried
    /// the target and it failed.
    Refused,
    /// The referee answered the REFER itself with a final non-2xx: the transfer
    /// never started.
    Rejected,
    /// The REFER was challenged and the challenge could not be answered (no
    /// credentials configured, an unparseable challenge, or the retry cap).
    Unauthorized,
    /// The subscription ended without a usable sipfrag status. Terminal by
    /// construction: never report a transfer of unknown outcome as a success.
    NoOutcome,
    /// The call was torn down with the transfer still outstanding, so its
    /// subscription can never report (RFC 3515 §2.4.4 — the implicit
    /// subscription lives inside the dialog and dies with it).
    CallEnded,
}

impl TransferStage {
    /// The exact `stage` token on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransferStage::Accepted => "accepted",
            TransferStage::Challenged => "challenged",
            TransferStage::Notify => "notify",
            TransferStage::Transferred => "transferred",
            TransferStage::Refused => "refused",
            TransferStage::Rejected => "rejected",
            TransferStage::Unauthorized => "unauthorized",
            TransferStage::NoOutcome => "no_outcome",
            TransferStage::CallEnded => "call_ended",
        }
    }

    /// The event name this stage is published under.
    pub fn event_name(&self) -> &'static str {
        match self {
            TransferStage::Accepted | TransferStage::Challenged | TransferStage::Notify => {
                "TransferProgress"
            }
            TransferStage::Transferred => "TransferCompleted",
            TransferStage::Refused
            | TransferStage::Rejected
            | TransferStage::Unauthorized
            | TransferStage::NoOutcome
            | TransferStage::CallEnded => "TransferFailed",
        }
    }

    /// Whether this stage ends the transfer. Exactly one terminal stage is
    /// emitted per outbound REFER — after it, no further verdict follows.
    pub fn is_terminal(&self) -> bool {
        !matches!(
            self,
            TransferStage::Accepted | TransferStage::Challenged | TransferStage::Notify
        )
    }

    /// Classify the **final** response to a siphon-originated REFER.
    /// `challenge_answered` is whether a credentialed retry actually went out
    /// (`false` when there are no credentials, the challenge was unparseable, or
    /// the retry cap was reached).
    ///
    /// Note what a `2xx` maps to: [`Accepted`](Self::Accepted), which is
    /// non-terminal. RFC 3515 §2.4.4 makes a `2xx` to a REFER mean "accepted for
    /// processing" and nothing more, so mapping it to a completion would report
    /// every failed transfer as a success.
    pub fn from_refer_response(status_code: u16, challenge_answered: bool) -> Self {
        if (200..300).contains(&status_code) {
            return TransferStage::Accepted;
        }
        match (status_code, challenge_answered) {
            // RFC 3261 §22: a 401/407 is a challenge, not a refusal.
            (401 | 407, true) => TransferStage::Challenged,
            (401 | 407, false) => TransferStage::Unauthorized,
            _ => TransferStage::Rejected,
        }
    }

    /// Classify a `message/sipfrag` NOTIFY on the REFER subscription siphon owns
    /// (RFC 3515 §2.4.4). `terminated` is whether the `Subscription-State`
    /// header ends the subscription (RFC 6665 §4.1.3); `sipfrag` is the parsed
    /// Status-Line status, if the body carried one.
    ///
    /// Returns `None` only for a *non*-terminating NOTIFY with no readable
    /// status — nothing happened worth reporting. A terminating NOTIFY always
    /// yields a stage, including
    /// [`NoOutcome`](Self::NoOutcome): the subscription is over either way, so
    /// silence there would leave the transfer pending forever.
    pub fn from_notify(terminated: bool, sipfrag: Option<u16>) -> Option<Self> {
        match (terminated, sipfrag) {
            (true, Some(code)) if (200..300).contains(&code) => Some(TransferStage::Transferred),
            (true, Some(code)) if code >= 300 => Some(TransferStage::Refused),
            // A terminating NOTIFY still carrying a provisional (the referee gave
            // up mid-flight), or a body with no Status-Line at all.
            (true, _) => Some(TransferStage::NoOutcome),
            (false, Some(_)) => Some(TransferStage::Notify),
            (false, None) => None,
        }
    }
}

/// One verdict on a siphon-originated (outbound) REFER, published on the control
/// rail as `TransferProgress` / `TransferCompleted` / `TransferFailed`.
///
/// Deliberately **never** folded into the `refer` command reply: the command
/// reports only that the REFER was accepted for local processing; the far end's
/// verdict is an event. Conflating them would make the reply wait on the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutcome {
    /// Where the verdict came from.
    pub stage: TransferStage,
    /// The `Refer-To` URI the REFER carried, when known.
    pub refer_to: Option<String>,
    /// The SIP status this verdict rests on: the REFER's own response status for
    /// `accepted` / `challenged` / `rejected` / `unauthorized`, the sipfrag
    /// status for the NOTIFY-driven stages.
    pub code: Option<u16>,
    /// That status's reason phrase, when the peer supplied one.
    pub reason: Option<String>,
    /// Which REFER attempt this verdict is about, 1-based — attempt 1 is the
    /// first send, attempt N a credentialed retry (RFC 7616 §3.3). `None` for
    /// the NOTIFY-driven stages, where the REFER transaction is long over.
    pub attempt: Option<u32>,
}

impl TransferOutcome {
    /// A verdict at `stage` with nothing else known yet.
    pub fn new(stage: TransferStage) -> Self {
        Self {
            stage,
            refer_to: None,
            code: None,
            reason: None,
            attempt: None,
        }
    }

    /// Attach the transfer target.
    pub fn with_refer_to(mut self, refer_to: impl Into<String>) -> Self {
        self.refer_to = Some(refer_to.into());
        self
    }

    /// Attach the SIP status (and reason phrase, when the peer supplied one)
    /// this verdict rests on.
    pub fn with_status(mut self, code: u16, reason: &str) -> Self {
        self.code = Some(code);
        if !reason.is_empty() {
            self.reason = Some(reason.to_string());
        }
        self
    }

    /// Attach the 1-based REFER attempt number this verdict is about.
    pub fn with_attempt(mut self, attempt: u32) -> Self {
        self.attempt = Some(attempt);
        self
    }

    /// The event name this verdict publishes under.
    pub fn event_name(&self) -> &'static str {
        self.stage.event_name()
    }

    /// The event payload — the wire shape an SDK decodes.
    pub fn payload(&self) -> serde_json::Value {
        serde_json::json!({
            "stage": self.stage.as_str(),
            "refer_to": self.refer_to,
            "code": self.code,
            "reason": self.reason,
            "attempt": self.attempt,
        })
    }
}

impl ControlBus {
    /// Surface an inbound REFER on a *controlled* call to the owning control
    /// connection as a `TransferRequested` event, so the app owns the transfer
    /// decision (`accept_refer` / `reject_refer`) instead of the in-process
    /// `@b2bua.on_refer` path. The dispatcher holds the REFER un-answered until
    /// the app decides or the decision deadline applies the 603 default — this
    /// method only emits the event; the pending REFER (and its deadline) live in
    /// the dispatcher's store, so this adds and removes **no** per-call state of
    /// its own and needs no leak coverage here.
    ///
    /// `channel_id` is the caller-resolved owner
    /// ([`channel_id_for_sip_call_id`](Self::channel_id_for_sip_call_id));
    /// `from_tag` identifies the referring party. The payload is
    /// `{refer_to, replaces?, from_tag}` alongside the stable id triple. Returns
    /// whether the event was pushed (idempotent no-op / `false` when the channel
    /// is unknown or its connection is gone).
    pub fn forward_transfer_requested(
        &self,
        channel_id: &str,
        sip_call_id: &str,
        refer_to: &crate::sip::headers::refer::ReferTo,
        from_tag: Option<&str>,
    ) -> bool {
        let (app, call_actor_id) = match self.channels.get(channel_id) {
            Some(entry) => (entry.app.clone(), entry.call_actor_id.clone()),
            None => return false,
        };
        let replaces = refer_to.replaces.as_ref().map(|replaces| {
            serde_json::json!({
                "call_id": replaces.call_id,
                "from_tag": replaces.from_tag,
                "to_tag": replaces.to_tag,
                "early_only": replaces.early_only,
            })
        });
        let payload = serde_json::json!({
            "refer_to": refer_to.uri,
            "replaces": replaces,
            "from_tag": from_tag,
        });
        let pushed = self.publish_to_channel(
            channel_id,
            EventFrame::new(
                "TransferRequested",
                channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                payload,
            ),
        );
        if pushed {
            debug!(%channel_id, %sip_call_id, target = %refer_to.uri, "control plane: TransferRequested forwarded");
        }
        pushed
    }

    /// Publish one verdict on a **siphon-originated (outbound) REFER** — the
    /// `refer` verb's far-end outcome — to the owning control connection.
    ///
    /// The `refer` command reply says only that the REFER was accepted for local
    /// processing; this is where the application learns what actually happened.
    /// Three event names come out of one call, chosen by
    /// [`TransferStage::event_name`]: `TransferProgress` while the transfer is
    /// still moving, then exactly one of `TransferCompleted` / `TransferFailed`.
    ///
    /// RFC 3515 §2.4.4 is why that split has to exist: a `2xx` to the REFER is
    /// "accepted for processing", *not* "transferred" — the real outcome arrives
    /// afterwards on the implicit subscription as a `message/sipfrag` NOTIFY.
    ///
    /// A non-terminal verdict arms the channel's teardown flush; a terminal one
    /// disarms it (see [`Self::flush_outbound_transfer`]), so a transfer is
    /// never left pending and exactly one terminal event is emitted per REFER.
    /// The only state involved is that one `Option<String>` on the channel
    /// entry, which drains with the channel — no leak coverage of its own.
    ///
    /// Idempotent no-op — never panics — when the call is uncontrolled (the
    /// common case) or the owning connection is gone. Returns whether an event
    /// was pushed.
    pub fn forward_transfer_outcome(&self, sip_call_id: &str, outcome: &TransferOutcome) -> bool {
        let Some(channel_id) = self.channel_id_for_sip_call_id(sip_call_id) else {
            return false;
        };
        let (app, call_actor_id) = match self.channels.get(&channel_id) {
            Some(entry) => {
                // Arm / disarm the teardown flush before publishing, so a
                // teardown racing this event cannot double-report the transfer.
                let mut pending = match entry.outbound_transfer.lock() {
                    Ok(pending) => pending,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *pending = if outcome.stage.is_terminal() {
                    None
                } else {
                    outcome.refer_to.clone().or_else(|| pending.clone())
                };
                drop(pending);
                (entry.app.clone(), entry.call_actor_id.clone())
            }
            None => return false,
        };
        let pushed = self.publish_to_channel(
            &channel_id,
            EventFrame::new(
                outcome.event_name(),
                &channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                outcome.payload(),
            ),
        );
        if pushed {
            debug!(
                %channel_id,
                %sip_call_id,
                event = outcome.event_name(),
                stage = outcome.stage.as_str(),
                code = outcome.code,
                "control plane: outbound REFER verdict forwarded"
            );
        }
        pushed
    }

    /// Emit the terminal verdict for an outbound REFER still outstanding on a
    /// channel that is about to go away, then disarm.
    ///
    /// The transfer's implicit subscription lives inside the dialog (RFC 3515
    /// §2.4.4), so once the call is gone no sipfrag NOTIFY can ever report it.
    /// Without this an application that asked for a transfer and then lost the
    /// call would wait forever for a verdict. Runs on every channel-removal
    /// funnel, ahead of the `StasisEnd` that ends the channel.
    pub(super) fn flush_outbound_transfer(&self, channel_id: &str, sip_call_id: &str) {
        let (app, call_actor_id, refer_to) = match self.channels.get(channel_id) {
            Some(entry) => {
                let refer_to = match entry.outbound_transfer.lock() {
                    Ok(mut pending) => pending.take(),
                    Err(poisoned) => poisoned.into_inner().take(),
                };
                match refer_to {
                    Some(refer_to) => (entry.app.clone(), entry.call_actor_id.clone(), refer_to),
                    None => return,
                }
            }
            None => return,
        };
        let outcome = TransferOutcome::new(TransferStage::CallEnded).with_refer_to(refer_to);
        self.publish_to_channel(
            channel_id,
            EventFrame::new(
                outcome.event_name(),
                channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                outcome.payload(),
            ),
        );
        debug!(
            %channel_id,
            %sip_call_id,
            "control plane: outbound REFER left outstanding by teardown — reported failed"
        );
    }
}
