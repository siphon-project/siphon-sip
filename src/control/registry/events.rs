//! Event publishing: channel events to a channel's owning connection,
//! application-level events to every subscribed app, DTMF forwarding, and the
//! `StasisEnd` a teardown emits.

use std::sync::atomic::Ordering;

use tracing::debug;

use crate::control::protocol::EventFrame;

use super::queue::record_push_outcome;
use super::ControlBus;

impl ControlBus {
    /// Push an event to whichever channel owns `sip_call_id`, if any.
    ///
    /// The by-Call-ID twin of [`publish_to_channel`](Self::publish_to_channel),
    /// for signalling-path callers (the B2BUA response handler) that hold the
    /// SIP Call-ID and not the channel id. Idempotent no-op — never panics,
    /// never blocks — when the call is uncontrolled (the common case), the
    /// channel is orphaned, or its connection is gone. Adds and removes no
    /// per-call state of its own. Returns whether an event was queued.
    pub fn forward_channel_event(
        &self,
        sip_call_id: &str,
        event: &str,
        payload: serde_json::Value,
    ) -> bool {
        let Some(channel_id) = self.channel_id_for_sip_call_id(sip_call_id) else {
            return false;
        };
        let (app, call_actor_id) = match self.channels.get(&channel_id) {
            Some(entry) => (entry.app.clone(), entry.call_actor_id.clone()),
            None => return false,
        };
        self.publish_to_channel(
            &channel_id,
            EventFrame::new(
                event,
                &channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                payload,
            ),
        )
    }

    /// Publish an event to a channel's owning connection (non-blocking).
    /// Returns `false` if the channel is unknown or currently orphaned.
    ///
    /// A slow consumer loses events here rather than blocking the call path, so
    /// the drop is counted — see [`record_push_outcome`].
    pub fn publish_to_channel(&self, channel_id: &str, frame: EventFrame) -> bool {
        let (app, conn_id) = match self.channels.get(channel_id) {
            Some(entry) => (entry.app.clone(), entry.conn_id.load(Ordering::SeqCst)),
            None => return false,
        };
        if conn_id == 0 {
            return false;
        }
        match self.connection(&app, conn_id) {
            Some(conn) => {
                record_push_outcome(&app, conn.events.try_push_event(frame));
                true
            }
            None => false,
        }
    }

    /// Publish an application-level event to every app that asked for its class.
    ///
    /// Unlike [`Self::publish_to_channel`], this is not about a call anyone
    /// owns: a registration changing concerns the deployment, and the app that
    /// wants it on a dashboard may own no channel at all. It goes to *every*
    /// connection of a subscribed app rather than one picked round robin — a
    /// dashboard behind two replicas needs both to see it, and there is no call
    /// here whose ownership would decide which.
    ///
    /// Opt-in per app (`control.apps[].events`): without that, a registration
    /// storm would land on the event queue of an application that only places
    /// outbound calls.
    pub fn publish_app_event(&self, class: &str, event: &str, payload: serde_json::Value) {
        for (app, config) in self.app_config.iter() {
            if !config.events.iter().any(|wanted| wanted == class) {
                continue;
            }
            let Some(fanout) = self.apps.get(app) else {
                continue;
            };
            let frame = EventFrame::for_app(event, app, payload.clone());
            for conn in fanout.lock().iter() {
                record_push_outcome(app, conn.events.try_push_event(frame.clone()));
            }
        }
    }

    /// Emit a `StasisEnd` for the call identified by `sip_call_id` and remove
    /// the channel. Idempotent — a no-op when the call is not controlled.
    /// Called from every B2BUA teardown junction, guarded internally.
    pub fn on_call_terminated(&self, sip_call_id: &str, reason: &str) {
        self.on_call_terminated_with_cause(sip_call_id, reason, None, None);
    }

    /// [`on_call_terminated`](Self::on_call_terminated) carrying the SIP cause
    /// that ended the call.
    ///
    /// A leg siphon *placed* (`originate`) can die on a final non-2xx —
    /// `486 Busy Here`, `603 Decline` — and the controller has no other way to
    /// learn which: there is no A-leg the response was relayed to and no reply
    /// frame it belongs to (RFC 3261 §8.1.3.4 leaves the meaning to the code +
    /// reason phrase, so both are surfaced). `code`/`response` ride alongside
    /// `reason` in the `StasisEnd` payload and are omitted when absent, so an
    /// ordinary BYE-driven teardown emits exactly the frame it emitted before.
    pub fn on_call_terminated_with_cause(
        &self,
        sip_call_id: &str,
        reason: &str,
        code: Option<u16>,
        response: Option<&str>,
    ) {
        let Some(channel_id) = self.channel_id_for_sip_call_id(sip_call_id) else {
            return;
        };
        let (app, call_actor_id) = match self.channels.get(&channel_id) {
            Some(entry) => (entry.app.clone(), entry.call_actor_id.clone()),
            None => return,
        };
        // A transfer still awaiting its verdict can never get one once the call
        // is gone — report it before the StasisEnd that ends the stream.
        self.flush_outbound_transfer(&channel_id, sip_call_id);
        let mut payload = serde_json::json!({ "reason": reason });
        if let Some(object) = payload.as_object_mut() {
            if let Some(code) = code {
                object.insert("code".to_string(), serde_json::json!(code));
            }
            if let Some(response) = response {
                object.insert("response".to_string(), serde_json::json!(response));
            }
        }
        self.publish_to_channel(
            &channel_id,
            EventFrame::new(
                "StasisEnd",
                &channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                payload,
            ),
        );
        self.remove_channel(&channel_id);
        debug!(%channel_id, %sip_call_id, reason, ?code, "control plane: StasisEnd + channel removed");
    }

    /// Forward an in-band DTMF digit (detected by the media engine on a
    /// controlled call's leg) to the owning control connection as a
    /// `ChannelDtmfReceived` event, so an external IVR / AI app collects digits
    /// from the event stream. **Additive** — this runs alongside, never in place
    /// of, the in-process `@rtpengine.on_dtmf` dispatch; a controlled channel
    /// gets the event *in addition*.
    ///
    /// `sip_call_id` is the media call-id the DTMF event carries. For every
    /// control-anchored call that is byte-identical to the SIP Call-ID the
    /// channel is keyed on: the ordinary anchored path records the media session
    /// with `rtpengine_call_id == call_id == SIP Call-ID`, and the answer-first
    /// (AI-park) path anchors on the INVITE's Call-ID for both the media session
    /// and the channel. The only path that decouples the media call-id from the
    /// SIP Call-ID is a siphon-terminated REFER re-anchor, which never applies to
    /// a control-owned channel. So the direct
    /// [`channel_id_for_sip_call_id`](Self::channel_id_for_sip_call_id) lookup is
    /// correct for every controlled call.
    ///
    /// Idempotent no-op — never panics — when the call is uncontrolled (the
    /// common case), the channel is orphaned, or the owning connection is gone.
    /// Adds and removes **no** per-call state (a channel scan + an
    /// [`EventFrame`] push), so it needs no leak coverage of its own. Returns
    /// whether an event was pushed to a connection.
    pub fn forward_dtmf(
        &self,
        sip_call_id: &str,
        digit: &str,
        duration_ms: u32,
        volume: i32,
        from_tag: &str,
    ) -> bool {
        let Some(channel_id) = self.channel_id_for_sip_call_id(sip_call_id) else {
            return false;
        };
        let (app, call_actor_id) = match self.channels.get(&channel_id) {
            Some(entry) => (entry.app.clone(), entry.call_actor_id.clone()),
            None => return false,
        };
        let pushed = self.publish_to_channel(
            &channel_id,
            EventFrame::new(
                "ChannelDtmfReceived",
                &channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                serde_json::json!({
                    "digit": digit,
                    "duration_ms": duration_ms,
                    "volume": volume,
                    "from_tag": from_tag,
                }),
            ),
        );
        if pushed {
            debug!(%channel_id, %sip_call_id, digit, "control plane: ChannelDtmfReceived forwarded");
        }
        pushed
    }
}
