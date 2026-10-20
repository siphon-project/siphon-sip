//! Application-level events on the SIP facade.
//!
//! An app that lists a class in `control.apps[].events` (`registration`,
//! `dialog`) is pushed events about the deployment rather than a channel. Their
//! frames carry no channel, so the facade's per-call routing has nowhere to put
//! them; they go to the handler registered here instead.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::debug;

use siphon_control_proto::sip::{
    DialogStateChangedPayload, OutboundRegistrationsReply, RegistrantChangedPayload,
    RegistrationChangedPayload, RegistrationsReply, SipEvent,
};
use siphon_control_proto::verbs::{OUTBOUND_REGISTRATIONS, REGISTRATIONS};
use siphon_control_proto::EventFrame;

use crate::error::ControlError;

use super::{lock, SipClient, SipFacade};

/// An application-level event: pushed to every connection of an app that opted
/// into its class (`control.apps[].events`), about the deployment rather than a
/// channel — `RegistrationChanged`, `DialogStateChanged`. The frame carries no
/// channel, so it reaches the app's [`SipClient::set_app_event_handler`] rather
/// than any call's stream.
#[derive(Debug, Clone)]
pub struct AppEvent {
    /// The parsed event kind.
    pub kind: SipEvent,
    /// The event-specific payload.
    pub payload: serde_json::Value,
    /// The raw frame.
    pub frame: EventFrame,
}

impl AppEvent {
    fn from_frame(frame: EventFrame) -> Self {
        Self {
            kind: frame.sip_kind(),
            payload: frame.payload.clone(),
            frame,
        }
    }

    /// The typed [`DialogStateChangedPayload`] when this is a
    /// [`SipEvent::DialogStateChanged`] event, else `None`: one dialog of a
    /// registered AoR moved to a new RFC 4235 state.
    pub fn dialog_state(&self) -> Option<DialogStateChangedPayload> {
        if self.kind != SipEvent::DialogStateChanged {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`RegistrationChangedPayload`] when this is a
    /// [`SipEvent::RegistrationChanged`] event, else `None`.
    pub fn registration(&self) -> Option<RegistrationChangedPayload> {
        if self.kind != SipEvent::RegistrationChanged {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`RegistrantChangedPayload`] when this is a
    /// [`SipEvent::RegistrantChanged`] event, else `None`.
    pub fn registrant(&self) -> Option<RegistrantChangedPayload> {
        if self.kind != SipEvent::RegistrantChanged {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }
}

pub(super) type AppEventHandler = Arc<dyn Fn(AppEvent) + Send + Sync>;

/// The `next` of a page that followed `after`: pages run in AoR order, so a
/// `next` that does not move past `after` would ask for the same page forever.
fn advancing(after: &str, next: Option<String>) -> Result<Option<String>, ControlError> {
    match next {
        Some(next) if next.as_str() <= after => Err(ControlError::Serde(format!(
            "a state page after {after:?} named {next:?} as the next, which does not advance"
        ))),
        next => Ok(next),
    }
}

/// A pull-style stream of application-level events (see
/// [`SipClient::app_events`]).
pub struct AppEventStream {
    receiver: mpsc::UnboundedReceiver<AppEvent>,
}

impl AppEventStream {
    /// Await the next application-level event. `None` once the client shuts
    /// down.
    pub async fn next(&mut self) -> Option<AppEvent> {
        self.receiver.recv().await
    }
}

impl SipFacade {
    pub(super) fn set_app_handler(&self, handler: AppEventHandler) {
        *lock(&self.app_handler) = Some(handler);
    }

    /// Hand a channel-less frame to the app event handler, if one is set.
    pub(super) fn deliver_app_event(&self, frame: EventFrame) {
        match lock(&self.app_handler).clone() {
            Some(handler) => handler(AppEvent::from_frame(frame)),
            None => debug!(event = %frame.event, "control(sip): no app event handler — dropped"),
        }
    }
}

impl SipClient {
    /// Register a handler for application-level events — the ones an app opts
    /// into with `control.apps[].events` (`RegistrationChanged`,
    /// `DialogStateChanged`), which concern no channel and so reach no call.
    /// Called on the client's receive path: keep it quick, or hand the event
    /// off. Replaces any previous handler.
    pub fn set_app_event_handler<F>(&self, handler: F)
    where
        F: Fn(AppEvent) + Send + Sync + 'static,
    {
        self.facade.set_app_handler(Arc::new(handler));
    }

    /// Everything the registrar holds now, and the `seq` it is current to
    /// (`registrations`; the app must subscribe to `registration`). Fetches
    /// every page and returns them as one, with the first page's `seq`.
    ///
    /// Ask on connecting and whenever `RegistrationChanged.seq` skips a
    /// number: replace your copy with the reply (an AoR not in it has no
    /// binding) and apply only events numbered above [`RegistrationsReply::seq`].
    pub async fn registrations(&self) -> Result<RegistrationsReply, ControlError> {
        let mut whole: RegistrationsReply =
            serde_json::from_value(self.state_page(REGISTRATIONS, None).await?)?;
        while let Some(after) = whole.next.take() {
            let page: RegistrationsReply =
                serde_json::from_value(self.state_page(REGISTRATIONS, Some(&after)).await?)?;
            whole.registrations.extend(page.registrations);
            whole.next = advancing(&after, page.next)?;
        }
        Ok(whole)
    }

    /// Every outbound registration's state, and its `seq`
    /// (`outbound_registrations`; the app must subscribe to
    /// `outbound_registration`). Fetches every page, as
    /// [`Self::registrations`] does.
    pub async fn outbound_registrations(&self) -> Result<OutboundRegistrationsReply, ControlError> {
        let mut whole: OutboundRegistrationsReply =
            serde_json::from_value(self.state_page(OUTBOUND_REGISTRATIONS, None).await?)?;
        while let Some(after) = whole.next.take() {
            let page: OutboundRegistrationsReply = serde_json::from_value(
                self.state_page(OUTBOUND_REGISTRATIONS, Some(&after))
                    .await?,
            )?;
            whole.registrations.extend(page.registrations);
            whole.next = advancing(&after, page.next)?;
        }
        Ok(whole)
    }

    /// One page of a state verb, from `after` (exclusive).
    async fn state_page(
        &self,
        verb: &str,
        after: Option<&str>,
    ) -> Result<serde_json::Value, ControlError> {
        let args = match after {
            Some(after) => serde_json::json!({ "after": after }),
            None => serde_json::Value::Null,
        };
        self.client
            .command(None, verb, serde_json::Value::Null, args)
            .await
    }

    /// A pull-style stream of application-level events (alternative to
    /// [`Self::set_app_event_handler`], which it replaces).
    pub fn app_events(&self) -> AppEventStream {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.facade.set_app_handler(Arc::new(move |event| {
            let _ = sender.send(event);
        }));
        AppEventStream { receiver }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::CommandTransport;
    use futures_util::future::BoxFuture;
    use serde_json::json;
    use std::sync::Mutex;

    /// A transport nothing in these tests commands.
    struct Unused;

    impl CommandTransport for Unused {
        fn command(
            &self,
            _module: Option<String>,
            _verb: String,
            _target: serde_json::Value,
            _args: serde_json::Value,
        ) -> BoxFuture<'_, Result<serde_json::Value, crate::error::ControlError>> {
            Box::pin(async { Ok(serde_json::Value::Null) })
        }
    }

    fn recorder(_result: serde_json::Value) -> Arc<Unused> {
        Arc::new(Unused)
    }

    #[test]
    fn a_next_page_must_move_past_the_last() {
        assert_eq!(
            advancing("sip:a@example.com", Some("sip:b@example.com".to_string()))
                .expect("advances"),
            Some("sip:b@example.com".to_string())
        );
        assert_eq!(
            advancing("sip:a@example.com", None).expect("last page"),
            None
        );
        assert!(advancing("sip:b@example.com", Some("sip:b@example.com".to_string())).is_err());
        assert!(advancing("sip:b@example.com", Some("sip:a@example.com".to_string())).is_err());
    }

    /// A frame with no channel is an application-level event: it reaches the
    /// app event handler, typed, and never a call's stream.
    #[test]
    fn a_channel_less_frame_reaches_the_app_event_handler() {
        let facade = SipFacade::new();
        let received = Arc::new(Mutex::new(Vec::<AppEvent>::new()));
        let sink = Arc::clone(&received);
        facade.set_app_handler(Arc::new(move |event| lock(&sink).push(event)));
        let transport: Arc<dyn CommandTransport> = recorder(json!({}));

        let mut frame = EventFrame::new(
            "DialogStateChanged",
            "unused",
            "presence",
            "unused",
            "unused",
            json!({
                "aor": "sip:201@example.com",
                "state": "confirmed",
                "direction": "recipient",
                "leg_id": "leg-1",
                "call_id": "b1@host",
                "local_tag": "phone-tag",
                "remote_tag": "server-tag",
                "remote_identity": {"uri": "sip:15550100042@example.com", "display_name": null},
            }),
        );
        frame.channel = None;
        frame.call_id = None;
        frame.sip_call_id = None;
        facade.handle_event(frame, &transport);

        let events = lock(&received).clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, SipEvent::DialogStateChanged);
        let payload = events[0].dialog_state().expect("typed payload");
        assert_eq!(payload.aor, "sip:201@example.com");
        assert_eq!(
            payload.state,
            siphon_control_proto::sip::DialogState::Confirmed
        );

        let mut registration = EventFrame::new(
            "RegistrationChanged",
            "unused",
            "presence",
            "unused",
            "unused",
            json!({
                "seq": 9,
                "aor": "sip:201@example.com",
                "event": "registered",
                "contacts": [{"uri": "sip:201@203.0.113.40", "expires": 600, "q": 1.0,
                              "received": "sip:192.0.2.50:5060;transport=udp"}],
            }),
        );
        registration.channel = None;
        registration.call_id = None;
        registration.sip_call_id = None;
        facade.handle_event(registration, &transport);
        let events = lock(&received).clone();
        assert_eq!(events.len(), 2);
        let payload = events[1].registration().expect("typed payload");
        assert_eq!(payload.seq, Some(9));
        assert_eq!(
            payload.contacts[0].received.as_deref(),
            Some("sip:192.0.2.50:5060;transport=udp")
        );
        assert!(events[1].registrant().is_none());
        assert!(events[1].dialog_state().is_none());

        // A channel event for a channel nobody holds is not an app event.
        let channel_frame = EventFrame::new(
            "ChannelStateChange",
            "ch9",
            "presence",
            "call",
            "sip@host",
            json!({"state": "answered"}),
        );
        facade.handle_event(channel_frame, &transport);
        assert_eq!(lock(&received).len(), 2);
    }
}
