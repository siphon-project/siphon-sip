//! The **SIP facade** over the protocol-agnostic core.
//!
//! [`Call`] is a typed handle whose verbs (`answer`/`progress`/`hangup`/`refer`/
//! …) are thin wrappers that send `command("sip", …)` on the underlying core and
//! await the correlated reply. The `StasisStart`→[`Call`] dispatch and the
//! `on_call` handler live here (they are SIP/ARI concepts) on top of the core's
//! generic event stream, so a future `smpp::Session` / `ss7::Dialog` is an
//! additive sibling module over the same core.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::future::BoxFuture;
use serde_json::json;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::{debug, warn};

use siphon_control_proto::sip::{SipEvent, SipVerb};
use siphon_control_proto::verbs::MODULE_SIP;
use siphon_control_proto::{ChannelSnapshot, EventFrame};

use crate::client::{ClientConfig, ClientEvent, ControlClient};
use crate::error::ControlError;
use crate::server::{ControlServer, ServerConfig};
use crate::session::CommandTransport;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// Call handle
// ---------------------------------------------------------------------------

/// One event delivered to a call's stream (`ChannelStateChange`,
/// `ChannelHangupRequest`, `StasisEnd`, …).
#[derive(Debug, Clone)]
pub struct CallEvent {
    /// The parsed event kind.
    pub kind: SipEvent,
    /// The event-specific payload.
    pub payload: serde_json::Value,
    /// The raw frame (for fields not surfaced above).
    pub frame: EventFrame,
}

impl CallEvent {
    fn from_frame(frame: EventFrame) -> Self {
        Self {
            kind: frame.sip_kind(),
            payload: frame.payload.clone(),
            frame,
        }
    }
}

struct CallInner {
    commander: Arc<dyn CommandTransport>,
    channel_id: String,
    call_id: Option<String>,
    sip_call_id: Option<String>,
    app: Option<String>,
    payload: serde_json::Value,
    reattached: bool,
    events: AsyncMutex<mpsc::UnboundedReceiver<CallEvent>>,
}

/// A handed-over SIP call. Cheap to clone (shares one connection + event stream).
#[derive(Clone)]
pub struct Call {
    inner: Arc<CallInner>,
}

impl Call {
    fn from_event(
        commander: Arc<dyn CommandTransport>,
        frame: &EventFrame,
        events: mpsc::UnboundedReceiver<CallEvent>,
        reattached: bool,
    ) -> Self {
        Self {
            inner: Arc::new(CallInner {
                commander,
                channel_id: frame.channel.clone().unwrap_or_default(),
                call_id: frame.call_id.clone(),
                sip_call_id: frame.sip_call_id.clone(),
                app: frame.app.clone(),
                payload: frame.payload.clone(),
                reattached,
                events: AsyncMutex::new(events),
            }),
        }
    }

    fn from_snapshot(
        commander: Arc<dyn CommandTransport>,
        snapshot: ChannelSnapshot,
        events: mpsc::UnboundedReceiver<CallEvent>,
    ) -> Self {
        let payload = serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null);
        Self {
            inner: Arc::new(CallInner {
                commander,
                channel_id: snapshot.channel,
                call_id: Some(snapshot.call_id),
                sip_call_id: Some(snapshot.sip_call_id),
                app: None,
                payload,
                reattached: true,
                events: AsyncMutex::new(events),
            }),
        }
    }

    // --- identity / context ------------------------------------------------

    /// The leg-scoped channel id — the address for every verb on this call.
    pub fn channel_id(&self) -> &str {
        &self.inner.channel_id
    }

    /// The internal `CallActor` id (the grouping key across legs), if known.
    pub fn call_id(&self) -> Option<&str> {
        self.inner.call_id.as_deref()
    }

    /// The per-leg SIP `Call-ID` — byte-identical to the CDR / HEP join key.
    pub fn sip_call_id(&self) -> Option<&str> {
        self.inner.sip_call_id.as_deref()
    }

    /// The application this call was handed to.
    pub fn app(&self) -> Option<&str> {
        self.inner.app.as_deref()
    }

    /// The `StasisStart` payload (full SIP context) — or the `resync` snapshot
    /// when [`Call::is_reattached`] is true.
    pub fn payload(&self) -> &serde_json::Value {
        &self.inner.payload
    }

    /// True when this call came from a `resync` re-attach after a reconnect.
    pub fn is_reattached(&self) -> bool {
        self.inner.reattached
    }

    fn target(&self) -> serde_json::Value {
        json!({ "channel": self.inner.channel_id })
    }

    async fn sip(&self, verb: SipVerb, args: serde_json::Value) -> Result<serde_json::Value, ControlError> {
        self.inner
            .commander
            .command(Some(MODULE_SIP.to_string()), verb.as_str().to_string(), self.target(), args)
            .await
    }

    // --- SIP verbs ---------------------------------------------------------

    /// Send a UAS 2xx (default `200 OK`) to the parked A-leg.
    pub async fn answer(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Answer, json!({})).await.map(drop)
    }

    /// Send a UAS 2xx with an explicit code / reason / body.
    pub async fn answer_with(
        &self,
        code: u16,
        reason: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Answer, response_args(code, reason, body, content_type))
            .await
            .map(drop)
    }

    /// Send a UAS 1xx / early media (default `183 Session Progress`).
    pub async fn progress(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Progress, json!({})).await.map(drop)
    }

    /// Send a UAS 1xx with an explicit code / reason / body.
    pub async fn progress_with(
        &self,
        code: u16,
        reason: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Progress, response_args(code, reason, body, content_type))
            .await
            .map(drop)
    }

    /// Send a final non-2xx and tear the call down.
    pub async fn reject(&self, code: u16, reason: Option<&str>) -> Result<(), ControlError> {
        let mut args = json!({ "code": code });
        if let Some(reason) = reason {
            args["reason"] = json!(reason);
        }
        self.sip(SipVerb::Reject, args).await.map(drop)
    }

    /// Hang up: BYE an answered call, or reject an unanswered one.
    pub async fn hangup(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Hangup, json!({})).await.map(drop)
    }

    /// Hang up with a `Reason` header value.
    pub async fn hangup_with_reason(&self, reason: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::Hangup, json!({ "reason": reason })).await.map(drop)
    }

    /// Send an in-dialog REFER on the A-leg (blind transfer).
    pub async fn refer(&self, to: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::Refer, json!({ "to": to })).await.map(drop)
    }

    /// Blind-transfer alias for [`Call::refer`].
    pub async fn transfer(&self, to: &str) -> Result<(), ControlError> {
        self.refer(to).await
    }

    /// Attended transfer — REFER with a `Replaces` triple (RFC 3891).
    pub async fn refer_replaces(
        &self,
        to: &str,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        early_only: bool,
    ) -> Result<(), ControlError> {
        let args = json!({
            "to": to,
            "replaces": { "call_id": call_id, "from_tag": from_tag, "to_tag": to_tag, "early_only": early_only }
        });
        self.sip(SipVerb::Refer, args).await.map(drop)
    }

    /// Set a header on the stored A-leg INVITE.
    pub async fn set_header(&self, name: &str, value: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::SetHeader, json!({ "name": name, "value": value }))
            .await
            .map(drop)
    }

    /// Read a header from the stored A-leg INVITE (`None` when absent).
    pub async fn get_header(&self, name: &str) -> Result<Option<String>, ControlError> {
        let result = self.sip(SipVerb::GetHeader, json!({ "name": name })).await?;
        Ok(string_value(&result))
    }

    // --- per-call variables (substrate verbs, no module) -------------------

    /// Set a per-call variable (survives a reconnect via `resync`).
    pub async fn set_var(&self, key: &str, value: &str) -> Result<(), ControlError> {
        self.inner
            .commander
            .command(None, "set_var".to_string(), self.target(), json!({ "key": key, "value": value }))
            .await
            .map(drop)
    }

    /// Read a per-call variable (`None` when unset).
    pub async fn get_var(&self, key: &str) -> Result<Option<String>, ControlError> {
        let result = self
            .inner
            .commander
            .command(None, "get_var".to_string(), self.target(), json!({ "key": key }))
            .await?;
        Ok(string_value(&result))
    }

    // --- media (server answers `unsupported_verb` today) -------------------

    /// Play an announcement. **Not yet implemented server-side** — resolves to
    /// [`ControlError::is_unsupported_verb`] until the media backend lands.
    pub async fn play_file(&self, file: &str) -> Result<(), ControlError> {
        self.command("play", json!({ "file": file })).await.map(drop)
    }

    /// Send DTMF. **Not yet implemented server-side** — see [`Call::play_file`].
    pub async fn dtmf(&self, digits: &str) -> Result<(), ControlError> {
        self.command("dtmf", json!({ "digits": digits })).await.map(drop)
    }

    // --- escape hatch + events --------------------------------------------

    /// Send an arbitrary SIP-adapter verb + args and return the raw result.
    pub async fn command(
        &self,
        verb: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, ControlError> {
        self.inner
            .commander
            .command(Some(MODULE_SIP.to_string()), verb.to_string(), self.target(), args)
            .await
    }

    /// Await the next event for this call (`ChannelStateChange`,
    /// `ChannelHangupRequest`, `StasisEnd`). `None` once the stream closes.
    pub async fn next_event(&self) -> Option<CallEvent> {
        self.inner.events.lock().await.recv().await
    }
}

impl std::fmt::Debug for Call {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Call")
            .field("channel_id", &self.inner.channel_id)
            .field("sip_call_id", &self.inner.sip_call_id)
            .field("reattached", &self.inner.reattached)
            .finish_non_exhaustive()
    }
}

fn string_value(result: &serde_json::Value) -> Option<String> {
    result.get("value").and_then(|value| value.as_str()).map(|value| value.to_string())
}

fn response_args(
    code: u16,
    reason: Option<&str>,
    body: Option<&str>,
    content_type: Option<&str>,
) -> serde_json::Value {
    let mut args = json!({ "code": code });
    if let Some(reason) = reason {
        args["reason"] = json!(reason);
    }
    if let Some(body) = body {
        args["body"] = json!(body);
    }
    if let Some(content_type) = content_type {
        args["content_type"] = json!(content_type);
    }
    args
}

// ---------------------------------------------------------------------------
// Call dispatch (handler closure or pull stream) + per-channel event routing
// ---------------------------------------------------------------------------

type CallHandler = Arc<dyn Fn(Call) -> BoxFuture<'static, Result<(), ControlError>> + Send + Sync>;

/// The SIP facade's event router: builds `Call`s from `StasisStart`/reattach,
/// routes channel-scoped events to the owning call, and dispatches new calls to
/// a handler or pull stream.
struct SipFacade {
    handler: Mutex<Option<CallHandler>>,
    call_tx: Mutex<Option<mpsc::UnboundedSender<Call>>>,
    channels: Mutex<HashMap<String, mpsc::UnboundedSender<CallEvent>>>,
}

impl SipFacade {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            handler: Mutex::new(None),
            call_tx: Mutex::new(None),
            channels: Mutex::new(HashMap::new()),
        })
    }

    fn set_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        let boxed: CallHandler = Arc::new(move |call| Box::pin(handler(call)) as BoxFuture<'static, _>);
        *lock(&self.handler) = Some(boxed);
    }

    fn set_stream(&self) -> mpsc::UnboundedReceiver<Call> {
        let (sender, receiver) = mpsc::unbounded_channel();
        *lock(&self.call_tx) = Some(sender);
        receiver
    }

    fn handle_client_event(&self, event: ClientEvent, commander: &Arc<dyn CommandTransport>) {
        match event {
            ClientEvent::Event(frame) => self.handle_event(frame, commander),
            ClientEvent::Reattach(snapshot) => self.reattach(snapshot, commander),
        }
    }

    fn handle_event(&self, frame: EventFrame, commander: &Arc<dyn CommandTransport>) {
        match frame.sip_kind() {
            SipEvent::StasisStart => {
                let Some(channel) = frame.channel.clone() else {
                    warn!("control(sip): StasisStart without a channel — dropping");
                    return;
                };
                let (event_tx, event_rx) = mpsc::unbounded_channel();
                lock(&self.channels).insert(channel, event_tx);
                let call = Call::from_event(Arc::clone(commander), &frame, event_rx, false);
                self.dispatch(call);
            }
            SipEvent::StasisEnd => {
                if let Some(channel) = frame.channel.clone() {
                    self.route(&channel, CallEvent::from_frame(frame));
                    lock(&self.channels).remove(&channel);
                }
            }
            _ => {
                if let Some(channel) = frame.channel.clone() {
                    self.route(&channel, CallEvent::from_frame(frame));
                }
            }
        }
    }

    fn reattach(&self, snapshot: ChannelSnapshot, commander: &Arc<dyn CommandTransport>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        lock(&self.channels).insert(snapshot.channel.clone(), event_tx);
        let call = Call::from_snapshot(Arc::clone(commander), snapshot, event_rx);
        self.dispatch(call);
    }

    fn route(&self, channel: &str, event: CallEvent) {
        if let Some(sender) = lock(&self.channels).get(channel) {
            let _ = sender.send(event);
        }
    }

    fn dispatch(&self, call: Call) {
        if let Some(handler) = lock(&self.handler).clone() {
            tokio::spawn(async move {
                if let Err(error) = handler(call).await {
                    warn!(%error, "control(sip): call handler returned an error");
                }
            });
        } else if let Some(sender) = lock(&self.call_tx).as_ref() {
            if sender.send(call).is_err() {
                debug!("control(sip): call queue closed — dropping call");
            }
        } else {
            debug!(channel = %call.channel_id(), "control(sip): no handler/stream — call dropped");
        }
    }
}

/// A pull-style stream of handed-over calls (see [`SipClient::calls`]).
pub struct CallStream {
    receiver: mpsc::UnboundedReceiver<Call>,
}

impl CallStream {
    /// Await the next handed-over call. `None` once the client shuts down.
    pub async fn next(&mut self) -> Option<Call> {
        self.receiver.recv().await
    }
}

// ---------------------------------------------------------------------------
// Inbound-persistent SIP facade
// ---------------------------------------------------------------------------

/// The SIP facade over an inbound-persistent [`ControlClient`].
///
/// ```no_run
/// # use siphon_control_client::{ClientConfig, sip::SipClient};
/// # async fn demo() -> Result<(), siphon_control_client::ControlError> {
/// let client = SipClient::connect(
///     ClientConfig::new("ws://siphon:9090/control/ws", "ivr-app", "s3cr3t"),
/// )
/// .await?;
/// client
///     .on_call(|call| async move {
///         call.answer().await?;
///         call.transfer("sip:agent@pbx").await
///     })
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct SipClient {
    client: Arc<ControlClient>,
    facade: Arc<SipFacade>,
}

impl std::fmt::Debug for SipClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SipClient").finish_non_exhaustive()
    }
}

impl SipClient {
    /// Connect + `hello`, then install the SIP event router.
    pub async fn connect(config: ClientConfig) -> Result<Self, ControlError> {
        let client = Arc::new(ControlClient::connect(config).await?);
        Ok(Self::wrap(client))
    }

    /// Wrap an already-connected generic client with the SIP facade.
    pub fn wrap(client: Arc<ControlClient>) -> Self {
        let facade = SipFacade::new();
        let commander = client.commander();
        let routed = Arc::clone(&facade);
        client
            .shared()
            .install_event_callback(Arc::new(move |event| {
                routed.handle_client_event(event, &commander);
            }));
        Self { client, facade }
    }

    /// The underlying generic client (for raw `command` on any module).
    pub fn client(&self) -> &ControlClient {
        &self.client
    }

    /// Register a call handler (does not block).
    pub fn set_call_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.facade.set_handler(handler);
    }

    /// Register a call handler **and drive the client to completion** (the
    /// supervised reconnect + resync loop).
    pub async fn on_call<F, Fut>(&self, handler: F) -> Result<(), ControlError>
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.set_call_handler(handler);
        self.client.run().await
    }

    /// A pull-style stream of handed-over calls (alternative to a handler).
    pub fn calls(&self) -> CallStream {
        CallStream {
            receiver: self.facade.set_stream(),
        }
    }

    /// Drive the supervised connection loop (reconnect + resync).
    pub async fn run(&self) -> Result<(), ControlError> {
        self.client.run().await
    }

    /// Fetch the registered adapters' schema (`describe`).
    pub async fn describe(&self) -> Result<serde_json::Value, ControlError> {
        self.client.describe().await
    }

    /// Send a raw command on any module (the generic escape hatch).
    pub async fn command(
        &self,
        module: Option<&str>,
        verb: &str,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, ControlError> {
        self.client.command(module, verb, target, args).await
    }

    /// Stop the client.
    pub fn shutdown(&self) {
        self.client.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Per-call-connect SIP facade
// ---------------------------------------------------------------------------

/// The SIP facade over a per-call-connect [`ControlServer`].
pub struct SipServer {
    server: Arc<ControlServer>,
    facade: Arc<SipFacade>,
}

impl std::fmt::Debug for SipServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SipServer").finish_non_exhaustive()
    }
}

impl SipServer {
    /// Bind the listener and install the SIP event router.
    pub async fn bind(config: ServerConfig) -> Result<Self, ControlError> {
        let server = Arc::new(ControlServer::bind(config).await?);
        let facade = SipFacade::new();
        let routed = Arc::clone(&facade);
        server.on_connection_event(Arc::new(move |frame, commander| {
            routed.handle_event(frame, &commander);
        }));
        Ok(Self { server, facade })
    }

    /// The actual bound address (useful when binding to port 0 in tests).
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ControlError> {
        self.server.local_addr()
    }

    /// Register a call handler (does not block).
    pub fn set_call_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.facade.set_handler(handler);
    }

    /// A pull-style stream of dialed-in calls (alternative to a handler).
    pub fn calls(&self) -> CallStream {
        CallStream {
            receiver: self.facade.set_stream(),
        }
    }

    /// Register a call handler **and run the accept loop** to completion.
    pub async fn on_call<F, Fut>(&self, handler: F) -> Result<(), ControlError>
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.set_call_handler(handler);
        self.server.run().await
    }

    /// Accept siphon's per-call dials forever.
    pub async fn run(&self) -> Result<(), ControlError> {
        self.server.run().await
    }
}
