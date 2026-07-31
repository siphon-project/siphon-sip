//! The **protocol-agnostic** inbound-persistent control client.
//!
//! Knows nothing about SIP: it owns the transport, the `hello` handshake,
//! request-id correlation, reconnect + `resync`, and a generic event stream. Its
//! headline primitive is [`ControlClient::command`] over `{module, verb, target,
//! args}`, which works for any adapter with zero changes. Typed per-protocol
//! facades (see [`crate::sip`]) are built on top.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tracing::{info, warn};

use siphon_control_proto::{
    ChannelSnapshot, EventFrame, HelloResult, ResyncResult, PROTOCOL_VERSION, SUBPROTOCOL,
};

use crate::error::ControlError;
use crate::session::{spawn_session, CommandTransport, EventSink, SessionCore};

/// How a [`ControlClient`] connects and behaves.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The control-plane URL, e.g. `ws://siphon:9090/control/ws` (or `wss://…`).
    pub url: String,
    /// The application name — must equal the token's configured app.
    pub app: String,
    /// The bearer token presented on the upgrade.
    pub token: String,
    /// Protocol version to advertise in `hello` (defaults to the built-in).
    pub protocol: u32,
    /// How long a command waits for its reply before [`ControlError::Timeout`].
    pub reply_timeout: Duration,
    /// Backoff between reconnect attempts in [`ControlClient::run`].
    pub reconnect_backoff: Duration,
}

impl ClientConfig {
    /// A config with sane defaults (10 s reply timeout, 1 s reconnect backoff).
    pub fn new(url: impl Into<String>, app: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            app: app.into(),
            token: token.into(),
            protocol: PROTOCOL_VERSION,
            reply_timeout: Duration::from_secs(10),
            reconnect_backoff: Duration::from_secs(1),
        }
    }
}

/// An item on the client's generic event stream.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// A pushed event frame from the server (any module).
    Event(EventFrame),
    /// A channel re-claimed after a reconnect — synthesized client-side from the
    /// `resync` reply so a facade can re-attach its per-call state.
    Reattach(ChannelSnapshot),
}

/// A generic subscription to the client's event stream (see
/// [`ControlClient::events`]).
pub struct EventStream {
    receiver: mpsc::UnboundedReceiver<ClientEvent>,
}

impl EventStream {
    /// Await the next event. `None` once the client shuts down.
    pub async fn next(&mut self) -> Option<ClientEvent> {
        self.receiver.recv().await
    }
}

type EventCallback = Arc<dyn Fn(ClientEvent) + Send + Sync>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) struct ClientShared {
    config: ClientConfig,
    next_id: Arc<AtomicU64>,
    current: Mutex<Option<Arc<SessionCore>>>,
    event_sink: Mutex<Option<EventCallback>>,
    shutdown: AtomicBool,
    shutdown_notify: Notify,
}

impl ClientShared {
    fn emit(&self, event: ClientEvent) {
        if let Some(sink) = lock(&self.event_sink).clone() {
            sink(event);
        }
    }

    fn current_session(&self) -> Option<Arc<SessionCore>> {
        lock(&self.current).clone()
    }

    /// The `EventFrame` sink handed to a session: wraps each frame as
    /// [`ClientEvent::Event`] and forwards to the registered event callback.
    fn session_event_sink(self: &Arc<Self>) -> EventSink {
        let shared = Arc::clone(self);
        Arc::new(move |frame: EventFrame| shared.emit(ClientEvent::Event(frame)))
    }

    async fn connect_and_handshake(self: &Arc<Self>) -> Result<Arc<SessionCore>, ControlError> {
        let request = build_client_request(&self.config.url, &self.config.token)?;
        let (websocket, _response) = tokio_tungstenite::connect_async(request).await?;
        let core = spawn_session(
            websocket,
            Arc::clone(&self.next_id),
            self.config.reply_timeout,
            self.session_event_sink(),
        );

        let hello_args = serde_json::json!({
            "app": self.config.app,
            "protocol": self.config.protocol,
        });
        let result = core
            .send_command(None, "hello", serde_json::Value::Null, hello_args)
            .await?;
        let hello: HelloResult = serde_json::from_value(result)
            .map_err(|error| ControlError::Handshake(format!("bad hello reply: {error}")))?;
        if hello.subprotocol != SUBPROTOCOL {
            return Err(ControlError::Handshake(format!(
                "server negotiated subprotocol {:?}, expected {SUBPROTOCOL:?}",
                hello.subprotocol
            )));
        }
        info!(app = %self.config.app, protocol = hello.protocol, "control: handshake complete");
        Ok(core)
    }

    async fn resync_and_reattach(self: &Arc<Self>, core: &Arc<SessionCore>) {
        match core
            .send_command(None, "resync", serde_json::Value::Null, serde_json::Value::Null)
            .await
        {
            Ok(value) => match serde_json::from_value::<ResyncResult>(value) {
                Ok(result) => {
                    let count = result.channels.len();
                    for snapshot in result.channels {
                        self.emit(ClientEvent::Reattach(snapshot));
                    }
                    if count > 0 {
                        info!(count, "control: reattached channels after reconnect");
                    }
                }
                Err(error) => warn!(%error, "control: resync result unparseable"),
            },
            Err(error) => warn!(%error, "control: resync after reconnect failed"),
        }
    }
}

/// The protocol-agnostic inbound-persistent control client.
///
/// Use [`ControlClient::command`] directly for any module, or wrap it in a typed
/// facade such as [`crate::sip::SipClient`].
pub struct ControlClient {
    shared: Arc<ClientShared>,
}

impl std::fmt::Debug for ControlClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlClient")
            .field("url", &self.shared.config.url)
            .field("app", &self.shared.config.app)
            .finish_non_exhaustive()
    }
}

impl ControlClient {
    /// Connect + `hello`. A bad token surfaces as [`ControlError::Unauthorized`]
    /// (the upgrade is rejected 401 before the socket opens).
    pub async fn connect(config: ClientConfig) -> Result<Self, ControlError> {
        let shared = Arc::new(ClientShared {
            config,
            next_id: Arc::new(AtomicU64::new(1)),
            current: Mutex::new(None),
            event_sink: Mutex::new(None),
            shutdown: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
        });
        let core = shared.connect_and_handshake().await?;
        *lock(&shared.current) = Some(core);
        Ok(Self { shared })
    }

    /// Register a callback for every event (pushed events + reconnect reattach).
    /// Overwrites any previous callback / stream. Facades set this internally.
    pub fn on_event<F>(&self, callback: F)
    where
        F: Fn(ClientEvent) + Send + Sync + 'static,
    {
        *lock(&self.shared.event_sink) = Some(Arc::new(callback));
    }

    /// A pull-style stream of every event. Overwrites any previous callback.
    pub fn events(&self) -> EventStream {
        let (sender, receiver) = mpsc::unbounded_channel();
        *lock(&self.shared.event_sink) = Some(Arc::new(move |event| {
            let _ = sender.send(event);
        }));
        EventStream { receiver }
    }

    /// Send a raw command on the current session and return the reply's `result`
    /// object. The generic primitive every facade is built on.
    pub async fn command(
        &self,
        module: Option<&str>,
        verb: &str,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, ControlError> {
        let core = self
            .shared
            .current_session()
            .ok_or(ControlError::Closed)?;
        core.send_command(module.map(str::to_string), verb, target, args)
            .await
    }

    /// Fetch the registered adapters' verb/event schema (`describe`).
    pub async fn describe(&self) -> Result<serde_json::Value, ControlError> {
        self.command(None, "describe", serde_json::Value::Null, serde_json::Value::Null)
            .await
    }

    /// Re-enumerate the channels this connection owns (`resync`).
    pub async fn resync(&self) -> Result<Vec<ChannelSnapshot>, ControlError> {
        let value = self
            .command(None, "resync", serde_json::Value::Null, serde_json::Value::Null)
            .await?;
        let result: ResyncResult = serde_json::from_value(value)?;
        Ok(result.channels)
    }

    /// Drive the client: keep the connection alive, reconnecting with backoff and
    /// re-attaching owned channels (`resync`, delivered as
    /// [`ClientEvent::Reattach`]) after each reconnect. Returns `Ok(())` on
    /// [`ControlClient::shutdown`], or a fatal error (token revoked →
    /// [`ControlError::Unauthorized`]).
    pub async fn run(&self) -> Result<(), ControlError> {
        loop {
            let existing = lock(&self.shared.current)
                .as_ref()
                .filter(|core| !core.is_closed())
                .cloned();

            let core = match existing {
                Some(core) => core,
                None => {
                    if self.shared.shutdown.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    match self.shared.connect_and_handshake().await {
                        Ok(core) => {
                            *lock(&self.shared.current) = Some(Arc::clone(&core));
                            self.shared.resync_and_reattach(&core).await;
                            core
                        }
                        Err(error @ ControlError::Unauthorized { .. }) => return Err(error),
                        Err(error) => {
                            warn!(%error, "control: reconnect failed — backing off");
                            tokio::select! {
                                _ = tokio::time::sleep(self.shared.config.reconnect_backoff) => {}
                                _ = self.shared.shutdown_notify.notified() => return Ok(()),
                            }
                            continue;
                        }
                    }
                }
            };

            tokio::select! {
                _ = core.wait_closed() => {
                    if self.shared.shutdown.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    warn!("control: connection closed — reconnecting");
                    *lock(&self.shared.current) = None;
                }
                _ = self.shared.shutdown_notify.notified() => return Ok(()),
            }
        }
    }

    /// Stop the client: close the current session and unblock [`ControlClient::run`].
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.shutdown_notify.notify_waiters();
        if let Some(core) = lock(&self.shared.current).take() {
            core.close();
        }
    }

    /// A [`CommandTransport`] that routes commands to the client's *current*
    /// session (so a facade handle keeps working across reconnects). Internal —
    /// used by [`crate::sip`].
    pub(crate) fn commander(&self) -> Arc<dyn CommandTransport> {
        Arc::new(ClientCommander(Arc::clone(&self.shared)))
    }

    /// The shared inner state (internal — lets a facade install its event sink).
    pub(crate) fn shared(&self) -> Arc<ClientShared> {
        Arc::clone(&self.shared)
    }
}

/// Routes commands to whatever session is current on the client.
struct ClientCommander(Arc<ClientShared>);

impl CommandTransport for ClientCommander {
    fn command(
        &self,
        module: Option<String>,
        verb: String,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> BoxFuture<'_, Result<serde_json::Value, ControlError>> {
        Box::pin(async move {
            let core = self.0.current_session().ok_or(ControlError::Closed)?;
            core.send_command(module, verb, target, args).await
        })
    }
}

/// Build the WS upgrade request with the bearer token + subprotocol header.
pub(crate) fn build_client_request(
    url: &str,
    token: &str,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, ControlError> {
    let mut request = url
        .into_client_request()
        .map_err(|error| ControlError::Config(format!("invalid control url {url:?}: {error}")))?;
    let headers = request.headers_mut();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| ControlError::Config(format!("invalid token header: {error}")))?,
    );
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(request)
}

impl ClientShared {
    /// Install an event callback (used by facades that own the client's shared
    /// state directly).
    pub(crate) fn install_event_callback(&self, callback: EventCallback) {
        *lock(&self.event_sink) = Some(callback);
    }
}
