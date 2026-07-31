//! Outbound per-call-connect mode: siphon *dials the application* at handover,
//! so the app is a WebSocket **server**. This is the documented default for
//! multi-pod controllers — the accepting socket owns exactly that one call, so
//! "the audio lands on the wrong pod" is structurally impossible.
//!
//! No `hello` is exchanged: siphon presents the token in the dial headers, and
//! the first frame the app receives is a pushed event (`StasisStart` for SIP).
//!
//! This is the **protocol-agnostic** substrate: it accepts connections, checks
//! the token, and hands each `(event, connection-commander)` pair to a sink. A
//! typed facade (see [`crate::sip::SipServer`]) interprets the events.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{header, HeaderValue, StatusCode};
use tracing::{debug, info, warn};

use siphon_control_proto::{EventFrame, SUBPROTOCOL};

use crate::error::ControlError;
use crate::session::{spawn_session, CommandTransport, EventSink, SessionCore};

/// A sink the server calls for each event, carrying the [`CommandTransport`] of
/// the connection that produced it (so a facade commands back on the right one).
pub(crate) type ConnEventSink =
    Arc<dyn Fn(EventFrame, Arc<dyn CommandTransport>) + Send + Sync>;

/// How a [`ControlServer`] listens for siphon's per-call dials.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The address to listen on (e.g. `0.0.0.0:8790`).
    pub listen: SocketAddr,
    /// The application name (context / logging).
    pub app: String,
    /// The bearer token siphon must present on the dial.
    pub token: String,
    /// How long a command waits for its reply before [`ControlError::Timeout`].
    pub reply_timeout: Duration,
}

impl ServerConfig {
    /// A config with a 10 s reply timeout.
    pub fn new(listen: SocketAddr, app: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            listen,
            app: app.into(),
            token: token.into(),
            reply_timeout: Duration::from_secs(10),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The protocol-agnostic per-call-connect control server.
pub struct ControlServer {
    config: ServerConfig,
    listener: TcpListener,
    next_id: Arc<AtomicU64>,
    event_sink: Mutex<Option<ConnEventSink>>,
}

impl std::fmt::Debug for ControlServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlServer")
            .field("listen", &self.config.listen)
            .field("app", &self.config.app)
            .finish_non_exhaustive()
    }
}

impl ControlServer {
    /// Bind the listener (so the assigned port is known before accepting).
    pub async fn bind(config: ServerConfig) -> Result<Self, ControlError> {
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|error| ControlError::Config(format!("bind {}: {error}", config.listen)))?;
        Ok(Self {
            config,
            listener,
            next_id: Arc::new(AtomicU64::new(1)),
            event_sink: Mutex::new(None),
        })
    }

    /// The actual bound address (useful when binding to port 0 in tests).
    pub fn local_addr(&self) -> Result<SocketAddr, ControlError> {
        self.listener
            .local_addr()
            .map_err(|error| ControlError::Config(error.to_string()))
    }

    /// Register the sink for `(event, connection-commander)` pairs. Facades set
    /// this internally.
    pub(crate) fn on_connection_event(&self, sink: ConnEventSink) {
        *lock(&self.event_sink) = Some(sink);
    }

    /// Accept siphon's per-call dials forever.
    pub async fn run(&self) -> Result<(), ControlError> {
        info!(listen = %self.config.listen, app = %self.config.app, "control: per-call-connect server listening");
        loop {
            let (stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(|error| ControlError::WebSocket(format!("accept: {error}")))?;
            let expected_token = self.config.token.clone();
            let next_id = Arc::clone(&self.next_id);
            let reply_timeout = self.config.reply_timeout;
            let sink = lock(&self.event_sink).clone();
            tokio::spawn(async move {
                drive_accepted(stream, peer, expected_token, next_id, reply_timeout, sink).await;
            });
        }
    }
}

/// Complete the WebSocket handshake for one dial (validating the token), then run
/// the session until it closes, funnelling its events (with this connection's
/// commander) to the server sink.
// The accept callback's `ErrorResponse` type is fixed by tungstenite's API.
#[allow(clippy::result_large_err)]
async fn drive_accepted(
    stream: TcpStream,
    peer: SocketAddr,
    expected_token: String,
    next_id: Arc<AtomicU64>,
    reply_timeout: Duration,
    server_sink: Option<ConnEventSink>,
) {
    let callback = |request: &Request, response: Response| {
        authorize_upgrade(request, response, &expected_token)
    };
    let websocket = match tokio_tungstenite::accept_hdr_async(stream, callback).await {
        Ok(websocket) => websocket,
        Err(error) => {
            debug!(%peer, %error, "control: rejected per-call dial");
            return;
        }
    };
    info!(%peer, "control: per-call dial accepted");

    // The event sink needs this connection's commander, but the commander is the
    // SessionCore that `spawn_session` returns — so read it lazily from a slot set
    // right after. Events only arrive once the read loop starts, after the set.
    let core_slot: Arc<OnceLock<Arc<SessionCore>>> = Arc::new(OnceLock::new());
    let per_conn_sink: EventSink = {
        let slot = Arc::clone(&core_slot);
        Arc::new(move |frame: EventFrame| {
            if let (Some(core), Some(server_sink)) = (slot.get(), server_sink.as_ref()) {
                let commander: Arc<dyn CommandTransport> = Arc::clone(core) as Arc<dyn CommandTransport>;
                server_sink(frame, commander);
            }
        })
    };

    let core = spawn_session(websocket, next_id, reply_timeout, per_conn_sink);
    let _ = core_slot.set(Arc::clone(&core));
    core.wait_closed().await;
    debug!(%peer, "control: per-call connection closed");
}

/// The accept callback: verify `Authorization: Bearer <token>` and echo the
/// subprotocol, or reject with `401` before the socket opens.
// The `ErrorResponse` return type is fixed by tungstenite's accept-callback API.
#[allow(clippy::result_large_err)]
fn authorize_upgrade(
    request: &Request,
    mut response: Response,
    expected_token: &str,
) -> Result<Response, ErrorResponse> {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        });

    match presented {
        Some(token) if token == expected_token => {
            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_static(SUBPROTOCOL),
            );
            Ok(response)
        }
        _ => {
            warn!("control: per-call dial presented a bad/missing token");
            let error = tokio_tungstenite::tungstenite::http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Some("unauthorized".to_string()))
                .unwrap_or_else(|_| {
                    let mut fallback: ErrorResponse =
                        ErrorResponse::new(Some("unauthorized".to_string()));
                    *fallback.status_mut() = StatusCode::UNAUTHORIZED;
                    fallback
                });
            Err(error)
        }
    }
}
