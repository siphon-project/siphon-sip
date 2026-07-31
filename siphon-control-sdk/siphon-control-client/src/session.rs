//! One live WebSocket connection: request-id correlation, the read/write tasks,
//! and **generic** event fan-out. Knows nothing about SIP — it moves opaque
//! `{module, verb, target, args}` frames and hands every event to a sink.
//!
//! Shared verbatim by the inbound client and the per-call-connect server — only
//! how the socket is *acquired* differs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, trace, warn};

use siphon_control_proto::{CommandFrame, ControlErrorCode, EventFrame, ReplyFrame, ReplyStatus};

use crate::error::ControlError;

/// A sink the read task calls for every inbound event frame (any module).
pub(crate) type EventSink = Arc<dyn Fn(EventFrame) + Send + Sync>;

/// Anything that can send a control command and await its correlated reply.
///
/// Implemented by [`SessionCore`] (bound to one connection — the per-call
/// -connect server) and by the client wrapper (routes to the current session,
/// surviving reconnects — the inbound client). Lets a facade's handle command
/// its call without caring which mode it runs in.
pub(crate) trait CommandTransport: Send + Sync {
    fn command(
        &self,
        module: Option<String>,
        verb: String,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> BoxFuture<'_, Result<serde_json::Value, ControlError>>;
}

/// Lock a `Mutex` without ever panicking on poison.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The shared, transport-agnostic state of one connection.
pub(crate) struct SessionCore {
    next_id: Arc<AtomicU64>,
    outbound_tx: mpsc::UnboundedSender<Message>,
    pending: Mutex<HashMap<String, oneshot::Sender<ReplyFrame>>>,
    reply_timeout: Duration,
    closed: AtomicBool,
    closed_notify: Notify,
    close_signal: Arc<Notify>,
}

impl SessionCore {
    fn new(
        next_id: Arc<AtomicU64>,
        outbound_tx: mpsc::UnboundedSender<Message>,
        reply_timeout: Duration,
        close_signal: Arc<Notify>,
    ) -> Arc<Self> {
        Arc::new(Self {
            next_id,
            outbound_tx,
            pending: Mutex::new(HashMap::new()),
            reply_timeout,
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
            close_signal,
        })
    }

    /// Explicitly close the connection.
    pub(crate) fn close(&self) {
        self.close_signal.notify_waiters();
        self.mark_closed();
    }

    /// Send a command and await its correlated reply. Maps a `status:"error"`
    /// reply to [`ControlError::Command`].
    pub(crate) async fn send_command(
        &self,
        module: Option<String>,
        verb: impl Into<String>,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, ControlError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ControlError::Closed);
        }
        let id = format!("c-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let (reply_tx, reply_rx) = oneshot::channel();
        lock(&self.pending).insert(id.clone(), reply_tx);

        let frame = CommandFrame::new(id.clone(), module, verb, target, args);
        let text = serde_json::to_string(&frame)?;
        trace!(%id, "control: sending command");
        if self.outbound_tx.send(Message::Text(text.into())).is_err() {
            lock(&self.pending).remove(&id);
            return Err(ControlError::Closed);
        }

        match tokio::time::timeout(self.reply_timeout, reply_rx).await {
            Ok(Ok(reply)) => reply_to_result(reply),
            Ok(Err(_)) => Err(ControlError::Closed),
            Err(_) => {
                lock(&self.pending).remove(&id);
                Err(ControlError::Timeout(self.reply_timeout))
            }
        }
    }

    fn route_reply(&self, reply: ReplyFrame) {
        if let Some(reply_tx) = lock(&self.pending).remove(&reply.id) {
            let _ = reply_tx.send(reply);
        } else {
            debug!(id = %reply.id, "control: reply for unknown/expired id — dropping");
        }
    }

    fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        lock(&self.pending).clear();
        self.closed_notify.notify_waiters();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_closed(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let notified = self.closed_notify.notified();
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

impl CommandTransport for SessionCore {
    fn command(
        &self,
        module: Option<String>,
        verb: String,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> BoxFuture<'_, Result<serde_json::Value, ControlError>> {
        Box::pin(self.send_command(module, verb, target, args))
    }
}

/// Convert a reply frame into a command result.
fn reply_to_result(reply: ReplyFrame) -> Result<serde_json::Value, ControlError> {
    match reply.status {
        ReplyStatus::Ok => Ok(reply.result.unwrap_or(serde_json::Value::Null)),
        ReplyStatus::Error => {
            let (code, message) = reply
                .error
                .map(|error| (error.code, error.message))
                .unwrap_or((
                    ControlErrorCode::ProtocolError,
                    "error reply without an error body".to_string(),
                ));
            Err(ControlError::Command { code, message })
        }
    }
}

/// Split a freshly-open WebSocket into the read + write tasks and return the
/// shared [`SessionCore`]. Every inbound event is handed to `event_sink`.
pub(crate) fn spawn_session<S>(
    websocket: WebSocketStream<S>,
    next_id: Arc<AtomicU64>,
    reply_timeout: Duration,
    event_sink: EventSink,
) -> Arc<SessionCore>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = websocket.split();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
    let close_signal = Arc::new(Notify::new());
    let core = SessionCore::new(next_id, outbound_tx, reply_timeout, Arc::clone(&close_signal));
    tokio::spawn(write_loop(sink, outbound_rx, close_signal));
    tokio::spawn(read_loop(stream, Arc::clone(&core), event_sink));
    core
}

async fn write_loop<S>(
    mut sink: SplitSink<WebSocketStream<S>, Message>,
    mut outbound_rx: mpsc::UnboundedReceiver<Message>,
    close_signal: Arc<Notify>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        tokio::select! {
            message = outbound_rx.recv() => match message {
                Some(message) => {
                    if sink.send(message).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            _ = close_signal.notified() => break,
        }
    }
    let _ = sink.send(Message::Close(None)).await;
}

async fn read_loop<S>(
    mut stream: SplitStream<WebSocketStream<S>>,
    core: Arc<SessionCore>,
    event_sink: EventSink,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(message) = stream.next().await {
        match message {
            Ok(Message::Text(text)) => dispatch_text(text.as_str(), &core, &event_sink),
            Ok(Message::Close(_)) => {
                debug!("control: peer closed the connection");
                break;
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            Ok(Message::Binary(_)) => warn!("control: ignoring unexpected binary frame"),
            Ok(Message::Frame(_)) => {}
            Err(error) => {
                debug!(%error, "control: read error");
                break;
            }
        }
    }
    core.mark_closed();
}

/// Route one inbound text frame by its `type` discriminator (generic — a reply
/// correlates to a pending command; every event goes to the sink verbatim).
fn dispatch_text(text: &str, core: &Arc<SessionCore>, event_sink: &EventSink) {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            warn!(%error, "control: malformed inbound frame — dropping");
            return;
        }
    };
    match value.get("type").and_then(|frame_type| frame_type.as_str()) {
        Some("reply") => match serde_json::from_value::<ReplyFrame>(value) {
            Ok(reply) => core.route_reply(reply),
            Err(error) => warn!(%error, "control: unparseable reply frame"),
        },
        Some("event") => match serde_json::from_value::<EventFrame>(value) {
            Ok(event) => event_sink(event),
            Err(error) => warn!(%error, "control: unparseable event frame"),
        },
        other => debug!(?other, "control: ignoring frame of unknown type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_to_result_maps_ok_and_error() {
        let ok = ReplyFrame {
            id: "1".into(),
            frame_type: siphon_control_proto::FrameType::Reply,
            status: ReplyStatus::Ok,
            result: Some(serde_json::json!({ "state": "answered" })),
            error: None,
        };
        assert_eq!(
            reply_to_result(ok).unwrap(),
            serde_json::json!({ "state": "answered" })
        );

        let error = ReplyFrame {
            id: "2".into(),
            frame_type: siphon_control_proto::FrameType::Reply,
            status: ReplyStatus::Error,
            result: None,
            error: Some(siphon_control_proto::ReplyError {
                code: ControlErrorCode::NotFound,
                message: "gone".into(),
            }),
        };
        match reply_to_result(error) {
            Err(ControlError::Command { code, message }) => {
                assert_eq!(code, ControlErrorCode::NotFound);
                assert_eq!(message, "gone");
            }
            other => panic!("expected Command error, got {other:?}"),
        }
    }
}
