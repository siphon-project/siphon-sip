//! The control connection: connect, hand-shake, read, route, reconnect.
//!
//! Split out of `siphon_rtp.rs` (which is at its size budget) because it is one
//! self-contained concern: the background task that owns the socket. The client
//! above it only writes frames and waits on the pending map this task resolves.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use siphon_rtp_proto::{frame, CmdResult, Command, Event, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tracing::{debug, error, info, trace, warn};

use super::events::convert_event;
use super::identity::{auth_frame_for, authenticate, controller_id};
use super::scope::{require_scope_support, CallScope, CallScopes};
use super::waiters::Waiters;
use super::{PlayWaiter, HANDSHAKE_REQUEST_ID, READ_CHUNK};
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::events::RtpEngineEvent;

/// Initial reconnect backoff; doubles up to [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
/// Maximum reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Background task: maintain the control connection, route responses/events, and
/// reconnect (with backoff + re-auth) until the client is dropped.
#[allow(clippy::too_many_arguments)]
pub(super) async fn connection_manager(
    address: SocketAddr,
    control_secret: Option<String>,
    scopes: Arc<CallScopes>,
    timeout_ms: u64,
    pending: Arc<DashMap<u64, oneshot::Sender<CmdResult>>>,
    play_pending: Arc<DashMap<u64, PlayWaiter>>,
    waiters: Arc<Waiters>,
    writer: Arc<Mutex<Option<OwnedWriteHalf>>>,
    connected_tx: watch::Sender<bool>,
    event_tx: mpsc::Sender<RtpEngineEvent>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        // Connect, cancellable by client shutdown.
        let stream = tokio::select! {
            biased;
            _ = shutdown_rx.recv() => return,
            result = TcpStream::connect(address) => match result {
                Ok(stream) => stream,
                Err(error) => {
                    warn!(%address, %error, "siphon-rtp control connect failed; retrying");
                    if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                        return;
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let (mut read_half, mut write_half) = stream.into_split();
        let mut buffer: Vec<u8> = Vec::with_capacity(READ_CHUNK);

        // Auth handshake (before publishing the writer, so concurrent commands
        // fail fast until the connection is authenticated and ready).
        //
        // Also runs with no secret configured, to present the identity claim:
        // the engine accepts any token when it has no secret, and without the
        // frame there is no way to say who is reconnecting, so every restart
        // would strand its own calls under a dead connection's id.
        if let Some(command) = auth_frame_for(control_secret.as_deref(), controller_id()) {
            match authenticate(
                &mut write_half,
                &mut read_half,
                &mut buffer,
                command,
                timeout_ms,
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    warn!(%address, %error, "siphon-rtp control auth failed; retrying");
                    if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                        return;
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            }
        }

        // A scoped node asks before it serves a call. An engine without the
        // feature reads a scoped frame as an unscoped one, silently, so this
        // node's calls would meet another node's under one Call-ID; refusing
        // the connection keeps that from ever happening and keeps retrying, so
        // an engine upgraded in place is picked up.
        if let Some(scope) = scopes.node() {
            if let Err(error) = require_scope_support(
                &mut write_half,
                &mut read_half,
                &mut buffer,
                scope,
                timeout_ms,
            )
            .await
            {
                error!(%address, %error, "siphon-rtp control connection refused; retrying");
                if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                    return;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        }

        // Reset only once the hand-shake has passed: an engine that accepts
        // the TCP connection and then refuses it would otherwise be retried at
        // the initial backoff forever.
        backoff = INITIAL_BACKOFF;
        scopes.connected();
        *writer.lock().await = Some(write_half);
        let _ = connected_tx.send(true);
        info!(%address, "siphon-rtp control connection established");

        let outcome = read_loop(
            &mut read_half,
            &mut buffer,
            &scopes,
            &pending,
            &play_pending,
            &waiters,
            &event_tx,
            &mut shutdown_rx,
        )
        .await;

        // Connection is gone: stop accepting commands and fail every in-flight
        // request (dropping the senders makes their receivers resolve to Err).
        // Blocking play_media waiters likewise unblock (dropped sender → Err →
        // treated as not-completed) instead of hanging until the fallback.
        let _ = connected_tx.send(false);
        *writer.lock().await = None;
        pending.clear();
        play_pending.clear();
        waiters.clear();

        match outcome {
            ReadOutcome::Shutdown => return,
            ReadOutcome::Disconnected => {
                warn!(%address, "siphon-rtp control disconnected; reconnecting");
                if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                    return;
                }
            }
        }
    }
}

/// Why [`read_loop`] returned.
enum ReadOutcome {
    /// The client was dropped — stop the manager entirely.
    Shutdown,
    /// The connection closed or errored — reconnect.
    Disconnected,
}

/// Drive the read half: decode frames, route responses to pending requests and
/// events onto `event_tx`, until shutdown or disconnect.
async fn read_loop(
    read_half: &mut OwnedReadHalf,
    buffer: &mut Vec<u8>,
    scopes: &CallScopes,
    pending: &DashMap<u64, oneshot::Sender<CmdResult>>,
    play_pending: &DashMap<u64, PlayWaiter>,
    waiters: &Waiters,
    event_tx: &mpsc::Sender<RtpEngineEvent>,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> ReadOutcome {
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        // Drain any whole frames already buffered (e.g. left over from auth).
        loop {
            match frame::decode::<serde_json::Value>(buffer) {
                Ok(Some((value, consumed))) => {
                    buffer.drain(..consumed);
                    route_frame(value, scopes, pending, play_pending, waiters, event_tx).await;
                }
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "siphon-rtp control frame decode failed; dropping connection");
                    return ReadOutcome::Disconnected;
                }
            }
        }

        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => return ReadOutcome::Shutdown,
            result = read_half.read(&mut chunk) => match result {
                Ok(0) => return ReadOutcome::Disconnected,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(error) => {
                    warn!(%error, "siphon-rtp control read error");
                    return ReadOutcome::Disconnected;
                }
            },
        }
    }
}

/// Send one frame on a connection that is not serving commands yet and wait
/// for its answer: the hand-shake (`authenticate`, `node_info`) that runs before
/// the writer is published, under the reserved [`HANDSHAKE_REQUEST_ID`].
/// `verb` names the step in the errors.
pub(super) async fn handshake(
    write_half: &mut OwnedWriteHalf,
    read_half: &mut OwnedReadHalf,
    buffer: &mut Vec<u8>,
    verb: &str,
    command: Command,
    timeout_ms: u64,
) -> Result<CmdResult, RtpEngineError> {
    let bytes = frame::encode(&Request {
        id: HANDSHAKE_REQUEST_ID,
        command,
    })
    .map_err(|error| RtpEngineError::Protocol(format!("{verb} frame encode failed: {error}")))?;

    let mut chunk = [0u8; READ_CHUNK];
    let deadline = Duration::from_millis(timeout_ms.max(1));

    // Bounded by the same deadline as the answer read below. Unbounded, an
    // engine that accepts the TCP connection and then never drains it wedges
    // the reconnect task here forever — and because that task is what
    // re-establishes control, every subsequent command then fails on its own
    // timeout with nothing left to recover it.
    match tokio::time::timeout(deadline, write_half.write_all(&bytes)).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(RtpEngineError::Timeout {
                timeout_ms: deadline.as_millis() as u64,
            });
        }
    }
    tokio::time::timeout(deadline, async {
        loop {
            // Consume buffered frames first; the answer is the Response with the
            // reserved id. Any events arriving first are ignored during the
            // hand-shake.
            loop {
                match frame::decode::<serde_json::Value>(buffer) {
                    Ok(Some((value, consumed))) => {
                        buffer.drain(..consumed);
                        if value.get("id").and_then(serde_json::Value::as_u64)
                            == Some(HANDSHAKE_REQUEST_ID)
                        {
                            let response: Response =
                                serde_json::from_value(value).map_err(|error| {
                                    RtpEngineError::Protocol(format!(
                                        "{verb} response decode failed: {error}"
                                    ))
                                })?;
                            return Ok(response.result);
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        return Err(RtpEngineError::Protocol(format!(
                            "{verb} frame decode failed: {error}"
                        )))
                    }
                }
            }
            let n = read_half.read(&mut chunk).await?;
            if n == 0 {
                return Err(RtpEngineError::Protocol(format!(
                    "siphon-rtp closed connection during {verb}"
                )));
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| RtpEngineError::Timeout {
        timeout_ms: deadline.as_millis() as u64,
    })?
}

/// Hand an event to the dispatcher without ever parking.
///
/// This runs on the control connection's **read** task, which is also what
/// routes every `Response` back to its pending request. Awaiting a bounded
/// channel here means a slow event consumer stops the read loop, so no response
/// is routed, every in-flight and future command fails on its own timeout, and
/// media control is dead process-wide with the connection still established —
/// far worse than dropping one DTMF event. The comment on the old `let _ =
/// send().await` called it best-effort; `try_send` is what actually makes it so.
fn forward_event(event_tx: &mpsc::Sender<RtpEngineEvent>, event: RtpEngineEvent) {
    match event_tx.try_send(event) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(
                "siphon-rtp event dropped: dispatcher event queue full (slow event \
                 consumer) — dropping the event rather than stalling the control \
                 read loop, which would fail every in-flight media command"
            );
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!("siphon-rtp event dropped: no event consumer");
        }
    }
}

/// Route one decoded JSON frame: a `Response` (has `id`) to its pending request,
/// or an `Event` (has `event`) onto the event channel.
async fn route_frame(
    value: serde_json::Value,
    scopes: &CallScopes,
    pending: &DashMap<u64, oneshot::Sender<CmdResult>>,
    play_pending: &DashMap<u64, PlayWaiter>,
    waiters: &Waiters,
    event_tx: &mpsc::Sender<RtpEngineEvent>,
) {
    if value.get("event").is_some() {
        // The engine sends a call's events to the connection that created it,
        // so this is a guard rather than a sort: an event this node's scope did
        // not create is never acted on, whatever its Call-ID.
        if !scopes.accepts(&value) {
            warn!(
                call_id = value.get("call_id").and_then(serde_json::Value::as_str),
                event_scope = value.get("scope").and_then(serde_json::Value::as_str),
                node_scope = scopes.node().map(CallScope::as_str),
                "siphon-rtp event for a call of another scope; skipping"
            );
            return;
        }
        match serde_json::from_value::<Event>(value) {
            Ok(event @ Event::PlayFinished { .. }) => {
                // Two consumers, and they are not alternatives. The waiter is a
                // blocking play_media(wait=True) in this process, which takes
                // the reason + played duration as its return value. The event
                // stream is everything else — script handlers and the control
                // rail — and a `play` issued over the rail is always
                // fire-and-forget, so dropping the event whenever a waiter
                // happened to exist would make an app's completion signal
                // depend on an unrelated caller's choice.
                if let Event::PlayFinished {
                    play_id,
                    reason,
                    played_ms,
                    ..
                } = &event
                {
                    debug!(play_id, ?reason, played_ms, "siphon-rtp play finished");
                    if let Some((_, sender)) = play_pending.remove(play_id) {
                        let _ = sender.send((*reason, *played_ms));
                    }
                }
                let converted = convert_event(event);
                forward_event(event_tx, converted);
            }
            Ok(event) => {
                let converted = convert_event(event);
                debug!(?converted, "siphon-rtp event received");
                match &converted {
                    // A digit a script's `read_digits` is collecting belongs
                    // to that read alone, so the global `on_dtmf` handlers do
                    // not act on it a second time.
                    RtpEngineEvent::Dtmf(dtmf)
                        if waiters.offer_digit(&dtmf.call_id, &dtmf.digit) =>
                    {
                        return;
                    }
                    // Both consumers, as for PlayFinished: a script waiting in
                    // `record` and the handlers / control rail.
                    RtpEngineEvent::RecordingFinished(finished) => {
                        waiters.recording_finished(finished);
                    }
                    _ => {}
                }
                forward_event(event_tx, converted);
            }
            Err(error) => warn!(%error, "siphon-rtp event decode failed; skipping"),
        }
    } else if value.get("id").is_some() {
        match serde_json::from_value::<Response>(value) {
            Ok(response) => {
                if let Some((_, sender)) = pending.remove(&response.id) {
                    let _ = sender.send(response.result);
                } else {
                    trace!(
                        id = response.id,
                        "siphon-rtp response for unknown/expired request"
                    );
                }
            }
            Err(error) => warn!(%error, "siphon-rtp response decode failed; skipping"),
        }
    } else {
        warn!("siphon-rtp frame had neither 'id' nor 'event'; skipping");
    }
}

/// Sleep for `duration`, returning `true` if a shutdown signal arrived first.
async fn sleep_or_shutdown(duration: Duration, shutdown_rx: &mut mpsc::Receiver<()>) -> bool {
    tokio::select! {
        biased;
        _ = shutdown_rx.recv() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}
