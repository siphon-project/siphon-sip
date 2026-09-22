//! The control connection's identity and its auth handshake.
//!
//! Split out of `siphon_rtp.rs` (which is at its size budget) because it is a
//! self-contained concern: who this siphon process says it is, and the one frame
//! that says it. Nothing here touches a call.

use super::{result_kind, Request, Response, AUTH_REQUEST_ID, READ_CHUNK};
use crate::rtpengine::error::RtpEngineError;
use siphon_rtp_proto::{frame, CmdResult, Command};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// This siphon process's stable control identity, presented on every siphon-rtp
/// connection so the engine keys the calls it owns on the process rather than on
/// the TCP connection.
///
/// Process-scoped rather than a constructor argument because that is what it
/// describes: every control connection this siphon opens, to every instance,
/// presents the same identity. A per-client parameter would let two connections
/// of one process disagree about who they are, which is the one thing the claim
/// must not allow.
static CONTROLLER_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Set the identity every siphon-rtp control connection presents. Call once,
/// before the media backend is built; later calls are ignored and return false.
///
/// Must be stable across restarts of this process — a pod or host name — and
/// must **not** mix in a boot epoch. The whole point is that the engine
/// recognises the reconnecting process as the same owner; an identity that
/// changes every boot strands the previous run's calls under a name that can
/// never be presented again, which is the state this exists to end.
pub fn set_controller_id(id: String) -> bool {
    CONTROLLER_ID.set(id).is_ok()
}

/// The identity to present, or `None` when none was set — in which case the
/// engine keys ownership on the connection, exactly as it did before.
pub(super) fn controller_id() -> Option<&'static str> {
    CONTROLLER_ID.get().map(String::as_str)
}

/// The `Authenticate` frame a fresh connection opens with, or `None` when it
/// has nothing to say and should go straight to serving commands.
///
/// Two reasons to send one, and either is enough. A configured `secret` must be
/// presented before the engine accepts any verb. A `claim` need not be
/// presented at all, but without it the engine keys this connection's calls on
/// the connection itself, so the next restart cannot reach them — which is why
/// the frame now goes on a secretless connection too. The engine accepts any
/// token when it has no secret configured, so the empty one here is not a
/// credential being invented; it is the field the frame requires.
pub(super) fn auth_frame_for(secret: Option<&str>, claim: Option<&str>) -> Option<Command> {
    if secret.is_none() && claim.is_none() {
        return None;
    }
    Some(Command::Authenticate {
        token: secret.unwrap_or("").to_string(),
        controller_id: claim.map(str::to_string),
    })
}

/// Perform the shared-secret auth handshake on a fresh connection.
pub(super) async fn authenticate(
    write_half: &mut OwnedWriteHalf,
    read_half: &mut OwnedReadHalf,
    buffer: &mut Vec<u8>,
    command: Command,
    timeout_ms: u64,
) -> Result<(), RtpEngineError> {
    let bytes = frame::encode(&Request {
        id: AUTH_REQUEST_ID,
        command,
    })
    .map_err(|error| RtpEngineError::Protocol(format!("auth frame encode failed: {error}")))?;

    let mut chunk = [0u8; READ_CHUNK];
    let deadline = Duration::from_millis(timeout_ms.max(1));

    // Bounded by the same deadline as the ack read below. Unbounded, an engine
    // that accepts the TCP connection and then never drains it wedges the
    // reconnect task here forever — and because that task is what re-establishes
    // control, every subsequent command then fails on its own timeout with
    // nothing left to recover it.
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
            // Consume buffered frames first; the auth ack is the Response with the
            // reserved id. Any events arriving first are ignored during handshake.
            loop {
                match frame::decode::<serde_json::Value>(buffer) {
                    Ok(Some((value, consumed))) => {
                        buffer.drain(..consumed);
                        if value.get("id").and_then(serde_json::Value::as_u64)
                            == Some(AUTH_REQUEST_ID)
                        {
                            let response: Response =
                                serde_json::from_value(value).map_err(|error| {
                                    RtpEngineError::Protocol(format!(
                                        "auth response decode failed: {error}"
                                    ))
                                })?;
                            return match response.result {
                                CmdResult::Ok { .. } => Ok(()),
                                CmdResult::Error { reason } => {
                                    Err(RtpEngineError::EngineError(reason))
                                }
                                other => Err(RtpEngineError::Protocol(format!(
                                    "unexpected '{}' response for authenticate",
                                    result_kind(&other)
                                ))),
                            };
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        return Err(RtpEngineError::Protocol(format!(
                            "auth frame decode failed: {error}"
                        )))
                    }
                }
            }
            let n = read_half.read(&mut chunk).await?;
            if n == 0 {
                return Err(RtpEngineError::Protocol(
                    "siphon-rtp closed connection during auth".to_string(),
                ));
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| RtpEngineError::Timeout {
        timeout_ms: deadline.as_millis() as u64,
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the control-identity claim on the auth frame --

    /// The pre-identity behaviour, and the one that must not change: a
    /// connection with neither a secret nor a claim sends no frame at all and
    /// goes straight to serving commands. Every mock in this file relies on it.
    #[test]
    fn a_connection_with_nothing_to_present_sends_no_auth_frame() {
        assert!(auth_frame_for(None, None).is_none());
    }

    /// The secretless case is the new one. Without this frame the engine keys
    /// the calls on the connection, so the next restart cannot reach them —
    /// which is the whole reason the reap finds nothing without an identity.
    #[test]
    fn a_claim_alone_still_sends_the_frame() {
        match auth_frame_for(None, Some("siphon-0")) {
            Some(Command::Authenticate {
                token,
                controller_id,
            }) => {
                assert_eq!(
                    token, "",
                    "no secret is configured, so there is none to send"
                );
                assert_eq!(controller_id.as_deref(), Some("siphon-0"));
            }
            other => panic!("expected an authenticate frame, got {other:?}"),
        }
    }

    #[test]
    fn a_secret_and_a_claim_travel_on_one_frame() {
        match auth_frame_for(Some("s3cret"), Some("siphon-0")) {
            Some(Command::Authenticate {
                token,
                controller_id,
            }) => {
                assert_eq!(token, "s3cret");
                assert_eq!(controller_id.as_deref(), Some("siphon-0"));
            }
            other => panic!("expected an authenticate frame, got {other:?}"),
        }
    }

    /// An older engine must keep working: with no claim to make, the frame has
    /// to serialize to exactly the bytes it did before the field existed. The
    /// proto skips a `None` controller_id, so this pins that we rely on it.
    #[test]
    fn a_secret_without_a_claim_keeps_the_old_wire_shape() {
        let command = auth_frame_for(Some("s3cret"), None).expect("a secret sends a frame");
        let frame = serde_json::to_string(&command).expect("serialize");
        assert_eq!(frame, r#"{"command":"authenticate","token":"s3cret"}"#);
    }

    /// The claim identifies the process, so the second caller must not be able
    /// to move it: two connections of one siphon disagreeing about who they are
    /// is the one thing the claim cannot allow.
    #[test]
    fn the_controller_identity_is_first_write_wins() {
        // Deliberately does NOT call set_controller_id: CONTROLLER_ID is
        // process-global, and setting it here would put an auth frame in front
        // of every other mock in this binary. The OnceLock's own semantics are
        // what this pins.
        let once: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        assert!(once.set("siphon-0".to_string()).is_ok());
        assert!(once.set("siphon-1".to_string()).is_err());
        assert_eq!(once.get().map(String::as_str), Some("siphon-0"));
    }
}
