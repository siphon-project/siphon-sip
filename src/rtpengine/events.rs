//! Inbound listener for rtpengine async event notifications (DTMF, etc.).
//!
//! When rtpengine is started with ``dtmf-log-ng-tcp-uri=tcp://<siphon>:<port>``,
//! it establishes a TCP connection to that endpoint and streams bencoded
//! event dictionaries.  This module binds the listener, parses the
//! bencode-framed messages, and converts recognised events to typed
//! [`RtpEngineEvent`] values for downstream dispatch.
//!
//! Message framing on the stream is the native bencode self-delimiting
//! format — each dict ends with ``e`` and the next one starts immediately.
//! [`crate::rtpengine::bencode::decode`] consumes one value and returns
//! the remaining bytes, which makes streaming parse straightforward.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::bencode::{self, BencodeValue};
use super::error::RtpEngineError;

/// One decoded media-engine event.
#[derive(Debug, Clone)]
pub enum RtpEngineEvent {
    /// DTMF digit detected on a call leg.
    Dtmf(DtmfEvent),
    /// A call's media went silent past the timeout and the engine tore it down
    /// (dead-path detection).  Emitted by the `siphon-rtp` native backend; the
    /// rtpengine NG backend does not currently surface this.
    MediaTimeout {
        call_id: String,
        from_tag: String,
    },
    /// End-of-call media summary (the structured twin of the `siphon_rtp::cdr`
    /// log block), emitted once when the engine tears a call down.  Carries the
    /// per-leg byte/packet counters and, when a userspace media actor measured
    /// them, the RFC 3550 loss/jitter and ITU-T G.107 MOS shape — so siphon
    /// writes a media CDR (correlated to the SIP CDR by Call-ID) instead of
    /// scraping logs.  Emitted by the `siphon-rtp` native backend only; the
    /// rtpengine NG backend does not surface it.
    CallSummary(CallSummary),
    /// An event we didn't recognise — passed through for logging.
    Unknown {
        event: String,
        call_id: Option<String>,
        from_tag: Option<String>,
    },
}

/// Decoded DTMF event.  Matches the payload rtpengine emits via
/// ``dtmf-log-ng-tcp-uri`` (TS 101 362, TS 24.229 §16 — DTMF telephony events).
#[derive(Debug, Clone)]
pub struct DtmfEvent {
    pub call_id: String,
    pub from_tag: String,
    /// Optional peer tag in MPTY / conference cases.
    pub to_tag: Option<String>,
    /// Digit as a single character ("0"–"9", "*", "#", "A"–"D").
    pub digit: String,
    /// Tone duration in milliseconds.
    pub duration_ms: u32,
    /// Volume in dBm0 (rtpengine reports negative values).
    pub volume: i32,
    /// rtpengine's view of the media source (IP:port) — informational.
    pub source: Option<String>,
}

/// End-of-call media summary for one call, carried by
/// [`RtpEngineEvent::CallSummary`].  A siphon-sip-owned mirror of the native
/// backend's `siphon_rtp_proto::Event::CallSummary` payload, so this generic
/// event enum stays free of the proto type (same posture as `MediaTimeout`
/// being native-only).
#[derive(Debug, Clone)]
pub struct CallSummary {
    /// SIP Call-ID the media session was keyed on — correlates to the SIP CDR.
    pub call_id: String,
    /// Why the call ended: `"delete"` (controller teardown) or `"media_timeout"`
    /// (dead-path reap).
    pub reason: String,
    /// Call lifetime in milliseconds (logical-clock resolution, ~1 s grain).
    pub duration_ms: u64,
    /// One entry per leg — index 0 is the near (offerer) leg, index 1 the far
    /// (answerer) leg.
    pub legs: Vec<CallLegSummary>,
}

/// One leg's end-of-call figures in a [`CallSummary`].  The quality fields are
/// `None` on a leg with no userspace actor (a plain in-kernel relay) or one that
/// never received media, so a consumer can tell "counters only" from "measured".
#[derive(Debug, Clone)]
pub struct CallLegSummary {
    /// The leg's tag: the offerer's `from_tag` (near) or the answerer's `to_tag`
    /// (far).
    pub tag: String,
    /// The leg's negotiated audio codec name, if known.
    pub codec: Option<String>,
    pub packets_in: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub bytes_out: u64,
    /// Packets dropped on the engine's side of this leg (source-gate / latch /
    /// jitter overflow), not network loss.
    pub packets_dropped: u64,
    /// The inbound stream's SSRC (RFC 3550), when measured.
    pub ssrc: Option<u32>,
    /// Cumulative network packets lost on the inbound stream (RFC 3550 §6.4.1),
    /// when measured.
    pub packets_lost: Option<u32>,
    /// Inbound network packet loss as a percentage, when measured.
    pub loss_percent: Option<f64>,
    /// Inbound interarrival jitter in milliseconds (RFC 3550 §6.4.1), when measured.
    pub jitter_ms: Option<f64>,
    /// Engine↔peer round-trip time in milliseconds, when a reception report
    /// yielded one.
    pub rtt_ms: Option<f64>,
    /// Mean / lowest / highest ITU-T G.107 MOS across the call, when measured.
    pub mos_average: Option<f64>,
    pub mos_min: Option<f64>,
    pub mos_max: Option<f64>,
    /// `"full"` (MOS includes the G.107 delay term) or `"loss+jitter"` — how the
    /// MOS was derived.
    pub mos_basis: Option<String>,
}

/// Helpers for extracting values from a bencoded event dict.
fn dict_str(dict: &BencodeValue, key: &str) -> Option<String> {
    dict.dict_get_str(key).map(String::from)
}

fn dict_u32(dict: &BencodeValue, key: &str) -> Option<u32> {
    match dict.dict_get(key) {
        Some(BencodeValue::Integer(n)) => u32::try_from(*n).ok(),
        _ => None,
    }
}

fn dict_i32(dict: &BencodeValue, key: &str) -> Option<i32> {
    match dict.dict_get(key) {
        Some(BencodeValue::Integer(n)) => i32::try_from(*n).ok(),
        _ => None,
    }
}

/// Convert a decoded bencode dict into an [`RtpEngineEvent`].
///
/// Unrecognised events are returned as [`RtpEngineEvent::Unknown`] so callers
/// can log them rather than silently dropping.
pub fn classify_event(dict: &BencodeValue) -> Result<RtpEngineEvent, RtpEngineError> {
    let event_name = dict_str(dict, "event").ok_or_else(|| {
        RtpEngineError::Decode("event dict missing 'event' key".to_string())
    })?;

    // rtpengine's current build emits "DTMF" (daemon/dtmf.c); older or
    // alternative builds emit "DTMF-receive", "DTMF-end".  Accept the set.
    let is_dtmf = matches!(
        event_name.as_str(),
        "DTMF" | "DTMF-receive" | "DTMF-end" | "dtmf" | "send-dtmf"
    );

    if is_dtmf {
        let call_id = dict_str(dict, "call-id").ok_or_else(|| {
            RtpEngineError::Decode("DTMF event missing 'call-id'".to_string())
        })?;
        let from_tag = dict_str(dict, "from-tag").ok_or_else(|| {
            RtpEngineError::Decode("DTMF event missing 'from-tag'".to_string())
        })?;
        // rtpengine uses "code" on some builds, "digit" on others.
        let digit = dict_str(dict, "code")
            .or_else(|| dict_str(dict, "digit"))
            .ok_or_else(|| {
                RtpEngineError::Decode("DTMF event missing 'code'/'digit'".to_string())
            })?;
        let duration_ms = dict_u32(dict, "duration").unwrap_or(0);
        let volume = dict_i32(dict, "volume").unwrap_or(0);

        return Ok(RtpEngineEvent::Dtmf(DtmfEvent {
            call_id,
            from_tag,
            to_tag: dict_str(dict, "to-tag"),
            digit,
            duration_ms,
            volume,
            source: dict_str(dict, "source"),
        }));
    }

    Ok(RtpEngineEvent::Unknown {
        event: event_name,
        call_id: dict_str(dict, "call-id"),
        from_tag: dict_str(dict, "from-tag"),
    })
}

/// Spawn a TCP listener that accepts rtpengine event connections.
///
/// Each accepted connection runs a streaming bencode parser in its own
/// task.  Decoded events are sent on ``event_tx``.  The task exits on
/// I/O error or when the sender is dropped.
pub async fn spawn_event_listener(
    listen_addr: SocketAddr,
    event_tx: mpsc::Sender<RtpEngineEvent>,
) -> Result<(), RtpEngineError> {
    let listener = TcpListener::bind(listen_addr).await.map_err(RtpEngineError::from)?;

    info!(%listen_addr, "rtpengine event listener bound");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    info!(%peer, "rtpengine event connection accepted");
                    let sender = event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(error) = read_event_stream(stream, sender).await {
                            warn!(%peer, %error, "rtpengine event stream closed");
                        }
                    });
                }
                Err(error) => {
                    warn!(%error, "rtpengine event accept failed; retry in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });

    Ok(())
}

/// Drive one TCP stream: read bytes into a buffer and emit every complete
/// bencode dict as an [`RtpEngineEvent`].
async fn read_event_stream(
    mut stream: TcpStream,
    event_tx: mpsc::Sender<RtpEngineEvent>,
) -> Result<(), RtpEngineError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        let n = stream.read(&mut tmp).await.map_err(RtpEngineError::from)?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&tmp[..n]);

        // Consume as many complete bencode dicts as we can from the buffer.
        loop {
            match bencode::decode(&buffer) {
                Ok((value, remaining)) => {
                    let consumed = buffer.len() - remaining.len();
                    match classify_event(&value) {
                        Ok(event) => {
                            debug!(?event, "rtpengine event decoded");
                            if event_tx.send(event).await.is_err() {
                                // Dispatcher dropped the receiver — shut down.
                                return Ok(());
                            }
                        }
                        Err(error) => {
                            warn!(%error, "rtpengine event decode failed; skipping");
                        }
                    }
                    buffer.drain(..consumed);
                    if buffer.is_empty() {
                        break;
                    }
                }
                Err(_) => {
                    // Incomplete or malformed — wait for more bytes.  If the
                    // buffer grows unboundedly we'll leak; cap at 1 MiB.
                    if buffer.len() > 1_048_576 {
                        return Err(RtpEngineError::Decode(
                            "rtpengine event buffer exceeded 1 MiB without a valid frame"
                                .to_string(),
                        ));
                    }
                    break;
                }
            }
        }
    }
}

// Shared Arc wrapper, used by callers that want to stash the event sender
// alongside other rtpengine state.
pub type EventSender = Arc<mpsc::Sender<RtpEngineEvent>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dtmf_dict(digit: &str) -> Vec<u8> {
        // d
        //   5:event 4:DTMF
        //   7:call-id 7:call-42
        //   8:from-tag 5:ftag1
        //   4:code 1:<digit>
        //   8:duration i120e
        //   6:volume i-8e
        // e
        format!(
            "d5:event4:DTMF7:call-id7:call-428:from-tag5:ftag14:code1:{digit}8:durationi120e6:volumei-8ee"
        )
        .into_bytes()
    }

    #[test]
    fn classify_dtmf_basic() {
        let bytes = make_dtmf_dict("5");
        let dict = bencode::decode_full_dict(&bytes).unwrap();
        let event = classify_event(&dict).unwrap();
        match event {
            RtpEngineEvent::Dtmf(dtmf) => {
                assert_eq!(dtmf.call_id, "call-42");
                assert_eq!(dtmf.from_tag, "ftag1");
                assert_eq!(dtmf.digit, "5");
                assert_eq!(dtmf.duration_ms, 120);
                assert_eq!(dtmf.volume, -8);
            }
            other => panic!("expected Dtmf, got {other:?}"),
        }
    }

    #[test]
    fn classify_event_accepts_digit_key() {
        // "digit" instead of "code"
        let bytes = b"d5:event4:DTMF7:call-id3:abc8:from-tag3:xyz5:digit1:78:durationi50e6:volumei0ee".to_vec();
        let dict = bencode::decode_full_dict(&bytes).unwrap();
        let event = classify_event(&dict).unwrap();
        match event {
            RtpEngineEvent::Dtmf(dtmf) => assert_eq!(dtmf.digit, "7"),
            other => panic!("expected Dtmf, got {other:?}"),
        }
    }

    #[test]
    fn classify_event_unknown() {
        let bytes = b"d5:event5:hello7:call-id3:xyze".to_vec();
        let dict = bencode::decode_full_dict(&bytes).unwrap();
        let event = classify_event(&dict).unwrap();
        match event {
            RtpEngineEvent::Unknown { event, call_id, .. } => {
                assert_eq!(event, "hello");
                assert_eq!(call_id.as_deref(), Some("xyz"));
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn classify_event_missing_event_key() {
        let bytes = b"d7:call-id3:abce".to_vec();
        let dict = bencode::decode_full_dict(&bytes).unwrap();
        assert!(classify_event(&dict).is_err());
    }

    #[test]
    fn streaming_decode_handles_two_concatenated_dicts() {
        let first = make_dtmf_dict("1");
        let second = make_dtmf_dict("2");
        let mut combined = first.clone();
        combined.extend_from_slice(&second);

        let mut digits = Vec::new();
        let mut remaining: &[u8] = &combined;
        while !remaining.is_empty() {
            let (value, rest) = bencode::decode(remaining).unwrap();
            let event = classify_event(&value).unwrap();
            if let RtpEngineEvent::Dtmf(dtmf) = event {
                digits.push(dtmf.digit);
            }
            remaining = rest;
        }
        assert_eq!(digits, vec!["1".to_string(), "2".to_string()]);
    }
}
