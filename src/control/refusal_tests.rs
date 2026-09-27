//! What a refused control verb leaves behind: a log line in siphon's own log,
//! and a refusal that describes the verb rather than the transport under it.
//!
//! Both halves were absent. A `play` refused on a live call wrote nothing at any
//! level, so the refusal could not be corroborated from siphon's side at all —
//! and the natural reading of a silent log is that the command never arrived.
//! What the controller did get named a JSON frame length it never constructed,
//! under `unavailable`, the code for an engine that is not there.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use futures_util::future::BoxFuture;

use super::protocol::{ControlErrorCode, ControlResult, ReplyStatus};
use super::registry::{ConnHandle, ControlBus, SlowConsumerPolicy};
use super::sip_adapter::{media_error, play_blob_refusal, SipControlAdapter};
use super::{dispatch, AdapterCommand, AdapterSchema, ControlAdapter};
use crate::config::ControlAppConfig;
use crate::log_capture::LogBuffer;
use crate::rtpengine::client::{PlayMediaSource, MAX_PLAY_BLOB_BYTES};

const APP: &str = "ivr-app";
const CHANNEL: &str = "ch_9f3a";
const SIP_CALL_ID: &str = "82540632-a79a-407c@203.0.113.10";

fn app_config(name: &str) -> ControlAppConfig {
    ControlAppConfig {
        name: name.to_string(),
        token: "tok".to_string(),
        per_call_connect: false,
        connect_url: None,
        on_lost: Some("hangup".to_string()),
        ca_file: None,
        events: Vec::new(),
    }
}

/// An adapter that answers every verb with a result the test chose, so the log
/// line's level and fields can be driven from a given [`ControlErrorCode`]
/// without going through a verb whose own preconditions would decide the code.
struct FixedAdapter(ControlResult);

impl ControlAdapter for FixedAdapter {
    fn module(&self) -> &str {
        "fixed"
    }

    fn apply<'a>(&'a self, _command: AdapterCommand) -> BoxFuture<'a, ControlResult> {
        Box::pin(async move { self.0.clone() })
    }

    fn describe(&self) -> AdapterSchema {
        AdapterSchema {
            module: "fixed".to_string(),
            verbs: Vec::new(),
            events: Vec::new(),
        }
    }
}

fn adapters(extra: Option<Arc<dyn ControlAdapter>>) -> HashMap<String, Arc<dyn ControlAdapter>> {
    let mut adapters: HashMap<String, Arc<dyn ControlAdapter>> = HashMap::new();
    adapters.insert("sip".to_string(), Arc::new(SipControlAdapter::new()));
    if let Some(adapter) = extra {
        adapters.insert(adapter.module().to_string(), adapter);
    }
    adapters
}

/// A bus with one controlled channel, and the connection that owns it.
fn bus_with_channel() -> (Arc<ControlBus>, Arc<ConnHandle>) {
    let (command_tx, _command_rx) = flume::unbounded();
    let bus = ControlBus::new(
        command_tx,
        vec![app_config(APP)],
        64,
        SlowConsumerPolicy::DropOldest,
        10,
        3000,
    );
    let conn = bus.register_connection(APP);
    bus.register_channel(
        CHANNEL,
        &conn,
        "6f0e-call-uuid",
        SIP_CALL_ID,
        "hangup",
        Default::default(),
    );
    (bus, conn)
}

/// Apply one command through the real dispatch path, returning its result and
/// every log line it wrote at `max_level` or above.
///
/// Deliberately the whole path rather than the log helper on its own: the defect
/// was that nothing reached the log from a command that really was applied, and
/// only driving the dispatch a controller's frame drives can prove otherwise.
async fn dispatch_capturing(
    max_level: tracing::Level,
    extra_adapter: Option<Arc<dyn ControlAdapter>>,
    module: Option<&str>,
    verb: &str,
    target: serde_json::Value,
    args: serde_json::Value,
) -> (ControlResult, Vec<String>) {
    let (bus, conn) = bus_with_channel();
    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(max_level)
        .with_writer(log.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let result = dispatch(
        &bus,
        &adapters(extra_adapter),
        APP,
        conn.id,
        module,
        verb,
        target,
        args,
    )
    .await;
    drop(guard);
    let lines = log.rendered().lines().map(str::to_string).collect();
    (result, lines)
}

/// Whether a rendered log line carries `name=value`, quoted or not — the
/// `tracing` formatter quotes a recorded string and does not quote a `Display`ed
/// one, and which of the two a field is recorded as is not what a test is about.
fn has_field(line: &str, name: &str, value: &str) -> bool {
    line.contains(&format!("{name}={value}")) || line.contains(&format!("{name}=\"{value}\""))
}

/// The single refusal line, or a panic naming everything that was logged.
fn refusal_line(lines: &[String]) -> &String {
    lines
        .iter()
        .find(|line| line.contains("control plane: command refused"))
        .unwrap_or_else(|| panic!("no refusal line in {lines:?}"))
}

/// A `play` carrying `bytes` of inline audio, base64 as the control wire is JSON.
fn play_blob_args(bytes: usize) -> serde_json::Value {
    let audio = vec![0xffu8; bytes];
    serde_json::json!({
        "blob": base64::engine::general_purpose::STANDARD.encode(&audio),
    })
}

fn channel_target() -> serde_json::Value {
    serde_json::json!({ "channel": CHANNEL })
}

/// The one line the whole entry is about: a refused verb has to say which
/// application, which call, which channel, which verb and why. Driven through
/// the real `play` verb, refused on its own argument.
#[tokio::test]
async fn a_refused_verb_is_logged_with_the_application_call_channel_verb_and_error() {
    let (result, lines) = dispatch_capturing(
        tracing::Level::WARN,
        None,
        Some("sip"),
        "play",
        channel_target(),
        play_blob_args(MAX_PLAY_BLOB_BYTES + 1),
    )
    .await;
    assert!(
        matches!(result, ControlResult::Error { .. }),
        "expected a refusal, got {result:?}"
    );
    let refusal = refusal_line(&lines);
    assert!(refusal.contains("WARN"), "{refusal}");
    assert!(has_field(refusal, "app", APP), "{refusal}");
    assert!(has_field(refusal, "sip_call_id", SIP_CALL_ID), "{refusal}");
    assert!(has_field(refusal, "channel", CHANNEL), "{refusal}");
    assert!(has_field(refusal, "module", "sip"), "{refusal}");
    assert!(has_field(refusal, "verb", "play"), "{refusal}");
    assert!(has_field(refusal, "code", "bad_request"), "{refusal}");
    // The error text, not just the fact of one.
    assert!(refusal.contains("args.blob"), "{refusal}");
}

/// A verb the stack could not serve is the operator's problem, not the
/// controller's, so it is an `error` — and the two are told apart by level, not
/// by reading the prose.
#[tokio::test]
async fn a_stack_failure_is_logged_at_error_where_a_caller_fault_is_a_warning() {
    let unavailable: Arc<dyn ControlAdapter> = Arc::new(FixedAdapter(ControlResult::error(
        ControlErrorCode::Unavailable,
        "the B2BUA is not running",
    )));
    let (_, lines) = dispatch_capturing(
        tracing::Level::WARN,
        Some(unavailable),
        Some("fixed"),
        "play",
        channel_target(),
        serde_json::Value::Null,
    )
    .await;
    let refusal = refusal_line(&lines);
    assert!(refusal.contains("ERROR"), "{refusal}");
    assert!(has_field(refusal, "code", "unavailable"), "{refusal}");
    assert!(has_field(refusal, "sip_call_id", SIP_CALL_ID), "{refusal}");
    assert!(refusal.contains("the B2BUA is not running"), "{refusal}");

    let caller_fault: Arc<dyn ControlAdapter> = Arc::new(FixedAdapter(ControlResult::error(
        ControlErrorCode::InvalidState,
        "leg has not answered",
    )));
    let (_, lines) = dispatch_capturing(
        tracing::Level::WARN,
        Some(caller_fault),
        Some("fixed"),
        "bridge",
        channel_target(),
        serde_json::Value::Null,
    )
    .await;
    let refusal = refusal_line(&lines);
    assert!(refusal.contains("WARN"), "{refusal}");
    assert!(has_field(refusal, "code", "invalid_state"), "{refusal}");
}

/// Every refusal code but `unavailable` is the controller having asked for
/// something impossible. The split is what the log level is graded on, so it is
/// asserted over the whole set rather than over the codes the tests above use.
#[test]
fn only_unavailable_counts_as_a_stack_failure() {
    for code in ControlErrorCode::ALL {
        assert_eq!(
            code.is_caller_fault(),
            code != ControlErrorCode::Unavailable,
            "{code:?}"
        );
    }
}

/// A verb that was carried out is not a refusal: it stays at `debug`, so a
/// deployment running at `info` sees refusals only. Driven through a substrate
/// verb, which the adapters never see — the logging has to cover those too.
#[tokio::test]
async fn an_applied_verb_is_not_logged_as_a_refusal() {
    let (result, lines) = dispatch_capturing(
        tracing::Level::DEBUG,
        None,
        None,
        "get_var",
        channel_target(),
        serde_json::json!({ "key": "queue" }),
    )
    .await;
    assert!(
        matches!(result, ControlResult::Ok(_)),
        "expected ok, got {result:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("control plane: command refused")),
        "{lines:?}"
    );
    let applied = lines
        .iter()
        .find(|line| line.contains("control plane: command applied"))
        .unwrap_or_else(|| panic!("no applied line in {lines:?}"));
    assert!(applied.contains("DEBUG"), "{applied}");
    assert!(has_field(applied, "verb", "get_var"), "{applied}");
    assert!(has_field(applied, "sip_call_id", SIP_CALL_ID), "{applied}");
}

/// An oversized `blob` is the caller's argument, not the engine's health: it is
/// `bad_request`, and it is refused *before* anything is encoded or even looked
/// up.
///
/// The ordering is what the second half proves. This channel has no anchored
/// media session, so a `play` that got as far as the backend answers `not_found`
/// — which is exactly what the in-limit blob does. The oversized one answering
/// `bad_request` can therefore only mean the size gate ran first.
#[tokio::test]
async fn an_oversized_play_blob_is_refused_as_bad_request_before_the_media_session_is_resolved() {
    let (oversized, _) = dispatch_capturing(
        tracing::Level::WARN,
        None,
        Some("sip"),
        "play",
        channel_target(),
        play_blob_args(MAX_PLAY_BLOB_BYTES + 1),
    )
    .await;
    let ControlResult::Error {
        code, ref message, ..
    } = oversized
    else {
        panic!("expected a refusal, got {oversized:?}");
    };
    assert_eq!(code, ControlErrorCode::BadRequest);
    // The verb, the offending argument and the bound — in bytes of audio, which
    // is the unit the controller supplied, never a JSON frame length.
    assert!(message.contains("play"), "{message}");
    assert!(message.contains("args.blob"), "{message}");
    assert!(
        message.contains(&(MAX_PLAY_BLOB_BYTES + 1).to_string()),
        "{message}"
    );
    assert!(
        message.contains(&MAX_PLAY_BLOB_BYTES.to_string()),
        "{message}"
    );
    assert!(
        !message.contains("frame"),
        "the refusal still names the transport: {message}"
    );

    let (in_limit, _) = dispatch_capturing(
        tracing::Level::WARN,
        None,
        Some("sip"),
        "play",
        channel_target(),
        play_blob_args(MAX_PLAY_BLOB_BYTES),
    )
    .await;
    let ControlResult::Error { code, .. } = in_limit else {
        panic!("expected a refusal, got {in_limit:?}");
    };
    assert_eq!(
        code,
        ControlErrorCode::NotFound,
        "a blob at the limit must pass the size gate and fail on the missing media session"
    );
}

/// An engine that is genuinely not reachable still answers `unavailable`. The
/// two codes must not collapse: retry later and never retry this prompt are
/// opposite responses, and a controller can only tell them apart by the code.
#[test]
fn an_unreachable_engine_still_maps_to_unavailable() {
    let timeout = media_error(crate::rtpengine::RtpEngineError::Timeout { timeout_ms: 2000 });
    let ControlResult::Error {
        code: unreachable, ..
    } = timeout
    else {
        panic!("expected a refusal, got {timeout:?}");
    };
    assert_eq!(unreachable, ControlErrorCode::Unavailable);

    let refusal = play_blob_refusal(&PlayMediaSource::Blob(vec![0; MAX_PLAY_BLOB_BYTES + 1]))
        .expect("an oversized blob is refused");
    let ControlResult::Error {
        code: out_of_range, ..
    } = refusal
    else {
        panic!("expected a refusal");
    };
    assert_ne!(out_of_range, unreachable);
}

/// A source that fits, and a source that carries a reference rather than the
/// bytes, are not touched by the size gate.
#[test]
fn only_an_oversized_inline_blob_is_gated() {
    for source in [
        PlayMediaSource::Blob(vec![0; MAX_PLAY_BLOB_BYTES]),
        PlayMediaSource::File("/var/lib/siphon/prompts/welcome.wav".to_string()),
        PlayMediaSource::DbId(42),
        PlayMediaSource::Tone("ringback_eu".to_string()),
        PlayMediaSource::Http("https://prompts.example.com/welcome.wav".to_string()),
    ] {
        assert!(
            play_blob_refusal(&source).is_none(),
            "{} must not be gated",
            source.kind()
        );
    }
}

/// The machine-readable fields beside the prose, and the exact names a controller
/// branches on. Asserted on the wire frame, not just on the `ControlResult`: the
/// point of them is that they survive serialization.
#[test]
fn an_oversized_play_blob_carries_stable_machine_readable_fields() {
    let refusal = play_blob_refusal(&PlayMediaSource::Blob(vec![0; MAX_PLAY_BLOB_BYTES + 7]))
        .expect("an oversized blob is refused");
    let reply = refusal.into_reply("c-1".to_string());
    assert_eq!(reply.status, ReplyStatus::Error);
    let error = reply.error.expect("an error body");
    assert_eq!(error.code, ControlErrorCode::BadRequest);
    let details = error.details.expect("machine-readable details");
    assert_eq!(details["verb"], "play");
    assert_eq!(details["argument"], "blob");
    assert_eq!(details["bytes"], MAX_PLAY_BLOB_BYTES as u64 + 7);
    assert_eq!(details["limit_bytes"], MAX_PLAY_BLOB_BYTES as u64);
}

/// The limit is a property of the frame budget, not a number somebody typed, and
/// it is content-independent: the same prompt is always either accepted or
/// refused, whatever bytes it happens to contain.
#[test]
fn the_blob_limit_leaves_room_for_the_worst_case_encoding() {
    // Every byte at its widest JSON rendering ("255,") plus the envelope still
    // has to fit the frame the media backend will build.
    let worst_case = MAX_PLAY_BLOB_BYTES * 4;
    assert!(
        worst_case <= siphon_rtp_proto::MAX_FRAME_LEN,
        "{worst_case} > {}",
        siphon_rtp_proto::MAX_FRAME_LEN
    );
    // Content-independent: all-zero bytes render at one JSON byte each and are
    // gated at exactly the same length as all-0xff bytes.
    assert!(PlayMediaSource::Blob(vec![0x00; MAX_PLAY_BLOB_BYTES + 1])
        .oversized_blob_len()
        .is_some());
    assert!(PlayMediaSource::Blob(vec![0xff; MAX_PLAY_BLOB_BYTES])
        .oversized_blob_len()
        .is_none());
}
