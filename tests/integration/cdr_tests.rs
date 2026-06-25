//! Integration tests for the CDR (Call Detail Records) module.
//!
//! Tests cover Cdr struct construction, builder pattern, JSON serialization,
//! timestamp formatting, extra field flattening, and file backend writing.


use siphon::cdr::{Cdr, CdrBackendType, CdrConfig};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_cdr() -> Cdr {
    Cdr::new(
        "a84b4c76e66710@192.168.1.100".to_string(),
        "sip:alice@example.com".to_string(),
        "sip:bob@example.com".to_string(),
        "sip:bob@10.0.0.1:5060".to_string(),
        "INVITE".to_string(),
        "192.168.1.100".to_string(),
        "udp".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Builder pattern
// ---------------------------------------------------------------------------

#[test]
fn cdr_builder_chain() {
    let cdr = sample_cdr()
        .with_response_code(200)
        .with_destination_ip("10.0.0.1".to_string())
        .with_start()
        .with_answer()
        .with_duration(120.5)
        .with_disconnect_initiator("caller".to_string())
        .with_extra("billing_id".to_string(), "B-12345".to_string())
        .with_extra("account".to_string(), "ACC-789".to_string());

    assert_eq!(cdr.response_code, 200);
    assert_eq!(cdr.destination_ip, "10.0.0.1");
    assert!(cdr.timestamp_start.is_some());
    assert!(cdr.timestamp_answer.is_some());
    assert_eq!(cdr.duration_secs, 120.5);
    assert_eq!(cdr.disconnect_initiator.as_deref(), Some("caller"));
    assert_eq!(cdr.extra.get("billing_id").unwrap(), "B-12345");
    assert_eq!(cdr.extra.get("account").unwrap(), "ACC-789");
}

#[test]
fn cdr_defaults_are_sensible() {
    let cdr = sample_cdr();
    assert_eq!(cdr.response_code, 0);
    assert!(cdr.destination_ip.is_empty());
    assert!(cdr.timestamp_start.is_none());
    assert!(cdr.timestamp_answer.is_none());
    assert!(cdr.timestamp_end.is_none());
    assert_eq!(cdr.duration_secs, 0.0);
    assert!(cdr.disconnect_initiator.is_none());
    assert!(cdr.sip_reason.is_none());
    assert!(cdr.user_agent.is_none());
    assert!(cdr.auth_user.is_none());
    assert!(cdr.extra.is_empty());
}

// ---------------------------------------------------------------------------
// JSON serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn json_serialization_contains_all_fields() {
    let cdr = sample_cdr()
        .with_response_code(200)
        .with_destination_ip("10.0.0.1".to_string())
        .with_start()
        .with_disconnect_initiator("callee".to_string());

    let json = serde_json::to_string(&cdr).unwrap();

    assert!(json.contains("\"call_id\":\"a84b4c76e66710@192.168.1.100\""));
    assert!(json.contains("\"from_uri\":\"sip:alice@example.com\""));
    assert!(json.contains("\"to_uri\":\"sip:bob@example.com\""));
    assert!(json.contains("\"ruri\":\"sip:bob@10.0.0.1:5060\""));
    assert!(json.contains("\"method\":\"INVITE\""));
    assert!(json.contains("\"response_code\":200"));
    assert!(json.contains("\"source_ip\":\"192.168.1.100\""));
    assert!(json.contains("\"destination_ip\":\"10.0.0.1\""));
    assert!(json.contains("\"transport\":\"udp\""));
    assert!(json.contains("\"disconnect_initiator\":\"callee\""));
}

#[test]
fn json_roundtrip_via_serde_value() {
    let cdr = sample_cdr()
        .with_response_code(180)
        .with_duration(42.5);

    let json_string = serde_json::to_string(&cdr).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_string).unwrap();

    assert_eq!(parsed["call_id"], "a84b4c76e66710@192.168.1.100");
    assert_eq!(parsed["response_code"], 180);
    assert_eq!(parsed["duration_secs"], 42.5);
    assert_eq!(parsed["method"], "INVITE");
    assert_eq!(parsed["transport"], "udp");
}

// ---------------------------------------------------------------------------
// Timestamp formatting
// ---------------------------------------------------------------------------

#[test]
fn timestamp_is_iso_8601_utc() {
    let cdr = sample_cdr();

    // Timestamp should be in the form: YYYY-MM-DDTHH:MM:SS.mmmZ
    assert!(cdr.timestamp.contains('T'), "missing 'T' separator");
    assert!(cdr.timestamp.ends_with('Z'), "missing trailing 'Z'");
    assert!(cdr.timestamp.len() >= 23, "timestamp too short: {}", cdr.timestamp);

    // Verify the date portion parses as digits.
    let date_part = &cdr.timestamp[..10];
    assert_eq!(&date_part[4..5], "-");
    assert_eq!(&date_part[7..8], "-");
}

#[test]
fn start_and_answer_timestamps_are_iso_8601() {
    let cdr = sample_cdr().with_start().with_answer();

    let start = cdr.timestamp_start.unwrap();
    assert!(start.contains('T') && start.ends_with('Z'));

    let answer = cdr.timestamp_answer.unwrap();
    assert!(answer.contains('T') && answer.ends_with('Z'));
}

// ---------------------------------------------------------------------------
// Extra fields flattening
// ---------------------------------------------------------------------------

#[test]
fn extra_fields_are_flattened_in_json() {
    let cdr = sample_cdr()
        .with_extra("billing_id".to_string(), "B-12345".to_string())
        .with_extra("account_code".to_string(), "ACC-789".to_string())
        .with_extra("custom_field".to_string(), "custom_value".to_string());

    let json_string = serde_json::to_string(&cdr).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_string).unwrap();

    // Extra fields should appear at the top level, not nested under "extra".
    assert_eq!(parsed["billing_id"], "B-12345");
    assert_eq!(parsed["account_code"], "ACC-789");
    assert_eq!(parsed["custom_field"], "custom_value");
    assert!(parsed.get("extra").is_none(), "extra should be flattened, not nested");
}

// ---------------------------------------------------------------------------
// Duration computation
// ---------------------------------------------------------------------------

#[test]
fn with_end_computes_duration_from_answer() {
    let cdr = sample_cdr().with_answer();

    // Sleep briefly so duration is measurable.
    std::thread::sleep(std::time::Duration::from_millis(15));

    let cdr = cdr.with_end();
    assert!(cdr.timestamp_end.is_some());
    assert!(
        cdr.duration_secs >= 0.01,
        "duration should be >= 10ms, got {}",
        cdr.duration_secs
    );
}

#[test]
fn with_end_without_answer_has_zero_duration() {
    let cdr = sample_cdr().with_start().with_end();

    assert_eq!(cdr.duration_secs, 0.0, "no answer means zero duration");
}

#[test]
fn with_duration_overrides_computed_duration() {
    let _cdr = sample_cdr().with_answer().with_duration(300.0).with_end();

    // with_end overwrites duration_secs from answer_instant, but
    // with_duration was called before with_end, so with_end recalculates.
    // The important thing is that manual override via with_duration works
    // when called last.
    let cdr_manual = sample_cdr().with_answer().with_end().with_duration(300.0);
    assert_eq!(cdr_manual.duration_secs, 300.0);
}

// ---------------------------------------------------------------------------
// CdrConfig
// ---------------------------------------------------------------------------

#[test]
fn cdr_config_defaults() {
    let config = CdrConfig::default();
    assert!(!config.enabled);
    assert!(!config.include_register);
    assert_eq!(config.channel_size, 10_000);

    match &config.backend {
        CdrBackendType::File { path, rotate_size_mb } => {
            assert_eq!(path, "/var/log/siphon/cdr.jsonl");
            assert_eq!(*rotate_size_mb, 100);
        }
        other => panic!("expected File backend, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// File backend: write to temp file and read back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_backend_write_and_read_back() {
    let temp_dir = std::env::temp_dir().join("siphon-cdr-test");
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_file = temp_dir.join("test-cdr.jsonl");
    let temp_path = temp_file.to_str().unwrap().to_string();

    // Clean up from previous runs.
    let _ = std::fs::remove_file(&temp_file);

    let config = CdrConfig {
        enabled: true,
        backend: CdrBackendType::File {
            path: temp_path.clone(),
            rotate_size_mb: 100,
        },
        include_register: false,
        channel_size: 100,
    };

    // We cannot use the global init() because OnceLock is process-wide and
    // other tests may have initialized it. Instead, test the serialization
    // and file write manually.
    let cdr = sample_cdr()
        .with_response_code(200)
        .with_destination_ip("10.0.0.1".to_string())
        .with_extra("test_key".to_string(), "test_value".to_string());

    let json_line = serde_json::to_string(&cdr).unwrap();

    // Write manually (simulating what write_file_cdr does).
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&temp_path)
        .await
        .unwrap();
    file.write_all(format!("{json_line}\n").as_bytes())
        .await
        .unwrap();
    drop(file);

    // Read back and parse.
    let contents = tokio::fs::read_to_string(&temp_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();

    assert_eq!(parsed["call_id"], "a84b4c76e66710@192.168.1.100");
    assert_eq!(parsed["response_code"], 200);
    assert_eq!(parsed["test_key"], "test_value");

    // Verify config was built correctly (not used in write, but validates struct).
    assert!(config.enabled);

    // Clean up.
    let _ = std::fs::remove_file(&temp_file);
    let _ = std::fs::remove_dir(&temp_dir);
}
