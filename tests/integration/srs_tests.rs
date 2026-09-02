//! Integration tests for the SRS (Session Recording Server) module.
//!
//! Tests cover the full SRS pipeline: multipart MIME parsing → metadata
//! extraction → session management → storage backend writing.  Also tests
//! cross-module integration between siprec::multipart, siprec::metadata,
//! srs::SrsManager, and srs::storage.

use siphon::config::SrsConfig;
use siphon::siprec::metadata::{build_recording_metadata, parse_recording_metadata};
use siphon::siprec::multipart::{find_part, parse_multipart};
use siphon::srs::{SrsManager, SrsSessionState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_srs_config() -> SrsConfig {
    SrsConfig {
        enabled: true,
        recording_dir: "/tmp/siphon-test-recordings".to_string(),
        max_sessions: 100,
        backend: "file".to_string(),
        file: None,
        http: None,
        rtpengine_profile: "srs_recording".to_string(),
    }
}

fn sample_siprec_body(session_id: &str, caller: &str, callee: &str) -> (String, Vec<u8>) {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 12345 12345 IN IP4 192.168.1.1\r\n",
        "s=-\r\n",
        "c=IN IP4 192.168.1.1\r\n",
        "t=0 0\r\n",
        "m=audio 20000 RTP/AVP 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=label:main-audio\r\n",
    );

    let metadata_xml = build_recording_metadata(session_id, caller, callee, None);

    let boundary = "siprec-boundary-12345";
    let body = format!(
        "--{boundary}\r\n\
         Content-Type: application/sdp\r\n\
         \r\n\
         {sdp}\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/rs-metadata+xml\r\n\
         \r\n\
         {metadata_xml}\r\n\
         --{boundary}--\r\n"
    );

    let content_type = format!("multipart/mixed;boundary={boundary}");
    (content_type, body.into_bytes())
}

// ---------------------------------------------------------------------------
// End-to-end: multipart parsing → metadata extraction
// ---------------------------------------------------------------------------

#[test]
fn siprec_body_round_trip() {
    let session_id = "abc12345-6789-0000-0000-000000000000";
    let (content_type, body) =
        sample_siprec_body(session_id, "sip:alice@example.com", "sip:bob@example.com");

    // Parse multipart body.
    let parts = parse_multipart(&content_type, &body).unwrap();
    assert!(
        parts.len() >= 2,
        "expected at least 2 MIME parts, got {}",
        parts.len()
    );

    // Extract SDP part.
    let sdp_part = find_part(&parts, "application/sdp");
    assert!(sdp_part.is_some(), "no SDP part found");
    let sdp_str = String::from_utf8_lossy(&sdp_part.unwrap().body);
    assert!(
        sdp_str.contains("m=audio"),
        "SDP should contain audio media line"
    );

    // Extract metadata part.
    let metadata_part = find_part(&parts, "application/rs-metadata");
    assert!(metadata_part.is_some(), "no rs-metadata+xml part found");

    let metadata_xml = String::from_utf8_lossy(&metadata_part.unwrap().body);
    let metadata = parse_recording_metadata(&metadata_xml).unwrap();

    assert_eq!(metadata.session_id, session_id);
    assert_eq!(metadata.participants.len(), 2);
    assert_eq!(metadata.participants[0].aor, "sip:alice@example.com");
    assert_eq!(metadata.participants[1].aor, "sip:bob@example.com");
    assert_eq!(metadata.streams.len(), 2);
    assert_eq!(metadata.streams[0].label, "0");
    assert_eq!(metadata.streams[1].label, "1");
}

// ---------------------------------------------------------------------------
// SrsManager + metadata integration
// ---------------------------------------------------------------------------

#[test]
fn srs_manager_session_lifecycle() {
    let config = sample_srs_config();
    let manager = SrsManager::new(config);

    let session_id = "test-session-0000-0000-000000000000";
    let metadata = parse_recording_metadata(&build_recording_metadata(
        session_id,
        "sip:caller@host.com",
        "sip:callee@host.com",
        None,
    ))
    .unwrap();

    // Create session.
    let (created_session_id, to_tag) = manager
        .create_session("call-id-123", "from-tag-abc", metadata)
        .unwrap();

    assert!(!created_session_id.is_empty());
    assert!(!to_tag.is_empty());
    assert!(manager.is_srs_session("call-id-123"));

    // Activate.
    manager.activate_session(&created_session_id);
    {
        let session = manager.get_session(&created_session_id).unwrap();
        assert!(matches!(session.state, SrsSessionState::Recording));
    }

    // Stop → get recording record.
    let record = manager.stop_session("call-id-123").unwrap();
    assert_eq!(record.session_id, created_session_id);
    assert_eq!(record.recording_call_id, "call-id-123");
    assert_eq!(record.participants.len(), 2);
    assert_eq!(record.participants[0].aor, "sip:caller@host.com");

    // Session should be gone after stop.
    assert!(!manager.is_srs_session("call-id-123"));
}

#[test]
fn srs_manager_multiple_sessions() {
    let config = sample_srs_config();
    let manager = SrsManager::new(config);

    let metadata1 = parse_recording_metadata(&build_recording_metadata(
        "session-aaaa-0000-0000-000000000001",
        "sip:a@x.com",
        "sip:b@x.com",
        None,
    ))
    .unwrap();

    let metadata2 = parse_recording_metadata(&build_recording_metadata(
        "session-bbbb-0000-0000-000000000002",
        "sip:c@x.com",
        "sip:d@x.com",
        None,
    ))
    .unwrap();

    let (sid1, _) = manager
        .create_session("cid-1", "ftag-1", metadata1)
        .unwrap();
    let (sid2, _) = manager
        .create_session("cid-2", "ftag-2", metadata2)
        .unwrap();

    assert_ne!(sid1, sid2);
    assert!(manager.is_srs_session("cid-1"));
    assert!(manager.is_srs_session("cid-2"));
    assert!(!manager.is_srs_session("cid-3"));

    // Activate and stop one.
    manager.activate_session(&sid1);
    let record = manager.stop_session("cid-1").unwrap();
    assert_eq!(record.participants[0].aor, "sip:a@x.com");

    // Second still active.
    assert!(manager.is_srs_session("cid-2"));
}

#[test]
fn srs_manager_fail_session() {
    let config = sample_srs_config();
    let manager = SrsManager::new(config);

    let metadata = parse_recording_metadata(&build_recording_metadata(
        "session-fail-0000-0000-000000000000",
        "sip:x@y.com",
        "sip:z@y.com",
        None,
    ))
    .unwrap();

    let (session_id, _) = manager
        .create_session("cid-fail", "ftag", metadata)
        .unwrap();
    manager.fail_session(&session_id, "RTPEngine timeout");

    let session_id_ref = manager.session_for_call_id("cid-fail").unwrap();
    let session = manager.get_session(&session_id_ref).unwrap();
    match &session.state {
        SrsSessionState::Failed(reason) => {
            assert!(reason.contains("RTPEngine timeout"));
        }
        other => panic!("expected Failed state, got {:?}", other),
    }
}

#[test]
fn srs_manager_max_sessions_enforced() {
    let mut config = sample_srs_config();
    config.max_sessions = 2;
    let manager = SrsManager::new(config);

    let make_metadata = |id: &str| {
        parse_recording_metadata(&build_recording_metadata(
            id,
            "sip:a@x.com",
            "sip:b@x.com",
            None,
        ))
        .unwrap()
    };

    // First two succeed.
    assert!(manager
        .create_session(
            "cid-1",
            "ft-1",
            make_metadata("sess-1111-0000-0000-000000000001")
        )
        .is_some());
    assert!(manager
        .create_session(
            "cid-2",
            "ft-2",
            make_metadata("sess-2222-0000-0000-000000000002")
        )
        .is_some());

    // Third should fail (max_sessions = 2).
    assert!(manager
        .create_session(
            "cid-3",
            "ft-3",
            make_metadata("sess-3333-0000-0000-000000000003")
        )
        .is_none());
}

// ---------------------------------------------------------------------------
// Storage integration (file backend)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn srs_file_storage_writes_metadata() {
    let temp_dir = std::env::temp_dir().join(format!("siphon-srs-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let config = SrsConfig {
        enabled: true,
        recording_dir: temp_dir.display().to_string(),
        max_sessions: 100,
        backend: "file".to_string(),
        file: Some(siphon::config::SrsFileConfig {
            base_dir: temp_dir.display().to_string(),
        }),
        http: None,
        rtpengine_profile: "srs_recording".to_string(),
    };

    let manager = SrsManager::new(config.clone());

    let metadata = parse_recording_metadata(&build_recording_metadata(
        "storage-test-0000-0000-000000000000",
        "sip:alice@storage.test",
        "sip:bob@storage.test",
        None,
    ))
    .unwrap();

    let (session_id, _) = manager
        .create_session("cid-storage", "ftag", metadata)
        .unwrap();
    manager.activate_session(&session_id);

    // Wait a tiny bit so duration > 0 is possible (not required).
    let record = manager.stop_session("cid-storage").unwrap();

    // Write using storage backend.
    siphon::srs::storage::store_recording(&config, &record).await;

    // Verify file was written.
    let metadata_path = std::path::Path::new(&config.file.as_ref().unwrap().base_dir)
        .join(&session_id)
        .join("metadata.json");
    assert!(
        metadata_path.exists(),
        "metadata.json should exist at {:?}",
        metadata_path
    );

    // Parse and verify contents.
    let contents = std::fs::read_to_string(&metadata_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(json["session_id"].as_str().unwrap(), session_id);
    assert_eq!(json["participants"].as_array().unwrap().len(), 2);
    assert_eq!(
        json["participants"][0]["aor"].as_str().unwrap(),
        "sip:alice@storage.test"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ---------------------------------------------------------------------------
// RTPEngine profile integration
// ---------------------------------------------------------------------------

#[test]
fn srs_recording_profile_has_record_call() {
    let registry = siphon::rtpengine::profile::ProfileRegistry::new();
    let profile = registry.get("srs_recording").unwrap();

    assert!(
        profile.offer.record_call,
        "srs_recording offer should have record_call=true"
    );
    assert!(
        profile.answer.record_call,
        "srs_recording answer should have record_call=true"
    );
    assert_eq!(profile.offer.ice.as_deref(), Some("remove"));
    assert_eq!(profile.offer.dtls.as_deref(), Some("off"));
    assert!(profile.offer.flags.contains(&"media handover".to_string()));
    assert!(profile.offer.flags.contains(&"port latching".to_string()));
    assert!(profile.offer.replace.contains(&"origin".to_string()));
    assert!(
        profile.offer.direction.is_empty(),
        "direction should be empty (use RTPEngine default)"
    );
}

#[test]
fn srs_manager_uses_configured_profile() {
    let mut config = sample_srs_config();
    config.rtpengine_profile = "custom_profile".to_string();
    let manager = SrsManager::new(config);
    assert_eq!(manager.rtpengine_profile(), "custom_profile");
}

// ---------------------------------------------------------------------------
// Multipart edge cases with SIPREC content
// ---------------------------------------------------------------------------

#[test]
fn siprec_multipart_with_extra_parts() {
    // Some SRCs include additional parts (e.g., PIDF for presence).
    let boundary = "extra-parts-boundary";
    let metadata_xml = build_recording_metadata(
        "extra-sess-0000-0000-000000000000",
        "sip:a@x.com",
        "sip:b@x.com",
        None,
    );
    let body = format!(
        "--{boundary}\r\n\
         Content-Type: application/sdp\r\n\
         \r\n\
         v=0\r\n\
         o=- 1 1 IN IP4 0.0.0.0\r\n\
         s=-\r\n\
         t=0 0\r\n\
         m=audio 10000 RTP/AVP 0\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/rs-metadata+xml\r\n\
         \r\n\
         {metadata_xml}\r\n\
         --{boundary}\r\n\
         Content-Type: application/pidf+xml\r\n\
         \r\n\
         <presence/>\r\n\
         --{boundary}--\r\n"
    );

    let content_type = format!("multipart/mixed;boundary={boundary}");
    let parts = parse_multipart(&content_type, body.as_bytes()).unwrap();
    assert_eq!(parts.len(), 3);

    // Should still find SDP and metadata correctly.
    assert!(find_part(&parts, "application/sdp").is_some());
    assert!(find_part(&parts, "application/rs-metadata").is_some());
    assert!(find_part(&parts, "application/pidf").is_some());
}

#[test]
fn srs_session_captures_original_call_id() {
    let config = sample_srs_config();
    let manager = SrsManager::new(config);

    // Metadata with sipSessionID referencing the original call.
    let xml = concat!(
        "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
        "  <session session_id=\"rec-session-001\">\n",
        "    <sipSessionID>original-dialog-call-id@10.0.0.1</sipSessionID>\n",
        "  </session>\n",
        "  <participant participant_id=\"p1\">\n",
        "    <nameID aor=\"sip:alice@example.com\"/>\n",
        "  </participant>\n",
        "  <participant participant_id=\"p2\">\n",
        "    <nameID aor=\"sip:bob@example.com\"/>\n",
        "  </participant>\n",
        "  <stream stream_id=\"s1\" session_id=\"rec-session-001\">\n",
        "    <label>0</label>\n",
        "  </stream>\n",
        "</recording>",
    );
    let metadata = parse_recording_metadata(xml).unwrap();
    assert_eq!(
        metadata.sip_session_ids,
        vec!["original-dialog-call-id@10.0.0.1"]
    );

    let (session_id, _) = manager
        .create_session("siprec-call-1", "from-tag", metadata)
        .unwrap();
    let session = manager.get_session(&session_id).unwrap();
    assert_eq!(
        session.original_call_id.as_deref(),
        Some("original-dialog-call-id@10.0.0.1")
    );

    drop(session);
    let record = manager.stop_session("siprec-call-1").unwrap();
    assert_eq!(
        record.original_call_id.as_deref(),
        Some("original-dialog-call-id@10.0.0.1")
    );
}

#[test]
fn metadata_with_participant_names() {
    let xml = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
        "  <datamode>complete</datamode>\n",
        "  <session session_id=\"named-sess-001\">\n",
        "    <sipSessionID>named-sess-001</sipSessionID>\n",
        "  </session>\n",
        "  <participant participant_id=\"p1\">\n",
        "    <nameID aor=\"sip:alice@example.com\"/>\n",
        "    <name>Alice Smith</name>\n",
        "  </participant>\n",
        "  <participant participant_id=\"p2\">\n",
        "    <nameID aor=\"sip:bob@example.com\"/>\n",
        "    <name>Bob Jones</name>\n",
        "  </participant>\n",
        "  <stream stream_id=\"s1\" session_id=\"named-sess-001\">\n",
        "    <label>caller-audio</label>\n",
        "  </stream>\n",
        "</recording>",
    );

    let metadata = parse_recording_metadata(xml).unwrap();
    assert_eq!(metadata.session_id, "named-sess-001");
    assert_eq!(
        metadata.participants[0].name.as_deref(),
        Some("Alice Smith")
    );
    assert_eq!(metadata.participants[1].name.as_deref(), Some("Bob Jones"));
}
