//! Integration tests for Lawful Intercept — X1/X2/X3/SIPREC end-to-end flows.
//!
//! Tests the full LI pipeline:
//! 1. Provision target via X1 API
//! 2. Match SIP message against target
//! 3. Emit IRI event to X2 channel
//! 4. Start X3 media capture / SIPREC recording
//! 5. Verify events are delivered correctly

use siphon::config::{LawfulInterceptConfig, LiX1Config, LiX2Config, LiX3Config, LiSiprecConfig};
use siphon::li::{IriEvent, IriEventType, LiManager, AuditOperation};
use siphon::li::target::{DeliveryType, InterceptTarget, TargetIdentity};
use siphon::li::x1::{self, X1State, TargetStatusResponse, TargetListResponse};
use siphon::li::x2;
use siphon::li::x3::X3Manager;
use siphon::li::siprec::SiprecManager;
use siphon::li::asn1;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn full_li_config() -> LawfulInterceptConfig {
    LawfulInterceptConfig {
        enabled: true,
        audit_log: Some("/tmp/li-integration-test.log".to_string()),
        x1: Some(LiX1Config {
            listen: "127.0.0.1:0".to_string(),
            tls: None,
            auth_token: Some("test-token".to_string()),
        }),
        x2: Some(LiX2Config {
            delivery_address: "127.0.0.1:0".to_string(),
            transport: "tcp".to_string(),
            reconnect_interval_secs: 1,
            channel_size: 1000,
            tls: None,
        }),
        x3: Some(LiX3Config {
            listen_udp: "127.0.0.1:0".to_string(),
            delivery_address: "127.0.0.1:19999".to_string(),
            transport: "udp".to_string(),
            encapsulation: "etsi".to_string(),
        }),
        siprec: Some(LiSiprecConfig {
            srs_uri: "sip:srs@recorder.example.com".to_string(),
            session_copies: 1,
            transport: "tcp".to_string(),
            rtpengine_profile: "siprec_src".to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// X1 → Target Store → Message Matching → X2 IRI (end-to-end)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x1_provision_then_match_then_iri_emitted() {
    let config = full_li_config();
    let (manager, mut iri_receiver, mut audit_receiver) = LiManager::new(config.clone(), 1000);

    // Drain startup audit entry
    let _ = audit_receiver.recv().await.unwrap();

    // Step 1: Provision target via X1 API
    let x1_state = X1State {
        manager: manager.clone(),
        config: Arc::new(config.x1.unwrap()),
    };
    let app = x1::x1_router(x1_state);

    let body = serde_json::json!({
        "liid": "LI-INTEG-001",
        "target_type": "sip_uri",
        "target_value": "sip:alice@example.com",
        "delivery_type": "iri_and_cc",
        "warrant_ref": "WARRANT-2026-001"
    });

    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x1/targets")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify audit trail recorded the activation
    let audit_entry = audit_receiver.recv().await.unwrap();
    assert!(matches!(audit_entry.operation, AuditOperation::TargetActivated));
    assert_eq!(audit_entry.liid.as_deref(), Some("LI-INTEG-001"));

    // Step 2: Simulate inbound SIP message — check_message matches
    let matches = manager.check_message(
        Some("sip:alice@example.com"),
        Some("sip:bob@external.com"),
        Some("sip:alice@example.com"),
        None,
    );

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].liid, "LI-INTEG-001");
    assert_eq!(matches[0].delivery_type, DeliveryType::IriAndCc);

    // Step 3: Emit IRI event for the match
    let iri_event = IriEvent {
        liid: matches[0].liid.clone(),
        correlation_id: "call-integ-001@example.com".to_string(),
        event_type: IriEventType::Begin,
        timestamp: SystemTime::now(),
        sip_method: "INVITE".to_string(),
        status_code: None,
        from_uri: "sip:bob@external.com".to_string(),
        to_uri: "sip:alice@example.com".to_string(),
        request_uri: Some("sip:alice@example.com".to_string()),
        source_ip: Some("10.0.0.1".parse().unwrap()),
        destination_ip: None,
        delivery_type: matches[0].delivery_type,
        raw_message: Some(b"INVITE sip:alice@example.com SIP/2.0\r\n\r\n".to_vec()),
    };

    manager.emit_iri(iri_event);

    // Step 4: Verify IRI event arrives on the X2 channel
    let received = iri_receiver.recv().await.unwrap();
    assert_eq!(received.liid, "LI-INTEG-001");
    assert_eq!(received.event_type, IriEventType::Begin);
    assert_eq!(received.sip_method, "INVITE");
    assert_eq!(received.correlation_id, "call-integ-001@example.com");
    assert_eq!(received.delivery_type, DeliveryType::IriAndCc);

    // Step 5: Verify via X1 GET that target is still active
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/x1/targets/LI-INTEG-001")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let status: TargetStatusResponse = serde_json::from_slice(&body).unwrap();
    assert!(status.active);
}

// ---------------------------------------------------------------------------
// Full call lifecycle: BEGIN → CONTINUE → END
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_call_lifecycle_iri_events() {
    let config = full_li_config();
    let (manager, mut iri_receiver, _audit_receiver) = LiManager::new(config, 1000);

    // Provision target directly (bypassing X1 for speed)
    manager.targets().activate(InterceptTarget {
        liid: "LI-CALL-001".to_string(),
        target_identity: TargetIdentity::PhoneNumber("+15551234567".to_string()),
        delivery_type: DeliveryType::IriAndCc,
        active: true,
        activated_at: SystemTime::now(),
        warrant_ref: Some("W-001".to_string()),
        mediation_id: None,
    });

    // INVITE — IRI-BEGIN
    let matches = manager.check_message(
        Some("sip:+15551234567@carrier.com"),
        Some("sip:caller@external.com"),
        Some("sip:+15551234567@carrier.com"),
        None,
    );
    assert_eq!(matches.len(), 1);

    manager.emit_iri(IriEvent {
        liid: "LI-CALL-001".to_string(),
        correlation_id: "call-lifecycle@example.com".to_string(),
        event_type: IriEventType::Begin,
        timestamp: SystemTime::now(),
        sip_method: "INVITE".to_string(),
        status_code: None,
        from_uri: "sip:caller@external.com".to_string(),
        to_uri: "sip:+15551234567@carrier.com".to_string(),
        request_uri: Some("sip:+15551234567@carrier.com".to_string()),
        source_ip: None,
        destination_ip: None,
        delivery_type: DeliveryType::IriAndCc,
        raw_message: None,
    });

    // 180 Ringing — IRI-CONTINUE
    manager.emit_iri(IriEvent {
        liid: "LI-CALL-001".to_string(),
        correlation_id: "call-lifecycle@example.com".to_string(),
        event_type: IriEventType::Continue,
        timestamp: SystemTime::now(),
        sip_method: "INVITE".to_string(),
        status_code: Some(180),
        from_uri: "sip:caller@external.com".to_string(),
        to_uri: "sip:+15551234567@carrier.com".to_string(),
        request_uri: None,
        source_ip: None,
        destination_ip: None,
        delivery_type: DeliveryType::IriAndCc,
        raw_message: None,
    });

    // BYE — IRI-END
    manager.emit_iri(IriEvent {
        liid: "LI-CALL-001".to_string(),
        correlation_id: "call-lifecycle@example.com".to_string(),
        event_type: IriEventType::End,
        timestamp: SystemTime::now(),
        sip_method: "BYE".to_string(),
        status_code: None,
        from_uri: "sip:caller@external.com".to_string(),
        to_uri: "sip:+15551234567@carrier.com".to_string(),
        request_uri: Some("sip:+15551234567@carrier.com".to_string()),
        source_ip: None,
        destination_ip: None,
        delivery_type: DeliveryType::IriAndCc,
        raw_message: None,
    });

    // Verify all three IRI events in order
    let begin = iri_receiver.recv().await.unwrap();
    assert_eq!(begin.event_type, IriEventType::Begin);
    assert_eq!(begin.sip_method, "INVITE");

    let cont = iri_receiver.recv().await.unwrap();
    assert_eq!(cont.event_type, IriEventType::Continue);
    assert_eq!(cont.status_code, Some(180));

    let end = iri_receiver.recv().await.unwrap();
    assert_eq!(end.event_type, IriEventType::End);
    assert_eq!(end.sip_method, "BYE");

    // All three share the same correlation ID
    assert_eq!(begin.correlation_id, cont.correlation_id);
    assert_eq!(cont.correlation_id, end.correlation_id);
}

// ---------------------------------------------------------------------------
// X2 delivery: IRI events encoded as BER and sent over TCP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x2_delivery_sends_ber_encoded_iri_over_tcp() {
    // Bind a mock mediation device
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mediation_address = listener.local_addr().unwrap().to_string();

    let x2_config = Arc::new(LiX2Config {
        delivery_address: mediation_address,
        transport: "tcp".to_string(),
        reconnect_interval_secs: 1,
        channel_size: 100,
        tls: None,
    });

    let (iri_sender, iri_receiver) = mpsc::channel(100);

    // Spawn X2 delivery task
    tokio::spawn(x2::delivery_task(iri_receiver, x2_config));

    // Accept connection and read PDU
    let read_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read length-prefixed PDU
        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes).await.unwrap();
        let length = u32::from_be_bytes(length_bytes) as usize;

        let mut pdu = vec![0u8; length];
        stream.read_exact(&mut pdu).await.unwrap();
        pdu
    });

    // Send IRI event
    iri_sender.send(IriEvent {
        liid: "LI-X2-001".to_string(),
        correlation_id: "call-x2@example.com".to_string(),
        event_type: IriEventType::Begin,
        timestamp: SystemTime::now(),
        sip_method: "INVITE".to_string(),
        status_code: None,
        from_uri: "sip:alice@example.com".to_string(),
        to_uri: "sip:bob@example.com".to_string(),
        request_uri: Some("sip:bob@example.com".to_string()),
        source_ip: None,
        destination_ip: None,
        delivery_type: DeliveryType::IriAndCc,
        raw_message: None,
    }).await.unwrap();

    // Verify the mediation device received a valid BER-encoded PS-PDU
    let pdu = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_handle,
    ).await.unwrap().unwrap();

    let (version, pdu_type, inner) = asn1::decode_ps_pdu(&pdu).unwrap();
    assert_eq!(version, 1);
    assert_eq!(pdu_type, 1); // IRI
    assert!(!inner.is_empty());
}

// ---------------------------------------------------------------------------
// X3 media capture: start/stop + ETSI encapsulation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x3_capture_lifecycle_with_encapsulation() {
    let x3_config = LiX3Config {
        listen_udp: "127.0.0.1:0".to_string(),
        delivery_address: "127.0.0.1:19998".to_string(),
        transport: "udp".to_string(),
        encapsulation: "etsi".to_string(),
    };

    let manager = X3Manager::new(&x3_config).unwrap();

    // Start capture for an intercepted call
    manager.start_capture(
        "LI-X3-001",
        "call-x3-integ@example.com",
        Some("10.0.0.100:20000".parse().unwrap()),
    );

    assert!(manager.is_capturing("call-x3-integ@example.com"));
    assert_eq!(manager.active_sessions(), 1);

    // Encapsulate a fake RTP packet
    let rtp_payload = vec![
        0x80, 0x08, // RTP header (V=2, PT=8 PCMA)
        0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0xA0, // timestamp
        0x12, 0x34, 0x56, 0x78, // SSRC
        0xD5, 0xD5, 0xD5, 0xD5, // payload (PCMA silence)
    ];

    let encapsulated = manager.encapsulate(
        "LI-X3-001",
        "call-x3-integ@example.com",
        &rtp_payload,
    );

    // Verify ETSI CC-PDU envelope
    let (version, pdu_type, inner) = asn1::decode_ps_pdu(&encapsulated).unwrap();
    assert_eq!(version, 1);
    assert_eq!(pdu_type, 2); // CC
    assert!(!inner.is_empty());

    // Stop capture
    let session = manager.stop_capture("call-x3-integ@example.com").unwrap();
    assert_eq!(session.liid, "LI-X3-001");
    assert!(!manager.is_capturing("call-x3-integ@example.com"));
}

// ---------------------------------------------------------------------------
// SIPREC: recording session lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn siprec_recording_lifecycle() {
    let siprec_config = LiSiprecConfig {
        srs_uri: "sip:srs@recorder.example.com".to_string(),
        session_copies: 1,
        transport: "tcp".to_string(),
        rtpengine_profile: "siprec_src".to_string(),
    };

    let manager = SiprecManager::new(&siprec_config);

    // Start recording for an intercepted call
    let session = manager.start_recording(
        "call-siprec-integ@example.com",
        Some("LI-SIPREC-001"),
    );

    assert!(session.recording_call_id.starts_with("siprec-"));
    assert_eq!(session.liid.as_deref(), Some("LI-SIPREC-001"));
    assert_eq!(session.srs_uri, "sip:srs@recorder.example.com");
    assert!(manager.is_recording("call-siprec-integ@example.com"));

    // Build recording metadata XML
    let xml = manager.build_metadata_xml(
        "call-siprec-integ@example.com",
        "sip:alice@example.com",
        "sip:bob@example.com",
        "sendrecv",
    );

    assert!(xml.contains("urn:ietf:params:xml:ns:recording:1"));
    assert!(xml.contains("call-siprec-integ@example.com"));
    assert!(xml.contains("sip:alice@example.com"));

    // SRS answers — mark active
    assert!(manager.mark_active("call-siprec-integ@example.com"));
    let active_session = manager.get_session("call-siprec-integ@example.com").unwrap();
    assert_eq!(active_session.state, siphon::li::siprec::RecordingState::Active);

    // Call ends — stop recording
    let stopped = manager.stop_recording("call-siprec-integ@example.com").unwrap();
    assert_eq!(stopped.original_call_id, "call-siprec-integ@example.com");
    assert!(!manager.is_recording("call-siprec-integ@example.com"));
}

// ---------------------------------------------------------------------------
// Combined: X1 provision → intercept match → X2 IRI + X3 capture + SIPREC
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_li_pipeline_x1_x2_x3_siprec() {
    let config = full_li_config();
    let (manager, mut iri_receiver, _audit_receiver) = LiManager::new(config.clone(), 1000);

    // X3 manager
    let x3_manager = X3Manager::new(config.x3.as_ref().unwrap()).unwrap();

    // SIPREC manager
    let siprec_manager = SiprecManager::new(config.siprec.as_ref().unwrap());

    // Step 1: Provision target via X1
    let x1_state = X1State {
        manager: manager.clone(),
        config: Arc::new(config.x1.unwrap()),
    };
    let app = x1::x1_router(x1_state);

    let body = serde_json::json!({
        "liid": "LI-FULL-001",
        "target_type": "phone_number",
        "target_value": "+15559876543",
        "delivery_type": "iri_and_cc"
    });

    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x1/targets")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Step 2: Inbound INVITE matches target
    let matches = manager.check_message(
        Some("sip:+15559876543@carrier.com"),
        Some("sip:caller@external.com"),
        None,
        None,
    );
    assert_eq!(matches.len(), 1);
    let target = &matches[0];
    assert_eq!(target.liid, "LI-FULL-001");
    assert_eq!(target.delivery_type, DeliveryType::IriAndCc);

    // Step 3: Emit IRI-BEGIN via X2
    manager.emit_iri(IriEvent {
        liid: target.liid.clone(),
        correlation_id: "call-full-pipeline@example.com".to_string(),
        event_type: IriEventType::Begin,
        timestamp: SystemTime::now(),
        sip_method: "INVITE".to_string(),
        status_code: None,
        from_uri: "sip:caller@external.com".to_string(),
        to_uri: "sip:+15559876543@carrier.com".to_string(),
        request_uri: Some("sip:+15559876543@carrier.com".to_string()),
        source_ip: Some("10.0.0.1".parse().unwrap()),
        destination_ip: None,
        delivery_type: target.delivery_type,
        raw_message: None,
    });

    let iri = iri_receiver.recv().await.unwrap();
    assert_eq!(iri.event_type, IriEventType::Begin);

    // Step 4: Start X3 media capture (target requires CC)
    x3_manager.start_capture(
        &target.liid,
        "call-full-pipeline@example.com",
        Some("10.0.0.100:30000".parse().unwrap()),
    );
    assert!(x3_manager.is_capturing("call-full-pipeline@example.com"));

    // Step 5: Start SIPREC recording
    let recording = siprec_manager.start_recording(
        "call-full-pipeline@example.com",
        Some(&target.liid),
    );
    assert!(siprec_manager.is_recording("call-full-pipeline@example.com"));
    assert_eq!(recording.liid.as_deref(), Some("LI-FULL-001"));

    // Step 6: Call terminates — emit IRI-END, stop X3, stop SIPREC
    manager.emit_iri(IriEvent {
        liid: target.liid.clone(),
        correlation_id: "call-full-pipeline@example.com".to_string(),
        event_type: IriEventType::End,
        timestamp: SystemTime::now(),
        sip_method: "BYE".to_string(),
        status_code: None,
        from_uri: "sip:caller@external.com".to_string(),
        to_uri: "sip:+15559876543@carrier.com".to_string(),
        request_uri: None,
        source_ip: None,
        destination_ip: None,
        delivery_type: target.delivery_type,
        raw_message: None,
    });

    let iri_end = iri_receiver.recv().await.unwrap();
    assert_eq!(iri_end.event_type, IriEventType::End);

    x3_manager.stop_capture("call-full-pipeline@example.com");
    assert!(!x3_manager.is_capturing("call-full-pipeline@example.com"));

    siprec_manager.stop_recording("call-full-pipeline@example.com");
    assert!(!siprec_manager.is_recording("call-full-pipeline@example.com"));

    // Step 7: Deactivate target via X1
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/x1/targets/LI-FULL-001")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify no more matches
    let no_match = manager.check_message(
        Some("sip:+15559876543@carrier.com"),
        None,
        None,
        None,
    );
    assert!(no_match.is_empty());
}

// ---------------------------------------------------------------------------
// X1 CRUD lifecycle — full REST flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x1_full_crud_lifecycle() {
    let config = full_li_config();
    let (manager, _iri_receiver, _audit_receiver) = LiManager::new(config.clone(), 100);

    let x1_state = X1State {
        manager,
        config: Arc::new(config.x1.unwrap()),
    };
    let app = x1::x1_router(x1_state);

    // CREATE
    let body = serde_json::json!({
        "liid": "LI-CRUD-001",
        "target_type": "ip_address",
        "target_value": "192.168.1.100",
        "delivery_type": "iri_only"
    });

    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x1/targets")
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // LIST — should have 1 target
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/x1/targets")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let list: TargetListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.count, 1);
    assert_eq!(list.targets[0].liid, "LI-CRUD-001");

    // MODIFY — upgrade to iri_and_cc
    let modify_body = serde_json::json!({
        "liid": "LI-CRUD-001",
        "target_type": "ip_address",
        "target_value": "192.168.1.100",
        "delivery_type": "iri_and_cc"
    });

    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/x1/targets/LI-CRUD-001")
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .body(Body::from(serde_json::to_vec(&modify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // GET — verify modification
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/x1/targets/LI-CRUD-001")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let status: TargetStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.delivery_type, "iri_and_cc");

    // PING
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x1/targets/LI-CRUD-001/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // DELETE
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/x1/targets/LI-CRUD-001")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // VERIFY GONE
    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/x1/targets/LI-CRUD-001")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// IP-based intercept: match by source IP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ip_based_intercept_match() {
    let config = full_li_config();
    let (manager, _iri_receiver, _audit_receiver) = LiManager::new(config, 1000);

    // Provision IP-based target
    manager.targets().activate(InterceptTarget {
        liid: "LI-IP-001".to_string(),
        target_identity: TargetIdentity::IpAddress("10.99.0.50".parse().unwrap()),
        delivery_type: DeliveryType::IriOnly,
        active: true,
        activated_at: SystemTime::now(),
        warrant_ref: None,
        mediation_id: None,
    });

    // Match by source IP
    let matches = manager.check_message(
        Some("sip:anyone@anywhere.com"),
        None,
        None,
        Some("10.99.0.50".parse().unwrap()),
    );

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].liid, "LI-IP-001");
    assert_eq!(matches[0].delivery_type, DeliveryType::IriOnly);

    // No match for different IP
    let no_match = manager.check_message(
        None,
        None,
        None,
        Some("10.99.0.51".parse().unwrap()),
    );
    assert!(no_match.is_empty());
}

// ---------------------------------------------------------------------------
// Multiple LEAs targeting same subject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_leas_same_target() {
    let config = full_li_config();
    let (manager, _iri_receiver, _audit_receiver) = LiManager::new(config, 1000);

    // LEA 1
    manager.targets().activate(InterceptTarget {
        liid: "LEA1-001".to_string(),
        target_identity: TargetIdentity::SipUri("sip:suspect@example.com".to_string()),
        delivery_type: DeliveryType::IriOnly,
        active: true,
        activated_at: SystemTime::now(),
        warrant_ref: Some("WARRANT-LEA1".to_string()),
        mediation_id: Some("mediation-lea1".to_string()),
    });

    // LEA 2 (different warrant, same target)
    manager.targets().activate(InterceptTarget {
        liid: "LEA2-001".to_string(),
        target_identity: TargetIdentity::SipUri("sip:suspect@example.com".to_string()),
        delivery_type: DeliveryType::IriAndCc,
        active: true,
        activated_at: SystemTime::now(),
        warrant_ref: Some("WARRANT-LEA2".to_string()),
        mediation_id: Some("mediation-lea2".to_string()),
    });

    // Both should match
    let matches = manager.check_message(
        None,
        Some("sip:suspect@example.com"),
        None,
        None,
    );

    assert_eq!(matches.len(), 2);
    let liids: Vec<&str> = matches.iter().map(|m| m.liid.as_str()).collect();
    assert!(liids.contains(&"LEA1-001"));
    assert!(liids.contains(&"LEA2-001"));

    // One is IRI-only, other is IRI+CC
    let lea1 = matches.iter().find(|m| m.liid == "LEA1-001").unwrap();
    let lea2 = matches.iter().find(|m| m.liid == "LEA2-001").unwrap();
    assert_eq!(lea1.delivery_type, DeliveryType::IriOnly);
    assert_eq!(lea2.delivery_type, DeliveryType::IriAndCc);
}

// ---------------------------------------------------------------------------
// Config parsing roundtrip: YAML → LawfulInterceptConfig
// ---------------------------------------------------------------------------

#[test]
fn config_parsing_integration() {
    use siphon::config::Config;

    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  audit_log: \"/var/log/siphon/li-audit.log\"\n",
        "  x1:\n",
        "    listen: \"127.0.0.1:8443\"\n",
        "    auth_token: \"secret\"\n",
        "  x2:\n",
        "    delivery_address: \"10.0.0.50:6543\"\n",
        "  x3:\n",
        "    delivery_address: \"10.0.0.50:6544\"\n",
        "  siprec:\n",
        "    srs_uri: \"sip:srs@recorder.example.com\"\n",
    );

    let config = Config::from_str(yaml).unwrap();
    let li = config.lawful_intercept.unwrap();

    assert!(li.enabled);
    assert_eq!(li.audit_log.unwrap(), "/var/log/siphon/li-audit.log");
    assert_eq!(li.x1.as_ref().unwrap().listen, "127.0.0.1:8443");
    assert_eq!(li.x2.as_ref().unwrap().delivery_address, "10.0.0.50:6543");
    assert_eq!(li.x3.as_ref().unwrap().delivery_address, "10.0.0.50:6544");
    assert_eq!(li.siprec.as_ref().unwrap().srs_uri, "sip:srs@recorder.example.com");

    // Verify defaults
    assert_eq!(li.x2.as_ref().unwrap().transport, "tcp");
    assert_eq!(li.x2.as_ref().unwrap().channel_size, 10_000);
    assert_eq!(li.x3.as_ref().unwrap().encapsulation, "etsi");
    assert_eq!(li.siprec.as_ref().unwrap().session_copies, 1);
}
