//! A loopback mock OCS and the CCR inspection helpers built on it, shared by
//! the Ro service's own tests and by the dispatcher tests that drive Ro through
//! a real call.
//!
//! Every assertion made with these reads a **decoded CCR the mock OCS actually
//! received**, not an intermediate value on siphon's side, so a test that
//! passes here has proven what a charging backend would see.

use super::*;
use crate::config::RoConfig;
use crate::diameter::peer::PeerConfig;
use std::sync::{Arc, Mutex as StdMutex};

pub(crate) fn ocs_peer_config() -> PeerConfig {
    PeerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        origin_host: "siphon.test".to_string(),
        origin_realm: "test".to_string(),
        destination_host: None,
        destination_realm: "test".to_string(),
        local_ip: "127.0.0.1".parse().expect("a literal address"),
        application_ids: vec![(0, dictionary::RO_APP_ID)],
        watchdog_interval: 3600,
        reconnect_delay: 5,
        product_name: "SIPhon".to_string(),
        firmware_revision: 1,
    }
}

/// A scriptable loopback mock OCS. Each inbound CCR is answered with a CCA
/// carrying `result_code` (+ optional MSCC grant), echoing Session-Id and
/// CC-Request-Type/Number. `grant_secs`/`fua` are put inside MSCC — the
/// correct RFC 8506 codes — so this doubles as the known-answer oracle.
pub(crate) async fn mock_ocs_manager(
    initial_result: u32,
    grant_secs: Option<u32>,
    update_result: u32,
    fua: Option<u32>,
) -> (
    Arc<DiameterManager>,
    tokio::sync::mpsc::Receiver<crate::diameter::peer::IncomingRequest>,
    Arc<StdMutex<Vec<serde_json::Value>>>,
) {
    use crate::diameter::codec::{
        self, encode_avp_grouped, encode_avp_u32, encode_avp_utf8, encode_diameter_message,
        FLAG_REQUEST,
    };
    use crate::diameter::dictionary::avp;
    use crate::diameter::peer::spawn_connection_tasks;
    use crate::diameter::DiameterClient;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let addr = listener.local_addr().expect("the listener's address");
    // Every CCR the OCS receives, decoded, for wire-level assertions.
    let captured: Arc<StdMutex<Vec<serde_json::Value>>> = Arc::new(StdMutex::new(Vec::new()));
    let cap_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
            let Some(msg) = codec::decode_diameter(&bytes) else {
                continue;
            };
            if !msg.is_request || msg.command_code != dictionary::CMD_CREDIT_CONTROL {
                // Answer anything else (a stray DWR) by clearing the R-bit.
                let mut answer = bytes;
                if answer.len() > 4 {
                    answer[4] &= !FLAG_REQUEST;
                }
                let _ = write_half.write_all(&answer).await;
                continue;
            }
            if let Ok(mut guard) = cap_task.lock() {
                guard.push(msg.avps.clone());
            }
            let req_type = msg
                .avps
                .get("CC-Request-Type")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // Answer per CC-Request-Type: UPDATE (2) gets update_result;
            // TERMINATION (3) is always acknowledged; INITIAL (1) / EVENT (4)
            // get initial_result. A grant is included only on success.
            let (result_code, include_grant) = match req_type {
                2 => (update_result, update_result == 2001),
                3 => (2001, false),
                _ => (initial_result, initial_result == 2001),
            };
            let mut avps = Vec::new();
            if let Some(sid) = msg.avps.get("Session-Id").and_then(|v| v.as_str()) {
                avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, sid));
            }
            avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
            avps.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_TYPE, req_type as u32));
            if let Some(rn) = msg.avps.get("CC-Request-Number").and_then(|v| v.as_u64()) {
                avps.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_NUMBER, rn as u32));
            }
            // MSCC grant (correct RFC 8506 codes) — only on a successful answer.
            if include_grant && (grant_secs.is_some() || fua.is_some()) {
                let mut mscc = Vec::new();
                if let Some(secs) = grant_secs {
                    let gsu = encode_avp_u32(avp::CC_TIME, secs);
                    mscc.extend_from_slice(&encode_avp_grouped(avp::GRANTED_SERVICE_UNIT, &gsu));
                }
                if let Some(action) = fua {
                    let fui = encode_avp_u32(avp::FINAL_UNIT_ACTION, action);
                    mscc.extend_from_slice(&encode_avp_grouped(avp::FINAL_UNIT_INDICATION, &fui));
                }
                avps.extend_from_slice(&encode_avp_grouped(
                    avp::MULTIPLE_SERVICES_CREDIT_CONTROL,
                    &mscc,
                ));
            }
            let cca = encode_diameter_message(
                0,
                dictionary::CMD_CREDIT_CONTROL,
                dictionary::RO_APP_ID,
                msg.hop_by_hop,
                msg.end_to_end,
                &avps,
            );
            if write_half.write_all(&cca).await.is_err() {
                break;
            }
        }
    });

    let client_stream = TcpStream::connect(addr)
        .await
        .expect("the mock OCS accepts");
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
    let peer = spawn_connection_tasks(ocs_peer_config(), client_stream, incoming_tx);
    let manager = Arc::new(DiameterManager::new());
    manager.register("ocs".to_string(), Arc::new(DiameterClient::new(peer)));
    (manager, incoming_rx, captured)
}

pub(crate) fn enabled_config() -> RoConfig {
    RoConfig {
        enabled: true,
        // Long fallback so no re-auth fires during the fast leak test.
        reauth_interval_secs: 3600,
        requested_seconds: 30,
        rating_group: Some(100),
        ..Default::default()
    }
}

/// Pull the IMS-Information block out of a captured CCR, if it carries one.
pub(crate) fn ims_information(ccr: &serde_json::Value) -> Option<&serde_json::Value> {
    ccr.get("Service-Information")?.get("IMS-Information")
}

pub(crate) fn ccr_of_type(ccrs: &[serde_json::Value], request_type: u64) -> serde_json::Value {
    ccrs.iter()
        .find(|c| c.get("CC-Request-Type").and_then(|v| v.as_u64()) == Some(request_type))
        .unwrap_or_else(|| panic!("no CCR of type {request_type} was sent"))
        .clone()
}

/// The `Outgoing-Trunk-Group-Id` a captured CCR carries, if any
/// (TS 32.299 §7.2.71 groups it under `Trunk-Group-Id`).
pub(crate) fn outgoing_trunk_group(ccr: &serde_json::Value) -> Option<String> {
    ims_information(ccr)?
        .get("Trunk-Group-Id")?
        .get("Outgoing-Trunk-Group-Id")?
        .as_str()
        .map(str::to_string)
}
