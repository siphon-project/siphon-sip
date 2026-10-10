//! A loopback mock HSS for the Cx requests this node sends.
//!
//! Every assertion made with it reads a request the mock HSS actually
//! received, so a test that passes here has proven what an HSS would see.

use super::*;
use crate::diameter::peer::PeerConfig;
use std::sync::{Arc, Mutex as StdMutex};

/// RAND || AUTN, the SIP-Authenticate of the vector the mock HSS answers with.
pub(crate) const MOCK_SIP_AUTHENTICATE: [u8; 32] = [0x5a; 32];
/// XRES, the SIP-Authorization of that vector.
pub(crate) const MOCK_SIP_AUTHORIZATION: [u8; 8] = [0x11; 8];
pub(crate) const MOCK_CONFIDENTIALITY_KEY: [u8; 16] = [0xc1; 16];
pub(crate) const MOCK_INTEGRITY_KEY: [u8; 16] = [0x1c; 16];

pub(crate) fn hss_peer_config() -> PeerConfig {
    PeerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        origin_host: "scscf.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
        origin_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
        destination_host: None,
        destination_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
        local_ip: "127.0.0.1".parse().expect("a literal address"),
        application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::CX_APP_ID)],
        watchdog_interval: 3600,
        reconnect_delay: 5,
        product_name: "SIPhon".to_string(),
        firmware_revision: 1,
    }
}

/// A Multimedia-Auth-Answer with one IMS AKA vector and Result-Code 2001.
fn multimedia_auth_answer(request: &codec::DiameterMessage) -> Vec<u8> {
    use crate::diameter::codec::{
        encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp,
        encode_avp_utf8, encode_avp_utf8_3gpp, encode_diameter_message,
        encode_vendor_specific_app_id, FLAG_PROXIABLE,
    };

    let mut item = Vec::new();
    item.extend_from_slice(&encode_avp_u32_3gpp(613, 1));
    item.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::SIP_AUTHENTICATION_SCHEME,
        cx::SCHEME_IMS_AKA,
    ));
    item.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SIP_AUTHENTICATE,
        &MOCK_SIP_AUTHENTICATE,
    ));
    item.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SIP_AUTHORIZATION,
        &MOCK_SIP_AUTHORIZATION,
    ));
    item.extend_from_slice(&encode_avp_octet_3gpp(
        avp::CONFIDENTIALITY_KEY,
        &MOCK_CONFIDENTIALITY_KEY,
    ));
    item.extend_from_slice(&encode_avp_octet_3gpp(
        avp::INTEGRITY_KEY,
        &MOCK_INTEGRITY_KEY,
    ));

    let mut avps = Vec::new();
    if let Some(session_id) = request.avps.get("Session-Id").and_then(|v| v.as_str()) {
        avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    }
    avps.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::CX_APP_ID,
    ));
    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
    avps.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss.example.com"));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
    avps.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    avps.extend_from_slice(&encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &item));

    encode_diameter_message(
        FLAG_PROXIABLE,
        dictionary::CMD_MULTIMEDIA_AUTH,
        dictionary::CX_APP_ID,
        request.hop_by_hop,
        request.end_to_end,
        &avps,
    )
}

/// A connected client whose peer is a mock HSS, and every request that HSS
/// received, as its decoded AVPs. A MAR is answered with one IMS AKA vector; anything
/// else is answered by clearing the R bit.
pub(crate) async fn mock_hss_client() -> (Arc<DiameterClient>, Arc<StdMutex<Vec<serde_json::Value>>>)
{
    use crate::diameter::codec::FLAG_REQUEST;
    use crate::diameter::peer::spawn_connection_tasks;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("the listener's address");
    let captured: Arc<StdMutex<Vec<serde_json::Value>>> = Arc::new(StdMutex::new(Vec::new()));
    let capture = Arc::clone(&captured);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
            let Some(message) = codec::decode_diameter(&bytes) else {
                continue;
            };
            let answer =
                if message.is_request && message.command_code == dictionary::CMD_MULTIMEDIA_AUTH {
                    multimedia_auth_answer(&message)
                } else {
                    let mut answer = bytes;
                    if answer.len() > 4 {
                        answer[4] &= !FLAG_REQUEST;
                    }
                    answer
                };
            if message.is_request {
                if let Ok(mut guard) = capture.lock() {
                    guard.push(message.avps);
                }
            }
            if write_half.write_all(&answer).await.is_err() {
                break;
            }
        }
    });

    let stream = TcpStream::connect(address)
        .await
        .expect("the mock HSS accepts");
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
    // Nothing is pushed at this client; keep the channel open for its lifetime.
    std::mem::forget(incoming_rx);
    let peer = spawn_connection_tasks(hss_peer_config(), stream, incoming_tx);
    (Arc::new(DiameterClient::new(peer)), captured)
}
