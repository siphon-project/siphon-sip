//! A loopback mock HSS for the Cx requests this node sends.
//!
//! Every assertion made with it reads a request the mock HSS actually
//! received, so a test that passes here has proven what an HSS would see.
//!
//! It checks each request against the command's ABNF in TS 29.229 clause 6.1
//! before it answers: a request without one of the AVPs in braces is refused
//! with DIAMETER_MISSING_AVP (5005) and a Failed-AVP naming it, which RFC 6733
//! clause 7.1.5 allows any server to do.

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

pub(crate) const REALM: &str = "ims.mnc001.mcc001.3gppnetwork.org";

/// DIAMETER_MISSING_AVP (RFC 6733 clause 7.1.5).
pub(crate) const DIAMETER_MISSING_AVP: u32 = 5005;
/// Failed-AVP (RFC 6733 clause 7.5).
const FAILED_AVP: u32 = 279;

/// The AVPs in braces of the Cx requests, beyond the ones every request of the
/// client carries (TS 29.229 clauses 6.1.1, 6.1.3, 6.1.5 and 6.1.7): code,
/// vendor, and name in the decoded request.
fn mandatory_avps(command_code: u32) -> &'static [(u32, u32, &'static str)] {
    const VENDOR: u32 = dictionary::VENDOR_3GPP;
    match command_code {
        dictionary::CMD_USER_AUTHORIZATION => &[
            (1, 0, "User-Name"),
            (601, VENDOR, "Public-Identity"),
            (600, VENDOR, "Visited-Network-Identifier"),
        ],
        dictionary::CMD_SERVER_ASSIGNMENT => &[
            (602, VENDOR, "Server-Name"),
            (614, VENDOR, "Server-Assignment-Type"),
            (624, VENDOR, "User-Data-Already-Available"),
        ],
        dictionary::CMD_LOCATION_INFO => &[(601, VENDOR, "Public-Identity")],
        dictionary::CMD_MULTIMEDIA_AUTH => &[
            (1, 0, "User-Name"),
            (601, VENDOR, "Public-Identity"),
            (612, VENDOR, "SIP-Auth-Data-Item"),
            (607, VENDOR, "SIP-Number-Auth-Items"),
            (602, VENDOR, "Server-Name"),
        ],
        _ => &[],
    }
}

/// The AVPs every Cx answer starts with.
pub(crate) fn answer_scaffold(request: &codec::DiameterMessage) -> Vec<u8> {
    use crate::diameter::codec::{encode_avp_u32, encode_avp_utf8, encode_vendor_specific_app_id};
    let mut avps = Vec::new();
    if let Some(session_id) = request.avps.get("Session-Id").and_then(|v| v.as_str()) {
        avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    }
    avps.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::CX_APP_ID,
    ));
    avps.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &format!("hss.{REALM}")));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, REALM));
    avps
}

/// Wrap answer AVPs in the header that matches `request`.
pub(crate) fn finish_answer(request: &codec::DiameterMessage, avps: &[u8]) -> Vec<u8> {
    codec::encode_diameter_message(
        codec::FLAG_PROXIABLE,
        request.command_code,
        dictionary::CX_APP_ID,
        request.hop_by_hop,
        request.end_to_end,
        avps,
    )
}

/// An answer that carries only an Experimental-Result of the 3GPP vendor.
pub(crate) fn experimental_answer(request: &codec::DiameterMessage, code: u32) -> Vec<u8> {
    use crate::diameter::codec::{encode_avp, encode_avp_u32, AVP_FLAG_MANDATORY};
    let mut result = Vec::new();
    result.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, dictionary::VENDOR_3GPP));
    result.extend_from_slice(&encode_avp_u32(avp::EXPERIMENTAL_RESULT_CODE, code));
    let mut avps = answer_scaffold(request);
    avps.extend_from_slice(&encode_avp(
        avp::EXPERIMENTAL_RESULT,
        AVP_FLAG_MANDATORY,
        &result,
    ));
    finish_answer(request, &avps)
}

/// DIAMETER_MISSING_AVP for the first mandatory AVP `request` lacks, if any.
/// The Failed-AVP holds "an example of the missing AVP complete with the
/// Vendor-Id if applicable" (RFC 6733 clause 7.5), with an empty value.
fn refuse_incomplete(request: &codec::DiameterMessage) -> Option<Vec<u8>> {
    use crate::diameter::codec::{
        encode_avp, encode_avp_u32, encode_avp_vendor, AVP_FLAG_MANDATORY,
    };
    let (code, vendor, _) = mandatory_avps(request.command_code)
        .iter()
        .find(|(_, _, name)| request.avps.get(name).is_none())?;
    let example = if *vendor == 0 {
        encode_avp(*code, AVP_FLAG_MANDATORY, &[])
    } else {
        encode_avp_vendor(*code, AVP_FLAG_MANDATORY, *vendor, &[])
    };
    let mut avps = answer_scaffold(request);
    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, DIAMETER_MISSING_AVP));
    avps.extend_from_slice(&encode_avp(FAILED_AVP, AVP_FLAG_MANDATORY, &example));
    Some(finish_answer(request, &avps))
}

/// A Multimedia-Auth-Answer with one IMS AKA vector and Result-Code 2001.
fn multimedia_auth_answer(request: &codec::DiameterMessage) -> Vec<u8> {
    use crate::diameter::codec::{
        encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp,
        encode_avp_utf8_3gpp,
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

    let mut avps = answer_scaffold(request);
    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
    avps.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    avps.extend_from_slice(&encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &item));
    finish_answer(request, &avps)
}

/// What the mock HSS says by default: a MAR is answered with one IMS AKA
/// vector, anything else with DIAMETER_SUCCESS and nothing more.
fn default_answer(request: &codec::DiameterMessage) -> Vec<u8> {
    if request.command_code == dictionary::CMD_MULTIMEDIA_AUTH {
        return multimedia_auth_answer(request);
    }
    let mut avps = answer_scaffold(request);
    avps.extend_from_slice(&codec::encode_avp_u32(avp::RESULT_CODE, 2001));
    finish_answer(request, &avps)
}

/// A mock HSS on a loopback connection and the client connected to it.
pub(crate) struct MockHss {
    pub(crate) client: Arc<DiameterClient>,
    /// Every request received, as its decoded AVPs.
    captured: Arc<StdMutex<Vec<serde_json::Value>>>,
}

impl MockHss {
    /// `answer` builds the answer to a request that passed the ABNF check.
    pub(crate) async fn start(
        answer: impl Fn(&codec::DiameterMessage) -> Vec<u8> + Send + 'static,
    ) -> Self {
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
                if !message.is_request {
                    continue;
                }
                let reply = refuse_incomplete(&message).unwrap_or_else(|| answer(&message));
                if let Ok(mut avps) = capture.lock() {
                    avps.push(message.avps);
                }
                if write_half.write_all(&reply).await.is_err() {
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
        Self {
            client: Arc::new(DiameterClient::new(peer)),
            captured,
        }
    }

    /// The decoded AVPs of the requests received so far.
    pub(crate) fn requests(&self) -> Vec<serde_json::Value> {
        self.captured.lock().expect("the capture").clone()
    }
}

/// A connected client whose peer is a mock HSS, and every request that HSS
/// received, as its decoded AVPs. A MAR is answered with one IMS AKA vector;
/// anything else with DIAMETER_SUCCESS.
pub(crate) async fn mock_hss_client() -> (Arc<DiameterClient>, Arc<StdMutex<Vec<serde_json::Value>>>)
{
    let hss = MockHss::start(default_answer).await;
    (hss.client, hss.captured)
}
