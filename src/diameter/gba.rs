//! GBA over Diameter (TS 29.109): the requests of the two reference points
//! a Bootstrapping Server Function sits between.
//!
//! - **Zh**, BSF to HSS: a Multimedia-Auth-Request (command 303, the Cx
//!   command) on application 16777221, for one authentication vector and the
//!   GBA user security settings.
//! - **Zn**, NAF to BSF: a Bootstrapping-Info-Request (command 310) on
//!   application 16777220, for the key material of a bootstrapping
//!   transaction.
//!
//! The AVPs go out in the order of the ABNF in clauses 4.2 and 5.2.

use super::codec::{
    encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp,
    encode_avp_utf8, encode_avp_utf8_3gpp, encode_avp_vendor, encode_diameter_message,
    encode_vendor_specific_app_id, DiameterMessage, FLAG_PROXIABLE, FLAG_REQUEST,
    NTP_UNIX_EPOCH_OFFSET,
};
use super::dictionary::{self, avp};
use super::peer::PeerConfig;
use super::DiameterClient;

/// SIP-Authorization in a request holds RAND and AUTS: "The Authorization
/// Information has a fixed length of 30 octets; the 16 most significant
/// octets shall contain the RAND, the 14 least significant octets shall
/// contain the AUTS" (TS 29.229 clause 6.3.11).
pub const RESYNCHRONISATION_LENGTH: usize = 30;

/// Auth-Session-State NO_STATE_MAINTAINED (RFC 6733 clause 8.11), which both
/// requests carry.
const NO_STATE_MAINTAINED: u32 = 1;

/// What a Multimedia-Auth-Request on Zh says (TS 29.109 clause 4.2, step 1).
#[derive(Debug, Default)]
pub struct ZhMultimediaAuth<'a> {
    /// The IMPI, sent as User-Name.
    pub user_name: Option<&'a str>,
    /// The IMPU, sent as Public-Identity. Only bootstrapping push uses it.
    pub public_identity: Option<&'a str>,
    /// SIP-Authentication-Scheme. `None` sends no SIP-Auth-Data-Item for it,
    /// which means Digest-AKAv1-MD5: "The SIP-Auth-Data-Item AVP should not
    /// be present to indicate the authentication scheme is Digest-AKAv1-MD5."
    pub sip_auth_scheme: Option<&'a str>,
    /// RAND || AUTS after a synchronisation failure: "the BSF shall include
    /// the SIP-Auth-Data-Item AVP within the MAR message".
    pub sip_authorization: Option<&'a [u8]>,
    /// The timestamp of the GUSS the BSF holds, in Unix seconds.
    pub guss_timestamp: Option<u64>,
}

/// What a Bootstrapping-Info-Request says (TS 29.109 clause 5.2, step 1).
#[derive(Debug)]
pub struct BootstrappingInfo<'a> {
    /// The B-TID, sent as Transaction-Identifier.
    pub transaction_identifier: &'a [u8],
    /// The FQDN of the NAF followed by the Ua security protocol identifier.
    pub naf_id: &'a [u8],
    /// One GAA-Service-Identifier per element.
    pub gaa_service_identifiers: &'a [Vec<u8>],
    /// GBA_U-Awareness-Indicator. `None` leaves the AVP out, which means the
    /// NAF is not GBA_U aware.
    pub gba_u_aware: Option<bool>,
    /// "The Destination-Realm AVP is set to subscriber's BSF. The address of
    /// the BSF is extracted from the B-TID." `None` uses the peer's.
    pub destination_realm: Option<&'a str>,
    pub destination_host: Option<&'a str>,
}

/// The AVPs both requests start with, in the order of the ABNF.
fn append_request_header(
    payload: &mut Vec<u8>,
    config: &PeerConfig,
    session_id: &str,
    application_id: u32,
    destination_realm: Option<&str>,
    destination_host: Option<&str>,
) {
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    payload.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        application_id,
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::AUTH_SESSION_STATE,
        NO_STATE_MAINTAINED,
    ));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        destination_realm.unwrap_or(&config.destination_realm),
    ));
    if let Some(host) = destination_host.or(config.destination_host.as_deref()) {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
    }
}

/// A Time AVP of the 3GPP vendor from Unix seconds (RFC 6733 clause 4.3.1:
/// seconds since 1900), with or without the M bit.
fn encode_time_3gpp(code: u32, unix_seconds: u64) -> Vec<u8> {
    let seconds = (unix_seconds.wrapping_add(NTP_UNIX_EPOCH_OFFSET) & 0xFFFF_FFFF) as u32;
    let flags = if dictionary::avp_is_mandatory(code, dictionary::VENDOR_3GPP) {
        super::codec::AVP_FLAG_MANDATORY
    } else {
        0
    };
    encode_avp_vendor(code, flags, dictionary::VENDOR_3GPP, &seconds.to_be_bytes())
}

/// Encode a Multimedia-Auth-Request on Zh, BSF to HSS.
pub fn build_zh_mar(
    config: &PeerConfig,
    session_id: &str,
    request: &ZhMultimediaAuth<'_>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let vendor_utf8 = encode_avp_utf8_3gpp;
    let mut payload = Vec::with_capacity(512);
    append_request_header(
        &mut payload,
        config,
        session_id,
        dictionary::ZH_APP_ID,
        None,
        None,
    );
    if let Some(user_name) = request.user_name {
        payload.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, user_name));
    }
    if let Some(public_identity) = request.public_identity {
        payload.extend_from_slice(&vendor_utf8(avp::PUBLIC_IDENTITY, public_identity));
    }
    if request.sip_auth_scheme.is_some() || request.sip_authorization.is_some() {
        let scheme = request.sip_auth_scheme.unwrap_or(super::cx::SCHEME_IMS_AKA);
        let mut members = vendor_utf8(avp::SIP_AUTHENTICATION_SCHEME, scheme);
        if let Some(authorization) = request.sip_authorization {
            members.extend_from_slice(&encode_avp_octet_3gpp(
                avp::SIP_AUTHORIZATION,
                authorization,
            ));
        }
        payload.extend_from_slice(&encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &members));
    }
    if let Some(timestamp) = request.guss_timestamp {
        payload.extend_from_slice(&encode_time_3gpp(avp::GUSS_TIMESTAMP, timestamp));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_MULTIMEDIA_AUTH,
        dictionary::ZH_APP_ID,
        hop_by_hop,
        end_to_end,
        &payload,
    )
}

/// Encode a Bootstrapping-Info-Request, NAF to BSF.
pub fn build_zn_bir(
    config: &PeerConfig,
    session_id: &str,
    request: &BootstrappingInfo<'_>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    append_request_header(
        &mut payload,
        config,
        session_id,
        dictionary::ZN_APP_ID,
        request.destination_realm,
        request.destination_host,
    );
    for service in request.gaa_service_identifiers {
        payload.extend_from_slice(&encode_avp_octet_3gpp(avp::GAA_SERVICE_IDENTIFIER, service));
    }
    payload.extend_from_slice(&encode_avp_octet_3gpp(
        avp::TRANSACTION_IDENTIFIER,
        request.transaction_identifier,
    ));
    payload.extend_from_slice(&encode_avp_octet_3gpp(avp::NAF_ID, request.naf_id));
    if let Some(aware) = request.gba_u_aware {
        payload.extend_from_slice(&encode_avp_u32_3gpp(
            avp::GBA_U_AWARENESS_INDICATOR,
            u32::from(aware),
        ));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_BOOTSTRAPPING_INFO,
        dictionary::ZN_APP_ID,
        hop_by_hop,
        end_to_end,
        &payload,
    )
}

impl DiameterClient {
    /// Send a Multimedia-Auth-Request on Zh and return the answer.
    pub async fn send_zh_mar(
        &self,
        request: &ZhMultimediaAuth<'_>,
    ) -> Result<DiameterMessage, String> {
        let peer = self.peer();
        let session_id = peer.new_session_id();
        let wire = build_zh_mar(
            peer.config(),
            &session_id,
            request,
            peer.next_hbh(),
            peer.next_e2e(),
        );
        peer.send_request(wire).await
    }

    /// Send a Bootstrapping-Info-Request and return the answer.
    pub async fn send_zn_bir(
        &self,
        request: &BootstrappingInfo<'_>,
    ) -> Result<DiameterMessage, String> {
        let peer = self.peer();
        let session_id = peer.new_session_id();
        let wire = build_zn_bir(
            peer.config(),
            &session_id,
            request,
            peer.next_hbh(),
            peer.next_e2e(),
        );
        peer.send_request(wire).await
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// The identity of a BSF whose Zh peer is the HSS of the test PLMN.
    pub(crate) fn bsf_peer_config() -> PeerConfig {
        PeerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            origin_host: "bsf.mnc001.mcc001.pub.3gppnetwork.org".to_string(),
            origin_realm: "mnc001.mcc001.pub.3gppnetwork.org".to_string(),
            destination_host: None,
            destination_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            local_ip: "127.0.0.1".parse().expect("a literal address"),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::ZH_APP_ID)],
            watchdog_interval: 3600,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        }
    }

    /// The identity of a NAF whose Zn peer is a BSF. Its configured
    /// Destination-Realm is not the BSF's, so a test can tell a realm taken
    /// from the request from the peer's.
    pub(crate) fn naf_peer_config() -> PeerConfig {
        PeerConfig {
            origin_host: "naf.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_realm: "configured.example.net".to_string(),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::ZN_APP_ID)],
            ..bsf_peer_config()
        }
    }

    /// A loopback peer that answers every request with `answer`, an encoded
    /// answer whose hop-by-hop and end-to-end identifiers are replaced by the
    /// request's, and keeps the octets of every request it received.
    pub(crate) async fn answering_peer(
        config: PeerConfig,
        answer: &'static [u8],
    ) -> (
        std::sync::Arc<DiameterClient>,
        std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    ) {
        use crate::diameter::codec;
        use crate::diameter::peer::spawn_connection_tasks;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let address = listener.local_addr().expect("the listener's address");
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = std::sync::Arc::clone(&captured);
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read_half, mut write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            while let Ok(request) = codec::read_diameter_message(&mut reader).await {
                let mut reply = answer.to_vec();
                reply[12..20].copy_from_slice(&request[12..20]);
                if let Ok(mut requests) = capture.lock() {
                    requests.push(request);
                }
                if write_half.write_all(&reply).await.is_err() {
                    break;
                }
            }
        });

        let stream = TcpStream::connect(address).await.expect("the peer accepts");
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
        // Nothing is pushed at this client; keep the channel open for its lifetime.
        std::mem::forget(incoming_rx);
        let peer = spawn_connection_tasks(config, stream, incoming_tx);
        (std::sync::Arc::new(DiameterClient::new(peer)), captured)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{answering_peer, bsf_peer_config, naf_peer_config};
    use super::*;
    use crate::diameter::codec::{hex, DiameterMsg};
    use crate::diameter::gba_test_vectors as vectors;

    fn zh_mar(request: &ZhMultimediaAuth<'_>, session: &str, end_to_end: u32) -> Vec<u8> {
        build_zh_mar(&bsf_peer_config(), session, request, 0x11, end_to_end)
    }

    #[test]
    fn a_zh_mar_for_ims_aka_is_the_request_of_the_abnf_octet_for_octet() {
        let wire = zh_mar(
            &ZhMultimediaAuth {
                user_name: Some(vectors::IMPI),
                ..Default::default()
            },
            "bsf.example.org;1;1",
            0x22,
        );
        assert_eq!(hex::encode(&wire), hex::encode(vectors::ZH_MAR));
    }

    #[test]
    fn a_zh_mar_after_a_synchronisation_failure_carries_rand_auts_and_the_guss_timestamp() {
        let mut authorization = vectors::RAND.to_vec();
        authorization.extend_from_slice(&vectors::AUTS);
        assert_eq!(authorization.len(), RESYNCHRONISATION_LENGTH);
        let wire = zh_mar(
            &ZhMultimediaAuth {
                user_name: Some(vectors::IMPI),
                sip_authorization: Some(&authorization),
                guss_timestamp: Some(vectors::GUSS_TIMESTAMP_UNIX),
                ..Default::default()
            },
            "bsf.example.org;1;2",
            0x23,
        );
        assert_eq!(hex::encode(&wire), hex::encode(vectors::ZH_MAR_RESYNC));
    }

    #[test]
    fn a_zh_mar_is_not_a_cx_mar() {
        // The Cx request names the S-CSCF and asks for a number of items; the
        // Zh ABNF has neither AVP, and the HSS must not run its Cx procedure.
        let wire = zh_mar(
            &ZhMultimediaAuth {
                user_name: Some(vectors::IMPI),
                public_identity: Some("sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"),
                sip_auth_scheme: Some("SIP Digest"),
                ..Default::default()
            },
            "bsf.example.org;1;3",
            0x24,
        );
        let message = DiameterMsg::from_wire(&wire).expect("a Zh MAR");
        assert_eq!(message.command_code, 303);
        assert_eq!(message.application_id, 16_777_221);
        let vendor = dictionary::VENDOR_3GPP;
        assert!(message.find(avp::SERVER_NAME, vendor).is_none());
        assert!(message.find(avp::SIP_NUMBER_AUTH_ITEMS, vendor).is_none());
        assert_eq!(
            message
                .find(avp::PUBLIC_IDENTITY, vendor)
                .and_then(|avp| avp.as_str())
                .as_deref(),
            Some("sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org")
        );
        // A scheme other than the default is named, in an item of its own.
        let item = message
            .find(avp::SIP_AUTH_DATA_ITEM, vendor)
            .expect("a SIP-Auth-Data-Item naming the scheme");
        let crate::diameter::codec::AvpData::Grouped(members) = &item.value else {
            panic!("SIP-Auth-Data-Item is grouped");
        };
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].code, avp::SIP_AUTHENTICATION_SCHEME);
        assert_eq!(members[0].as_str().as_deref(), Some("SIP Digest"));
    }

    fn bootstrapping_info<'a>(services: &'a [Vec<u8>]) -> BootstrappingInfo<'a> {
        BootstrappingInfo {
            transaction_identifier: vectors::B_TID.as_bytes(),
            naf_id: &vectors::NAF_ID,
            gaa_service_identifiers: services,
            gba_u_aware: Some(true),
            destination_realm: Some("mnc001.mcc001.pub.3gppnetwork.org"),
            destination_host: None,
        }
    }

    #[test]
    fn a_zn_bir_is_the_request_of_the_abnf_octet_for_octet() {
        let services = vec![b"1".to_vec(), b"4".to_vec()];
        let wire = build_zn_bir(
            &naf_peer_config(),
            "naf.example.com;7;1",
            &bootstrapping_info(&services),
            0x33,
            0x44,
        );
        assert_eq!(hex::encode(&wire), hex::encode(vectors::ZN_BIR));
    }

    #[test]
    fn a_zn_bir_leaves_out_what_the_naf_did_not_say() {
        let wire = build_zn_bir(
            &naf_peer_config(),
            "naf.example.com;7;3",
            &BootstrappingInfo {
                gba_u_aware: None,
                destination_realm: None,
                destination_host: Some("bsf.mnc001.mcc001.pub.3gppnetwork.org"),
                ..bootstrapping_info(&[])
            },
            1,
            2,
        );
        let message = DiameterMsg::from_wire(&wire).expect("a BIR");
        let vendor = dictionary::VENDOR_3GPP;
        assert!(message.find(avp::GAA_SERVICE_IDENTIFIER, vendor).is_none());
        assert!(message
            .find(avp::GBA_U_AWARENESS_INDICATOR, vendor)
            .is_none());
        assert_eq!(
            message.get_str(avp::DESTINATION_REALM).as_deref(),
            Some("configured.example.net")
        );
        assert_eq!(
            message.get_str(avp::DESTINATION_HOST).as_deref(),
            Some("bsf.mnc001.mcc001.pub.3gppnetwork.org")
        );
    }

    #[tokio::test]
    async fn the_client_sends_a_zh_mar_and_returns_the_answer_of_the_hss() {
        let (client, requests) = answering_peer(bsf_peer_config(), vectors::ZH_MAA).await;
        let answer = client
            .send_zh_mar(&ZhMultimediaAuth {
                user_name: Some(vectors::IMPI),
                ..Default::default()
            })
            .await
            .expect("the HSS answers");
        assert_eq!(answer.command_code, 303);
        assert_eq!(answer.application_id, 16_777_221);
        assert_eq!(answer.avps["Result-Code"], 2001);
        assert_eq!(
            answer.avps["GBA-UserSecSettings"],
            hex::encode(vectors::GUSS.as_bytes())
        );

        let requests = requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let request = DiameterMsg::from_wire(&requests[0]).expect("the MAR the HSS received");
        assert!(request.is_request());
        assert_eq!(request.application_id, 16_777_221);
        assert_eq!(
            request.get_str(avp::USER_NAME).as_deref(),
            Some(vectors::IMPI)
        );
    }

    #[tokio::test]
    async fn the_client_sends_a_zn_bir_and_returns_the_answer_of_the_bsf() {
        let (client, requests) = answering_peer(naf_peer_config(), vectors::ZN_BIA).await;
        let services = vec![b"1".to_vec()];
        let answer = client
            .send_zn_bir(&bootstrapping_info(&services))
            .await
            .expect("the BSF answers");
        assert_eq!(answer.command_code, 310);
        assert_eq!(answer.application_id, 16_777_220);
        assert_eq!(
            answer.avps["ME-Key-Material"],
            hex::encode(&vectors::KS_EXT_NAF)
        );
        assert_eq!(answer.avps["Key-ExpiryTime"], vectors::KEY_EXPIRY_UNIX);
        assert_eq!(answer.avps["GBA-Type"], 0);

        let requests = requests.lock().unwrap().clone();
        let request = DiameterMsg::from_wire(&requests[0]).expect("the BIR the BSF received");
        assert_eq!(request.command_code, 310);
        assert_eq!(
            request
                .find(avp::TRANSACTION_IDENTIFIER, dictionary::VENDOR_3GPP)
                .and_then(|avp| avp.raw_bytes()),
            Some(vectors::B_TID.as_bytes())
        );
    }
}
