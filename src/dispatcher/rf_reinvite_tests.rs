//! Rf: a re-INVITE answered 2xx opens no accounting session.
//!
//! TS 32.260 Table 5.2.1.1-1 has the Charging Data Request [Start] triggered
//! by a "SIP 2xx acknowledging an initial SIP INVITE", and gives a "SIP 2xx
//! acknowledging a SIP RE-INVITE or SIP UPDATE" to the [Interim] of the
//! session that is already open. The automatic ACR-START ran for every INVITE
//! that got a 2xx. A re-INVITE that carried the dialog's ICID was caught by
//! the duplicate check; one without a P-Charging-Vector, or sent by the
//! called party (whose From tag is the dialog's other tag), resolved to a key
//! nothing was filed under and opened a second session for the same call,
//! with no IMS-Charging-Identifier for the collector to correlate it by.

use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::sip::parse_sip_message;
use std::sync::Mutex as StdMutex;

type ReceivedAcrs = Arc<StdMutex<Vec<serde_json::Value>>>;

/// A loopback charging function that answers every ACR with 2001 and keeps
/// the decoded AVPs of each one it was sent.
async fn mock_cdf() -> (Arc<crate::diameter::DiameterManager>, ReceivedAcrs) {
    use crate::diameter::codec::{self, encode_avp_u32, encode_avp_utf8, encode_diameter_message};
    use crate::diameter::dictionary::{self, avp};
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("the listener's address");
    let received: ReceivedAcrs = Arc::new(StdMutex::new(Vec::new()));
    let record = Arc::clone(&received);
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
            if !message.is_request || message.command_code != dictionary::CMD_ACCOUNTING {
                continue;
            }
            let mut avps = Vec::new();
            if let Some(session_id) = message.avps.get("Session-Id").and_then(|v| v.as_str()) {
                avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
            }
            avps.extend_from_slice(&encode_avp_u32(
                avp::RESULT_CODE,
                dictionary::DIAMETER_SUCCESS,
            ));
            for (name, code) in [
                ("Accounting-Record-Type", avp::ACCOUNTING_RECORD_TYPE),
                ("Accounting-Record-Number", avp::ACCOUNTING_RECORD_NUMBER),
            ] {
                if let Some(value) = message.avps.get(name).and_then(|v| v.as_u64()) {
                    avps.extend_from_slice(&encode_avp_u32(code, value as u32));
                }
            }
            record.lock().unwrap().push(message.avps.clone());
            let answer = encode_diameter_message(
                0,
                dictionary::CMD_ACCOUNTING,
                message.application_id,
                message.hop_by_hop,
                message.end_to_end,
                &avps,
            );
            if write_half.write_all(&answer).await.is_err() {
                break;
            }
        }
    });

    let stream = TcpStream::connect(address).await.expect("the CDF accepts");
    let (incoming, incoming_receiver) = tokio::sync::mpsc::channel(16);
    // Nothing is pushed at this client; keep the channel open for its lifetime.
    std::mem::forget(incoming_receiver);
    let config = crate::diameter::peer::PeerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        origin_host: "pcscf.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
        origin_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
        destination_host: None,
        destination_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
        local_ip: "127.0.0.1".parse().expect("a literal address"),
        application_ids: vec![(0, dictionary::RF_APP_ID)],
        watchdog_interval: 3600,
        reconnect_delay: 5,
        product_name: "SIPhon".to_string(),
        firmware_revision: 1,
    };
    let peer = crate::diameter::peer::spawn_connection_tasks(config, stream, incoming);
    let manager = Arc::new(crate::diameter::DiameterManager::new());
    manager.register(
        "cdf".to_string(),
        Arc::new(crate::diameter::DiameterClient::new(peer)),
    );
    (manager, received)
}

const CALLER: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
const CALLEE: &str = "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org";
const ICID: &str = "60bb19af-04f2-4397-8a34-dac6d78465fe";

/// An INVITE of one call. `from` and `to` are whole header values, tags
/// included, and `extra` any further header lines.
fn invite(branch: &str, from: &str, to: &str, extra: &str) -> SipMessage {
    let raw = format!(
        "INVITE {CALLEE} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: rf-reinvite@192.0.2.10\r\n\
         CSeq: 1 INVITE\r\n\
         Max-Forwards: 70\r\n\
         {extra}\
         Content-Length: 0\r\n\
         \r\n"
    );
    parse_sip_message(&raw).expect("the INVITE parses").1
}

/// Tell the dispatcher `request` was answered 2xx, as the response path does.
fn answered(state: &DispatcherState, branch: &str, request: &SipMessage) {
    let server_key = TransactionKey {
        branch: branch.to_string(),
        method: crate::sip::message::Method::Invite,
        sent_by: "192.0.2.10:5060".to_string(),
    };
    let session = Arc::new(std::sync::RwLock::new(
        crate::proxy::session::ProxySession::new(
            server_key.clone(),
            "192.0.2.10:5060".parse().expect("a literal address"),
            "192.0.2.1:5060".parse().expect("a literal address"),
            ConnectionId::default(),
            Transport::Udp,
            request.clone(),
            true,
        ),
    ));
    spawn_rf_proxy_start_if_invite(state, &server_key, request, &session);
}

/// Wait until the CDF has been sent `count` ACRs, or give up.
async fn acrs(received: &ReceivedAcrs, count: usize) -> Vec<serde_json::Value> {
    for _ in 0..200 {
        if received.lock().unwrap().len() >= count {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    received.lock().unwrap().clone()
}

async fn charging_dispatcher() -> (DispatcherState, ReceivedAcrs) {
    let mut state = test_dispatcher().state;
    let (manager, received) = mock_cdf().await;
    state.local_domains = Arc::new(vec!["ims.mnc001.mcc001.3gppnetwork.org".to_string()]);
    state.rf_charger = Some(crate::diameter::rf_service::RfChargingService::new(
        manager,
        crate::config::RfConfig {
            enabled: true,
            node_functionality: "pcscf".to_string(),
            ..Default::default()
        },
    ));
    (state, received)
}

/// The call of the report: the initial INVITE carries the ICID, the called
/// party then puts the call on hold with a re-INVITE that reaches this node
/// with no P-Charging-Vector.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reinvite_from_the_called_party_opens_no_second_accounting_session() {
    let (state, received) = charging_dispatcher().await;

    let initial = invite(
        "z9hG4bKinitial",
        &format!("<{CALLER}>;tag=caller-tag"),
        &format!("<{CALLEE}>"),
        &format!("P-Charging-Vector: icid-value={ICID}\r\n"),
    );
    answered(&state, "z9hG4bKinitial", &initial);
    let started = acrs(&received, 1).await;
    assert_eq!(started.len(), 1, "the initial INVITE opens the session");
    assert_eq!(started[0]["Accounting-Record-Type"], 2, "START_RECORD");

    // In the dialog, from the called party: its tag is the From tag now.
    let reinvite = invite(
        "z9hG4bKhold",
        &format!("<{CALLEE}>;tag=callee-tag"),
        &format!("<{CALLER}>;tag=caller-tag"),
        "",
    );
    answered(&state, "z9hG4bKhold", &reinvite);

    // Long enough for a second ACR to have reached the CDF had one been sent.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let all = acrs(&received, 2).await;
    assert_eq!(
        all.len(),
        1,
        "a re-INVITE must not open an accounting session: {all:#?}"
    );
    let sessions: std::collections::HashSet<String> = state
        .rf_sessions
        .iter()
        .map(|entry| entry.value().session.session_id().to_string())
        .collect();
    assert_eq!(sessions.len(), 1, "one call, one accounting session");
}

/// The same from the calling party: the re-INVITE keeps the From tag of the
/// initial INVITE, and without a P-Charging-Vector the duplicate check has
/// nothing to match the ICID-keyed session by.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reinvite_from_the_calling_party_opens_no_second_accounting_session() {
    let (state, received) = charging_dispatcher().await;

    let initial = invite(
        "z9hG4bKinitial",
        &format!("<{CALLER}>;tag=caller-tag"),
        &format!("<{CALLEE}>"),
        &format!("P-Charging-Vector: icid-value={ICID}\r\n"),
    );
    answered(&state, "z9hG4bKinitial", &initial);
    assert_eq!(acrs(&received, 1).await.len(), 1);

    let reinvite = invite(
        "z9hG4bKresume",
        &format!("<{CALLER}>;tag=caller-tag"),
        &format!("<{CALLEE}>;tag=callee-tag"),
        "P-Served-User: <sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;sescase=term\r\n",
    );
    answered(&state, "z9hG4bKresume", &reinvite);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(acrs(&received, 2).await.len(), 1);
}

/// An initial INVITE still opens its session when it carries no
/// P-Charging-Vector at all: what decides is the To tag, not the ICID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initial_invite_without_a_charging_vector_still_opens_a_session() {
    let (state, received) = charging_dispatcher().await;
    let initial = invite(
        "z9hG4bKinitial",
        &format!("<{CALLER}>;tag=caller-tag"),
        &format!("<{CALLEE}>"),
        "",
    );
    answered(&state, "z9hG4bKinitial", &initial);
    let started = acrs(&received, 1).await;
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["Accounting-Record-Type"], 2);
}

/// A BYE of the same call, with no P-Charging-Vector. `from` and `to` are
/// whole header values.
fn bye(from: &str, to: &str) -> SipMessage {
    let raw = format!(
        "BYE {CALLEE} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKbye\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: rf-reinvite@192.0.2.10\r\n\
         CSeq: 3 BYE\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    parse_sip_message(&raw).expect("the BYE parses").1
}

/// Wait until the accounting session map holds `filed` entries or none.
async fn sessions_settle(state: &DispatcherState, empty: bool) {
    for _ in 0..200 {
        if state.rf_sessions.is_empty() == empty {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// One call with a hold re-INVITE from the called party, ended by `ending`.
/// Returns the Accounting-Record-Type of every ACR the CDF was sent and
/// whether the session map drained.
async fn records_of_a_call_with_a_hold(ending: SipMessage) -> (Vec<u64>, bool) {
    let (state, received) = charging_dispatcher().await;
    let initial = invite(
        "z9hG4bKinitial",
        &format!("<{CALLER}>;tag=caller-tag"),
        &format!("<{CALLEE}>"),
        &format!("P-Charging-Vector: icid-value={ICID}\r\n"),
    );
    answered(&state, "z9hG4bKinitial", &initial);
    sessions_settle(&state, false).await;

    let reinvite = invite(
        "z9hG4bKhold",
        &format!("<{CALLEE}>;tag=callee-tag"),
        &format!("<{CALLER}>;tag=caller-tag"),
        "",
    );
    answered(&state, "z9hG4bKhold", &reinvite);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    spawn_rf_proxy_stop_if_tracked(&state, &ending);
    sessions_settle(&state, true).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let types = received
        .lock()
        .unwrap()
        .iter()
        .map(|acr| acr["Accounting-Record-Type"].as_u64().unwrap())
        .collect();
    (types, state.rf_sessions.is_empty())
}

/// With the re-INVITE opening nothing, the one session is the one the BYE
/// finds, whichever party hangs up and with no P-Charging-Vector on the BYE:
/// one START (2), one STOP (4), and nothing left filed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_with_a_hold_is_one_start_and_one_stop_whoever_hangs_up() {
    for ending in [
        bye(
            &format!("<{CALLER}>;tag=caller-tag"),
            &format!("<{CALLEE}>;tag=callee-tag"),
        ),
        bye(
            &format!("<{CALLEE}>;tag=callee-tag"),
            &format!("<{CALLER}>;tag=caller-tag"),
        ),
    ] {
        let (types, drained) = records_of_a_call_with_a_hold(ending).await;
        assert_eq!(types, [2, 4], "one START and its STOP");
        assert!(drained, "no accounting session is left without its STOP");
    }
}
