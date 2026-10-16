//! Role-Of-Node on the charging records of a B2BUA call.
//!
//! TS 32.299 V18 clause 7.2.177 defines three values: ORIGINATING_ROLE (0),
//! TERMINATING_ROLE (1) and FORWARDING_ROLE (2). The role is the session case
//! the node serves, not the kind of node it is: a B2BUA application server on
//! the originating side of a call is in the originating role. The Ro gate and
//! the Rf auto-emit both sent 3 (B2BUA_ROLE of earlier releases), which a
//! Release 18 charging function refuses with DIAMETER_INVALID_AVP_VALUE.
//!
//! Each assertion reads a request the mock charging function received, decoded
//! on its side of the socket.

use super::rf_reinvite_tests::{mock_cdf, ReceivedAcrs};
use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::diameter::ro::NodeRole;
use crate::diameter::ro_service::RoChargingService;
use crate::diameter::ro_test_support::{
    ccr_of_type, enabled_config, ims_information, mock_ocs_manager,
};
use crate::sip::parse_sip_message;

const DOMAIN: &str = "ims.mnc001.mcc001.3gppnetwork.org";
const CALLER: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
const CALLEE: &str = "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org";

/// The INVITE an application server receives over ISC, with the session case
/// the S-CSCF put in P-Served-User (TS 24.229 clause 5.4.3.3, RFC 8498).
fn isc_invite(served_user: &str, sescase: &str) -> SipMessage {
    let raw = format!(
        "INVITE {CALLEE} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKrole\r\n\
         From: <{CALLER}>;tag=caller-tag\r\n\
         To: <{CALLEE}>\r\n\
         Call-ID: role-of-node@192.0.2.10\r\n\
         CSeq: 1 INVITE\r\n\
         Max-Forwards: 70\r\n\
         P-Served-User: <{served_user}>;sescase={sescase};regstate=reg\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    parse_sip_message(&raw).expect("the INVITE parses").1
}

fn role_of_node(request: &serde_json::Value) -> Option<u64> {
    ims_information(request)?.get("Role-of-Node")?.as_u64()
}

/// The Role-Of-Node of the CCR-INITIAL that `call.ro_authorize()` sends for
/// `invite`, with `role` the script's override.
async fn ro_initial_role(invite: SipMessage, role: Option<NodeRole>) -> Option<u64> {
    let (manager, _incoming, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
    let control = RoControlHandle {
        charger: RoChargingService::new(manager, enabled_config()),
        ro_sessions: Arc::new(DashMap::new()),
        local_domains: Arc::new(vec![DOMAIN.to_string()]),
    };
    let outcome = ro_authorize_with(
        &control,
        "role-of-node-call".to_string(),
        invite,
        None,
        None,
        role,
    )
    .await;
    assert!(outcome.authorized, "the mock OCS grants");
    let ccrs = captured.lock().expect("the capture lock").clone();
    role_of_node(&ccr_of_type(&ccrs, 1))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ro_an_originating_b2bua_call_is_in_the_originating_role() {
    let role = ro_initial_role(isc_invite(CALLER, "orig"), None).await;
    assert_eq!(role, Some(0), "ORIGINATING_ROLE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ro_a_terminating_b2bua_call_is_in_the_terminating_role() {
    let role = ro_initial_role(isc_invite(CALLEE, "term"), None).await;
    assert_eq!(role, Some(1), "TERMINATING_ROLE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ro_a_diverted_b2bua_call_is_in_the_forwarding_role() {
    let role = ro_initial_role(isc_invite(CALLEE, "orig-cdiv"), None).await;
    assert_eq!(role, Some(2), "FORWARDING_ROLE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ro_the_script_role_overrides_the_session_case() {
    let role = ro_initial_role(isc_invite(CALLER, "orig"), Some(NodeRole::ForwardingRole)).await;
    assert_eq!(role, Some(2), "the script asked for FORWARDING_ROLE");
}

/// The Role-Of-Node of the ACR-START the Rf auto-emit sends when a B2BUA call
/// carried by `invite` is answered.
async fn rf_start_role(invite: SipMessage) -> Option<u64> {
    let mut state = test_dispatcher().state;
    let (manager, received): (_, ReceivedAcrs) = mock_cdf().await;
    state.local_domains = Arc::new(vec![DOMAIN.to_string()]);
    state.rf_charger = Some(crate::diameter::rf_service::RfChargingService::new(
        manager,
        crate::config::RfConfig {
            enabled: true,
            auto_emit_b2bua: true,
            node_functionality: "as".to_string(),
            ..Default::default()
        },
    ));
    let a_leg = Arc::new(std::sync::Mutex::new(invite));
    spawn_rf_b2bua_start(&state, "role-of-node-call", &a_leg);
    for _ in 0..200 {
        if let Some(start) = received.lock().expect("the capture lock").first() {
            return role_of_node(start);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no ACR-START reached the CDF");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rf_an_originating_b2bua_call_is_in_the_originating_role() {
    assert_eq!(rf_start_role(isc_invite(CALLER, "orig")).await, Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rf_a_terminating_b2bua_call_is_in_the_terminating_role() {
    assert_eq!(rf_start_role(isc_invite(CALLEE, "term")).await, Some(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rf_a_diverted_b2bua_call_is_in_the_forwarding_role() {
    assert_eq!(
        rf_start_role(isc_invite(CALLEE, "orig-cdiv")).await,
        Some(2)
    );
}
