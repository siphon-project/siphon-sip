//! The registrant's answers handled by the dispatcher for UEs that register
//! from addresses of their own: the IPsec SAs, the protected REGISTER and the
//! digest retry all use the entry's address, never the process's.

use super::*;
use crate::ipsec::IpsecManager;
use crate::registrant::test_support::{self, impu, trunk, ue};
use crate::registrant::{EgressDefaults, RegistrantManager};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const UE_ADDR: &str = "192.0.2.77";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

/// The dispatcher under test (bound to 192.0.2.1:5060), with a registrant and
/// a mock-kernel IPsec manager.
fn dispatcher(
    registrant: &Arc<RegistrantManager>,
) -> (super::test_dispatcher::TestDispatcher, Arc<IpsecManager>) {
    let mut dispatcher = super::test_dispatcher::test_dispatcher();
    let ipsec = Arc::new(IpsecManager::with_test_kernel());
    dispatcher.state.ipsec_manager = Some(Arc::clone(&ipsec));
    dispatcher.state.registrant_manager = Some(Arc::clone(registrant));
    dispatcher
        .state
        .listen_addrs
        .insert(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"));
    (dispatcher, ipsec)
}

/// Send the initial REGISTER and return its Call-ID.
fn initial_register(registrant: &RegistrantManager, aor: &str) -> String {
    let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
    let built = registrant
        .build_register(
            aor,
            EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &listen),
            600000,
        )
        .expect("built");
    built
        .message
        .headers
        .get("Call-ID")
        .cloned()
        .expect("a Call-ID")
}

fn response(status: &str, call_id: &str, extra: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "SIP/2.0 {status}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.77:5060;branch=z9hG4bK-reg-test\r\n",
            "From: <sip:ue@example.invalid>;tag=reg-1\r\n",
            "To: <sip:ue@example.invalid>;tag=pcscf\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 REGISTER\r\n",
            "{extra}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status = status,
        call_id = call_id,
        extra = extra,
    );
    crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("a response that parses")
}

async fn wait_for<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    probe().expect("the condition came true in time")
}

#[tokio::test]
async fn a_ue_on_its_own_address_installs_its_sas_and_sends_protected_from_there() {
    let registrant = Arc::new(test_support::manager());
    registrant.try_add(ue(1, Some(ip(UE_ADDR)))).expect("added");
    let (dispatcher, ipsec) = dispatcher(&registrant);
    let call_id = initial_register(&registrant, &impu(1));

    // A stale pair on the entry's address and port is replaced, not collided.
    let challenge = response(
        "401 Unauthorized",
        &call_id,
        &format!(
            "WWW-Authenticate: {}\r\nSecurity-Server: {}\r\n",
            test_support::aka_challenge_value("ff9bb4d0b607"),
            test_support::SECURITY_SERVER
        ),
    );
    handle_registrant_response(
        &registrant,
        &challenge,
        401,
        "z9hG4bK-reg-test",
        &dispatcher.state,
    );

    let protected = tokio::time::timeout(Duration::from_secs(2), dispatcher.udp.recv_async())
        .await
        .expect("the protected REGISTER in time")
        .expect("channel open");
    assert_eq!(
        protected.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6100)),
        "from the UE protected client port on the entry's address"
    );
    assert_eq!(
        protected.destination,
        "198.51.100.10:5066".parse().expect("addr")
    );
    let raw = String::from_utf8_lossy(&protected.data).into_owned();
    assert!(raw.contains("Security-Verify:"), "{raw}");
    // A REGISTER protected by an SA set names the protected server port in
    // its Via (TS 24.229 5.1.1.4.2 c), where the P-CSCF answers it.
    assert!(
        raw.contains(&format!("Via: SIP/2.0/UDP {UE_ADDR}:6101;")),
        "{raw}"
    );

    let sa = ipsec
        .get_sa(&ip(UE_ADDR), 6100)
        .expect("the SA pair is keyed on the entry's address");
    assert_eq!(sa.ue_addr, ip(UE_ADDR));
    assert_eq!(sa.pcscf_addr, ip("198.51.100.10"));
    assert!(
        ipsec.get_sa(&ip("192.0.2.1"), 6100).is_none(),
        "nothing on the process address"
    );

    // The 200 re-pins the lifetime of the pair on the entry's address.
    let ok = response("200 OK", &call_id, "Expires: 600\r\n");
    handle_registrant_response(&registrant, &ok, 200, "z9hG4bK-reg-test", &dispatcher.state);
    assert_eq!(
        registrant.state(&impu(1)),
        Some(crate::registrant::RegistrantState::Registered)
    );
    let lifetime = wait_for(|| {
        ipsec
            .get_sa(&ip(UE_ADDR), 6100)
            .and_then(|sa| sa.hard_lifetime_secs)
            .filter(|lifetime| *lifetime == 632)
    })
    .await;
    assert_eq!(lifetime, 632);
}

#[tokio::test]
async fn two_ues_on_the_same_ports_get_two_sa_pairs() {
    let registrant = Arc::new(test_support::manager());
    registrant
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    registrant
        .try_add(ue(2, Some(ip("192.0.2.78"))))
        .expect("added");
    let (dispatcher, ipsec) = dispatcher(&registrant);
    for index in [1, 2] {
        let call_id = initial_register(&registrant, &impu(index));
        let challenge = response(
            "401 Unauthorized",
            &call_id,
            &format!(
                "WWW-Authenticate: {}\r\nSecurity-Server: {}\r\n",
                test_support::aka_challenge_value("ff9bb4d0b607"),
                test_support::SECURITY_SERVER
            ),
        );
        handle_registrant_response(
            &registrant,
            &challenge,
            401,
            "z9hG4bK-reg-test",
            &dispatcher.state,
        );
        tokio::time::timeout(Duration::from_secs(2), dispatcher.udp.recv_async())
            .await
            .expect("sent in time")
            .expect("open");
    }
    assert!(ipsec.get_sa(&ip("192.0.2.77"), 6100).is_some());
    assert!(ipsec.get_sa(&ip("192.0.2.78"), 6100).is_some());
    assert_eq!(ipsec.active_count(), 2);
}

#[tokio::test]
async fn the_digest_retry_leaves_from_the_socket_the_register_did() {
    let registrant = Arc::new(test_support::manager());
    registrant
        .try_add(trunk("sip:own@carrier.example").with_local_addr(ip(UE_ADDR)))
        .expect("added");
    registrant.add(trunk("sip:process@carrier.example"));
    let (dispatcher, _ipsec) = dispatcher(&registrant);

    for (aor, expected) in [
        ("sip:own@carrier.example", "192.0.2.77:5060"),
        // A process-address trunk: pinned to the first UDP listener, which it
        // used to reach only as the default.
        ("sip:process@carrier.example", "192.0.2.1:5060"),
    ] {
        let call_id = initial_register(&registrant, aor);
        let challenge = response(
            "401 Unauthorized",
            &call_id,
            "WWW-Authenticate: Digest realm=\"carrier.example\", nonce=\"abc\", qop=\"auth\"\r\n",
        );
        handle_registrant_response(
            &registrant,
            &challenge,
            401,
            "z9hG4bK-reg-test",
            &dispatcher.state,
        );
        let retry = dispatcher.udp.try_recv().expect("the authenticated retry");
        assert_eq!(
            retry.source_local_addr,
            Some(expected.parse().expect("addr")),
            "{aor}"
        );
        assert!(String::from_utf8_lossy(&retry.data).contains("Authorization: Digest"));
    }
}
