//! The REGISTERs of an entry with `register_body` / `register_headers` and the
//! `mcptt` feature, read as bytes: initial, refresh, the answer to a digest or
//! AKA challenge, the protected re-REGISTER and the de-REGISTER.

use std::collections::HashMap;

use super::RegisterExtras;
use crate::registrant::messages::EgressDefaults;
use crate::registrant::test_support::{self, impu, ue};
use crate::registrant::{build_contact_header, ImsContactParams, RegistrantEntry};
use crate::transport::Transport;

const CONTENT_TYPE: &str = "application/vnd.3gpp.mcptt-info+xml";
const BODY: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
    "<mcpttinfo><mcptt-Params><mcptt-access-token>token-1</mcptt-access-token>",
    "<mcptt-client-id>client-1</mcptt-client-id></mcptt-Params></mcpttinfo>",
);
const MCPTT_ICSI: &str = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt";
const MMTEL_ICSI: &str = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";

fn extras() -> RegisterExtras {
    RegisterExtras::new(
        Some((CONTENT_TYPE.to_string(), BODY.as_bytes().to_vec())),
        vec![
            (
                "P-Preferred-Service".to_string(),
                "urn:urn-7:3gpp-service.ims.icsi.mcptt".to_string(),
            ),
            ("X-Extra".to_string(), "one".to_string()),
        ],
    )
    .expect("accepted")
}

fn mcptt(mmtel: bool) -> ImsContactParams {
    ImsContactParams {
        mcptt: true,
        mmtel,
        ..ImsContactParams::default()
    }
}

fn listen() -> HashMap<Transport, std::net::SocketAddr> {
    HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))])
}

fn defaults(listen: &HashMap<Transport, std::net::SocketAddr>) -> EgressDefaults<'_> {
    EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), listen)
}

/// The wire form split at the blank line.
fn wire(message: &crate::sip::message::SipMessage) -> (String, Vec<u8>) {
    let bytes = message.to_bytes();
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a header terminator");
    (
        String::from_utf8(bytes[..split].to_vec()).expect("utf-8 headers"),
        bytes[split + 4..].to_vec(),
    )
}

fn assert_carries(message: &crate::sip::message::SipMessage) {
    let (head, body) = wire(message);
    assert!(head.contains("\r\nP-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt"));
    assert!(head.contains("\r\nX-Extra: one"));
    assert!(head.contains(&format!("\r\nContent-Type: {CONTENT_TYPE}")));
    assert!(head.contains(&format!("\r\nContent-Length: {}", BODY.len())));
    assert_eq!(head.matches("Content-Length").count(), 1);
    assert_eq!(body, BODY.as_bytes());
}

fn assert_plain(message: &crate::sip::message::SipMessage) {
    let (head, body) = wire(message);
    assert!(!head.contains("X-Extra"));
    assert!(!head.contains("Content-Type"));
    assert!(head.contains("\r\nContent-Length: 0"));
    assert!(body.is_empty());
}

#[test]
fn the_mcptt_contact_carries_both_feature_tags_exactly() {
    assert_eq!(
        build_contact_header("sip:ue@192.0.2.9:5060", Some(&mcptt(false))),
        format!("<sip:ue@192.0.2.9:5060>;q=1.0;+g.3gpp.icsi-ref=\"{MCPTT_ICSI}\";+g.3gpp.mcptt")
    );
}

#[test]
fn mcptt_with_mmtel_shares_one_icsi_ref_parameter() {
    let header = build_contact_header("sip:ue@192.0.2.9:5060", Some(&mcptt(true)));
    assert_eq!(
        header,
        format!(
            "<sip:ue@192.0.2.9:5060>;q=1.0;+g.3gpp.icsi-ref=\"{MMTEL_ICSI},{MCPTT_ICSI}\";+g.3gpp.mcptt"
        )
    );
    assert_eq!(header.matches("icsi-ref").count(), 1);
}

#[test]
fn features_parse_case_insensitively_and_unknown_ones_are_refused() {
    let params = ImsContactParams::from_features(None, &["MCPTT".to_string(), "mmtel".to_string()])
        .expect("known");
    assert!(params.mcptt && params.mmtel && !params.video && !params.smsip);
    let refused = ImsContactParams::from_features(None, &["mcptx".to_string()]);
    assert!(refused.is_err_and(|error| error.contains("mcptx")));
}

#[test]
fn a_digest_entry_carries_the_extras_on_initial_refresh_and_retry_but_not_the_de_register() {
    let manager = test_support::manager();
    let aor = "sip:alice@carrier.example";
    manager.add(
        test_support::trunk(aor)
            .with_ims_contact(mcptt(false))
            .with_register_extras(extras()),
    );
    let listen = listen();

    let initial = manager
        .build_register(aor, defaults(&listen), 3600)
        .expect("built");
    assert_carries(&initial.message);
    let (head, _) = wire(&initial.message);
    assert!(head.contains(&format!("+g.3gpp.icsi-ref=\"{MCPTT_ICSI}\";+g.3gpp.mcptt")));

    let challenge = crate::auth::parse_challenge(
        "Digest realm=\"carrier.example\", nonce=\"abc123\", qop=\"auth\", algorithm=MD5",
    )
    .expect("a challenge");
    let retry = manager
        .build_register_with_auth(aor, defaults(&listen), &challenge, false, 3600)
        .expect("built");
    assert_carries(&retry.message);
    assert!(wire(&retry.message).0.contains("\r\nAuthorization: Digest"));

    manager.handle_success(aor, 3600);
    let refresh = manager
        .build_register(aor, defaults(&listen), 3600)
        .expect("built");
    assert_carries(&refresh.message);

    let de_register = manager
        .build_register(aor, defaults(&listen), 0)
        .expect("built");
    assert_plain(&de_register.message);
    assert!(wire(&de_register.message)
        .0
        .contains(&format!("+g.3gpp.icsi-ref=\"{MCPTT_ICSI}\";+g.3gpp.mcptt")));
}

#[test]
fn an_entry_without_extras_is_unchanged() {
    let manager = test_support::manager();
    let aor = "sip:alice@carrier.example";
    manager.add(test_support::trunk(aor));
    let listen = listen();
    let built = manager
        .build_register(aor, defaults(&listen), 3600)
        .expect("built");
    assert_plain(&built.message);
}

/// An AKA entry without IPsec (a core that does not offer sec-agree).
fn aka_without_ipsec(index: u32) -> RegistrantEntry {
    let mut entry = ue(index, None);
    entry.ue_ipsec = None;
    entry
}

#[test]
fn an_aka_entry_carries_the_extras_on_initial_and_challenge_answer() {
    let manager = test_support::manager();
    let aor = impu(1);
    manager.add(
        aka_without_ipsec(1)
            .with_ims_contact(mcptt(true))
            .with_register_extras(extras()),
    );
    let listen = listen();

    let initial = manager
        .build_register(&aor, defaults(&listen), 600000)
        .expect("built");
    assert_carries(&initial.message);
    assert!(wire(&initial.message)
        .0
        .contains("\r\nAuthorization: Digest"));

    let challenge =
        crate::auth::parse_challenge(&test_support::aka_challenge_value("ff9bb4d0b607"))
            .expect("a challenge");
    let answer = manager
        .build_register_aka(&aor, defaults(&listen), &challenge, 600000, None)
        .expect("built");
    assert_carries(&answer.message);
    assert!(wire(&answer.message).0.contains("algorithm=AKAv1-MD5"));
}

#[test]
fn an_ipsec_entry_carries_the_extras_on_every_register_but_the_de_register() {
    let manager = test_support::manager();
    let aor = impu(1);
    manager
        .try_add(
            ue(1, Some("192.0.2.77".parse().expect("ip")))
                .with_ims_contact(mcptt(false))
                .with_register_extras(extras()),
        )
        .expect("added");
    let listen = listen();
    let defaults = defaults(&listen);

    let initial = manager
        .build_register(&aor, defaults, 600000)
        .expect("built");
    assert_carries(&initial.message);
    assert!(wire(&initial.message).0.contains("\r\nSecurity-Client:"));

    let challenge =
        crate::auth::parse_challenge(&test_support::aka_challenge_value("ff9bb4d0b607"))
            .expect("a challenge");
    let server = crate::ipsec::parse_security_client(test_support::SECURITY_SERVER)
        .expect("a Security-Server");
    manager.store_security_server(&aor, &server, test_support::SECURITY_SERVER);
    let verify = manager.security_server_value(&aor);
    let authenticated = manager
        .build_register_aka(&aor, defaults, &challenge, 600000, verify.as_deref())
        .expect("built");
    assert_carries(&authenticated.message);
    assert!(wire(&authenticated.message)
        .0
        .contains("\r\nSecurity-Verify:"));
    let authorization = authenticated
        .message
        .headers
        .get("Authorization")
        .cloned()
        .expect("an Authorization");
    manager.begin_authentication(&aor, &authorization);
    manager.conclude_ipsec_exchange(&aor).expect("concluded");
    manager.handle_success(&aor, 600);

    let refresh = manager
        .build_register(&aor, defaults, 600000)
        .expect("built");
    assert!(refresh.protected);
    assert_carries(&refresh.message);

    let de_register = manager.build_register(&aor, defaults, 0).expect("built");
    assert!(de_register.protected);
    assert_plain(&de_register.message);
}
