//! What a wildcard listener puts in a REGISTER's Via and Contact: the
//! advertised address, never the bind address (RFC 3261 §18.2.1, §20.42,
//! §10.2.1).

use std::collections::HashMap;
use std::net::SocketAddr;

use super::test_support::{self, trunk};
use super::{BuiltRegister, EgressDefaults};
use crate::transport::Transport;

const AOR: &str = "sip:trunk@carrier.example";

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("an address")
}

fn build(
    transport: Transport,
    listen: &HashMap<Transport, SocketAddr>,
    per_transport: &HashMap<Transport, String>,
    global: Option<&str>,
) -> BuiltRegister {
    let manager = test_support::manager();
    let mut entry = trunk(AOR);
    entry.transport = transport;
    manager.add(entry);
    let defaults =
        EgressDefaults::new(addr("0.0.0.0:5060"), listen).with_advertised(per_transport, global);
    manager
        .build_register(AOR, defaults, 600)
        .expect("a REGISTER")
}

fn via(built: &BuiltRegister) -> String {
    built
        .message
        .headers
        .get("Via")
        .cloned()
        .unwrap_or_default()
}

fn contact(built: &BuiltRegister) -> String {
    built
        .message
        .headers
        .get("Contact")
        .cloned()
        .unwrap_or_default()
}

fn wildcards() -> HashMap<Transport, SocketAddr> {
    HashMap::from([
        (Transport::Udp, addr("0.0.0.0:5060")),
        (Transport::Tcp, addr("0.0.0.0:5060")),
    ])
}

#[test]
fn a_wildcard_udp_listener_names_the_advertised_address() {
    let built = build(
        Transport::Udp,
        &wildcards(),
        &HashMap::new(),
        Some("203.0.113.10"),
    );
    assert!(
        via(&built).starts_with("SIP/2.0/UDP 203.0.113.10:5060;"),
        "{}",
        via(&built)
    );
    assert!(
        contact(&built).contains("sip:trunk@203.0.113.10:5060"),
        "{}",
        contact(&built)
    );
    assert_eq!(built.sent_by, addr("203.0.113.10:5060"));
    // It still leaves from the listener's socket.
    assert_eq!(built.source_local_addr, Some(addr("0.0.0.0:5060")));
}

#[test]
fn a_wildcard_tcp_listener_names_the_advertised_address() {
    let built = build(
        Transport::Tcp,
        &wildcards(),
        &HashMap::new(),
        Some("203.0.113.10"),
    );
    assert!(
        via(&built).starts_with("SIP/2.0/TCP 203.0.113.10:5060;"),
        "{}",
        via(&built)
    );
    assert!(
        contact(&built).contains("sip:trunk@203.0.113.10:5060"),
        "{}",
        contact(&built)
    );
}

#[test]
fn a_per_transport_advertised_address_wins_over_the_global_one() {
    let per_transport = HashMap::from([(Transport::Udp, "203.0.113.20".to_string())]);
    let built = build(
        Transport::Udp,
        &wildcards(),
        &per_transport,
        Some("203.0.113.10"),
    );
    assert_eq!(built.sent_by, addr("203.0.113.20:5060"));
    assert!(contact(&built).contains("203.0.113.20:5060"));
    // The other transport has none of its own: the global one.
    let built = build(
        Transport::Tcp,
        &wildcards(),
        &per_transport,
        Some("203.0.113.10"),
    );
    assert_eq!(built.sent_by, addr("203.0.113.10:5060"));
}

#[test]
fn a_specific_bind_address_keeps_naming_itself() {
    let listen = HashMap::from([(Transport::Udp, addr("192.0.2.1:5070"))]);
    let built = build(
        Transport::Udp,
        &listen,
        &HashMap::new(),
        Some("203.0.113.10"),
    );
    assert_eq!(built.sent_by, addr("192.0.2.1:5070"));
    assert!(
        contact(&built).contains("sip:trunk@192.0.2.1:5070"),
        "{}",
        contact(&built)
    );
}

#[test]
fn a_wildcard_without_an_advertised_address_never_puts_the_wildcard_on_the_wire() {
    for transport in [Transport::Udp, Transport::Tcp] {
        let built = build(transport, &wildcards(), &HashMap::new(), None);
        assert!(!built.sent_by.ip().is_unspecified());
        assert_eq!(built.sent_by.port(), 5060);
        assert!(!via(&built).contains("0.0.0.0"), "{}", via(&built));
        assert!(!contact(&built).contains("0.0.0.0"), "{}", contact(&built));
    }
}

/// Wildcard UDP and TCP, TLS on one concrete address behind a reverse proxy,
/// an advertised address on no local interface: the concrete TLS listener must
/// not become the source or Contact of a UDP or TCP registration, and the TLS
/// one keeps naming its own listener.
#[test]
fn a_concrete_tls_listener_does_not_leak_into_the_wildcard_transports() {
    let mut listen = wildcards();
    listen.insert(Transport::Tls, addr("192.0.2.20:5062"));
    let merged = HashMap::from([
        (Transport::Udp, "203.0.113.10".to_string()),
        (Transport::Tcp, "203.0.113.10".to_string()),
        (Transport::Tls, "203.0.113.10".to_string()),
    ]);
    for transport in [Transport::Udp, Transport::Tcp] {
        let built = build(transport, &listen, &merged, Some("203.0.113.10"));
        assert_eq!(built.sent_by, addr("203.0.113.10:5060"), "{transport}");
        assert!(
            !contact(&built).contains("192.0.2.20"),
            "{}",
            contact(&built)
        );
        if transport == Transport::Udp {
            assert_eq!(built.source_local_addr, Some(addr("0.0.0.0:5060")));
        }
    }
    let built = build(Transport::Tls, &listen, &merged, Some("203.0.113.10"));
    assert_eq!(built.sent_by, addr("192.0.2.20:5062"));
}

#[tokio::test]
async fn the_stored_contact_is_the_one_that_went_on_the_wire() {
    let manager = test_support::manager();
    let store = super::persist::BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(std::sync::Arc::clone(&store));
    manager.add(trunk(AOR));
    let listen = wildcards();
    let merged = HashMap::new();
    let defaults = EgressDefaults::new(addr("0.0.0.0:5060"), &listen)
        .with_advertised(&merged, Some("203.0.113.10"));
    let built = manager
        .build_register(AOR, defaults, 600)
        .expect("a REGISTER");
    manager.handle_success(AOR, 600);

    let stored = store.load().await.expect("loaded").pop().expect("a record");
    assert_eq!(stored.contact, "sip:trunk@203.0.113.10:5060");
    assert!(contact(&built).contains(&stored.contact));
}

/// RFC 3261 §20.42 and §19.1 allow a host name in sent-by and in a Contact: an
/// advertised FQDN is what goes on the wire, with the listener's port, while
/// the socket address stays an address.
#[test]
fn an_advertised_host_name_is_what_the_via_and_contact_carry() {
    for transport in [Transport::Udp, Transport::Tcp] {
        let built = build(
            transport,
            &wildcards(),
            &HashMap::new(),
            Some("sbc.example.org"),
        );
        assert!(
            via(&built).contains(" sbc.example.org:5060;"),
            "{}",
            via(&built)
        );
        assert!(
            contact(&built).contains("sip:trunk@sbc.example.org:5060"),
            "{}",
            contact(&built)
        );
        assert!(!built.sent_by.ip().is_unspecified());
    }
}

#[test]
fn a_per_transport_host_name_wins_over_a_global_ip_literal() {
    let per_transport = HashMap::from([(Transport::Udp, "sbc.example.org".to_string())]);
    let built = build(
        Transport::Udp,
        &wildcards(),
        &per_transport,
        Some("203.0.113.10"),
    );
    assert!(
        contact(&built).contains("sip:trunk@sbc.example.org:5060"),
        "{}",
        contact(&built)
    );
    assert!(
        via(&built).contains(" sbc.example.org:5060;"),
        "{}",
        via(&built)
    );
    // Another transport without one of its own takes the global address.
    let built = build(
        Transport::Tcp,
        &wildcards(),
        &per_transport,
        Some("203.0.113.10"),
    );
    assert!(
        contact(&built).contains("203.0.113.10:5060"),
        "{}",
        contact(&built)
    );
}

#[tokio::test]
async fn the_stored_contact_carries_the_advertised_host_name_as_sent() {
    let manager = test_support::manager();
    let store = super::persist::BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(std::sync::Arc::clone(&store));
    manager.add(trunk(AOR));
    let listen = wildcards();
    let merged = HashMap::new();
    let defaults = EgressDefaults::new(addr("0.0.0.0:5060"), &listen)
        .with_advertised(&merged, Some("sbc.example.org"));
    let built = manager
        .build_register(AOR, defaults, 600)
        .expect("a REGISTER");
    manager.handle_success(AOR, 600);

    let stored = store.load().await.expect("loaded").pop().expect("a record");
    assert_eq!(stored.contact, "sip:trunk@sbc.example.org:5060");
    assert!(contact(&built).contains(&stored.contact));
}

// ---------------------------------------------------------------------------
// The per-node token in a generated Contact
// ---------------------------------------------------------------------------

fn node_manager(instance: &str) -> super::RegistrantManager {
    test_support::manager().with_instance_id(instance.to_string())
}

fn token_of(built: &BuiltRegister) -> String {
    let header = contact(built);
    super::contact::contact_token_of(header.trim_matches(|c| c == '<' || c == '>'))
        .unwrap_or_default()
}

fn challenge() -> crate::auth::DigestChallenge {
    crate::auth::parse_challenge(
        "Digest realm=\"registrar.example\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"",
    )
    .expect("a challenge")
}

/// Every REGISTER of one registration carries the same Contact, token
/// included: the initial, the challenged retry, a refresh and the de-REGISTER.
/// A registrar keys the binding by it (RFC 3261 §10.3).
#[test]
fn every_register_of_a_registration_carries_the_same_contact_with_its_token() {
    let manager = node_manager("node-a");
    manager.add(trunk(AOR));
    let listen = wildcards();
    let merged = HashMap::new();
    let defaults = EgressDefaults::new(addr("0.0.0.0:5060"), &listen)
        .with_advertised(&merged, Some("203.0.113.10"));

    let initial = manager.build_register(AOR, defaults, 600).expect("initial");
    let challenged = manager
        .build_register_with_auth(AOR, defaults, &challenge(), false, 600)
        .expect("challenged");
    let refresh = manager.build_register(AOR, defaults, 600).expect("refresh");
    let deregister = manager
        .build_register(AOR, defaults, 0)
        .expect("de-REGISTER");

    let expected = format!(
        "<sip:trunk@203.0.113.10:5060;rnode={}>",
        super::contact::instance_token("node-a", AOR)
    );
    for (name, built) in [
        ("initial", &initial),
        ("challenged", &challenged),
        ("refresh", &refresh),
        ("de-REGISTER", &deregister),
    ] {
        assert_eq!(contact(built), expected, "{name}");
    }
}

#[test]
fn two_instances_registering_one_aor_behind_one_address_hold_different_contacts() {
    let mut contacts = Vec::new();
    for instance in ["node-a", "node-b"] {
        let manager = node_manager(instance);
        manager.add(trunk(AOR));
        let listen = wildcards();
        let merged = HashMap::new();
        let defaults = EgressDefaults::new(addr("0.0.0.0:5060"), &listen)
            .with_advertised(&merged, Some("203.0.113.10"));
        let built = manager
            .build_register(AOR, defaults, 600)
            .expect("REGISTER");
        assert!(
            !contact(&built).contains(instance),
            "the instance id is not on the wire"
        );
        contacts.push(contact(&built));
    }
    assert_ne!(contacts[0], contacts[1]);
}

/// With no instance id (an embedder) or an explicit contact from the source
/// row, the Contact is what it always was.
#[test]
fn a_contact_without_an_instance_or_with_an_explicit_one_has_no_token() {
    let listen = wildcards();
    let merged = HashMap::new();
    let defaults = EgressDefaults::new(addr("0.0.0.0:5060"), &listen)
        .with_advertised(&merged, Some("203.0.113.10"));

    let manager = test_support::manager();
    manager.add(trunk(AOR));
    let built = manager
        .build_register(AOR, defaults, 600)
        .expect("REGISTER");
    assert!(!contact(&built).contains("rnode"), "{}", contact(&built));

    let manager = node_manager("node-a");
    let mut explicit = trunk(AOR);
    explicit.contact_uri = Some("sip:trunk@192.0.2.1:5060".to_string());
    manager.add(explicit);
    let built = manager
        .build_register(AOR, defaults, 600)
        .expect("REGISTER");
    assert_eq!(contact(&built), "<sip:trunk@192.0.2.1:5060>");
}

/// An AKA / IPsec entry registers from an address of its own into a core, is
/// not persisted and is never cleared by the restart clean-up: its Contact
/// stays as it was, on the unprotected and the protected REGISTER alike.
#[test]
fn an_aka_ipsec_entry_keeps_its_contact_without_a_token() {
    let manager = node_manager("node-a");
    manager.add(test_support::ue(1, Some(addr("192.0.2.77:0").ip())));
    let listen = wildcards();
    let defaults = EgressDefaults::new(addr("192.0.2.1:5060"), &listen);
    let built = manager
        .build_register(&test_support::impu(1), defaults, 600)
        .expect("REGISTER");
    assert!(!contact(&built).contains("rnode"), "{}", contact(&built));
    assert_eq!(token_of(&built), "");
}

#[tokio::test]
async fn the_stored_contact_carries_the_token_as_sent() {
    let manager = node_manager("node-a");
    let store = super::persist::BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(std::sync::Arc::clone(&store));
    manager.add(trunk(AOR));
    let listen = wildcards();
    let merged = HashMap::new();
    let defaults = EgressDefaults::new(addr("0.0.0.0:5060"), &listen)
        .with_advertised(&merged, Some("sbc.example.org"));
    let built = manager
        .build_register(AOR, defaults, 600)
        .expect("REGISTER");
    manager.handle_success(AOR, 600);

    let stored = store.load().await.expect("loaded").pop().expect("a record");
    assert_eq!(
        stored.contact,
        format!(
            "sip:trunk@sbc.example.org:5060;rnode={}",
            super::contact::instance_token("node-a", AOR)
        )
    );
    assert!(contact(&built).contains(&stored.contact));
}
