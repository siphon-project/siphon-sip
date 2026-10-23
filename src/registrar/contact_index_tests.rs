//! The contact index stays in step with the bindings through every path that
//! changes them, and the lookups it serves answer as the scans they replace.
//!
//! After every step the index is compared with one rebuilt from the bindings
//! (`contact_index_is_consistent`): an entry missing is a binding a Contact
//! lookup cannot find, and one too many is memory that is never given back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::sip::parser::parse_uri_standalone;

fn uri(text: &str) -> SipUri {
    parse_uri_standalone(text).expect("a URI")
}

fn source() -> Option<SocketAddr> {
    Some("192.0.2.10:5060".parse().expect("an address"))
}

/// A REGISTER of `contact` for `aor`, over `transport`, on stream connection
/// `connection_id`, with an optional `+sip.instance`.
fn register(
    registrar: &Registrar,
    aor: &str,
    contact: &str,
    expires: u32,
    instance: Option<&str>,
    connection_id: Option<u64>,
) {
    let transport = if connection_id.is_some() {
        Some(Transport::Tcp)
    } else {
        Some(Transport::Udp)
    };
    registrar
        .save_full(
            aor,
            uri(contact),
            expires,
            1.0,
            format!("{aor}-{contact}"),
            1,
            source(),
            transport,
            instance.map(str::to_string),
            None,
            vec![],
            FlowCapture {
                inbound_connection_id: connection_id,
                ..FlowCapture::default()
            },
            Vec::new(),
        )
        .expect("the REGISTER is accepted");
}

fn consistent(registrar: &Registrar, step: &str) {
    assert!(
        registrar.contact_index_is_consistent(),
        "the contact index left the bindings after: {step}"
    );
}

/// Age every binding of `aor` past its expiry.
fn expire(registrar: &Registrar, aor: &str) {
    if let Some(mut entry) = registrar.bindings.get_mut(aor) {
        for contact in entry.value_mut().iter_mut() {
            contact.registered_at =
                Instant::now() - Duration::from_secs(u64::from(contact.expires_secs) + 1);
        }
    }
}

const ALICE: &str = "sip:alice@example.invalid";
const BOB: &str = "sip:bob@example.invalid";

#[test]
fn every_mutation_path_keeps_the_index_in_step() {
    let registrar = Registrar::default();

    register(
        &registrar,
        ALICE,
        "sip:alice@192.0.2.1:5070",
        3600,
        None,
        None,
    );
    consistent(&registrar, "a first binding");
    assert_eq!(
        registrar.lookup_contact("sip:alice@192.0.2.1:5070").len(),
        1
    );

    register(
        &registrar,
        ALICE,
        "sip:alice@192.0.2.1:5070",
        3600,
        None,
        None,
    );
    consistent(&registrar, "a refresh of the same Contact");

    register(&registrar, ALICE, "sip:alice@192.0.2.2", 3600, None, None);
    consistent(&registrar, "a second device");

    // RFC 5627: the same instance from a rotated port replaces its binding.
    register(
        &registrar,
        ALICE,
        "sip:alice@192.0.2.3:6000",
        3600,
        Some("<urn:uuid:00000000-0000-0000-0000-000000000001>"),
        None,
    );
    register(
        &registrar,
        ALICE,
        "sip:alice@192.0.2.3:6001",
        3600,
        Some("<urn:uuid:00000000-0000-0000-0000-000000000001>"),
        None,
    );
    consistent(&registrar, "an instance re-registering from a new port");
    assert!(!registrar.is_registered_contact("sip:alice@192.0.2.3:6000"));
    assert!(registrar.is_registered_contact("sip:alice@192.0.2.3:6001"));

    register(&registrar, ALICE, "sip:alice@192.0.2.2", 0, None, None);
    consistent(&registrar, "an Expires: 0 de-registration");
    assert!(!registrar.is_registered_contact("sip:alice@192.0.2.2"));

    registrar.remove_contact(ALICE, "sip:alice@192.0.2.3:6001");
    consistent(&registrar, "remove_contact");

    // An AS capability record is not indexed, and does not disturb what is.
    assert!(registrar
        .save_as_contact(
            ALICE,
            uri("sip:mmtel@as.example.invalid"),
            3600,
            1.0,
            vec![]
        )
        .expect("an AS contact"));
    consistent(&registrar, "an AS contact");
    assert!(!registrar.is_registered_contact("sip:mmtel@as.example.invalid"));
    assert!(registrar
        .save_as_contact(ALICE, uri("sip:mmtel@as.example.invalid"), 0, 1.0, vec![])
        .expect("the AS contact removed"));
    consistent(&registrar, "an AS contact removed");

    registrar.save_pending(
        ALICE,
        uri("sip:alice@192.0.2.4"),
        3600,
        1.0,
        "pending".into(),
        1,
    );
    consistent(&registrar, "a pending binding");
    registrar.confirm_pending(ALICE);
    consistent(&registrar, "its confirmation");

    registrar.remove_all(ALICE);
    consistent(&registrar, "remove_all");
    assert!(registrar
        .lookup_contact("sip:alice@192.0.2.1:5070")
        .is_empty());

    register(&registrar, BOB, "sip:bob@192.0.2.5", 3600, None, None);
    registrar.clear_bindings(BOB);
    consistent(&registrar, "clear_bindings");

    register(&registrar, BOB, "sip:bob@192.0.2.5", 3600, None, None);
    registrar
        .save_with_source(
            BOB,
            uri("sip:bob@192.0.2.6"),
            3600,
            1.0,
            "forced".into(),
            2,
            source(),
            None,
        )
        .expect("a save");
    consistent(&registrar, "a second save");
    assert!(registrar.is_registered_contact("sip:bob@192.0.2.5"));
}

#[test]
fn a_forced_save_replaces_the_aors_bindings_in_the_index() {
    let registrar = Registrar::default();
    register(&registrar, BOB, "sip:bob@192.0.2.5", 3600, None, None);
    register(&registrar, BOB, "sip:bob@192.0.2.6", 3600, None, None);
    registrar
        .apply_register(
            BOB,
            vec![update::ContactUpdate {
                uri: uri("sip:bob@192.0.2.7"),
                expires_secs: 3600,
                q: 1.0,
                call_id: "forced".into(),
                cseq: 3,
                source_addr: source(),
                source_transport: Some(Transport::Udp),
                sip_instance: None,
                reg_id: None,
                path: vec![],
                flow: FlowCapture::default(),
                params: vec![],
                auth_user: None,
            }],
            true,
        )
        .expect("the forced REGISTER is accepted");
    consistent(&registrar, "a forced save");
    assert!(!registrar.is_registered_contact("sip:bob@192.0.2.5"));
    assert!(registrar.is_registered_contact("sip:bob@192.0.2.7"));
}

#[test]
fn expiry_flow_failure_and_restart_eviction_keep_the_index_in_step() {
    let registrar = Registrar::default();
    register(&registrar, ALICE, "sip:alice@192.0.2.1", 60, None, None);
    register(
        &registrar,
        BOB,
        "sip:bob@192.0.2.5;transport=tcp",
        3600,
        None,
        Some(41),
    );
    register(&registrar, BOB, "sip:bob@192.0.2.6", 3600, None, None);

    expire(&registrar, ALICE);
    assert!(
        !registrar.is_registered_contact("sip:alice@192.0.2.1"),
        "an expired binding is not found"
    );
    consistent(&registrar, "expiry before the sweep");
    assert_eq!(registrar.expire_stale(), 1);
    consistent(&registrar, "the expiry sweep");

    // RFC 5626 §4.2.2: the stream connection closes, its binding goes.
    let removed = registrar.close_flow(41, &std::collections::HashSet::new());
    assert_eq!(removed.len(), 1);
    consistent(&registrar, "a flow failure");
    assert!(!registrar.is_registered_contact("sip:bob@192.0.2.5"));
    assert!(registrar.is_registered_contact("sip:bob@192.0.2.6"));

    register(
        &registrar,
        ALICE,
        "sip:alice@192.0.2.1;transport=tls",
        3600,
        None,
        None,
    );
    register(&registrar, ALICE, "sip:alice@192.0.2.2", 3600, None, None);
    assert_eq!(registrar.evict_connection_oriented(), 1);
    consistent(&registrar, "the restart eviction of stream bindings");
    assert!(!registrar.is_registered_contact("sip:alice@192.0.2.1"));
    assert!(registrar.is_registered_contact("sip:alice@192.0.2.2"));
}

#[tokio::test]
async fn a_restore_from_the_backend_indexes_what_it_installs() {
    let backend = backend::MemoryBackend::new();
    let writer = Registrar::default();
    register(&writer, ALICE, "sip:alice@192.0.2.1:5070", 3600, None, None);
    register(&writer, BOB, "sip:bob@192.0.2.5", 3600, None, None);
    for (aor, contacts) in [ALICE, BOB].map(|aor| {
        let entry = writer.bindings.get(aor).expect("a binding");
        let stored: Vec<backend::StoredContact> = entry
            .value()
            .iter()
            .map(backend::StoredContact::from_contact)
            .collect();
        (aor, stored)
    }) {
        backend::RegistrarBackend::save(&backend, aor, &contacts)
            .await
            .expect("stored");
    }

    let restored = Registrar::default();
    // A binding already held for one of the AoRs is replaced by the restore.
    register(&restored, BOB, "sip:bob@192.0.2.9", 3600, None, None);
    backend::restore_from_backend(&backend, &restored)
        .await
        .expect("restored");
    consistent(&restored, "a restore");
    assert_eq!(restored.lookup_contact("sip:alice@192.0.2.1:5070").len(), 1);
    assert!(restored.is_registered_contact("sip:bob@192.0.2.5"));
    assert!(!restored.is_registered_contact("sip:bob@192.0.2.9"));
}

#[test]
fn a_contact_lookup_matches_the_device_however_it_is_spelled() {
    let registrar = Registrar::default();
    register(
        &registrar,
        ALICE,
        "sip:1001@Pbx.Example.Invalid:5060;transport=udp",
        3600,
        None,
        None,
    );
    for spelled in [
        "sip:1001@pbx.example.invalid",
        "<sip:1001@pbx.example.invalid:5060>",
        "sip:1001@PBX.EXAMPLE.INVALID;ob",
        "1001@pbx.example.invalid",
    ] {
        assert!(registrar.is_registered_contact(spelled), "{spelled}");
        assert_eq!(registrar.lookup_contact(spelled).len(), 1, "{spelled}");
        assert_eq!(
            registrar.aor_for_contact(spelled).as_deref(),
            Some(ALICE),
            "{spelled}"
        );
    }
    for other in [
        "sip:1002@pbx.example.invalid",
        "sip:1001@pbx.example.invalid:5070",
        "sips:1001@pbx.example.invalid",
        "not a uri at all <<<",
    ] {
        assert!(!registrar.is_registered_contact(other), "{other}");
        assert!(registrar.aor_for_contact(other).is_none(), "{other}");
    }
}

/// A device two AoRs registered: both come back from `lookup_contact`, and
/// `binding_for_contact` names neither, as the scan it replaces did.
#[test]
fn a_contact_two_aors_share_is_found_under_both_and_owned_by_neither() {
    let registrar = Registrar::default();
    register(&registrar, ALICE, "sip:desk@192.0.2.8", 3600, None, None);
    register(
        &registrar,
        BOB,
        "sip:desk@192.0.2.8;transport=udp",
        3600,
        None,
        None,
    );
    assert_eq!(registrar.lookup_contact("sip:desk@192.0.2.8").len(), 2);
    assert!(registrar
        .binding_for_contact("sip:desk@192.0.2.8")
        .is_none());
    registrar.remove_all(BOB);
    consistent(&registrar, "one of the two AoRs removed");
    assert_eq!(
        registrar.binding_for_contact("sip:desk@192.0.2.8"),
        Some((ALICE.to_string(), "sip:desk@192.0.2.8".to_string()))
    );
}

/// Saves, refreshes, de-registrations and removals from many threads at once,
/// over Contacts the AoRs share, leave an index a rebuild would agree with.
#[test]
fn concurrent_mutation_leaves_the_index_in_step() {
    let registrar = Arc::new(Registrar::default());
    let threads: Vec<_> = (0..8)
        .map(|thread| {
            let registrar = Arc::clone(&registrar);
            std::thread::spawn(move || {
                for round in 0..200u32 {
                    let aor = format!("sip:user{}@example.invalid", (thread + round) % 16);
                    let contact = format!("sip:device{}@192.0.2.{}", round % 7, 1 + round % 5);
                    match round % 5 {
                        0 | 1 => register(&registrar, &aor, &contact, 3600, None, None),
                        2 => register(&registrar, &aor, &contact, 0, None, None),
                        3 => {
                            registrar.remove_contact(&aor, &contact);
                        }
                        _ => registrar.remove_all(&aor),
                    }
                    let _ = registrar.lookup_contact(&contact);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("a thread");
    }
    consistent(&registrar, "concurrent mutation");
}

/// A lookup costs the AoRs the index names, not the table: at any size it
/// reads the same one binding.
#[test]
fn a_lookup_reads_only_the_aors_the_index_names() {
    let registrar = Registrar::default();
    for index in 0..5_000 {
        register(
            &registrar,
            &format!("sip:user{index}@example.invalid"),
            &format!("sip:user{index}@198.51.100.7:5060"),
            3600,
            None,
            None,
        );
    }
    // One entry by Contact and one by source address per binding.
    assert_eq!(registrar.contact_index.len(), 5_001);
    // All 5000 came from one address, as behind a PBX: owned by no one AoR.
    assert!(registrar
        .binding_for_source(source().expect("a source"))
        .is_none());
    assert_eq!(
        registrar.contact_index.aors(
            registrar
                .contact_index
                .key_of(&uri("sip:user42@198.51.100.7"))
        ),
        ["sip:user42@example.invalid"]
    );
    assert!(registrar
        .contact_index
        .aors(
            registrar
                .contact_index
                .key_of(&uri("sip:nobody@198.51.100.7"))
        )
        .is_empty());
}

/// Binding `index`'s own source address.
fn own_source(index: u32) -> SocketAddr {
    SocketAddr::from((
        [203, 0, 113, (index % 250 + 1) as u8],
        10_000 + (index / 250) as u16,
    ))
}

fn register_from(registrar: &Registrar, aor: &str, contact: &str, from: SocketAddr, expires: u32) {
    registrar
        .save_with_source(
            aor,
            uri(contact),
            expires,
            1.0,
            format!("{aor}-{from}"),
            1,
            Some(from),
            Some(Transport::Udp),
        )
        .expect("the REGISTER is accepted");
}

/// `binding_for_source` reads the AoRs the index names for the address a
/// binding's REGISTER came from, and answers as the scan it replaces did: the
/// one AoR with a live binding from there, none when two share it.
#[test]
fn a_binding_is_found_by_the_address_its_register_came_from() {
    let registrar = Registrar::default();
    for index in 0..1_000 {
        register_from(
            &registrar,
            &format!("sip:user{index}@example.invalid"),
            &format!("sip:user{index}@198.51.100.7:{}", 20_000 + index),
            own_source(index),
            3600,
        );
    }
    consistent(&registrar, "bindings with their sources");
    assert_eq!(
        registrar.binding_for_source(own_source(42)),
        Some((
            "sip:user42@example.invalid".to_string(),
            "sip:user42@198.51.100.7:20042".to_string()
        ))
    );
    assert_eq!(
        registrar
            .contact_index
            .aors(registrar.contact_index.source_key_of(own_source(42))),
        ["sip:user42@example.invalid"],
        "the index names the one AoR"
    );
    let nowhere = SocketAddr::from(([203, 0, 113, 1], 9_999));
    assert!(registrar.binding_for_source(nowhere).is_none());

    // A second AoR registering from the same address: owned by neither.
    register_from(
        &registrar,
        BOB,
        "sip:bob@198.51.100.8",
        own_source(42),
        3600,
    );
    assert!(registrar.binding_for_source(own_source(42)).is_none());
    registrar.remove_all(BOB);
    consistent(&registrar, "the second AoR removed");
    assert!(registrar.binding_for_source(own_source(42)).is_some());

    // A de-registered or expired binding is not found by its source.
    register_from(
        &registrar,
        "sip:user42@example.invalid",
        "sip:user42@198.51.100.7:20042",
        own_source(42),
        0,
    );
    consistent(&registrar, "a de-registration");
    assert!(registrar.binding_for_source(own_source(42)).is_none());
    expire(&registrar, "sip:user43@example.invalid");
    assert!(registrar.binding_for_source(own_source(43)).is_none());
    registrar.expire_stale();
    consistent(&registrar, "the expiry sweep");

    // A refresh from a new address moves the binding's source.
    register_from(
        &registrar,
        "sip:user44@example.invalid",
        "sip:user44@198.51.100.7:20044",
        nowhere,
        3600,
    );
    consistent(&registrar, "a refresh from a new address");
    assert!(registrar.binding_for_source(own_source(44)).is_none());
    assert_eq!(
        registrar
            .binding_for_source(nowhere)
            .map(|(aor, _)| aor)
            .as_deref(),
        Some("sip:user44@example.invalid")
    );
}

/// `has_live_binding_from` answers whether ANY AoR still holds a live binding
/// registered from an address — the question a P-CSCF asks before it deletes
/// the security associations a UE's registrations used (3GPP TS 33.203 clause
/// 7.4.2a: "once all the associated IMPUs are de-registered"). Unlike
/// `binding_for_source`, two AoRs sharing the address is still a yes.
#[test]
fn any_live_binding_from_an_address_is_seen_whichever_aor_holds_it() {
    let registrar = Registrar::default();
    let from = SocketAddr::from(([203, 0, 113, 77], 6_100));
    let elsewhere = SocketAddr::from(([203, 0, 113, 77], 6_200));
    assert!(!registrar.has_live_binding_from(from));

    register_from(
        &registrar,
        "sip:impu1@example.invalid",
        "sip:ue@198.51.100.77:6101",
        from,
        3600,
    );
    register_from(
        &registrar,
        "sip:impu2@example.invalid",
        "sip:ue@198.51.100.77:6101",
        from,
        3600,
    );
    assert!(registrar.has_live_binding_from(from));
    assert!(!registrar.has_live_binding_from(elsewhere));

    // One IMPU de-registered: the other still holds the address.
    register_from(
        &registrar,
        "sip:impu1@example.invalid",
        "sip:ue@198.51.100.77:6101",
        from,
        0,
    );
    assert!(registrar.has_live_binding_from(from));

    // The last one de-registered: nothing holds it.
    register_from(
        &registrar,
        "sip:impu2@example.invalid",
        "sip:ue@198.51.100.77:6101",
        from,
        0,
    );
    assert!(!registrar.has_live_binding_from(from));

    // An expired binding does not count either.
    register_from(
        &registrar,
        "sip:impu3@example.invalid",
        "sip:ue@198.51.100.77:6101",
        from,
        3600,
    );
    expire(&registrar, "sip:impu3@example.invalid");
    assert!(!registrar.has_live_binding_from(from));
}
