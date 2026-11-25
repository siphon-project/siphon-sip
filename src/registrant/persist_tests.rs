//! The stored form of a binding: what it holds, what it must not, and how the
//! store keeps it.

use std::collections::HashMap;

use super::*;
use crate::registrant::test_support::{self, trunk};

fn record(aor: &str) -> BindingRecord {
    BindingRecord {
        instance: "node-a".to_string(),
        aor: aor.to_string(),
        registrar_uri: "sip:198.51.100.10:5060".to_string(),
        destination: "198.51.100.10:5060".parse().expect("an address"),
        address_str: Some("registrar.example.invalid:5060".to_string()),
        transport: Transport::Udp,
        contact: "sip:siphon@192.0.2.1:5060".to_string(),
        call_id: "reg-0001".to_string(),
        next_cseq: 7,
        local_addr: Some("192.0.2.77".parse().expect("an address")),
        interval_secs: 600,
        binding_until_unix: unix_now() + 600,
        origin: EntryOrigin::Source,
        attempts: 1,
    }
}

fn fields_of(record: &BindingRecord) -> HashMap<String, String> {
    record
        .to_fields()
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
}

#[test]
fn a_record_survives_its_stored_form() {
    let original = record("sip:trunk@carrier.example");
    let back = BindingRecord::from_fields(&fields_of(&original)).expect("a readable record");
    assert_eq!(back, original);

    let mut without_options = original.clone();
    without_options.address_str = None;
    without_options.local_addr = None;
    let back = BindingRecord::from_fields(&fields_of(&without_options)).expect("readable");
    assert_eq!(back, without_options);
}

#[test]
fn the_stored_fields_are_exactly_the_documented_ones_and_none_is_a_credential() {
    let names: Vec<&str> = record("sip:a@b.example")
        .to_fields()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, FIELDS);
    for name in names {
        for secret in ["user", "pass", "ha1", "secret", "auth"] {
            assert!(
                !name.contains(secret),
                "a stored field named {name} reads as a credential"
            );
        }
    }
}

/// The credentials of the entry are in no value of its record: not the
/// username, not the password.
#[test]
fn a_record_built_from_an_entry_carries_no_credential() {
    let mut entry = trunk("sip:trunk@carrier.example");
    entry.credentials = crate::registrant::RegistrantCredentials::password(
        "sentinel-username".to_string(),
        "sentinel-password".to_string(),
        Some("sentinel-realm".to_string()),
    );
    entry.contact_uri = Some("sip:siphon@192.0.2.1:5060".to_string());
    entry.sent_contact = entry.contact_uri.clone();
    let manager = test_support::manager();
    manager.attach_binding_store(BindingStore::in_memory("node-a", 30));

    let record = manager
        .binding_record(&entry, 600)
        .expect("a digest entry is persisted");
    let everything = record
        .to_fields()
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    for secret in ["sentinel-username", "sentinel-password", "sentinel-realm"] {
        assert!(!everything.contains(secret), "{secret} reached a record");
    }
}

#[test]
fn a_hash_that_is_not_a_binding_is_not_read() {
    let mut fields = fields_of(&record("sip:trunk@carrier.example"));
    fields.remove("call_id");
    assert!(BindingRecord::from_fields(&fields).is_none());

    let mut fields = fields_of(&record("sip:trunk@carrier.example"));
    fields.insert("destination".to_string(), "not an address".to_string());
    assert!(BindingRecord::from_fields(&fields).is_none());

    let mut fields = fields_of(&record("sip:trunk@carrier.example"));
    fields.insert("origin".to_string(), "elsewhere".to_string());
    assert!(BindingRecord::from_fields(&fields).is_none());
}

#[tokio::test]
async fn the_store_keeps_the_latest_record_per_aor_and_removes_it() {
    let store = BindingStore::in_memory("node-a", 30);
    let mut first = record("sip:trunk@carrier.example");
    store.save(first.clone());
    first.call_id = "reg-0002".to_string();
    store.save(first.clone());

    let loaded = store.load().await.expect("loaded");
    assert_eq!(loaded, vec![first]);

    store.remove("sip:trunk@carrier.example");
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn the_store_reads_only_its_own_instance_and_only_unexpired_bindings() {
    let store = BindingStore::in_memory("node-a", 30);
    let mut other = record("sip:other@carrier.example");
    other.instance = "node-b".to_string();
    let mut expired = record("sip:expired@carrier.example");
    expired.binding_until_unix = unix_now().saturating_sub(5);
    store.save(record("sip:mine@carrier.example"));
    store.save(other);
    store.save(expired);

    let loaded = store.load().await.expect("loaded");
    let aors: Vec<&str> = loaded.iter().map(|record| record.aor.as_str()).collect();
    assert_eq!(aors, ["sip:mine@carrier.example"]);
}

/// A record leaves by itself once the registrar would have dropped the binding
/// (plus the slack): the TTL is what is left of the grant, and at least one
/// second.
#[test]
fn a_record_lives_for_the_rest_of_the_grant_plus_the_slack() {
    let store = BindingStore::in_memory("node-a", 30);
    store.save(record("sip:trunk@carrier.example"));
    let ttl = store
        .memory_ttl("sip:trunk@carrier.example")
        .expect("a stored record");
    assert!((629..=630).contains(&ttl), "ttl {ttl}");

    let mut nearly_over = record("sip:late@carrier.example");
    nearly_over.binding_until_unix = unix_now();
    let store = BindingStore::in_memory("node-a", 0);
    store.save(nearly_over);
    assert_eq!(store.memory_ttl("sip:late@carrier.example"), Some(1));
}

#[test]
fn the_key_names_the_instance_apart_from_the_registrar_prefix() {
    let store = BindingStore::in_memory("node-a", 30);
    let key = store.key_of("sip:trunk@carrier.example");
    assert_eq!(key, "siphon:registrant:node-a:sip:trunk@carrier.example");
    // The registrar builds its index by scanning `siphon:reg:*`.
    assert!(!key.starts_with("siphon:reg:"));
}
