//! Registrar liveness judges a binding against this instance's security
//! associations only when this instance accepted the binding. With a shared
//! registrar a P-CSCF also holds bindings other instances accepted, and a UE
//! address is reassigned when a PDN connection ends: an abandoned pair here for
//! 192.0.2.10 says nothing about the UE now registered from 192.0.2.10 through
//! another instance.
//!
//! Before: the abandoned-SA sweep and the idle sweep matched bindings by UE
//! address alone, so a P-CSCF reaping a pair left by a departed UE
//! network-deregistered the live UE that had been given the same address and
//! registered elsewhere, in the middle of its calls.

use std::net::{IpAddr, SocketAddr};

use super::liveness::{accepted_here, reaped_sa_bindings};
use crate::registrar::{Contact, FlowCapture, InstanceIdentity, Registrar};
use crate::transport::Transport;

const AOR: &str = "sip:001010000000001@ims.example.invalid";

fn identity(id: &str) -> InstanceIdentity {
    InstanceIdentity {
        id: id.to_string(),
        epoch: format!("{id}-epoch"),
    }
}

/// A binding as the instance named `accepted_by` saved it, registered from `ue`.
fn binding(accepted_by: &str, ue: &str) -> Contact {
    let ue: SocketAddr = ue.parse().expect("a socket address");
    let registrar = Registrar::default();
    registrar.set_instance_identity(identity(accepted_by));
    registrar
        .save_full(
            AOR,
            crate::sip::parser::parse_uri_standalone(&format!(
                "sip:001010000000001@{}:{}",
                ue.ip(),
                ue.port() + 1
            ))
            .expect("a URI"),
            3600,
            1.0,
            "ownership-call".to_string(),
            1,
            Some(ue),
            Some(Transport::Udp),
            None,
            None,
            vec![],
            FlowCapture {
                client_transport: None,
                flow_token: Some("tok-ownership".into()),
                inbound_local_addr: None,
                inbound_connection_id: None,
            },
            Vec::new(),
        )
        .expect("the binding is saved");
    registrar
        .lookup(AOR)
        .into_iter()
        .next()
        .expect("the binding is there")
}

fn reaped(ue: &str) -> (IpAddr, u16) {
    let ue: SocketAddr = ue.parse().expect("a socket address");
    (ue.ip(), ue.port())
}

#[test]
fn a_binding_another_instance_accepted_is_not_this_instances_to_judge() {
    let here = identity("pcscf-2");
    assert!(accepted_here(
        Some(&here),
        &binding("pcscf-2", "192.0.2.10:6100")
    ));
    assert!(!accepted_here(
        Some(&here),
        &binding("pcscf-0", "192.0.2.10:6100")
    ));
}

#[test]
fn without_an_identity_every_binding_is_this_instances() {
    assert!(accepted_here(None, &binding("pcscf-0", "192.0.2.10:6100")));
}

#[test]
fn a_reaped_pair_takes_only_the_binding_it_protected() {
    let here = identity("pcscf-2");
    let contacts = vec![
        // The UE now holding the address, registered through another instance.
        (AOR.to_string(), binding("pcscf-0", "192.0.2.10:6100")),
        // This instance's own binding from the reaped pair's client port.
        (AOR.to_string(), binding("pcscf-2", "192.0.2.10:6100")),
        // This instance's binding on the same address from a newer pair
        // (re-authentication moved the UE to new ports).
        (AOR.to_string(), binding("pcscf-2", "192.0.2.10:6200")),
        // Someone else entirely.
        (AOR.to_string(), binding("pcscf-2", "192.0.2.11:6100")),
    ];

    let victims = reaped_sa_bindings(contacts, &[reaped("192.0.2.10:6100")], Some(&here));

    let chosen: Vec<_> = victims
        .iter()
        .map(|(_, contact, port)| {
            (
                contact.instance_id().map(str::to_owned),
                contact.source_addr,
                *port,
            )
        })
        .collect();
    assert_eq!(
        chosen,
        vec![(
            Some("pcscf-2".to_string()),
            Some("192.0.2.10:6100".parse().expect("an address")),
            6100
        )]
    );
}
