//! `registrar.save()` answering the REGISTERs the registrar refuses, seen from
//! a script and from the metrics.
//!
//! A refusal is the registrar applying its own policy, not a script failing, so
//! it must count under `siphon_registrar_refusals_total{reason}` and leave
//! `siphon_script_errors_total` alone. These counters are process-global; this
//! binary has no other test that refuses a REGISTER or raises in a handler, so
//! exact deltas are safe here.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::script::api::registrar::PyRegistrar;
use siphon::script::api::request::PyRequest;
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::message::Method;
use siphon::sip::uri::SipUri;

const AOR: &str = "sip:001010000000001@ims.example.com";
/// The only public identity of an implicit set whose primary is not a safe
/// registrar storage key.
const UNSAFE_ALIAS: &str = "sip:001010000000999@ims.example.com";

fn register(aor: &str, contact: &str, expires: &str) -> PyRequest {
    let message = SipMessageBuilder::new()
        .request(Method::Register, SipUri::new("ims.example.com".to_string()))
        .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-refusal".to_string())
        .to(format!("<{aor}>"))
        .from(format!("<{aor}>;tag=refusal"))
        .call_id("refusal@192.0.2.10".to_string())
        .cseq("1 REGISTER".to_string())
        .header("Contact", contact.to_string())
        .header("Expires", expires.to_string())
        .content_length(0)
        .build()
        .unwrap();
    PyRequest::new(
        Arc::new(Mutex::new(message)),
        "udp".to_string(),
        "192.0.2.10".to_string(),
        5060,
    )
}

fn device(host: &str, instance: char) -> String {
    format!(
        "<sip:001010000000001@{host}:5060>;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-00000000000{instance}>\""
    )
}

#[test]
fn refused_registers_count_as_refusals_not_as_script_errors() {
    siphon::metrics::init().unwrap();
    let metrics = siphon::metrics::metrics().unwrap();
    let refusals = |reason: &str| {
        metrics
            .registrar_refusals_total
            .with_label_values(&[reason])
            .get()
    };
    let script_errors_before = metrics.script_errors_total.get();
    let too_many_before = refusals("too_many_contacts");
    let too_brief_before = refusals("interval_too_brief");
    let invalid_before = refusals("invalid_aor");

    let registrar = Arc::new(Registrar::new(RegistrarConfig {
        max_contacts: 1,
        min_expires: 60,
        ..Default::default()
    }));
    registrar.set_associated_uris(
        "sip:unsafe\u{1}key@ims.example.com",
        vec![UNSAFE_ALIAS.to_string()],
    );

    Python::initialize();
    Python::attach(|python| {
        let namespace = Py::new(python, PyRegistrar::new(Arc::clone(&registrar))).unwrap();
        let save = |request: PyRequest| -> bool {
            let request = Py::new(python, request).unwrap();
            namespace
                .bind(python)
                .call_method1("save", (request,))
                .unwrap_or_else(|_| panic!("registrar.save() must answer a refusal, not raise"))
                .extract()
                .unwrap()
        };

        assert!(save(register(AOR, &device("192.0.2.10", 'a'), "3600")));
        assert!(!save(register(AOR, &device("192.0.2.11", 'b'), "3600")));
        assert!(!save(register(AOR, &device("192.0.2.11", 'b'), "30")));
        assert!(!save(register(
            UNSAFE_ALIAS,
            &device("192.0.2.12", 'c'),
            "3600"
        )));
    });

    assert_eq!(refusals("too_many_contacts") - too_many_before, 1);
    assert_eq!(refusals("interval_too_brief") - too_brief_before, 1);
    assert_eq!(refusals("invalid_aor") - invalid_before, 1);
    assert_eq!(
        metrics.script_errors_total.get(),
        script_errors_before,
        "a refused REGISTER is not a script error"
    );
}
