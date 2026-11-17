//! The `headers=` of `handle.notify()` / `handle.terminate()`: headers a
//! script adds to a NOTIFY siphon sends as the notifier of a subscription.
//!
//! An event package or a profile of one puts headers of its own on a NOTIFY:
//! a conference focus or an application server asserts the identity the
//! notification is sent under (`P-Asserted-Identity`, RFC 3325 §9.1) and the
//! service it belongs to (`P-Asserted-Service`, RFC 6050 §4.2). Those go out
//! as written, in the order the mapping gives them (the serializer still
//! writes a `Content-*` one with the others of its kind, last, as on every
//! message: the order of differently named headers carries no meaning, RFC
//! 3261 §7.3.1). What a script cannot
//! touch is what makes the NOTIFY a request inside the subscription's dialog
//! (RFC 3261 §12.2.1.1) and a notification of that subscription (RFC 6665
//! §4.2.1.2): a script value for any of those would send the NOTIFY outside
//! the dialog it belongs to, so it is refused, never dropped quietly.

use pyo3::prelude::*;

/// The headers siphon owns on a NOTIFY it sends inside a subscription, and why.
///
/// Compared with [`crate::sip::headers::same_header_name`], so a compact form
/// (`o` for `Event`, `i` for `Call-ID`) is refused like its long name.
const NOTIFIER_OWNED: &[(&str, &str)] = &[
    ("Via", "names this transaction (RFC 3261 §8.1.1.7)"),
    (
        "From",
        "is the dialog's local URI and tag (RFC 3261 §12.2.1.1)",
    ),
    (
        "To",
        "is the dialog's remote URI and tag (RFC 3261 §12.2.1.1)",
    ),
    ("Call-ID", "is the dialog's (RFC 3261 §12.2.1.1)"),
    (
        "CSeq",
        "is numbered by siphon within the dialog (RFC 3261 §12.2.1.1)",
    ),
    (
        "Contact",
        "is the dialog's target siphon advertises (RFC 3261 §12.2.1.1)",
    ),
    ("Route", "is the dialog's route set (RFC 3261 §12.2.1.1)"),
    ("Max-Forwards", "is managed by siphon (RFC 3261 §8.1.1.6)"),
    ("Content-Length", "is computed from the body"),
    (
        "Content-Type",
        "goes with the body: pass content_type= instead",
    ),
    (
        "Event",
        "is the subscription's event package (RFC 6665 §4.2.1.2)",
    ),
    (
        "Subscription-State",
        "is the subscription's state (RFC 6665 §4.2.1.2): pass state= or reason= instead",
    ),
];

/// Why siphon refuses `name` on a NOTIFY it sends inside a subscription, or
/// `None` when a script may set it.
fn notifier_owned_reason(name: &str) -> Option<&'static str> {
    NOTIFIER_OWNED
        .iter()
        .find(|(owned, _)| crate::sip::headers::same_header_name(owned, name))
        .map(|(_, reason)| *reason)
}

/// Check the headers a script asked to add to a NOTIFY.
///
/// `Err` names the first header refused and why: one siphon owns, a name that
/// is not a header field name, or a value carrying a line break or NUL.
pub(crate) fn validate(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        crate::b2bua::uas_headers::check_syntax(name, value)?;
        if let Some(reason) = notifier_owned_reason(name) {
            return Err(format!(
                "{name} cannot be set by a script on a NOTIFY of a subscription: it {reason}"
            ));
        }
    }
    Ok(())
}

/// The `headers=` of `handle.notify()` / `handle.terminate()`, in the order
/// the mapping gives them, checked with [`validate`]. A refused header raises
/// `ValueError` naming `method` and the header, and a name or value that is
/// not a `str` raises `TypeError`: nothing is sent either way.
pub(super) fn from_script(
    method: &str,
    headers: Option<&Bound<'_, pyo3::types::PyDict>>,
) -> PyResult<Vec<(String, String)>> {
    let Some(headers) = headers else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        let (Ok(name), Ok(value)) = (name.extract::<String>(), value.extract::<String>()) else {
            return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "{method}(headers=…) takes a mapping of str header names to str values"
            )));
        };
        pairs.push((name, value));
    }
    validate(&pairs).map_err(|refusal| {
        pyo3::exceptions::PyValueError::new_err(format!("{method}(headers=…): {refusal}"))
    })?;
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn identity_and_service_headers_are_allowed() {
        assert_eq!(
            validate(&headers(&[
                ("P-Asserted-Identity", "<sip:group@example.com>"),
                (
                    "P-Asserted-Service",
                    "urn:urn-7:3gpp-service.ims.icsi.mcptt"
                ),
                ("Require", "eventlist"),
                ("X-Anything", ""),
            ])),
            Ok(())
        );
    }

    #[test]
    fn every_header_siphon_owns_is_refused_by_name() {
        for owned in [
            "Via",
            "From",
            "To",
            "Call-ID",
            "CSeq",
            "Contact",
            "Route",
            "Max-Forwards",
            "Content-Length",
            "Content-Type",
            "Event",
            "Subscription-State",
        ] {
            let refusal = validate(&headers(&[("X-Before", "kept"), (owned, "value")]))
                .expect_err("an owned header is refused");
            assert!(
                refusal.starts_with(&format!("{owned} cannot be set")),
                "the refusal names {owned}, got {refusal:?}"
            );
        }
    }

    #[test]
    fn an_owned_header_is_refused_in_any_case_and_in_its_compact_form() {
        for spelled in [
            "event",
            "SUBSCRIPTION-STATE",
            "call-id",
            "v",
            "f",
            "t",
            "i",
            "m",
            "l",
            "c",
            "o",
        ] {
            assert!(
                validate(&headers(&[(spelled, "value")])).is_err(),
                "{spelled} names a header siphon owns"
            );
        }
    }

    #[test]
    fn a_name_that_is_no_header_name_or_a_value_with_a_line_break_is_refused() {
        assert!(validate(&headers(&[("X Bad", "value")])).is_err());
        assert!(validate(&headers(&[("", "value")])).is_err());
        let refusal = validate(&headers(&[("X-Smuggle", "one\r\nEvent: other")]))
            .expect_err("a line break is refused");
        assert!(refusal.contains("X-Smuggle"), "got {refusal:?}");
    }

    #[test]
    fn the_mapping_order_is_kept_and_no_mapping_is_no_headers() {
        Python::initialize();
        Python::attach(|python| {
            assert_eq!(from_script("notify", None).unwrap(), Vec::new());
            let mapping = PyDict::new(python);
            mapping
                .set_item("P-Asserted-Service", "urn:example")
                .unwrap();
            mapping
                .set_item("P-Asserted-Identity", "<sip:a@example.com>")
                .unwrap();
            assert_eq!(
                from_script("notify", Some(&mapping)).unwrap(),
                headers(&[
                    ("P-Asserted-Service", "urn:example"),
                    ("P-Asserted-Identity", "<sip:a@example.com>"),
                ])
            );
        });
    }

    #[test]
    fn a_name_or_value_that_is_not_a_str_raises_type_error() {
        Python::initialize();
        Python::attach(|python| {
            let number_value = PyDict::new(python);
            number_value.set_item("X-Count", 5).unwrap();
            let number_name = PyDict::new(python);
            number_name.set_item(5, "value").unwrap();
            let bytes_value = PyDict::new(python);
            bytes_value
                .set_item("X-Raw", pyo3::types::PyBytes::new(python, b"raw"))
                .unwrap();
            for mapping in [number_value, number_name, bytes_value] {
                let error = from_script("terminate", Some(&mapping)).unwrap_err();
                assert!(
                    error.is_instance_of::<pyo3::exceptions::PyTypeError>(python),
                    "got {error}"
                );
                assert!(error.to_string().contains("terminate(headers=…)"));
            }
        });
    }

    #[test]
    fn an_owned_header_raises_value_error_naming_the_method_and_the_header() {
        Python::initialize();
        Python::attach(|python| {
            let mapping = PyDict::new(python);
            mapping.set_item("Subscription-State", "active").unwrap();
            let error = from_script("notify", Some(&mapping)).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            let text = error.to_string();
            assert!(
                text.contains("notify(headers=…)") && text.contains("Subscription-State"),
                "got {text}"
            );
        });
    }
}
