//! Route entries a script hands over, as they go into a `Route`, `Path` or
//! `Record-Route` header (RFC 3261 §20.34, §20.30, RFC 3327 §4).
//!
//! Each of those headers carries `name-addr` values. RFC 3261 §20: "If the URI
//! is not enclosed in angle brackets, any semicolon-delimited parameters are
//! header-parameters, not URI parameters." A script writes a URI and means its
//! parameters, `lr` first among them, to be the URI's, so whatever form it
//! writes is put into angle brackets here before it reaches a message.

use pyo3::prelude::*;

/// The route set a script supplied, one `name-addr` per entry (RFC 3261
/// §20.34), whatever form each was written in
/// ([`route_name_addrs`](crate::sip::headers::route::route_name_addrs)): a
/// `Route` header carries `name-addr` values, and a URI written to it without
/// angle brackets has its parameters, `lr` among them, read as the header's.
/// A `ValueError` names an entry that is not a SIP URI, when the script makes
/// the call rather than when the INVITE is built.
pub(super) fn route_set_from(entries: &[String]) -> PyResult<Vec<String>> {
    let mut route_set = Vec::with_capacity(entries.len());
    for entry in entries {
        route_set.extend(
            crate::sip::headers::route::route_name_addrs(entry)
                .map_err(pyo3::exceptions::PyValueError::new_err)?,
        );
    }
    Ok(route_set)
}

/// Build a loose-route header value (`<uri;lr>`) idempotently.
///
/// Accepts URIs with or without surrounding angle brackets and with or
/// without an existing `;lr` URI parameter, returning the canonical
/// `<uri;lr>` form exactly once.  Required so scripts can pass back
/// values they previously received from siphon (stored Path entries,
/// Service-Route bindings) without producing wire forms like
/// `<<sip:host;lr>;lr>` or `<sip:host;lr;lr>` — both of which break
/// downstream loose-route detection (RFC 3261 §16.4 / §16.12).
pub(super) fn format_loose_route_entry(uri: &str) -> String {
    let trimmed = uri.trim();
    // A full `name-addr` (a display name, or header parameters after the `>`)
    // keeps both around its URI. Anything that does not read as exactly one
    // route entry takes the lenient path below, as it always has.
    if trimmed.contains('<') {
        if let Ok([entry]) = crate::sip::headers::route::route_parts(trimmed).as_deref() {
            return if has_lr_uri_param(entry.uri) {
                entry.to_name_addr()
            } else {
                entry.with_uri(&format!("{};lr", entry.uri))
            };
        }
    }
    let inner = if trimmed.starts_with('<') && trimmed.ends_with('>') {
        trimmed[1..trimmed.len() - 1].trim()
    } else {
        trimmed
    };
    if has_lr_uri_param(inner) {
        format!("<{inner}>")
    } else {
        format!("<{inner};lr>")
    }
}

/// True when `uri` (the contents inside `<...>`) already carries `;lr`
/// as a URI parameter.  RFC 3261 §25.1 allows URI parameters in any
/// order, so this checks every `;`-delimited parameter (not just the
/// last).  The `?headers` portion of a URI is excluded — `lr` after
/// `?` is a URI header named `lr`, not the loose-route parameter.
fn has_lr_uri_param(uri: &str) -> bool {
    let params_section = uri.split('?').next().unwrap_or(uri);
    let mut parts = params_section.split(';');
    parts.next();
    parts.any(|param| {
        let name = param.split('=').next().unwrap_or("").trim();
        name.eq_ignore_ascii_case("lr")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_set_is_one_name_addr_per_entry() {
        let entries = vec![
            "sip:orig@198.51.100.7:6060;lr".to_string(),
            "<sip:198.51.100.8;lr>, Core <sip:198.51.100.9;lr>;hop=3".to_string(),
        ];
        assert_eq!(
            route_set_from(&entries).expect("three SIP URIs"),
            vec![
                "<sip:orig@198.51.100.7:6060;lr>".to_string(),
                "<sip:198.51.100.8;lr>".to_string(),
                "Core <sip:198.51.100.9;lr>;hop=3".to_string(),
            ]
        );
        assert_eq!(
            route_set_from(&[]).expect("no entries"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_entry_that_is_no_sip_uri_is_a_value_error_naming_it() {
        pyo3::Python::initialize();
        let error = route_set_from(&["tel:+15550100".to_string()]).expect_err("no SIP URI");
        Python::attach(|python| {
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            let text = error.value(python).to_string();
            assert!(text.contains("\"tel:+15550100\""), "{text}");
        });
    }

    #[test]
    fn a_loose_route_entry_gains_brackets_and_lr_once() {
        for (given, written) in [
            ("sip:proxy.example.com", "<sip:proxy.example.com;lr>"),
            ("sip:proxy.example.com;lr", "<sip:proxy.example.com;lr>"),
            ("<sip:proxy.example.com>", "<sip:proxy.example.com;lr>"),
            (" <sip:proxy.example.com;LR> ", "<sip:proxy.example.com;LR>"),
            (
                "sip:proxy.example.com;lrid=1",
                "<sip:proxy.example.com;lrid=1;lr>",
            ),
            (
                "Edge <sip:proxy.example.com>;hop=1",
                "Edge <sip:proxy.example.com;lr>;hop=1",
            ),
            // Not one route entry: written as it always was.
            ("proxy.example.com", "<proxy.example.com;lr>"),
        ] {
            assert_eq!(format_loose_route_entry(given), written, "{given}");
        }
    }
}
