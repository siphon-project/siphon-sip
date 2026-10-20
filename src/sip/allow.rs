//! The method set siphon advertises in `Allow` (RFC 3261 §20.5), and the checks
//! a narrowed set (`gateway.groups[].allow_methods`) must pass.
//!
//! `Allow` lists the methods a UA understands. Some peers read it to decide how
//! to do a call transfer: with no `REFER` listed they transfer the call
//! themselves instead of handing siphon a REFER. So an operator may want a
//! smaller set toward one peer than the full [`SUPPORTED_METHODS`]. A smaller
//! set is only ever a subset of what siphon implements, and never one a peer
//! could not finish a call with.

use super::SUPPORTED_METHODS;

/// Methods every advertised set keeps: without them a peer cannot set up,
/// acknowledge, cancel or end a call.
pub const REQUIRED_METHODS: &[&str] = &["INVITE", "ACK", "CANCEL", "BYE"];

/// Is `method` one siphon implements, as [`SUPPORTED_METHODS`] lists it?
///
/// Compared case-sensitively: the method is a case-sensitive token (RFC 3261
/// §7.1), so `Bye` is not a method siphon implements.
pub fn is_implemented_method(method: &str) -> bool {
    SUPPORTED_METHODS
        .split(',')
        .any(|supported| supported.trim() == method)
}

/// An RFC 3261 §25.1 `token`, what a `Method` is made of.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        })
}

/// Check a configured method list and render it as an `Allow` value, in the
/// order it was written.
///
/// Refused, naming the first offending entry: an entry that is not a method
/// token, a method siphon does not implement (`Allow` must not advertise what
/// siphon cannot do), a method listed twice, and a list missing any of
/// [`REQUIRED_METHODS`].
pub fn render_allow_methods(methods: &[String]) -> Result<String, String> {
    for (index, method) in methods.iter().enumerate() {
        if !is_token(method) {
            return Err(format!("{method:?} is not a SIP method token"));
        }
        if !is_implemented_method(method) {
            return Err(format!(
                "{method} is not a method siphon implements (methods are case-sensitive); \
                 the methods it can advertise are {SUPPORTED_METHODS}"
            ));
        }
        if methods[..index].contains(method) {
            return Err(format!("{method} is listed twice"));
        }
    }
    let missing: Vec<&str> = REQUIRED_METHODS
        .iter()
        .copied()
        .filter(|required| !methods.iter().any(|method| method == required))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "must list {} so a peer can set up and end a call; missing {}",
            REQUIRED_METHODS.join(", "),
            missing.join(", ")
        ));
    }
    Ok(methods.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(methods: &[&str]) -> Vec<String> {
        methods.iter().map(|method| method.to_string()).collect()
    }

    #[test]
    fn a_subset_without_refer_renders_in_written_order() {
        assert_eq!(
            render_allow_methods(&list(&[
                "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "PRACK", "UPDATE"
            ])),
            Ok("INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK, UPDATE".to_string())
        );
    }

    #[test]
    fn the_full_supported_set_is_accepted_and_renders_identically() {
        let full: Vec<String> = SUPPORTED_METHODS
            .split(',')
            .map(|method| method.trim().to_string())
            .collect();
        assert_eq!(
            render_allow_methods(&full),
            Ok(SUPPORTED_METHODS.to_string())
        );
    }

    #[test]
    fn each_required_method_is_refused_when_missing() {
        for missing in REQUIRED_METHODS {
            let methods: Vec<String> = REQUIRED_METHODS
                .iter()
                .filter(|method| *method != missing)
                .map(|method| method.to_string())
                .collect();
            let error = render_allow_methods(&methods).expect_err("a required method is missing");
            assert!(error.contains(&format!("missing {missing}")), "{error}");
        }
    }

    #[test]
    fn an_empty_list_is_refused() {
        let error = render_allow_methods(&[]).expect_err("an empty list");
        assert!(
            error.contains("missing INVITE, ACK, CANCEL, BYE"),
            "{error}"
        );
    }

    #[test]
    fn a_method_siphon_does_not_implement_is_refused() {
        let error = render_allow_methods(&list(&["INVITE", "ACK", "CANCEL", "BYE", "REGISTER"]))
            .expect_err("REGISTER is not advertised");
        assert!(
            error.starts_with("REGISTER is not a method siphon implements"),
            "{error}"
        );
    }

    #[test]
    fn a_method_in_the_wrong_case_is_refused() {
        let error = render_allow_methods(&list(&["INVITE", "ACK", "CANCEL", "bye"]))
            .expect_err("methods are case-sensitive");
        assert!(
            error.starts_with("bye is not a method siphon implements"),
            "{error}"
        );
    }

    #[test]
    fn a_non_token_is_refused() {
        for bad in ["", "IN VITE", "INVITE,ACK", "REFER;x"] {
            let error = render_allow_methods(&list(&["INVITE", "ACK", "CANCEL", "BYE", bad]))
                .expect_err("not a token");
            assert!(
                error.contains("is not a SIP method token"),
                "{bad:?}: {error}"
            );
        }
    }

    #[test]
    fn a_duplicate_is_refused() {
        let error = render_allow_methods(&list(&["INVITE", "ACK", "CANCEL", "BYE", "ACK"]))
            .expect_err("ACK twice");
        assert_eq!(error, "ACK is listed twice");
    }

    #[test]
    fn implemented_methods_are_matched_case_sensitively() {
        assert!(is_implemented_method("REFER"));
        assert!(!is_implemented_method("refer"));
        assert!(!is_implemented_method("REGISTER"));
    }
}
