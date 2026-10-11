//! `auth.set_integrity_protected`: the P-CSCF side of the `integrity-protected`
//! Authorization parameter for the mechanisms other than IMS-AKA over IPsec,
//! which `auth.stamp_integrity_protected` decides from the security
//! association.

use pyo3::prelude::*;

use crate::script::api::ipsec::{
    auth_scheme_and_params, split_top_level_commas, with_integrity_protected,
};
use crate::script::api::request::PyRequest;

/// The values of TS 24.229 table 7.2A.2.
const VALUES: [&str; 8] = [
    "yes",
    "no",
    "tls-pending",
    "tls-yes",
    "ip-assoc-pending",
    "ip-assoc-yes",
    "auth-done",
    "tls-connected",
];

/// `value` without any `integrity-protected` parameter, every other parameter
/// kept byte for byte.
fn without_integrity_protected(value: &str) -> String {
    let (scheme, params) = auth_scheme_and_params(value);
    let kept: Vec<&str> = split_top_level_commas(params)
        .into_iter()
        .map(str::trim)
        .filter(|token| {
            let name = token.split_once('=').map_or(*token, |(name, _)| name);
            !token.is_empty() && !name.trim().eq_ignore_ascii_case("integrity-protected")
        })
        .collect();
    if kept.is_empty() {
        scheme.to_string()
    } else {
        format!("{scheme} {}", kept.join(", "))
    }
}

/// Rewrite every Authorization header of `request` to carry `protected` as
/// its only `integrity-protected`, or none with `None`. Returns whether there
/// was a header to rewrite.
pub(super) fn set_integrity_protected(
    request: &PyRequest,
    protected: Option<&str>,
) -> PyResult<bool> {
    if let Some(protected) = protected {
        if !VALUES.contains(&protected) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "integrity-protected is one of {}, not \"{protected}\"",
                VALUES.join(", ")
            )));
        }
    }
    let message = request.message();
    let mut message = message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })?;
    let Some(values) = message
        .headers
        .get_all("Authorization")
        .filter(|values| !values.is_empty())
        .cloned()
    else {
        return Ok(false);
    };
    let rewritten = values
        .iter()
        .map(|value| match protected {
            Some(protected) => with_integrity_protected(value, protected),
            None => without_integrity_protected(value),
        })
        .collect();
    message.headers.set_all("Authorization", rewritten);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::script::api::ipsec::auth_header_param;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    fn register(authorization: &[&str]) -> PyRequest {
        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, SipUri::new("example.org".to_string()))
            .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-ip".to_string())
            .to("<sip:alice@example.org>".to_string())
            .from("<sip:alice@example.org>;tag=ip".to_string())
            .call_id("integrity@192.0.2.10".to_string())
            .cseq("1 REGISTER".to_string())
            .content_length(0);
        for value in authorization {
            builder = builder.header("Authorization", (*value).to_string());
        }
        PyRequest::new(
            Arc::new(Mutex::new(builder.build().unwrap())),
            "udp".to_string(),
            "192.0.2.10".to_string(),
            5060,
        )
    }

    fn authorization(request: &PyRequest) -> Vec<String> {
        let message = request.message();
        let message = message.lock().unwrap();
        message
            .headers
            .get_all("Authorization")
            .cloned()
            .unwrap_or_default()
    }

    /// TS 24.229 table 7.2A.2 lists eight values, and clause 5.2.2.1 step 4B
    /// has the P-CSCF remove what the UE sent.
    #[test]
    fn every_listed_value_replaces_what_the_ue_sent() {
        for value in VALUES {
            let request = register(&[
                "Digest username=\"alice@example.org\", realm=\"example.org\", \
                 integrity-protected=\"auth-done\", nonce=\"n,1\", response=\"r\"",
            ]);

            assert!(set_integrity_protected(&request, Some(value)).unwrap());

            let header = &authorization(&request)[0];
            assert_eq!(header.matches("integrity-protected").count(), 1, "{header}");
            assert_eq!(
                auth_header_param(header, "integrity-protected").as_deref(),
                Some(value)
            );
            // The rest of the header is untouched, quoted comma included.
            assert_eq!(auth_header_param(header, "nonce").as_deref(), Some("n,1"));
            assert_eq!(
                auth_header_param(header, "username").as_deref(),
                Some("alice@example.org")
            );
        }
    }

    /// TS 24.229 clause 5.2.2.3 step 1 a): a first REGISTER under SIP Digest
    /// goes on without the parameter.
    #[test]
    fn none_removes_the_parameter_and_nothing_else() {
        let request = register(&[
            "Digest username=\"alice@example.org\", integrity-protected=yes, realm=\"example.org\"",
            "Digest Integrity-Protected=\"tls-yes\"",
        ]);

        assert!(set_integrity_protected(&request, None).unwrap());

        assert_eq!(
            authorization(&request),
            vec![
                "Digest username=\"alice@example.org\", realm=\"example.org\"".to_string(),
                "Digest".to_string(),
            ]
        );
    }

    #[test]
    fn a_request_without_authorization_is_left_alone() {
        let request = register(&[]);

        assert!(!set_integrity_protected(&request, Some("tls-pending")).unwrap());

        assert!(authorization(&request).is_empty());
    }

    #[test]
    fn a_value_the_table_does_not_list_is_refused() {
        pyo3::Python::initialize();
        let request = register(&["Digest username=\"alice@example.org\""]);

        let error = set_integrity_protected(&request, Some("maybe")).unwrap_err();

        assert!(error.to_string().contains("maybe"), "{error}");
        assert_eq!(
            authorization(&request),
            vec!["Digest username=\"alice@example.org\"".to_string()]
        );
    }
}
