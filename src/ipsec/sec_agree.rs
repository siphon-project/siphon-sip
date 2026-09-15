//! RFC 3329 security agreement on a request siphon receives over an IPsec
//! security association (3GPP TS 33.203): whether the request requires it,
//! whether its `Security-Verify` mirrors the association it arrived over, and
//! what of the agreement must not leave the hop it was made on.

use super::{parse_security_client, SaProtocol, SecurityAssociationPair, SecurityClient};
use crate::sip::headers::SipHeaders;

/// The option tag of the security agreement (RFC 3329 §6.5).
const OPTION_TAG: &str = "sec-agree";

/// Whether `headers` require the security agreement: `sec-agree` in `Require`
/// or in `Proxy-Require`, both of which RFC 3329 §2.3.1 holds a server to.
pub fn requires_sec_agree(headers: &SipHeaders) -> bool {
    ["Require", "Proxy-Require"]
        .iter()
        .any(|name| lists_option_tag(headers, name, OPTION_TAG))
}

fn lists_option_tag(headers: &SipHeaders, name: &str, tag: &str) -> bool {
    headers
        .get_all(name)
        .into_iter()
        .flatten()
        .flat_map(|value| value.split(','))
        .any(|listed| listed.trim().eq_ignore_ascii_case(tag))
}

/// Why a request that requires `sec-agree` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecAgreeRefusal {
    /// It did not arrive over a security association, "an unprotected request"
    /// (RFC 3329 §2.3.1).
    Unprotected,
    /// It arrived over one but carries no `Security-Verify`, which every request
    /// after the agreement MUST carry (RFC 3329 §2.3.1).
    MissingVerify,
    /// Its `Security-Verify` does not mirror the `Security-Server` the
    /// association was set up from: the list was modified (RFC 3329 §2.3.1).
    VerifyMismatch,
}

/// What RFC 3329 §2.3.1 makes of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecAgreeVerdict {
    /// It does not require `sec-agree`, so there is nothing to verify.
    NotRequired,
    /// It requires `sec-agree` and mirrors the association it arrived over.
    Verified,
    /// It requires `sec-agree` and is answered `494 Security Agreement
    /// Required`.
    Refused(SecAgreeRefusal),
}

/// Verify a request against the security association it arrived over, `sa`
/// (`None` when it arrived unprotected).
///
/// RFC 3329 §2.3.1: requests after the agreement "MUST contain a
/// Security-Verify header field that mirrors the server's list received
/// previously in the Security-Server header field", and the server "MUST check
/// that the security mechanisms listed in the Security-Verify header field of
/// incoming requests correspond to its static list". siphon does not keep the
/// `Security-Server` line a script put on the 401, only the association it set
/// up from it, so a `Security-Verify` passes when one of its entries names that
/// association: `ipsec-3gpp` with its integrity and encryption algorithms (an
/// absent `ealg` meaning `null`) and the P-CSCF's SPIs and protected ports.
/// Parameters the association does not record (`q`, `prot`, `mod`) are not
/// compared.
pub fn verify_sec_agree(
    headers: &SipHeaders,
    sa: Option<&SecurityAssociationPair>,
) -> SecAgreeVerdict {
    if !requires_sec_agree(headers) {
        return SecAgreeVerdict::NotRequired;
    }
    let Some(sa) = sa else {
        return SecAgreeVerdict::Refused(SecAgreeRefusal::Unprotected);
    };
    let Some(lines) = headers.get_all("Security-Verify") else {
        return SecAgreeVerdict::Refused(SecAgreeRefusal::MissingVerify);
    };
    let mirrored = lines
        .iter()
        .flat_map(|line| line.split(','))
        .filter_map(parse_security_client)
        .any(|entry| mirrors(&entry, sa));
    if mirrored {
        SecAgreeVerdict::Verified
    } else {
        SecAgreeVerdict::Refused(SecAgreeRefusal::VerifyMismatch)
    }
}

/// Whether one `Security-Verify` entry names `sa`.
fn mirrors(entry: &SecurityClient, sa: &SecurityAssociationPair) -> bool {
    entry.mechanism.eq_ignore_ascii_case("ipsec-3gpp")
        && entry
            .algorithm
            .eq_ignore_ascii_case(sa.aalg.sec_agree_name())
        && entry
            .ealg
            .as_deref()
            .unwrap_or("null")
            .eq_ignore_ascii_case(sa.ealg.sec_agree_name())
        && entry.spi_c == sa.spi_pc
        && entry.spi_s == sa.spi_ps
        && entry.port_c == sa.pcscf_port_c
        && entry.port_s == sa.pcscf_port_s
}

/// The `Security-Server` value `sa` stands for, which a 494 refusing a request
/// that arrived over it carries: "the server's unmodified list of supported
/// security mechanisms" (RFC 3329 §2.3.1). Spelled the way a script builds the
/// header from `SecurityServerParams`, with `protocol=tcp` only on an
/// association pinned to TCP.
pub fn security_server_value(sa: &SecurityAssociationPair) -> String {
    let mut value = format!(
        "ipsec-3gpp; alg={}; ealg={}; spi-c={}; spi-s={}; port-c={}; port-s={}",
        sa.aalg.sec_agree_name(),
        sa.ealg.sec_agree_name(),
        sa.spi_pc,
        sa.spi_ps,
        sa.pcscf_port_c,
        sa.pcscf_port_s,
    );
    if sa.protocol == SaProtocol::Tcp {
        value.push_str("; protocol=tcp");
    }
    value
}

/// Take the security agreement of the hop a request arrived on off the request
/// siphon sends on to the next one.
///
/// `sec-agree` comes out of `Require` and `Proxy-Require`, each removed when no
/// value remains: RFC 3329 §2.3.1 has the server "remove the "sec-agree" value
/// from both the Require and Proxy-Require header fields, and then remove the
/// header fields if no values remain". `Security-Verify` and `Security-Client`
/// describe that hop's association and go too, as siphon's in-dialog forwarding
/// already drops them. A header `keep` names is left as it is: one a script set
/// for an agreement of the next hop's own.
pub fn strip_sec_agree(headers: &mut SipHeaders, keep: impl Fn(&str) -> bool) {
    for name in ["Require", "Proxy-Require"] {
        if !keep(name) {
            remove_option_tag(headers, name, OPTION_TAG);
        }
    }
    for name in ["Security-Verify", "Security-Client"] {
        if !keep(name) {
            headers.remove(name);
        }
    }
}

/// Remove `tag` from every `name` line, dropping the header when nothing is
/// left. A header that never listed the tag is not touched.
fn remove_option_tag(headers: &mut SipHeaders, name: &str, tag: &str) {
    if !lists_option_tag(headers, name, tag) {
        return;
    }
    let Some(values) = headers.get_all(name).cloned() else {
        return;
    };
    let remaining: Vec<String> = values
        .iter()
        .filter_map(|value| {
            let tags: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|listed| !listed.is_empty() && !listed.eq_ignore_ascii_case(tag))
                .collect();
            (!tags.is_empty()).then(|| tags.join(", "))
        })
        .collect();
    if remaining.is_empty() {
        headers.remove(name);
    } else {
        headers.set_all(name, remaining);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm, SaRole};

    /// The association a P-CSCF at 192.0.2.10 set up for a UE at 198.51.100.20:
    /// SPIs 10000/10001 and protected ports 5064/5066 on its side,
    /// HMAC-SHA-1-96 with NULL encryption.
    fn association(protocol: SaProtocol) -> SecurityAssociationPair {
        SecurityAssociationPair {
            ue_addr: "198.51.100.20".parse().expect("a literal address"),
            pcscf_addr: "192.0.2.10".parse().expect("a literal address"),
            ue_port_c: 50001,
            ue_port_s: 50002,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 1000,
            spi_us: 1001,
            spi_pc: 10000,
            spi_ps: 10001,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
            hard_lifetime_secs: None,
            protocol,
            expires_at: std::time::Instant::now(),
            created_at: std::time::Instant::now(),
            role: SaRole::PCscf,
            impi: None,
        }
    }

    fn headers(lines: &[(&str, &str)]) -> SipHeaders {
        let mut headers = SipHeaders::new();
        for (name, value) in lines {
            headers.add(name, value.to_string());
        }
        headers
    }

    /// The Security-Verify a UE sends back for [`association`].
    const VERIFY: &str = "ipsec-3gpp;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5064;port-s=5066;alg=hmac-sha-1-96;ealg=null";

    #[test]
    fn sec_agree_is_required_by_require_or_proxy_require_only() {
        assert!(requires_sec_agree(&headers(&[("Require", "SEC-AGREE")])));
        assert!(requires_sec_agree(&headers(&[(
            "Proxy-Require",
            "precondition, sec-agree"
        )])));
        assert!(!requires_sec_agree(&headers(&[("Supported", "sec-agree")])));
        assert!(!requires_sec_agree(&headers(&[(
            "Require",
            "precondition"
        )])));
    }

    #[test]
    fn a_request_that_does_not_require_it_is_not_verified() {
        assert_eq!(
            verify_sec_agree(&headers(&[("Security-Verify", VERIFY)]), None),
            SecAgreeVerdict::NotRequired
        );
    }

    #[test]
    fn an_unprotected_request_that_requires_it_is_refused() {
        let request = headers(&[("Require", "sec-agree"), ("Security-Verify", VERIFY)]);
        assert_eq!(
            verify_sec_agree(&request, None),
            SecAgreeVerdict::Refused(SecAgreeRefusal::Unprotected)
        );
    }

    #[test]
    fn a_protected_request_without_security_verify_is_refused() {
        let request = headers(&[("Proxy-Require", "sec-agree")]);
        assert_eq!(
            verify_sec_agree(&request, Some(&association(SaProtocol::Any))),
            SecAgreeVerdict::Refused(SecAgreeRefusal::MissingVerify)
        );
    }

    #[test]
    fn a_security_verify_that_mirrors_the_association_is_verified() {
        let sa = association(SaProtocol::Any);
        for verify in [
            VERIFY,
            // Spaced, reordered, with a q-value and no ealg (NULL).
            "ipsec-3gpp; q=0.1; alg=HMAC-SHA-1-96; spi-s=10001; spi-c=10000; port-s=5066; port-c=5064",
            // The mechanism in use among others the server listed.
            "ipsec-3gpp;alg=hmac-md5-96;spi-c=10000;spi-s=10001;port-c=5064;port-s=5066, ipsec-3gpp;alg=hmac-sha-1-96;spi-c=10000;spi-s=10001;port-c=5064;port-s=5066",
        ] {
            let request = headers(&[("Require", "sec-agree"), ("Security-Verify", verify)]);
            assert_eq!(
                verify_sec_agree(&request, Some(&sa)),
                SecAgreeVerdict::Verified,
                "{verify}"
            );
        }
    }

    #[test]
    fn a_modified_security_verify_is_refused() {
        let sa = association(SaProtocol::Any);
        for verify in [
            VERIFY.replace("spi-c=10000", "spi-c=10002"),
            VERIFY.replace("spi-s=10001", "spi-s=10003"),
            VERIFY.replace("port-c=5064", "port-c=5070"),
            VERIFY.replace("port-s=5066", "port-s=5072"),
            VERIFY.replace("alg=hmac-sha-1-96", "alg=hmac-md5-96"),
            VERIFY.replace("ealg=null", "ealg=aes-cbc"),
            VERIFY.replace("ipsec-3gpp", "tls"),
            "not a security mechanism".to_string(),
        ] {
            let request = headers(&[("Require", "sec-agree"), ("Security-Verify", &verify)]);
            assert_eq!(
                verify_sec_agree(&request, Some(&sa)),
                SecAgreeVerdict::Refused(SecAgreeRefusal::VerifyMismatch),
                "{verify}"
            );
        }
    }

    #[test]
    fn the_security_server_value_names_the_association() {
        assert_eq!(
            security_server_value(&association(SaProtocol::Any)),
            "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=10000; spi-s=10001; port-c=5064; port-s=5066"
        );
        assert!(security_server_value(&association(SaProtocol::Tcp)).ends_with("; protocol=tcp"));
        // What siphon would send is what it accepts back.
        let request = headers(&[
            ("Require", "sec-agree"),
            (
                "Security-Verify",
                &security_server_value(&association(SaProtocol::Any)),
            ),
        ]);
        assert_eq!(
            verify_sec_agree(&request, Some(&association(SaProtocol::Any))),
            SecAgreeVerdict::Verified
        );
    }

    #[test]
    fn strip_takes_the_agreement_off_and_leaves_the_rest() {
        let mut request = headers(&[
            ("Require", "sec-agree, precondition"),
            ("Require", "sec-agree"),
            ("Proxy-Require", "sec-agree"),
            ("Security-Verify", VERIFY),
            ("Security-Client", VERIFY),
            ("Supported", "sec-agree, 100rel"),
        ]);
        strip_sec_agree(&mut request, |_| false);
        assert_eq!(
            request.get_all("Require"),
            Some(&vec!["precondition".to_string()])
        );
        assert!(!request.has("Proxy-Require"));
        assert!(!request.has("Security-Verify"));
        assert!(!request.has("Security-Client"));
        // Supported is a statement of capability, not the agreement.
        assert_eq!(
            request.get("Supported").map(String::as_str),
            Some("sec-agree, 100rel")
        );
    }

    #[test]
    fn strip_leaves_a_header_it_is_told_to_keep_and_one_without_the_tag() {
        let mut request = headers(&[
            ("Proxy-Require", "sec-agree"),
            ("Security-Verify", VERIFY),
            ("Require", "precondition"),
        ]);
        strip_sec_agree(&mut request, |name| {
            name == "Proxy-Require" || name == "Security-Verify"
        });
        assert_eq!(
            request.get("Proxy-Require").map(String::as_str),
            Some("sec-agree")
        );
        assert!(request.has("Security-Verify"));
        assert_eq!(
            request.get("Require").map(String::as_str),
            Some("precondition")
        );
    }
}
