//! RFC 3329 security agreement on a request siphon receives over an IPsec
//! security association (3GPP TS 33.203): whether the request requires it,
//! whether its `Security-Verify` mirrors the association it arrived over, and
//! what of the agreement must not leave the hop it was made on.

use std::net::IpAddr;

use super::{
    parse_security_client, EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager,
    SecurityAssociationPair, SecurityClient,
};
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
/// incoming requests correspond to its static list".
///
/// That list is the `Security-Server` recorded on the association from the 401
/// siphon relayed for the REGISTER that set it up, and the `Security-Verify` must
/// match it parameter for parameter, `q`, `prot` and `mod` included, as
/// [`Mechanism`] reads both. An association with nothing recorded (installed
/// before siphon recorded the value, or from a 401 siphon did not relay) falls
/// back to what it holds: one entry must name `ipsec-3gpp` with its integrity and
/// encryption algorithms (an absent `ealg` meaning `null`) and the P-CSCF's SPIs
/// and protected ports.
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
    let mirrored = match &sa.security_server {
        Some(recorded) => mirrors_recorded(lines, recorded),
        None => lines
            .iter()
            .flat_map(|line| line.split(','))
            .filter_map(parse_security_client)
            .any(|entry| mirrors(&entry, sa)),
    };
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
/// header from `SecurityServerParams`.
///
/// No transport `protocol=` parameter, on any association. No sec-agree spec
/// defines one: not RFC 3329 §2.2 or its Appendix A, and not TS 33.203 Annex H,
/// whose `mech-parameters` list is closed and whose own `protocol` rule is
/// `prot=ah|esp`. One pair carries UDP and TCP alike (TS 33.203 §6.3, §7.1), so
/// there is no transport for the header to name. A `sa.protocol` pinned to TCP
/// still narrows the kernel XFRM selectors; it just does not show up here.
pub fn security_server_value(sa: &SecurityAssociationPair) -> String {
    format!(
        "ipsec-3gpp; alg={}; ealg={}; spi-c={}; spi-s={}; port-c={}; port-s={}",
        sa.aalg.sec_agree_name(),
        sa.ealg.sec_agree_name(),
        sa.spi_pc,
        sa.spi_ps,
        sa.pcscf_port_c,
        sa.pcscf_port_s,
    )
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

/// The `Security-Server` lines a 494 refusing a request carries, "the server's
/// unmodified list of supported security mechanisms" (RFC 3329 §2.3.1).
///
/// Over an association that is the value recorded from the 401 that set it up
/// ([`IpsecManager::record_security_server`]), or failing that the one built from
/// the association. With no association, the mechanisms siphon supports
/// ([`supported_security_server_values`]).
pub fn refusal_security_server(sa: Option<&SecurityAssociationPair>) -> Vec<String> {
    match sa {
        Some(sa) => vec![sa
            .security_server
            .clone()
            .unwrap_or_else(|| security_server_value(sa))],
        None => supported_security_server_values(),
    }
}

/// The `Security-Server` a 494 to an unprotected request carries: one
/// `ipsec-3gpp` line per transform siphon supports (`Transform` in the script
/// API), with `alg` and `ealg` and nothing else.
///
/// TS 33.203 Annex H makes `spi-c`, `spi-s`, `port-c` and `port-s` mandatory for
/// `ipsec-3gpp`. They are left out on purpose, as a reading of RFC 3329 §2.3.1:
/// the 494 carries the server's list of supported mechanisms, and an unprotected
/// request has no association whose SPIs and ports could be named. The UE gets
/// the full syntax on the 401 to its REGISTER.
pub fn supported_security_server_values() -> Vec<String> {
    const INTEGRITY: [IntegrityAlgorithm; 3] = [
        IntegrityAlgorithm::HmacSha1,
        IntegrityAlgorithm::HmacMd5,
        IntegrityAlgorithm::HmacSha256,
    ];
    // DES-EDE3-CBC is not one of the script API's transforms.
    const ENCRYPTION: [EncryptionAlgorithm; 2] =
        [EncryptionAlgorithm::Null, EncryptionAlgorithm::AesCbc128];
    ENCRYPTION
        .iter()
        .flat_map(|ealg| {
            INTEGRITY.iter().map(move |aalg| {
                format!(
                    "ipsec-3gpp; alg={}; ealg={}",
                    aalg.sec_agree_name(),
                    ealg.sec_agree_name()
                )
            })
        })
        .collect()
}

impl IpsecManager {
    /// Record `value`, the `Security-Server` siphon relays to the UE at `ue_addr`
    /// on a 401 to its REGISTER, on the pair it was built from: that UE's pair
    /// whose P-CSCF SPIs one of its entries names in `spi-c` and `spi-s`. A later
    /// `Security-Verify` over the pair must mirror it ([`verify_sec_agree`]).
    /// Returns whether a pair took it.
    pub fn record_security_server(&self, ue_addr: &IpAddr, value: &str) -> bool {
        let named: Vec<(u32, u32)> = mechanism_list([value])
            .iter()
            .filter_map(|mechanism| Some((mechanism.number("spi-c")?, mechanism.number("spi-s")?)))
            .collect();
        if named.is_empty() {
            return false;
        }
        let mut recorded = false;
        for mut entry in self.associations.iter_mut() {
            let sa = entry.value_mut();
            if sa.ue_addr == *ue_addr && named.contains(&(sa.spi_pc, sa.spi_ps)) {
                sa.security_server = Some(value.to_string());
                recorded = true;
            }
        }
        recorded
    }
}

/// Keep the value recorded on `sa`'s stored pair when `sa` replaces that pair with
/// new keys under the same SPIs, as `PendingSA.refresh()` does: its own copy of
/// the pair predates the 401 that recorded the value, and deleting the stored
/// pair would lose it.
pub fn carry_recorded_security_server(manager: &IpsecManager, sa: &mut SecurityAssociationPair) {
    let stored = manager
        .get_sa(&sa.ue_addr, sa.ue_port_c)
        .filter(|stored| stored.spi_pc == sa.spi_pc && stored.spi_ps == sa.spi_ps);
    if let Some(recorded) = stored.and_then(|stored| stored.security_server) {
        sa.security_server = Some(recorded);
    }
}

/// Whether the `Security-Verify` `lines` mirror `recorded`, the `Security-Server`
/// the association was set up from: the same mechanisms with the same
/// parameters, compared as [`Mechanism`] reads them.
fn mirrors_recorded(lines: &[String], recorded: &str) -> bool {
    mechanism_list(lines.iter().map(String::as_str)) == mechanism_list([recorded])
}

/// One entry of a `Security-Server` or `Security-Verify` list in the form RFC
/// 3329 §2.2's grammar compares it: the mechanism and parameter names without
/// case, values without case unless quoted (RFC 3261 §7.3.1), whitespace around
/// the separators dropped, `q` as a number, and the parameters in a fixed order.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Mechanism {
    name: String,
    parameters: Vec<(String, Option<String>)>,
}

impl Mechanism {
    fn read(entry: &str) -> Mechanism {
        let mut fields = split_outside_quotes(entry, ';').into_iter();
        let name = fields
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let mut parameters: Vec<(String, Option<String>)> = fields
            .filter(|field| !field.trim().is_empty())
            .map(|field| {
                let (name, value) = match field.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (field, None),
                };
                let name = name.trim().to_ascii_lowercase();
                let value = value.map(|value| comparable_value(&name, value.trim()));
                (name, value)
            })
            .collect();
        parameters.sort();
        Mechanism { name, parameters }
    }

    fn number(&self, name: &str) -> Option<u32> {
        self.parameters
            .iter()
            .find(|(parameter, _)| parameter == name)
            .and_then(|(_, value)| value.as_deref()?.parse().ok())
    }
}

/// The mechanisms of every line in `lines`, in a fixed order.
fn mechanism_list<'a>(lines: impl IntoIterator<Item = &'a str>) -> Vec<Mechanism> {
    let mut list: Vec<Mechanism> = lines
        .into_iter()
        .flat_map(|line| split_outside_quotes(line, ','))
        .filter(|entry| !entry.trim().is_empty())
        .map(Mechanism::read)
        .collect();
    list.sort();
    list
}

fn comparable_value(name: &str, value: &str) -> String {
    if value.starts_with('"') {
        return value.to_string();
    }
    if name == "q" {
        if let Ok(q) = value.parse::<f64>() {
            return format!("{q:.3}");
        }
    }
    value.to_ascii_lowercase()
}

/// `text` split on `separator` wherever it is not inside a quoted string.
fn split_outside_quotes(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == separator && !quoted {
            parts.push(&text[start..index]);
            start = index + character.len_utf8();
        }
    }
    parts.push(&text[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm, SaProtocol, SaRole};

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
            security_server: None,
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

    /// No sec-agree spec defines a transport `protocol=` parameter: not RFC
    /// 3329 §2.2 or its Appendix A, and not TS 33.203 Annex H, whose
    /// `mech-parameters` list is closed and whose own `protocol` rule is
    /// `prot=ah|esp`. One pair carries UDP and TCP alike (TS 33.203 §6.3, "all
    /// shared by TCP and UDP"; §7.1, "The transport protocol selector shall
    /// allow UDP and TCP"), so the transport a pair is pinned to is not
    /// something the header has to carry. siphon leaves the parameter off for
    /// every association, a TCP-pinned one included.
    #[test]
    fn the_security_server_value_names_the_association() {
        const VALUE: &str = "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=10000; spi-s=10001; port-c=5064; port-s=5066";
        for protocol in [SaProtocol::Any, SaProtocol::Udp, SaProtocol::Tcp] {
            let value = security_server_value(&association(protocol));
            assert_eq!(value, VALUE, "{protocol}");
            assert!(!value.contains("protocol="), "{protocol}: {value}");
            // What siphon sends is what it accepts back.
            let request = headers(&[("Require", "sec-agree"), ("Security-Verify", &value)]);
            assert_eq!(
                verify_sec_agree(&request, Some(&association(protocol))),
                SecAgreeVerdict::Verified,
                "{protocol}"
            );
        }
    }

    /// What a P-CSCF script put on the 401 for [`association`]: a q-value and
    /// `prot`/`mod`, which the association itself does not record.
    const RECORDED: &str = "ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; ealg=null; prot=esp; mod=trans; spi-c=10000; spi-s=10001; port-c=5064; port-s=5066";

    fn recorded_association() -> SecurityAssociationPair {
        let mut sa = association(SaProtocol::Any);
        sa.security_server = Some(RECORDED.to_string());
        sa
    }

    #[test]
    fn a_security_verify_that_mirrors_the_recorded_security_server_is_verified() {
        let sa = recorded_association();
        for verify in [
            RECORDED,
            // Names in another case, parameters in another order, no spaces.
            "IPSEC-3GPP;PORT-S=5066;port-c=5064;SPI-S=10001;spi-c=10000;MOD=trans;prot=esp;EALG=null;alg=HMAC-SHA-1-96;Q=0.1",
            // Whitespace around every separator, and the same q-value written longer.
            " ipsec-3gpp ;  q = 0.100 ; alg = hmac-sha-1-96 ; ealg = null ; prot = esp ; mod = trans ; spi-c = 10000 ; spi-s = 10001 ; port-c = 5064 ; port-s = 5066 ",
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
    fn a_security_verify_that_differs_from_the_recorded_security_server_is_refused() {
        let sa = recorded_association();
        for verify in [
            RECORDED.replace("q=0.1", "q=0.2"),
            RECORDED.replace("; q=0.1", ""),
            RECORDED.replace("; prot=esp", ""),
            RECORDED.replace("mod=trans", "mod=tun"),
            RECORDED.replace("; ealg=null", ""),
            format!("{RECORDED}; d-alg=md5"),
            RECORDED.replace("spi-c=10000", "spi-c=10002"),
            // The recorded entry among others the server never listed.
            format!("{RECORDED}, ipsec-3gpp; alg=hmac-md5-96; ealg=null; spi-c=10000; spi-s=10001; port-c=5064; port-s=5066"),
            // What the association alone would have accepted.
            VERIFY.to_string(),
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
    fn a_recorded_list_is_mirrored_whole_across_lines() {
        let mut sa = association(SaProtocol::Any);
        let second = "ipsec-3gpp; q=0.5; alg=hmac-md5-96; ealg=null; prot=esp; mod=trans; spi-c=10000; spi-s=10001; port-c=5064; port-s=5066";
        sa.security_server = Some(format!("{RECORDED}, {second}"));
        let mut request = headers(&[("Require", "sec-agree")]);
        request.add("Security-Verify", second.to_string());
        request.add("Security-Verify", RECORDED.to_string());
        assert_eq!(
            verify_sec_agree(&request, Some(&sa)),
            SecAgreeVerdict::Verified
        );
        let only_one = headers(&[("Require", "sec-agree"), ("Security-Verify", RECORDED)]);
        assert_eq!(
            verify_sec_agree(&only_one, Some(&sa)),
            SecAgreeVerdict::Refused(SecAgreeRefusal::VerifyMismatch)
        );
    }

    #[test]
    fn an_association_without_a_recorded_security_server_is_verified_on_its_parameters() {
        let sa = association(SaProtocol::Any);
        assert_eq!(sa.security_server, None);
        let request = headers(&[
            ("Require", "sec-agree"),
            ("Security-Verify", &format!("{VERIFY};q=0.5")),
        ]);
        assert_eq!(
            verify_sec_agree(&request, Some(&sa)),
            SecAgreeVerdict::Verified
        );
    }

    #[test]
    fn the_security_server_for_an_unprotected_494_lists_every_supported_transform() {
        assert_eq!(
            supported_security_server_values(),
            [
                "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null",
                "ipsec-3gpp; alg=hmac-md5-96; ealg=null",
                "ipsec-3gpp; alg=hmac-sha-256-128; ealg=null",
                "ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc",
                "ipsec-3gpp; alg=hmac-md5-96; ealg=aes-cbc",
                "ipsec-3gpp; alg=hmac-sha-256-128; ealg=aes-cbc",
            ]
        );
        assert_eq!(
            refusal_security_server(None),
            supported_security_server_values()
        );
    }

    #[test]
    fn a_494_over_an_association_names_its_recorded_security_server() {
        assert_eq!(
            refusal_security_server(Some(&recorded_association())),
            [RECORDED]
        );
        assert_eq!(
            refusal_security_server(Some(&association(SaProtocol::Any))),
            [security_server_value(&association(SaProtocol::Any))]
        );
    }

    fn pair(ue_addr: &str, ue_port_c: u16, spi_pc: u32, spi_ps: u32) -> SecurityAssociationPair {
        let mut sa = association(SaProtocol::Any);
        sa.ue_addr = ue_addr.parse().expect("a literal address");
        sa.ue_port_c = ue_port_c;
        sa.spi_pc = spi_pc;
        sa.spi_ps = spi_ps;
        sa
    }

    fn manager_with(pairs: &[SecurityAssociationPair]) -> IpsecManager {
        let manager = IpsecManager::new();
        for sa in pairs {
            manager.associations.insert(
                IpsecManager::contact_key(&sa.ue_addr, sa.ue_port_c),
                sa.clone(),
            );
        }
        manager
    }

    #[test]
    fn a_relayed_security_server_is_recorded_on_the_pair_its_spis_name() {
        let manager = manager_with(&[
            pair("198.51.100.20", 50001, 10000, 10001),
            pair("198.51.100.20", 50003, 10002, 10003),
            pair("198.51.100.21", 50001, 10000, 10001),
        ]);
        let ue: IpAddr = "198.51.100.20".parse().expect("a literal address");
        assert!(manager.record_security_server(&ue, RECORDED));
        let recorded = |ue_addr: &str, port: u16| {
            manager
                .get_sa(&ue_addr.parse().expect("a literal address"), port)
                .and_then(|sa| sa.security_server)
        };
        assert_eq!(recorded("198.51.100.20", 50001).as_deref(), Some(RECORDED));
        assert_eq!(recorded("198.51.100.20", 50003), None);
        assert_eq!(recorded("198.51.100.21", 50001), None);

        // A value naming no pair of that UE records nothing.
        assert!(
            !manager.record_security_server(&ue, &RECORDED.replace("spi-c=10000", "spi-c=20000"))
        );
        assert!(!manager.record_security_server(&ue, "not a security mechanism"));
    }

    #[test]
    fn a_re_keyed_pair_keeps_the_value_recorded_on_the_pair_it_replaces() {
        let manager = manager_with(&[recorded_association()]);
        let mut re_keyed = association(SaProtocol::Any);
        carry_recorded_security_server(&manager, &mut re_keyed);
        assert_eq!(re_keyed.security_server.as_deref(), Some(RECORDED));

        let mut new_ue = pair("198.51.100.30", 50001, 10000, 10001);
        carry_recorded_security_server(&manager, &mut new_ue);
        assert_eq!(new_ue.security_server, None);
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
