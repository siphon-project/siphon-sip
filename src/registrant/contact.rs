//! The Contact header an outbound registration registers: the binding and the
//! IMS feature tags it advertises.

use super::{AuthMode, RegistrantEntry, RegistrantManager, Transport};

/// IMS Contact-header feature tags (3GPP TS 24.229 §5.1.1.2 / GSMA IR.92,
/// NG.114). These let the S-CSCF match iFCs and register the UE's MMTel /
/// voice / video / SMS services, and carry the instance ID for GRUU/outbound
/// (RFC 5626). Emitted after the `<sip:…>` of the Contact when present.
#[derive(Debug, Clone, Default)]
pub struct ImsContactParams {
    /// IMEI for `+sip.instance="<urn:gsma:imei:…>"` (RFC 5626 instance ID).
    /// `None` → no instance tag.
    pub instance_id: Option<String>,
    /// Emit the MMTel ICSI tag (`+g.3gpp.icsi-ref` mmtel).
    pub mmtel: bool,
    /// Emit `;video`.
    pub video: bool,
    /// Emit `+g.3gpp.mcptt` and the MCPTT ICSI (TS 24.379 clause 7.2.1).
    pub mcptt: bool,
    /// Emit `+g.3gpp.smsip` (SMS-over-IP).
    pub smsip: bool,
}

impl ImsContactParams {
    /// The tags `features` name (any of "mmtel", "video", "smsip", "mcptt",
    /// case-insensitive) beside `instance_id`; `Err` names an unknown one.
    pub fn from_features(instance_id: Option<String>, features: &[String]) -> Result<Self, String> {
        let mut params = Self {
            instance_id,
            ..Self::default()
        };
        for feature in features {
            match feature.to_ascii_lowercase().as_str() {
                "mmtel" => params.mmtel = true,
                "video" => params.video = true,
                "smsip" => params.smsip = true,
                "mcptt" => params.mcptt = true,
                _ => {
                    return Err(format!(
                        "unknown ims feature '{feature}' (mmtel, video, smsip, mcptt)"
                    ))
                }
            }
        }
        Ok(params)
    }
}

/// Build the Contact header value: `<contact_uri>` plus any IMS feature tags
/// (3GPP TS 24.229 §5.1.1.2 / GSMA IR.92). The instance ID, `q=1.0`, MMTel
/// ICSI, `video` and SMS-over-IP tags are emitted in handset order so the
/// S-CSCF registers the implied services. Without `ims`, just `<contact_uri>`.
pub(super) fn build_contact_header(contact_uri: &str, ims: Option<&ImsContactParams>) -> String {
    let mut header = format!("<{}>", contact_uri);
    if let Some(ims) = ims {
        if let Some(ref imei) = ims.instance_id {
            header.push_str(&format!(";+sip.instance=\"<urn:gsma:imei:{imei}>\""));
        }
        header.push_str(";q=1.0");
        // One `+g.3gpp.icsi-ref` parameter holds every ICSI as a comma-separated
        // list inside its quoted string (TS 24.229 clause 7.9.2, RFC 3840 §9).
        let mut icsi_references = Vec::new();
        if ims.mmtel {
            icsi_references.push("urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel");
        }
        if ims.mcptt {
            icsi_references.push("urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt");
        }
        if !icsi_references.is_empty() {
            header.push_str(&format!(
                ";+g.3gpp.icsi-ref=\"{}\"",
                icsi_references.join(",")
            ));
        }
        if ims.mcptt {
            header.push_str(";+g.3gpp.mcptt");
        }
        if ims.video {
            header.push_str(";video");
        }
        if ims.smsip {
            header.push_str(";+g.3gpp.smsip");
        }
    }
    header
}

impl RegistrantManager {
    /// The instance id the Contact token of every generated Contact is made
    /// of. `None`, or no call, adds no token (a Contact as older versions
    /// built it) and claims no binding by token in the restart clean-up. Call
    /// before anything registers.
    ///
    /// A token is as unique as the id: two nodes with one id hold one token,
    /// and one's clean-up would take the other's binding for its own
    /// (`others_holding` skips records of its own instance id, which is the id
    /// both use). So the id must name one node; the built-in fallback, the same
    /// on every node, is not passed here, and says so once at start-up.
    pub fn with_instance_id(mut self, instance_id: impl Into<Option<String>>) -> Self {
        self.instance_id = instance_id.into();
        if self.instance_id.is_none() {
            tracing::warn!(
                "neither server.instance_id nor HOSTNAME is set: trunk Contacts carry no node \
                 token and the restart clean-up only clears bindings on a concrete listener \
                 socket (it needs a unique server.instance_id on every node)"
            );
        }
        self
    }

    /// The token this instance puts in the Contact it generates for `aor`.
    pub(super) fn instance_token(&self, aor: &str) -> Option<String> {
        self.instance_id
            .as_deref()
            .map(|instance| instance_token(instance, aor))
    }

    /// The token for `entry`'s generated Contact: a digest entry's only. An
    /// AKA / IPsec entry registers from an address of its own into a core that
    /// keys the binding by that address, is not persisted and never cleared by
    /// the restart clean-up, so its Contact stays as it was.
    pub(super) fn contact_token(&self, entry: &RegistrantEntry) -> Option<String> {
        (entry.auth_mode == AuthMode::Digest && entry.ue_ipsec.is_none())
            .then(|| self.instance_token(&entry.aor))
            .flatten()
    }
}

/// Build a default Contact URI from the entry's username, effective address, and transport.
///
/// Appends `;transport=<proto>` for non-UDP transports (UDP is the default per RFC 3261).
pub(super) fn default_contact_uri(
    username: &str,
    address: impl std::fmt::Display,
    transport: Transport,
    token: Option<&str>,
) -> String {
    let transport_param = match transport {
        Transport::Udp => "",
        Transport::Tcp => ";transport=tcp",
        Transport::Tls => ";transport=tls",
        Transport::WebSocket => ";transport=ws",
        Transport::WebSocketSecure => ";transport=wss",
        Transport::Sctp => ";transport=sctp",
    };
    // For IMS the username is the IMPI (`user@home-domain`); the Contact
    // userpart is just the `user` portion — otherwise we'd emit a malformed
    // `sip:user@domain@ip:port` (two `@`). For a plain trunk username with no
    // `@`, this is a no-op.
    let user = username.split('@').next().unwrap_or(username);
    let token = token
        .map(|token| format!(";{}={token}", TOKEN_PARAMETER))
        .unwrap_or_default();
    format!("sip:{}@{}{}{}", user, address, transport_param, token)
}

/// The token of `instance_id`'s Contact for `aor`, for the dispatcher's tests.
#[cfg(test)]
pub(crate) fn contact_token_for_tests(instance_id: &str, aor: &str) -> String {
    instance_token(instance_id, aor)
}

/// The URI parameter that carries a node's token in a Contact siphon generates.
/// Not one RFC 3261 §19.1.1 or any registry assigns a meaning to.
pub(super) const TOKEN_PARAMETER: &str = "rnode";

/// A token naming `instance_id`'s registration of `aor`: 16 hex digits of the
/// 64-bit FNV-1a hash of `instance_id`, a zero byte and `aor`.
///
/// It goes in the Contact of every registration siphon generates a Contact for
/// (see [`TOKEN_PARAMETER`]). A registrar keys a binding by its Contact URI,
/// parameters included (RFC 3261 §10.3, §19.1.4), so two nodes registering the
/// same AoR behind one shared address hold two bindings, and a node can tell
/// from the stored Contact alone whether a binding is its own. A hash rather
/// than the name keeps the instance id off the wire.
///
/// The hash is written out here, not taken from `std`: the token is stored in
/// Redis and compared after a restart, possibly by a binary built with another
/// Rust version, and `DefaultHasher` makes no promise to give the same value
/// across releases. FNV-1a is fixed by its published constants.
pub(super) fn instance_token(instance_id: &str, aor: &str) -> String {
    let bytes = instance_id
        .bytes()
        .chain(std::iter::once(0))
        .chain(aor.bytes());
    format!("{:016x}", fnv1a_64(bytes))
}

/// The 64-bit FNV-1a hash of `bytes` (offset basis `0xcbf29ce484222325`, prime
/// `0x100000001b3`).
fn fnv1a_64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.into_iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    })
}

/// Whether two Contact URIs name the same binding at a registrar (RFC 3261
/// §19.1.4). Text that does not parse as a URI is compared as text.
pub(super) fn contacts_equivalent(left: &str, right: &str) -> bool {
    // The scheme is case-insensitive (RFC 3261 §19.1.1) but the parser only
    // knows the lower-case ones, so the token before the first colon is
    // lower-cased first.
    let scheme_lowered = |text: &str| match text.split_once(':') {
        Some((scheme, rest)) => format!("{}:{rest}", scheme.to_ascii_lowercase()),
        None => text.to_string(),
    };
    match (
        crate::sip::parser::parse_uri_complete(&scheme_lowered(left)),
        crate::sip::parser::parse_uri_complete(&scheme_lowered(right)),
    ) {
        (Ok(left), Ok(right)) => left.is_equivalent_to(&right),
        _ => left == right,
    }
}

/// The URIs a registrar's answer lists in its `Contact` header lines (RFC 3261
/// §10.2.3, §20.10): each line may fold several comma-separated values, each
/// either `<uri>;params` (with an optional display name) or a bare `uri;params`
/// whose parameters are the header's, not the URI's. `*` is no URI and is
/// skipped.
pub(super) fn listed_contact_uris(lines: &[String]) -> Vec<String> {
    let mut uris = Vec::new();
    for line in lines {
        let mut start = 0;
        let mut depth = 0i32;
        let mut in_quotes = false;
        let mut values = Vec::new();
        for (index, byte) in line.bytes().enumerate() {
            match byte {
                b'"' => in_quotes = !in_quotes,
                b'<' if !in_quotes => depth += 1,
                b'>' if !in_quotes => depth -= 1,
                b',' if !in_quotes && depth == 0 => {
                    values.push(&line[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        values.push(&line[start..]);
        for value in values {
            let value = value.trim();
            let uri = match (value.find('<'), value.find('>')) {
                (Some(open), Some(close)) if open < close => &value[open + 1..close],
                _ => value.split(';').next().unwrap_or(value),
            };
            let uri = uri.trim();
            if !uri.is_empty() && uri != "*" {
                uris.push(uri.to_string());
            }
        }
    }
    uris
}

/// The token a Contact URI carries, if it has one. The parameter name is read
/// as RFC 3261 §19.1.4 compares it, after the decoding of escaped unreserved
/// characters and without case (the same decoding as
/// [`crate::sip::uri::SipUri::is_equivalent_to`]), so `%72node` is the token;
/// the value is decoded the same way, and compared without case at the use.
pub(super) fn contact_token_of(contact: &str) -> Option<String> {
    let rest = contact.split('?').next()?;
    rest.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        crate::sip::uri::comparable_octets(name)
            .eq_ignore_ascii_case(TOKEN_PARAMETER.as_bytes())
            .then(|| {
                String::from_utf8_lossy(&crate::sip::uri::comparable_octets(value)).into_owned()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published FNV-1a 64-bit test vectors (draft-eastlake-fnv).
    #[test]
    fn fnv1a_matches_the_published_vectors() {
        assert_eq!(fnv1a_64(*b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(*b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(*b"foobar"), 0x8594_4171_f739_67e8);
    }

    /// Fixed forever: a stored Contact's token is compared with the one a
    /// later binary computes, so these values must never move.
    #[test]
    fn the_token_is_a_known_answer() {
        assert_eq!(
            instance_token("node-a", "sip:trunk@carrier.example"),
            "b2e45f9359b95ae3"
        );
        assert_eq!(
            instance_token("node-b", "sip:trunk@carrier.example"),
            "866ac152f2ad37fa"
        );
    }

    #[test]
    fn the_token_differs_by_instance_and_by_aor_and_hides_the_instance() {
        let token = instance_token("node-a", "sip:trunk@carrier.example");
        assert_eq!(token.len(), 16);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(token, instance_token("node-b", "sip:trunk@carrier.example"));
        assert_ne!(token, instance_token("node-a", "sip:other@carrier.example"));
        // The separator keeps ("ab", "c") apart from ("a", "bc").
        assert_ne!(instance_token("ab", "c"), instance_token("a", "bc"));
        assert!(!token.contains("node"));
    }

    #[test]
    fn listed_contacts_are_read_from_angle_brackets_or_bare_uris() {
        let lines = vec![
            "<sip:u@203.0.113.10:5060;rnode=ab>;expires=60, \"Name, Q\" <sip:v@198.51.100.1>"
                .to_string(),
            "sip:w@192.0.2.9:5070;expires=30".to_string(),
            "*".to_string(),
        ];
        assert_eq!(
            listed_contact_uris(&lines),
            vec![
                "sip:u@203.0.113.10:5060;rnode=ab".to_string(),
                "sip:v@198.51.100.1".to_string(),
                "sip:w@192.0.2.9:5070".to_string(),
            ]
        );
        assert!(listed_contact_uris(&[]).is_empty());
    }

    #[test]
    fn a_contacts_token_is_read_from_its_parameters_only() {
        assert_eq!(
            contact_token_of("sip:u@203.0.113.10:5060;transport=tcp;rnode=00ff00ff00ff00ff")
                .as_deref(),
            Some("00ff00ff00ff00ff")
        );
        assert_eq!(contact_token_of("sip:u@203.0.113.10:5060"), None);
        assert_eq!(contact_token_of("sip:rnode=x@203.0.113.10:5060"), None);
    }
}

#[cfg(test)]
mod case_tests {
    use super::*;

    #[test]
    fn the_token_parameter_name_is_read_without_case() {
        assert_eq!(
            contact_token_of("sip:u@h:5060;RNode=00ff00ff00ff00ff").as_deref(),
            Some("00ff00ff00ff00ff")
        );
        assert_eq!(
            contact_token_of("sip:u@h:5060;transport=tcp;RNODE=aa").as_deref(),
            Some("aa")
        );
    }

    #[test]
    fn the_token_parameter_name_is_read_after_unreserved_decoding() {
        assert_eq!(
            contact_token_of("sip:u@h:5060;%72node=00ff00ff00ff00ff").as_deref(),
            Some("00ff00ff00ff00ff")
        );
        assert_eq!(
            contact_token_of("sip:u@h:5060;%52NODE=00ff").as_deref(),
            Some("00ff")
        );
        assert_eq!(contact_token_of("sip:u@h:5060;%2Fnode=00ff"), None);
    }

    #[test]
    fn contacts_are_compared_as_uris() {
        assert!(contacts_equivalent(
            "sip:u@vip:5060;transport=tcp;rnode=AB",
            "sip:u@VIP:5060;rnode=ab;Transport=TCP"
        ));
        assert!(contacts_equivalent(
            "sip:u@vip:5060;rnode=ab",
            "sip:u@vip:5060"
        ));
        assert!(!contacts_equivalent(
            "sip:u@vip:5060;rnode=ab",
            "sip:u@vip:5061"
        ));
    }
}
