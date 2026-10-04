//! How a leg replacement reaches its target and what it presents there.
//!
//! A replacement dials its target from the call's stored A-leg INVITE, so left
//! alone the new leg goes to wherever the target URI resolves and presents the
//! identity that INVITE carried. Neither is right for every transfer:
//!
//! * a phone registered over TCP, TLS or WebSocket is reachable only over the
//!   connection it registered on (RFC 5626 §5.3), through the Path its binding
//!   carries (RFC 3327 §5.3), so a target named by its AoR is dialled the way
//!   a `dial` dials one — over that flow, called as the AoR;
//! * the party a transferred call presents is a decision of whoever accepts the
//!   transfer, the same decision `dial` takes with `from`, `from_display`,
//!   `p_asserted_identity`, `privacy` and `headers`.

use crate::dispatcher::*;

/// Where a replacement leg goes beyond its target URI, and what it presents.
///
/// The default dials the target URI as written and presents the template's own
/// identity, which is what a replacement did before any of this could be named.
#[derive(Debug, Clone, Default)]
pub struct ReplacementDial {
    /// The registered contact's captured inbound flow.
    pub flow: Option<crate::script::api::registrar::PyFlow>,
    /// The binding's Path, as a route set.
    pub route: Vec<String>,
    /// The registered AoR the target is a contact of: what the leg is called
    /// as (its `To`), the contact URI staying the Request-URI.
    pub aor: Option<String>,
    /// The identity the leg presents. Its `profile` is not read: a replacement
    /// names its media profile on its own.
    pub shaping: DialShaping,
    /// Headers for the leg, injected after the header policy.
    pub headers: Vec<(String, String)>,
}

/// What shaping a replacement's template settled for the send.
pub(super) struct ShapedReplacement {
    /// The `From` host the leg pins, when `from` named one.
    pub(super) from_host: Option<String>,
    /// The whole `To` the leg is addressed to, for a registered contact: its
    /// AoR, which the B-leg builder would otherwise rewrite to the contact's
    /// authority.
    pub(super) to: Option<String>,
    /// Every header injected after the header policy.
    pub(super) headers: Vec<(String, String)>,
}

impl ReplacementDial {
    /// Dial one registered contact of an AoR: its URI, with the flow, Path and
    /// AoR the registrar holds for it.
    pub fn to_contact(
        contact: DialTarget,
        shaping: DialShaping,
        headers: Vec<(String, String)>,
    ) -> (String, Self) {
        (
            contact.uri,
            Self {
                flow: contact.flow,
                route: contact.route,
                aor: contact.aor,
                shaping,
                headers,
            },
        )
    }

    /// Whether the target is a registered contact, dialled exactly as it
    /// registered: its URI is not a number to reshape.
    pub(super) fn is_registered_contact(&self) -> bool {
        self.aor.is_some()
    }

    /// Point `template` at the target and put the identity on it.
    ///
    /// `To` names the AoR for a registered contact and the target URI
    /// otherwise (RFC 3261 §8.1.1.2). `From` is shaped through the same path a
    /// `dial` shapes it, which keeps the dialog tag and reports the host to
    /// pin. `triggered` are the headers the referral itself owes the INVITE
    /// (`Replaces`, `Referred-By`); they go last, so nothing named here can
    /// displace them.
    pub(super) fn shape(
        &self,
        template: &mut SipMessage,
        target_uri: &str,
        triggered: Vec<(String, String)>,
    ) -> Result<ShapedReplacement, String> {
        let called = self.aor.as_deref().unwrap_or(target_uri);
        template.headers.set("To", format!("<{called}>"));
        let shaped = super::dial_target::shape_from(template, &self.shaping)?;
        let from_host = shaped.and_then(|shaped| {
            template.headers.set("From", shaped.header);
            shaped.host
        });
        let mut headers = super::control::dial_headers_with_asserted_identity(
            &self.headers,
            self.shaping.p_asserted_identity.as_deref(),
        );
        // An identity named as an argument is the one carried.
        if self.shaping.p_asserted_identity.is_some() {
            template.headers.remove("P-Asserted-Identity");
        }
        headers.extend(triggered);
        Ok(ShapedReplacement {
            from_host,
            to: self.aor.as_ref().map(|aor| format!("<{aor}>")),
            headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> SipMessage {
        let raw = concat!(
            "INVITE sip:15550100077@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-replacement\r\n",
            "Max-Forwards: 70\r\n",
            "From: \"Desk 203\" <sip:203@siphon.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100077@siphon.example.com>\r\n",
            "Call-ID: replacement@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:203@192.0.2.10:5060>\r\n",
            "P-Asserted-Identity: <sip:203@siphon.example.com>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the template parses")
    }

    fn header(message: &SipMessage, name: &str) -> String {
        message.headers.get(name).cloned().unwrap_or_default()
    }

    #[test]
    fn a_target_named_by_uri_is_called_as_that_uri_and_keeps_the_identity() {
        let mut invite = template();
        let shaped = ReplacementDial::default()
            .shape(&mut invite, "sip:204@198.51.100.7", Vec::new())
            .expect("shaped");
        assert_eq!(header(&invite, "To"), "<sip:204@198.51.100.7>");
        assert_eq!(
            header(&invite, "From"),
            "\"Desk 203\" <sip:203@siphon.example.com>;tag=caller-tag",
            "untouched"
        );
        assert_eq!(shaped.from_host, None);
        assert_eq!(shaped.to, None, "the builder addresses it to the target");
        assert!(shaped.headers.is_empty());
        assert!(invite.headers.has("P-Asserted-Identity"));
    }

    #[test]
    fn a_registered_contact_is_called_as_its_aor() {
        let mut invite = template();
        let (uri, dial) = ReplacementDial::to_contact(
            DialTarget {
                uri: "sip:204@198.51.100.7:61234;transport=tls".to_string(),
                route: vec!["<sip:edge.example.com;lr>".to_string()],
                aor: Some("sip:204@siphon.example.com".to_string()),
                ..Default::default()
            },
            DialShaping::default(),
            Vec::new(),
        );
        assert_eq!(uri, "sip:204@198.51.100.7:61234;transport=tls");
        assert!(dial.is_registered_contact());
        assert_eq!(dial.route, ["<sip:edge.example.com;lr>"]);
        let shaped = dial.shape(&mut invite, &uri, Vec::new()).expect("shaped");
        assert_eq!(header(&invite, "To"), "<sip:204@siphon.example.com>");
        assert_eq!(shaped.to.as_deref(), Some("<sip:204@siphon.example.com>"));
    }

    #[test]
    fn the_named_identity_replaces_the_templates_and_keeps_the_dialog_tag() {
        let mut invite = template();
        let dial = ReplacementDial {
            shaping: DialShaping {
                from: Some("sip:+15550100000@trunk.example.com".to_string()),
                from_display: Some("Front Desk".to_string()),
                p_asserted_identity: Some("sip:+15550100000@trunk.example.com".to_string()),
                ..Default::default()
            },
            headers: vec![
                ("X-Account".to_string(), "main".to_string()),
                (
                    "P-Asserted-Identity".to_string(),
                    "<sip:ignored@example.com>".to_string(),
                ),
            ],
            ..Default::default()
        };
        let shaped = dial
            .shape(
                &mut invite,
                "sip:204@198.51.100.7",
                vec![(
                    "Referred-By".to_string(),
                    "<sip:203@siphon.example.com>".to_string(),
                )],
            )
            .expect("shaped");
        assert_eq!(
            header(&invite, "From"),
            "\"Front Desk\" <sip:+15550100000@trunk.example.com>;tag=caller-tag"
        );
        assert_eq!(shaped.from_host.as_deref(), Some("trunk.example.com"));
        assert!(
            !invite.headers.has("P-Asserted-Identity"),
            "the template's own is not carried beside the named one"
        );
        let names: Vec<&str> = shaped
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(
            names,
            ["X-Account", "P-Asserted-Identity", "Referred-By"],
            "one asserted identity, and the referral's own headers last"
        );
        assert!(shaped.headers[1]
            .1
            .contains("+15550100000@trunk.example.com"));
    }

    #[test]
    fn an_identity_that_is_not_a_uri_is_refused() {
        let mut invite = template();
        let dial = ReplacementDial {
            shaping: DialShaping {
                from: Some("not a uri".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(dial
            .shape(&mut invite, "sip:204@198.51.100.7", Vec::new())
            .is_err());
    }
}
