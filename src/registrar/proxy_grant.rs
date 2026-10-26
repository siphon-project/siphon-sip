//! What the registrar of record granted each Contact of a REGISTER a proxy
//! relayed, read from its 2xx (RFC 3261 §10.3 step 8).
//!
//! "The response SHOULD include a Contact header field value enumerating all
//! current bindings. Each Contact value MUST feature an "expires" parameter
//! indicating its expiration interval chosen by the registrar." A top-level
//! `Expires` is optional, and a Contact's own `expires` wins over it for that
//! binding. A 2xx to a de-REGISTER commonly carries nothing but
//! `Contact: <...>;expires=0`, so reading the `Expires` header alone refused
//! it and left the binding cached.

use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::headers::SipHeaders;

use super::same_contact;

/// What a proxy caches from the 2xx to a REGISTER it relayed.
#[derive(Debug)]
pub(crate) enum ProxyGrant {
    /// Every binding of the AoR goes: the REGISTER was a `Contact: *`, or the
    /// 2xx says `Expires: 0` and gives no Contact an expiration of its own.
    ClearAll,
    /// Each Contact of the REGISTER with the lifetime granted to it, in
    /// seconds; zero removes that binding.
    PerContact(Vec<(NameAddr, u32)>),
}

fn expires_header(headers: &SipHeaders) -> Option<u32> {
    headers
        .get("Expires")
        .and_then(|value| value.trim().parse::<u32>().ok())
}

fn contacts(headers: &SipHeaders) -> Vec<NameAddr> {
    headers
        .get_all("Contact")
        .into_iter()
        .flatten()
        .filter_map(|value| NameAddr::parse_multi(value).ok())
        .flatten()
        .collect()
}

/// The grant of each Contact of `request` from the 2xx `reply`. For a Contact
/// the 2xx lists (matched by URI the way the registrar matches a Contact,
/// RFC 3261 §19.1.4): its `expires` parameter, else the 2xx's `Expires`. For
/// one it does not list: the 2xx's `Expires`, or zero when the REGISTER asked
/// for zero (a de-registered binding is not a current one, so the 2xx need
/// not list it). With a top-level `Expires` as the grant, a shorter value the
/// UE asked for on its Contact wins, as before.
///
/// `Err` names a Contact whose grant the 2xx does not give at all.
pub(crate) fn proxy_grants(request: &SipHeaders, reply: &SipHeaders) -> Result<ProxyGrant, String> {
    if request
        .get_all("Contact")
        .is_some_and(|values| values.iter().any(|value| value.trim() == "*"))
    {
        return Ok(ProxyGrant::ClearAll);
    }
    let reply_expires = expires_header(reply);
    let listed = contacts(reply);
    if reply_expires == Some(0) && listed.iter().all(|contact| contact.expires.is_none()) {
        return Ok(ProxyGrant::ClearAll);
    }
    let request_expires = expires_header(request);
    let missing = |contact: &NameAddr| {
        format!(
            "save_proxy: the reply gives no expiration for Contact {}: no expires \
             parameter on its Contact and no Expires header (RFC 3261 §10.3 step 8)",
            contact.uri
        )
    };
    let mut grants = Vec::new();
    for contact in contacts(request) {
        let asked = contact.expires;
        let capped = |granted: u32| asked.map_or(granted, |asked| asked.min(granted));
        let granted = match listed
            .iter()
            .find(|listed| same_contact(&listed.uri, &contact.uri))
        {
            Some(listed) => match listed.expires {
                Some(granted) => granted,
                None => capped(reply_expires.ok_or_else(|| missing(&contact))?),
            },
            None => match reply_expires {
                Some(granted) => capped(granted),
                None if asked.or(request_expires) == Some(0) => 0,
                None => return Err(missing(&contact)),
            },
        };
        grants.push((contact, granted));
    }
    Ok(ProxyGrant::PerContact(grants))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(lines: &[(&str, &str)]) -> SipHeaders {
        let mut headers = SipHeaders::new();
        for (name, value) in lines {
            headers.add(name, value.to_string());
        }
        headers
    }

    fn per_contact(grant: ProxyGrant) -> Vec<(String, u32)> {
        match grant {
            ProxyGrant::PerContact(grants) => grants
                .into_iter()
                .map(|(contact, granted)| (contact.uri.to_string(), granted))
                .collect(),
            ProxyGrant::ClearAll => panic!("expected per-contact grants"),
        }
    }

    #[test]
    fn the_reply_contacts_expires_wins_over_its_expires_header() {
        let request = headers(&[
            ("Contact", "<sip:ue@192.0.2.1:5060>"),
            ("Expires", "600000"),
        ]);
        let reply = headers(&[
            ("Contact", "<sip:UE@192.0.2.1>;expires=600"),
            ("Contact", "<sip:ue@192.0.2.1>;expires=900"),
            ("Expires", "3600"),
        ]);
        // The user part is case-sensitive, the default port is 5060.
        assert_eq!(
            per_contact(proxy_grants(&request, &reply).expect("granted")),
            [("sip:ue@192.0.2.1:5060".to_string(), 900)]
        );
    }

    #[test]
    fn an_unlisted_contact_takes_the_expires_header_capped_by_its_own_ask() {
        let request = headers(&[("Contact", "<sip:ue@192.0.2.1>;expires=120")]);
        let reply = headers(&[("Expires", "3600")]);
        assert_eq!(
            per_contact(proxy_grants(&request, &reply).expect("granted")),
            [("sip:ue@192.0.2.1".to_string(), 120)]
        );
    }

    #[test]
    fn an_unlisted_contact_the_register_zeroed_is_removed() {
        let request = headers(&[("Contact", "<sip:ue@192.0.2.1>"), ("Expires", "0")]);
        let reply = headers(&[("Contact", "<sip:other@192.0.2.2>;expires=600")]);
        assert_eq!(
            per_contact(proxy_grants(&request, &reply).expect("granted")),
            [("sip:ue@192.0.2.1".to_string(), 0)]
        );
    }

    #[test]
    fn a_wildcard_or_a_bare_expires_zero_clears_the_aor() {
        let wildcard = headers(&[("Contact", "*"), ("Expires", "0")]);
        assert!(matches!(
            proxy_grants(&wildcard, &headers(&[])),
            Ok(ProxyGrant::ClearAll)
        ));
        let request = headers(&[("Contact", "<sip:ue@192.0.2.1>"), ("Expires", "0")]);
        assert!(matches!(
            proxy_grants(&request, &headers(&[("Expires", "0")])),
            Ok(ProxyGrant::ClearAll)
        ));
    }

    #[test]
    fn no_grant_anywhere_is_an_error() {
        let request = headers(&[("Contact", "<sip:ue@192.0.2.1>"), ("Expires", "600")]);
        assert!(proxy_grants(&request, &headers(&[("Contact", "<sip:ue@192.0.2.1>")])).is_err());
        assert!(proxy_grants(&request, &headers(&[])).is_err());
    }
}
