//! The user part siphon presents in its own Contact on a leg a controller
//! names it for (`contact_user`, beside `contact_host`).
//!
//! siphon's Contact is userless by default (RFC 3261 §8.1.1.8 puts no identity
//! there). A trunk peer that documents its Contact as `<sip:user@host>` keys
//! the account on that user, which a script reaches with
//! `call.set_contact_user()` and a controller reaches with this. Only the user
//! part changes: host (siphon's, or the `contact_host` named beside it), port
//! and transport stay, so the in-dialog requests the peer sends to the Contact
//! still reach the listener the INVITE left from (RFC 3261 §12.1.2).
//!
//! The leg it is named for keeps it the way it keeps a `contact_host`: a placed
//! leg as its dialog's local Contact, the caller's side on the call, from where
//! every response and request siphon sends that dialog takes it.
//!
//! Precedence on a leg siphon places: a script's whole Contact
//! (`call.set_contact_uri()`, a GRUU or an edge that fronts siphon) wins, then
//! the target's `contact_user`, then a script's `call.set_contact_user()`.

use crate::dispatcher::*;

use super::contact_host::rewrite_contact_uri;

/// A `contact_user` as the Contact carries it: an RFC 3261 `user`
/// ([`crate::sip::uri::checked_uri_user`]) and nothing else. A scheme, a host,
/// a port, a parameter or an empty value is refused.
pub(crate) fn checked_contact_user(value: &str) -> Result<String, String> {
    crate::sip::uri::checked_uri_user(value.trim()).ok_or_else(|| {
        format!(
            "contact_user {value:?} is not a SIP URI user: expected one or more of letters, \
             digits, -_.!~*'()&=+$,?/ and %HH escapes, with no scheme, host, port or ';' \
             parameters"
        )
    })
}

/// Check every target's `contact_user` and store it as the Contact carries it,
/// before any branch is sent, as [`check_branch_contact_hosts`] does for the
/// host.
pub(super) fn check_branch_contact_users(targets: &mut [DialTarget]) -> Result<(), String> {
    for target in targets.iter_mut() {
        if let Some(user) = target.contact_user.as_deref() {
            target.contact_user = Some(checked_contact_user(user)?);
        }
    }
    Ok(())
}

/// The `contact_host` and `contact_user` of an originate, each checked, as its
/// Contact carries them. A value siphon cannot put there refuses the originate
/// before anything is staged, naming the argument.
pub(super) fn checked_originate_contact(
    route: &OriginateRoute,
) -> Result<(Option<String>, Option<String>), OriginateError> {
    let refused = |field: &'static str| move |detail| OriginateError::InvalidUri { field, detail };
    let host = route
        .contact_host
        .as_deref()
        .map(checked_contact_host)
        .transpose()
        .map_err(refused("contact_host"))?;
    let user = route
        .contact_user
        .as_deref()
        .map(checked_contact_user)
        .transpose()
        .map_err(refused("contact_user"))?;
    Ok((host, user))
}

/// The user part a leg siphon places presents: the target's own over the
/// script's `call.set_contact_user()`, since the target is the more specific
/// instruction.
pub(super) fn presented_contact_user<'a>(
    branch: Option<&'a str>,
    script: Option<&'a str>,
) -> Option<&'a str> {
    branch.or(script)
}

/// Present `value` as the user part of siphon's own Contact toward the caller
/// of `internal_call_id`, on every response and request siphon sends that
/// dialog from here on.
///
/// The user twin of [`set_caller_contact_host`], with the same stickiness: the
/// same value again is a no-op, a different one is refused once the caller has
/// been sent an 18x or 2xx carrying a Contact (or the call is one siphon
/// placed, whose INVITE carried it). Before that the last one set wins.
pub(crate) fn set_caller_contact_user(
    state: &DispatcherState,
    internal_call_id: &str,
    value: &str,
) -> Result<(), CallerContactHostRefusal> {
    let user = checked_contact_user(value).map_err(CallerContactHostRefusal::Invalid)?;
    let mut call = state
        .call_actors
        .get_call_mut(internal_call_id)
        .ok_or(CallerContactHostRefusal::UnknownCall)?;
    if call.caller_contact_user.as_deref() == Some(user.as_str()) {
        return Ok(());
    }
    if call.originated
        || call
            .caller_contact_presented
            .load(std::sync::atomic::Ordering::Acquire)
    {
        let presented = call.caller_contact_user.clone().or_else(|| {
            call.a_leg
                .dialog
                .local_contact
                .as_deref()
                .and_then(contact_uri_user)
        });
        if presented.as_deref() == Some(user.as_str()) {
            return Ok(());
        }
        return Err(CallerContactHostRefusal::UserAlreadyPresented { presented });
    }
    if let Some(contact) = call.a_leg.dialog.local_contact.as_deref() {
        match rewrite_contact_uri(contact, |uri| uri.user = Some(user.clone())) {
            Some(rewritten) => call.a_leg.dialog.local_contact = Some(rewritten),
            None => warn!(
                call_id = %internal_call_id,
                %contact,
                "B2BUA: cannot put the caller contact_user into the dialog's Contact"
            ),
        }
    }
    info!(call_id = %internal_call_id, contact_user = %user, "B2BUA: caller-side Contact user set");
    call.caller_contact_user = Some(user);
    Ok(())
}

/// The user of the URI in a Contact header value, `None` when it has none or
/// does not parse.
fn contact_uri_user(contact: &str) -> Option<String> {
    let uri = match (contact.find('<'), contact.find('>')) {
        (Some(open), Some(close)) if open < close => &contact[open + 1..close],
        _ => contact.trim(),
    };
    parse_uri_standalone(uri).ok().and_then(|uri| uri.user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contact_user_is_an_rfc_3261_user_alone() {
        assert_eq!(checked_contact_user("trunk-7").as_deref(), Ok("trunk-7"));
        assert_eq!(
            checked_contact_user(" +15550100077 ").as_deref(),
            Ok("+15550100077")
        );
        for refused in [
            "",
            "   ",
            "trunk@tenant-a.example.com",
            "sip:trunk",
            "trunk:5060",
            "trunk;transport=tls",
            "tr unk",
            "100%",
        ] {
            let error = checked_contact_user(refused).expect_err(refused);
            assert!(error.contains("contact_user"), "{refused:?}: {error}");
        }
    }

    #[test]
    fn every_targets_contact_user_is_checked() {
        let mut targets = vec![
            DialTarget {
                uri: "sip:100@198.51.100.7".to_string(),
                contact_user: Some(" trunk-7".to_string()),
                ..Default::default()
            },
            DialTarget {
                uri: "sip:100@198.51.100.8".to_string(),
                ..Default::default()
            },
        ];
        check_branch_contact_users(&mut targets).expect("both are fine");
        assert_eq!(targets[0].contact_user.as_deref(), Some("trunk-7"));
        assert_eq!(targets[1].contact_user, None);

        targets[1].contact_user = Some("trunk@tenant.example.com".to_string());
        assert!(check_branch_contact_users(&mut targets).is_err());
    }

    #[test]
    fn the_targets_user_outranks_the_scripts() {
        assert_eq!(
            presented_contact_user(Some("trunk-7"), Some("1001")),
            Some("trunk-7")
        );
        assert_eq!(presented_contact_user(None, Some("1001")), Some("1001"));
        assert_eq!(presented_contact_user(None, None), None);
    }

    #[test]
    fn the_user_of_a_contact_is_read_from_its_uri() {
        assert_eq!(
            contact_uri_user("<sip:trunk@192.0.2.1:5060;transport=udp>").as_deref(),
            Some("trunk")
        );
        assert_eq!(contact_uri_user("<sip:192.0.2.1:5060;transport=udp>"), None);
        assert_eq!(contact_uri_user("<not a uri>"), None);
    }
}
