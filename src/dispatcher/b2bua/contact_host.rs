//! The host siphon presents in its own Contact on a leg a controller places
//! (`contact_host` on a `dial` or `route` target, and on `originate`).
//!
//! siphon advertises one address per transport, so without this every leg
//! presents the same Contact host, and a peer that identifies the tenant or
//! account by the host of the Contact can be served for one tenant per siphon.
//! The host alone is replaced, where each path builds its Contact
//! ([`b2bua_dial_b_leg`], [`prepare_originate_routed`]); this module holds the
//! check every path shares and the originate entry points that carry it.
//! Split from [`dial_target`](super::dial_target) and
//! [`originate`](super::originate) to keep both inside their size budgets.

use crate::dispatcher::*;

/// A `contact_host` as the Contact carries it: a hostname, an IPv4 address or
/// an IPv6 address (bracketed here whether or not it came bracketed), and
/// nothing else. A port, a scheme, a user part or a parameter is refused: the
/// port and transport of siphon's own Contact are what keep in-dialog requests
/// reaching the listener that sent the INVITE, so they are not the
/// controller's to change.
pub(crate) fn checked_contact_host(value: &str) -> Result<String, String> {
    crate::sip::uri::checked_uri_host(value.trim()).ok_or_else(|| {
        format!(
            "contact_host {value:?} is not a host: expected a hostname, an IPv4 address or an \
             IPv6 address, with no scheme, user, port or parameters"
        )
    })
}

/// Check every target's `contact_host` and store it as the Contact carries it,
/// before any branch is sent: a host siphon cannot put on the wire refuses the
/// dial before anything rings, as a `to` does ([`branch_called_parties`]). Its
/// `contact_user` is checked the same way, here, so no dial path can check one
/// and not the other ([`super::contact_user::check_branch_contact_users`]).
pub(super) fn check_branch_contact_hosts(targets: &mut [DialTarget]) -> Result<(), String> {
    for target in targets.iter_mut() {
        if let Some(host) = target.contact_host.as_deref() {
            target.contact_host = Some(checked_contact_host(host)?);
        }
    }
    super::contact_user::check_branch_contact_users(targets)
}

/// [`b2bua_originate_prepare`] presenting `contact_host` as the host and
/// `contact_user` as the user part of siphon's own Contact on the call, with
/// `media_flags` over the anchor profile (the `originate` verb's arguments of
/// those names).
pub(crate) fn b2bua_originate_prepare_with_contact_host(
    params: OriginateParams,
    contact_host: Option<String>,
    contact_user: Option<String>,
    media_flags: Option<crate::rtpengine::media_flags::MediaFlags>,
) -> Result<PreparedOriginate, OriginateError> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(OriginateError::Unavailable(
            "b2bua is not running — nothing to originate from".to_string(),
        ));
    };
    prepare_originate_with_contact_host(
        &control.state,
        params,
        contact_host,
        contact_user,
        media_flags,
    )
}

/// [`prepare_originate`] presenting `contact_host` as the host and
/// `contact_user` as the user part of siphon's own Contact on the call, with
/// `media_flags` over the anchor profile.
pub(crate) fn prepare_originate_with_contact_host(
    state: &DispatcherState,
    params: OriginateParams,
    contact_host: Option<String>,
    contact_user: Option<String>,
    media_flags: Option<crate::rtpengine::media_flags::MediaFlags>,
) -> Result<PreparedOriginate, OriginateError> {
    prepare_originate_routed(
        state,
        params,
        &OriginateRoute {
            contact_host,
            contact_user,
            media_flags,
            ..OriginateRoute::default()
        },
    )
}

/// Why a caller-side Contact host was not set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CallerContactHostRefusal {
    /// Not a host siphon can put in its Contact ([`checked_contact_host`]).
    #[error("{0}")]
    Invalid(String),
    /// The caller already holds a Contact with another host, from an 18x or
    /// 2xx siphon sent it: it may have taken that as its remote target (RFC
    /// 3261 §12.1.2), so siphon does not move it under the dialog.
    #[error(
        "the caller was already sent siphon's Contact with host {presented:?}, which it may \
         hold as its remote target; contact_host can only repeat it now"
    )]
    AlreadyPresented {
        /// The host the caller was sent.
        presented: String,
    },
    /// No such call.
    #[error("call is gone")]
    UnknownCall,
    /// The `contact_user` twin of [`Self::AlreadyPresented`]: the caller
    /// already holds a Contact whose user part is `presented` (`None` for the
    /// userless one siphon presents by default).
    #[error(
        "the caller was already sent siphon's Contact with {}, which it may hold as its remote \
         target; contact_user can only repeat it now",
        presented.as_deref().map_or_else(|| "no user part".to_string(), |user| format!("user {user:?}"))
    )]
    UserAlreadyPresented {
        /// The user part the caller was sent, if any.
        presented: Option<String>,
    },
}

/// Present `value` as the host of siphon's own Contact toward the caller of
/// `internal_call_id`, on every response and request siphon sends that dialog
/// from here on.
///
/// The caller side of [`DialTarget::contact_host`]: a call that came in from a
/// peer which identifies the tenant or account by the host of the Contact
/// needs that host in what siphon answers it with too. Only the host changes;
/// port (the listener the INVITE arrived on), transport and user part stay (the
/// user part is [`set_caller_contact_user`]'s).
/// It sticks for the dialog: the same value again is a no-op, and a different
/// one is refused once the caller has been sent an 18x or 2xx carrying a
/// Contact. Before that the last one set wins.
pub(crate) fn set_caller_contact_host(
    state: &DispatcherState,
    internal_call_id: &str,
    value: &str,
) -> Result<(), CallerContactHostRefusal> {
    let host = checked_contact_host(value).map_err(CallerContactHostRefusal::Invalid)?;
    let mut call = state
        .call_actors
        .get_call_mut(internal_call_id)
        .ok_or(CallerContactHostRefusal::UnknownCall)?;
    if call.caller_contact_host.as_deref() == Some(host.as_str()) {
        return Ok(());
    }
    // A call siphon placed has no caller: siphon is the UAC of its INVITE,
    // which already carried its Contact (an `originate`'s own `contact_host`),
    // so that Contact is as fixed as one an answer presented.
    if call.originated
        || call
            .caller_contact_presented
            .load(std::sync::atomic::Ordering::Acquire)
    {
        let presented = call.caller_contact_host.clone().unwrap_or_else(|| {
            call.a_leg
                .dialog
                .local_contact
                .as_deref()
                .and_then(contact_uri_host)
                .unwrap_or_default()
        });
        if presented == host {
            return Ok(());
        }
        return Err(CallerContactHostRefusal::AlreadyPresented { presented });
    }
    // The dialog's local Contact is what siphon's own answers and every
    // request it sends the caller carry, so the host goes there as well.
    if let Some(contact) = call.a_leg.dialog.local_contact.as_deref() {
        match rewrite_contact_host(contact, &host) {
            Some(rewritten) => call.a_leg.dialog.local_contact = Some(rewritten),
            None => warn!(
                call_id = %internal_call_id,
                %contact,
                "B2BUA: cannot put the caller contact_host into the dialog's Contact"
            ),
        }
    }
    info!(call_id = %internal_call_id, contact_host = %host, "B2BUA: caller-side Contact host set");
    call.caller_contact_host = Some(host);
    Ok(())
}

/// The Contact a response to the caller of `internal_call_id` carries, from
/// the one siphon built for it (`built`): its host replaced by the caller's
/// `contact_host` when one was named. An 18x or 2xx marks the Contact as
/// presented, which is what fixes the host for the rest of the dialog.
pub(crate) fn caller_response_contact(
    state: &DispatcherState,
    internal_call_id: &str,
    status_code: Option<u16>,
    built: String,
) -> String {
    let Some(call) = state.call_actors.get_call(internal_call_id) else {
        return built;
    };
    if status_code.is_some_and(|code| (101..300).contains(&code)) {
        call.caller_contact_presented
            .store(true, std::sync::atomic::Ordering::Release);
    }
    // The host and the user part a controller named (`contact_host`,
    // `contact_user`), each replacing its own part of the built Contact alone.
    let (host, user) = (
        call.caller_contact_host.clone(),
        call.caller_contact_user.clone(),
    );
    if host.is_none() && user.is_none() {
        return built;
    }
    rewrite_contact_uri(&built, |uri| {
        if let Some(host) = host {
            uri.host = host;
        }
        if user.is_some() {
            uri.user = user;
        }
    })
    .unwrap_or(built)
}

/// Record that the caller of `internal_call_id` was sent siphon's Contact on
/// an 18x or 2xx, for a response whose Contact is the dialog's own.
pub(crate) fn note_caller_contact_presented(state: &DispatcherState, internal_call_id: &str) {
    if let Some(call) = state.call_actors.get_call(internal_call_id) {
        call.caller_contact_presented
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

/// `contact` (a Contact header value, `<uri>` with any parameters after it, or
/// a bare URI) with the URI's host replaced by `host`, everything else as it
/// was. `None` when the URI does not parse.
fn rewrite_contact_host(contact: &str, host: &str) -> Option<String> {
    rewrite_contact_uri(contact, |uri| uri.host = host.to_string())
}

/// `contact` (a Contact header value, `<uri>` with any parameters after it, or
/// a bare URI) with its URI changed by `change`, everything around the URI as
/// it was. `None` when the URI does not parse.
pub(super) fn rewrite_contact_uri(
    contact: &str,
    change: impl FnOnce(&mut SipUri),
) -> Option<String> {
    let (before, uri, after) = match (contact.find('<'), contact.find('>')) {
        (Some(open), Some(close)) if open < close => (
            &contact[..=open],
            &contact[open + 1..close],
            &contact[close..],
        ),
        _ => ("", contact.trim(), ""),
    };
    let mut parsed = parse_uri_standalone(uri).ok()?;
    change(&mut parsed);
    Some(format!("{before}{parsed}{after}"))
}

/// The host of the URI in a Contact header value.
fn contact_uri_host(contact: &str) -> Option<String> {
    let uri = match (contact.find('<'), contact.find('>')) {
        (Some(open), Some(close)) if open < close => &contact[open + 1..close],
        _ => contact.trim(),
    };
    parse_uri_standalone(uri).ok().map(|uri| uri.host)
}

/// The dialog a request siphon answers itself arrived on.
#[derive(Debug, Clone, Copy)]
pub(crate) enum AnsweringDialog<'a> {
    /// The call's A-leg: the caller of a call that came in, or the leg siphon
    /// placed for an `originate`.
    Caller,
    /// The callee leg whose INVITE rode this Via branch.
    Callee {
        /// That INVITE's Via branch.
        branch: &'a str,
    },
}

/// The Contact a 2xx siphon sends itself to a target refresh request (a
/// re-INVITE or an UPDATE) carries: the local Contact of the dialog it arrived
/// on (RFC 3261 §12.2.2, §13.3.1.4; RFC 3311 §5.2). The answer is the peer's
/// remote target from then on, so it has to be the one that dialog already
/// presents: a caller's `contact_host`, a placed leg's target `contact_host`, a
/// flow-pinned leg's own socket. A leg that recorded none gets one built the
/// way the other responses on that side build it. `None` when the call is
/// gone.
pub(crate) fn local_answer_contact(
    state: &DispatcherState,
    internal_call_id: &str,
    dialog: AnsweringDialog<'_>,
    inbound: &InboundMessage,
) -> Option<String> {
    let (recorded, built) = {
        let call = state.call_actors.get_call(internal_call_id)?;
        match dialog {
            AnsweringDialog::Caller => {
                let built = format!(
                    "<sip:{}:{};transport={}>",
                    state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
                    state.a_leg_advertised_port(Some(inbound.local_addr), &inbound.transport),
                    inbound.transport.to_string().to_lowercase(),
                );
                (call.a_leg.dialog.local_contact.clone(), built)
            }
            AnsweringDialog::Callee { branch } => {
                let (_, leg) = call.find_b_leg_by_branch(branch)?;
                let (host, port) = placed_leg_sent_by(leg, state);
                let built = format!(
                    "<sip:{host}:{port};transport={}>",
                    leg.transport.transport.to_string().to_lowercase(),
                );
                return Some(leg.dialog.local_contact.clone().unwrap_or(built));
            }
        }
    };
    Some(match recorded {
        Some(contact) => {
            note_caller_contact_presented(state, internal_call_id);
            contact
        }
        None => caller_response_contact(state, internal_call_id, Some(200), built),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contact_host_is_a_host_alone_with_ipv6_bracketed() {
        assert_eq!(
            checked_contact_host("tenant-a.example.com").as_deref(),
            Ok("tenant-a.example.com")
        );
        assert_eq!(
            checked_contact_host("203.0.113.5").as_deref(),
            Ok("203.0.113.5")
        );
        assert_eq!(
            checked_contact_host("2001:db8::5").as_deref(),
            Ok("[2001:db8::5]")
        );
        for refused in [
            "",
            "tenant-a.example.com:5060",
            "sip:tenant-a.example.com",
            "trunk@tenant-a.example.com",
            "tenant-a.example.com;transport=tls",
        ] {
            assert!(
                checked_contact_host(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
    }

    #[test]
    fn every_targets_contact_host_is_checked_and_normalised() {
        let mut targets = vec![
            DialTarget {
                uri: "sip:100@198.51.100.7".to_string(),
                contact_host: Some("2001:db8::5".to_string()),
                ..Default::default()
            },
            DialTarget {
                uri: "sip:100@198.51.100.8".to_string(),
                ..Default::default()
            },
        ];
        check_branch_contact_hosts(&mut targets).expect("both are fine");
        assert_eq!(targets[0].contact_host.as_deref(), Some("[2001:db8::5]"));
        assert_eq!(targets[1].contact_host, None);

        targets[1].contact_host = Some("tenant.example.com:5070".to_string());
        assert!(check_branch_contact_hosts(&mut targets).is_err());
    }

    #[test]
    fn a_contact_keeps_everything_but_its_host() {
        assert_eq!(
            rewrite_contact_host("<sip:192.0.2.1:5060;transport=udp>", "tenant-a.example.com")
                .as_deref(),
            Some("<sip:tenant-a.example.com:5060;transport=udp>")
        );
        assert_eq!(
            rewrite_contact_host("<sip:focus@192.0.2.1:5070>;isfocus", "[2001:db8::5]").as_deref(),
            Some("<sip:focus@[2001:db8::5]:5070>;isfocus")
        );
        assert_eq!(
            rewrite_contact_host("<not a uri>", "tenant-a.example.com"),
            None
        );
        assert_eq!(
            contact_uri_host("<sip:192.0.2.1:5060;transport=udp>").as_deref(),
            Some("192.0.2.1")
        );
    }
}
