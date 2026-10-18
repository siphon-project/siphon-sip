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
/// dial before anything rings, as a `to` does ([`branch_called_parties`]).
pub(super) fn check_branch_contact_hosts(targets: &mut [DialTarget]) -> Result<(), String> {
    for target in targets.iter_mut() {
        if let Some(host) = target.contact_host.as_deref() {
            target.contact_host = Some(checked_contact_host(host)?);
        }
    }
    Ok(())
}

/// [`b2bua_originate_prepare`] presenting `contact_host` as the host of
/// siphon's own Contact on the call (the `originate` verb's `contact_host`).
pub(crate) fn b2bua_originate_prepare_with_contact_host(
    params: OriginateParams,
    contact_host: Option<String>,
) -> Result<PreparedOriginate, OriginateError> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(OriginateError::Unavailable(
            "b2bua is not running — nothing to originate from".to_string(),
        ));
    };
    prepare_originate_with_contact_host(&control.state, params, contact_host)
}

/// [`prepare_originate`] presenting `contact_host` as the host of siphon's own
/// Contact on the call.
pub(crate) fn prepare_originate_with_contact_host(
    state: &DispatcherState,
    params: OriginateParams,
    contact_host: Option<String>,
) -> Result<PreparedOriginate, OriginateError> {
    prepare_originate_routed(
        state,
        params,
        &OriginateRoute {
            contact_host,
            ..OriginateRoute::default()
        },
    )
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
}
