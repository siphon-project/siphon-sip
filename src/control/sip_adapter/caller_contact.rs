//! The caller side of `contact_host` and `contact_user`: the host and user
//! part of siphon's own Contact toward a call that came in, named on `answer`
//! / `ring` / `progress` as `contact_host` / `contact_user` and on `dial` /
//! `route` as `caller_contact_host` / `caller_contact_user` (whose targets
//! already own the unprefixed names for the legs siphon places).
//!
//! Read and checked before anything is sent, then set on the call, from which
//! every Contact siphon presents the caller takes its host and user part.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::dispatcher::{CallerContactHostRefusal, DispatcherHandle};

/// The caller's side of siphon's Contact as a verb named it: the host
/// (`contact_host` / `caller_contact_host`) and the user part (`contact_user`
/// / `caller_contact_user`), each already checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CallerContact {
    pub(super) host: Option<String>,
    pub(super) user: Option<String>,
}

/// Read a verb's caller Contact arguments, `{prefix}contact_host` and
/// `{prefix}contact_user` (`prefix` is `""` on `answer` / `ring` /
/// `progress`, `"caller_"` on `dial` / `route`). Absent or `null` is none;
/// anything else must be a hostname or IP address, or an RFC 3261 user. Checked
/// here so a bad one is `bad_request` before a verb sends anything.
pub(super) fn parse(
    verb: &str,
    prefix: &str,
    args: &serde_json::Value,
) -> Result<CallerContact, ControlResult> {
    let host = parse_one(
        verb,
        &format!("{prefix}contact_host"),
        args,
        "a hostname or IP address string",
        crate::dispatcher::checked_contact_host,
    )?;
    let user = parse_one(
        verb,
        &format!("{prefix}contact_user"),
        args,
        "a SIP URI user string",
        crate::dispatcher::checked_contact_user,
    )?;
    Ok(CallerContact { host, user })
}

fn parse_one(
    verb: &str,
    argument: &str,
    args: &serde_json::Value,
    expected: &str,
    check: fn(&str) -> Result<String, String>,
) -> Result<Option<String>, ControlResult> {
    let bad = |message: String| ControlResult::error(ControlErrorCode::BadRequest, message);
    match args.get(argument) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => check(value)
            .map(Some)
            .map_err(|error| bad(format!("{verb} args.{argument}: {error}"))),
        Some(_) => Err(bad(format!("{verb} args.{argument} must be {expected}"))),
    }
}

/// Set `contact` on the channel's call, on `dispatcher` (the running B2BUA, or
/// a test's own): the host first, then the user part. A value other than the
/// one the caller was already sent is `invalid_state`; a host refused leaves
/// the user unset, and a user refused can only follow a host that repeated
/// the one the caller holds, so a refusal changes nothing.
pub(super) fn apply(
    dispatcher: &dyn DispatcherHandle,
    channel: &ChannelRef,
    verb: &str,
    prefix: &str,
    contact: &CallerContact,
) -> Result<(), ControlResult> {
    if contact.host.is_none() && contact.user.is_none() {
        return Ok(());
    }
    let Some(state) = dispatcher.state() else {
        return Err(ControlResult::error(
            ControlErrorCode::Unavailable,
            "b2bua is not running",
        ));
    };
    if let Some(host) = contact.host.as_deref() {
        crate::dispatcher::set_caller_contact_host(state, &channel.call_actor_id, host)
            .map_err(|refusal| refused(verb, &format!("{prefix}contact_host"), refusal))?;
    }
    if let Some(user) = contact.user.as_deref() {
        crate::dispatcher::set_caller_contact_user(state, &channel.call_actor_id, user)
            .map_err(|refusal| refused(verb, &format!("{prefix}contact_user"), refusal))?;
    }
    Ok(())
}

/// The wire code for each refusal.
pub(super) fn refused(
    verb: &str,
    argument: &str,
    refusal: CallerContactHostRefusal,
) -> ControlResult {
    let message = format!("{verb} args.{argument}: {refusal}");
    match refusal {
        CallerContactHostRefusal::Invalid(_) => {
            ControlResult::error(ControlErrorCode::BadRequest, message)
        }
        CallerContactHostRefusal::AlreadyPresented { presented } => {
            ControlResult::error_with_details(
                ControlErrorCode::InvalidState,
                message,
                serde_json::json!({
                    "verb": verb,
                    "argument": argument,
                    "reason": "contact_already_presented",
                    "presented": presented,
                }),
            )
        }
        CallerContactHostRefusal::UserAlreadyPresented { presented } => {
            ControlResult::error_with_details(
                ControlErrorCode::InvalidState,
                message,
                serde_json::json!({
                    "verb": verb,
                    "argument": argument,
                    "reason": "contact_already_presented",
                    "presented": presented,
                }),
            )
        }
        CallerContactHostRefusal::UnknownCall => {
            ControlResult::error(ControlErrorCode::NotFound, message)
        }
    }
}
