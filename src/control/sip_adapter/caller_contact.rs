//! The caller side of `contact_host`: the host of siphon's own Contact toward
//! a call that came in, named on `answer` / `ring` / `progress` as
//! `contact_host` and on `dial` / `route` as `caller_contact_host` (whose
//! targets already own `contact_host` for the legs siphon places).
//!
//! Read and checked before anything is sent, then set on the call, from which
//! every Contact siphon presents the caller takes its host.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::dispatcher::{CallerContactHostRefusal, DispatcherHandle};

/// Read `args[argument]` as a caller Contact host: absent or `null` is none,
/// anything else must be a hostname or an IP address. Checked here so a bad
/// one is `bad_request` before a verb sends anything.
pub(super) fn parse(
    verb: &str,
    argument: &str,
    args: &serde_json::Value,
) -> Result<Option<String>, ControlResult> {
    let bad = |message: String| ControlResult::error(ControlErrorCode::BadRequest, message);
    match args.get(argument) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(host)) => crate::dispatcher::checked_contact_host(host)
            .map(Some)
            .map_err(|error| bad(format!("{verb} args.{argument}: {error}"))),
        Some(_) => Err(bad(format!(
            "{verb} args.{argument} must be a hostname or IP address string"
        ))),
    }
}

/// Set `host` on the channel's call, on `dispatcher` (the running B2BUA, or a
/// test's own). A host other than the one the caller was already sent is
/// `invalid_state`.
pub(super) fn apply(
    dispatcher: &dyn DispatcherHandle,
    channel: &ChannelRef,
    verb: &str,
    argument: &str,
    host: Option<&str>,
) -> Result<(), ControlResult> {
    let Some(host) = host else {
        return Ok(());
    };
    let Some(state) = dispatcher.state() else {
        return Err(ControlResult::error(
            ControlErrorCode::Unavailable,
            "b2bua is not running",
        ));
    };
    crate::dispatcher::set_caller_contact_host(state, &channel.call_actor_id, host)
        .map_err(|refusal| refused(verb, argument, refusal))
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
        CallerContactHostRefusal::UnknownCall => {
            ControlResult::error(ControlErrorCode::NotFound, message)
        }
    }
}
