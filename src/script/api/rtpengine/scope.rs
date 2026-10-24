//! `scope=` on `rtpengine.offer` / `answer` / `delete`, and on every other
//! media verb that addresses a call ([`leg`]).
//!
//! A proxy that anchors both legs of one call (the originating and the
//! terminating leg of a call between two of its own users, which arrive under
//! one Call-ID, RFC 3261 §16.6) names a scope per leg, and each leg is an engine
//! call of its own ([`crate::rtpengine::backend`]'s `scoped` module says how
//! each backend keys it). Its session is kept in the store of its scope, under
//! the Call-ID, so the bookkeeping an answer or a re-offer reads (the profile,
//! the tags) is the leg's own.
//!
//! A B2BUA does not need it: its legs have Call-IDs of their own, and the
//! dispatcher's own media handling (re-INVITEs, bridges, transfers, the
//! teardown safety net) addresses a call's session by the Call-ID alone, so a
//! scope on a Call is refused rather than left to half of that.

use std::sync::Arc;

use pyo3::prelude::*;
use tracing::{debug, warn};

use crate::rtpengine::backend::ScopedLeg;
use crate::rtpengine::session::MediaSessionStore;
use crate::rtpengine::{CallScope, MediaBackend};

use super::{PyCall, PyReply, PyRtpEngine};

/// Read a verb's `scope=` argument: `None` for the node's own scope (left out,
/// or equal to the node's configured one), else the per-call scope.
///
/// `targets` are the objects the verb was handed; a B2BUA one (a Call, or a
/// Reply carrying its A-leg reference) is refused.
pub(super) fn per_call_scope(
    scope: Option<&str>,
    targets: &[Option<&Bound<'_, PyAny>>],
    client: &MediaBackend,
    verb: &str,
) -> PyResult<Option<CallScope>> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    let scope = CallScope::per_call(scope).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("rtpengine.{verb}: {error}"))
    })?;
    let b2bua = targets.iter().flatten().any(|target| {
        target.cast::<PyCall>().is_ok()
            || target
                .cast::<PyReply>()
                .is_ok_and(|reply| reply.borrow().a_leg_message().is_some())
    });
    if b2bua {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "rtpengine.{verb}(scope=...) names one leg of a call a proxy anchors twice under \
             one Call-ID; a B2BUA call's legs have Call-IDs of their own, so pass no scope"
        )));
    }
    Ok((!client.is_node_scope(&scope)).then_some(scope))
}

/// The leg of `call_id` a media verb other than `offer` / `answer` /
/// `delete` addresses: prompts, DTMF, gating, recording, digit reads,
/// subscriptions, tees and bridges.
///
/// With `scope=` it is that leg (checked as [`per_call_scope`] checks it).
/// Without one it is the node's call, as it always was, except when the call
/// has no session of its own and exactly one leg of it was offered under a
/// scope: then that leg, since it is the only one the verb can mean. With two
/// scoped legs and no `scope=` the verb still goes to the node's call, which
/// is not either leg, so the engine refuses it rather than guess.
pub(super) fn leg(
    scope: Option<&str>,
    target: Option<&Bound<'_, PyAny>>,
    client: &MediaBackend,
    sessions: &MediaSessionStore,
    call_id: &str,
    verb: &str,
) -> PyResult<ScopedLeg> {
    let scope = match scope {
        Some(_) => per_call_scope(scope, &[target], client, verb)?,
        None => sessions.sole_scope_of(call_id),
    };
    Ok(client.leg(call_id, scope.as_ref()))
}

impl PyRtpEngine {
    /// [`leg`] against this namespace's engine and sessions.
    pub(super) fn leg(
        &self,
        scope: Option<&str>,
        target: Option<&Bound<'_, PyAny>>,
        call_id: &str,
        verb: &str,
    ) -> PyResult<ScopedLeg> {
        leg(scope, target, &self.client, &self.sessions, call_id, verb)
    }
}

/// The session store a verb under `scope` reads and writes: the call's own
/// without one, the scope's otherwise.
pub(super) fn store_for(
    sessions: &Arc<MediaSessionStore>,
    scope: Option<&CallScope>,
) -> PyResult<Arc<MediaSessionStore>> {
    match scope {
        None => Ok(Arc::clone(sessions)),
        Some(scope) => sessions
            .scoped(scope)
            .map_err(pyo3::exceptions::PyValueError::new_err),
    }
}

/// Delete the leg of `call_id` anchored under `scope` and free its bookkeeping:
/// `rtpengine.delete(message, scope=...)`. The bookkeeping goes first and
/// whatever the engine says, as the leg is ending either way.
pub(super) async fn delete_leg(
    client: &MediaBackend,
    sessions: &MediaSessionStore,
    call_id: &str,
    from_tag: &str,
    scope: &CallScope,
) {
    if let Some(store) = sessions.scoped_existing(scope) {
        store.remove(call_id);
    }
    run_deletes(client, call_id, from_tag, vec![scope.clone()]).await;
}

/// Delete the per-call-scoped legs of `call_id` and free their bookkeeping:
/// what `rtpengine.delete(message)` adds to the delete of the call's own
/// session, which it sends as it always has.
pub(super) async fn delete_scoped_legs(
    client: &MediaBackend,
    sessions: &MediaSessionStore,
    call_id: &str,
    from_tag: &str,
) {
    let scopes = sessions
        .take_scoped(call_id)
        .into_iter()
        .map(|(scope, _session)| scope)
        .collect();
    run_deletes(client, call_id, from_tag, scopes).await;
}

/// Delete the leg of `call_id` under each of `scopes`, every one whatever the
/// others did, naming the party `from_tag` (empty: the whole engine call).
/// Teardown is best-effort, as `rtpengine.delete` has always been: a refusal
/// is logged.
async fn run_deletes(client: &MediaBackend, call_id: &str, from_tag: &str, scopes: Vec<CallScope>) {
    for scope in scopes {
        let result = if from_tag.is_empty() {
            client.delete_call_in(Some(&scope), call_id).await
        } else {
            client.delete_in(Some(&scope), call_id, from_tag).await
        };
        let scope_name = scope.as_str();
        match result {
            Ok(()) => {
                debug!(%call_id, scope = scope_name, "media session deleted");
            }
            // Not a failure: the engine had already released it (a media
            // timeout, or a teardown that raced this one).
            Err(error) if error.is_call_not_found() => {
                debug!(%call_id, scope = scope_name, "media session already released");
            }
            Err(error) => {
                warn!(%call_id, scope = scope_name, %error, "media session delete failed");
            }
        }
    }
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
