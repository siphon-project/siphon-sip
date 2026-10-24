//! The call verbs that may name a **per-call scope**: `offer`, `reoffer`,
//! `answer`, `delete` and the tagless `delete_call`.
//!
//! A node's own scope (`media.siphon_rtp.scope`) separates it from the other
//! nodes on a shared engine. It cannot separate two legs of one call that the
//! same node anchors: a proxy that handles both the originating and the
//! terminating leg of a call between two of its own users sees both under one
//! Call-ID (RFC 3261 §16.6 leaves the Call-ID alone), and the second offer would
//! land on the first leg's engine call. A script names a scope per leg instead
//! (`rtpengine.offer(request, scope="orig")`), and the frame carries that scope
//! in place of the node's: the engine keys the call by `(scope, call_id)`, so
//! the legs are two engine calls.
//!
//! `None` is the node's scope, and the frame is byte for byte what it always
//! was. A per-call scope equal to the node's is the node's.
//!
//! Every **other** verb that addresses a call (prompts, DTMF, gating,
//! recording, digit reads, subscriptions, tees, bridges) runs under a leg's
//! scope through [`in_frame_scope`]: the scope is set for the verb's task, and
//! the one place every frame is written ([`SiphonRtpClient::request`]), the
//! instance selection and the waiters read it there. That keeps those verbs'
//! signatures (and their callers in the dispatcher, which never name a scope)
//! as they were, rather than threading one more argument through each of them.
//! A verb outside such a task carries the node's scope, exactly as before.

use std::borrow::Cow;
use std::future::Future;

use siphon_rtp_proto::Command;
use tracing::warn;

use super::scope::{require_scope_feature, CallScope};
use super::{
    expect_ok, expect_sdp, is_codec_change_refusal, profile_flags_from_ng, SiphonRtpClient,
    SiphonRtpClientSet,
};
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;

/// What siphon keys an engine call by in its own maps (instance affinity,
/// active sessions): the Call-ID, or the Call-ID and a per-call scope joined by
/// a line feed, which no parsed header value holds, so a per-call-scoped key
/// can never be some other call's Call-ID.
pub(crate) fn scoped_key<'a>(call_id: &'a str, scope: Option<&CallScope>) -> Cow<'a, str> {
    match scope {
        Some(scope) => Cow::Owned(format!("{call_id}\n{scope}")),
        None => Cow::Borrowed(call_id),
    }
}

tokio::task_local! {
    /// The per-call scope the current task's media verb addresses; see the
    /// module documentation.
    static FRAME_SCOPE: CallScope;
}

/// Run `verb` with every frame it sends carrying `scope`, and with siphon's own
/// bookkeeping for it (instance affinity, active sessions, digit reads) keyed
/// on the leg rather than on the Call-ID alone.
pub(crate) async fn in_frame_scope<F: Future>(scope: CallScope, verb: F) -> F::Output {
    FRAME_SCOPE.scope(scope, verb).await
}

/// The per-call scope the current task runs under ([`in_frame_scope`]), if
/// any.
pub(crate) fn frame_scope() -> Option<CallScope> {
    FRAME_SCOPE.try_with(CallScope::clone).ok()
}

/// `scope`, or without one the scope of the current task ([`in_frame_scope`]):
/// a verb that takes a scope reads the task's when its caller named none.
fn framed(scope: Option<&CallScope>) -> Option<CallScope> {
    scope.cloned().or_else(frame_scope)
}

/// What a waiter keyed on a call (a digit read) and the event that resolves it
/// both name the leg by: the Call-ID, or under a per-call scope its engine
/// call-id (`<call-id>;<scope>`), which is how a scoped leg's events reach
/// [`super::connection`]'s router (see [`report_under_leg`]).
pub(super) fn leg_call_id(call_id: &str) -> Cow<'_, str> {
    match frame_scope() {
        Some(scope) => Cow::Owned(
            crate::rtpengine::backend::engine_call_id(call_id, Some(&scope)).into_owned(),
        ),
        None => Cow::Borrowed(call_id),
    }
}

/// The per-call scope an event frame was raised under: its `scope`, when that
/// is not the node's own.
pub(super) fn event_scope(
    node: Option<&CallScope>,
    event: &serde_json::Value,
) -> Option<CallScope> {
    let scope = event.get("scope").and_then(serde_json::Value::as_str)?;
    if node.is_some_and(|node| node.as_str() == scope) {
        return None;
    }
    CallScope::per_call(scope).ok()
}

/// Report an event of a leg anchored under the per-call `scope` under the
/// leg's engine call-id (`<call-id>;<scope>`), the shape rtpengine and rtpproxy
/// report a scoped leg's events in. The dispatcher splits it back into the SIP
/// Call-ID and the scope for the script; a read waiting on the leg's digits
/// meets it as it is.
pub(super) fn report_under_leg(
    event: &mut crate::rtpengine::events::RtpEngineEvent,
    scope: Option<&CallScope>,
) {
    let Some(scope) = scope else {
        return;
    };
    if let Some(call_id) = event.call_id_mut() {
        *call_id = crate::rtpengine::backend::engine_call_id(call_id, Some(scope)).into_owned();
    }
}

impl SiphonRtpClient {
    /// Send `command` under the per-call scope of the current task
    /// ([`in_frame_scope`]), or the node's outside one.
    pub(super) async fn request_in_frame(
        &self,
        command: Command,
    ) -> Result<siphon_rtp_proto::CmdResult, RtpEngineError> {
        let scope = frame_scope();
        let scope = self.per_call_scope(scope.as_ref()).await?;
        self.request_in(scope, command).await
    }

    /// Ready a frame to carry `scope`: `None` when it is the node's own (the
    /// frame then carries the node's, as every frame always has), else the
    /// scope, noted as named on this connection so its call's events are
    /// recognised, once the engine is known to key calls by scope.
    ///
    /// An unscoped node's hand-shake never asked the engine, and an engine
    /// before 0.14.0 reads a scoped frame as an unscoped one, silently: both legs
    /// would meet in one call. So the first per-call scope on a connection asks
    /// `node_info`, and a refusal is the verb's error.
    async fn per_call_scope<'a>(
        &self,
        scope: Option<&'a CallScope>,
    ) -> Result<Option<&'a CallScope>, RtpEngineError> {
        let Some(scope) = scope.filter(|scope| Some(*scope) != self.scopes.node()) else {
            return Ok(None);
        };
        if !self.scopes.engine_supports() {
            let result = self.request_in(None, Command::NodeInfo).await?;
            require_scope_feature(result, &format!("scope={scope:?} was named for one call"))?;
            self.scopes.mark_supported();
        }
        self.scopes.name(scope)?;
        Ok(Some(scope))
    }

    /// Send an `offer` under `scope` (the node's when `None`), returning the
    /// rewritten SDP.
    pub async fn offer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let framed = framed(scope);
        let scope = self.per_call_scope(framed.as_ref()).await?;
        let result = self
            .request_in(
                scope,
                Command::Offer {
                    call_id: call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    sdp: String::from_utf8_lossy(sdp).into_owned(),
                    profile: profile_flags_from_ng(flags),
                },
            )
            .await?;
        let rewritten = expect_sdp(result)?;
        self.sessions
            .insert(scoped_key(call_id, scope).into_owned(), ());
        Ok(rewritten)
    }

    /// Send a `reoffer` under `scope`: see [`SiphonRtpClient::reoffer`].
    pub async fn reoffer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let framed = framed(scope);
        let scope = self.per_call_scope(framed.as_ref()).await?;
        let result = self
            .request_in(
                scope,
                Command::Reoffer {
                    call_id: call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    sdp: String::from_utf8_lossy(sdp).into_owned(),
                    profile: profile_flags_from_ng(flags),
                },
            )
            .await?;
        expect_sdp(result)
    }

    /// Send an `answer` under `scope`, returning the rewritten SDP.
    pub async fn answer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let framed = framed(scope);
        let scope = self.per_call_scope(framed.as_ref()).await?;
        let result = self
            .request_in(
                scope,
                Command::Answer {
                    call_id: call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: to_tag.to_string(),
                    sdp: String::from_utf8_lossy(sdp).into_owned(),
                    profile: profile_flags_from_ng(flags),
                },
            )
            .await?;
        expect_sdp(result)
    }

    /// Send a `delete` under `scope` and drop the call's active-session entry.
    ///
    /// An empty `from_tag` deletes the whole call: the engine matches a
    /// `delete` on the call-id and the owning control identity, not the tags,
    /// which is what lets a call whose tags are no longer known be deleted.
    pub async fn delete_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let framed = framed(scope);
        let scope = self.per_call_scope(framed.as_ref()).await?;
        let result = self
            .request_in(
                scope,
                Command::Delete {
                    call_id: call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: None,
                },
            )
            .await;
        self.sessions.remove(scoped_key(call_id, scope).as_ref());
        expect_ok(result?)
    }
}

impl SiphonRtpClientSet {
    /// The node's own scope, which every instance's connection carries.
    pub fn node_scope(&self) -> Option<&CallScope> {
        self.clients.first().and_then(|client| client.scopes.node())
    }

    /// Send an `offer` under `scope`, binding the engine call's affinity to the
    /// selected instance. Two legs of one Call-ID under two scopes are two
    /// engine calls, and each may land on its own instance.
    pub async fn offer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let framed = framed(scope);
        let scope = framed.as_ref();
        let key = scoped_key(call_id, scope);
        let result = self
            .select_key(&key)
            .offer_in(scope, call_id, from_tag, sdp, flags)
            .await?;
        self.bind_affinity_key(&key);
        Ok(result)
    }

    /// Renegotiate a live call under `scope` on the affinity-bound instance,
    /// keeping its ports and everything attached to them.
    ///
    /// Falls back to a replacement `offer` for the one case the engine refuses:
    /// a re-offer that changes the negotiated codec needs a pipeline rebuild the
    /// engine does not do on a live call, and its own error says to replace the
    /// call instead. That fallback re-allocates ports and drops the call's
    /// bridge/tee/SIPREC attachments, so it is logged rather than performed
    /// silently.
    pub async fn reoffer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let framed = framed(scope);
        let scope = framed.as_ref();
        let key = scoped_key(call_id, scope);
        match self
            .select_key(&key)
            .reoffer_in(scope, call_id, from_tag, sdp, flags)
            .await
        {
            Ok(rewritten) => Ok(rewritten),
            Err(error) if is_codec_change_refusal(&error) => {
                warn!(
                    %call_id,
                    %error,
                    "re-offer changes the negotiated codec; replacing the media session — its \
                     ports are re-allocated and any WebSocket bridge, tee or SIPREC subscription \
                     on it is torn down"
                );
                self.offer_in(scope, call_id, from_tag, sdp, flags).await
            }
            Err(error) => Err(error),
        }
    }

    /// Send an `answer` under `scope` to the affinity-bound instance.
    pub async fn answer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let framed = framed(scope);
        let scope = framed.as_ref();
        self.select_key(&scoped_key(call_id, scope))
            .answer_in(scope, call_id, from_tag, to_tag, sdp, flags)
            .await
    }

    /// Send a `delete` under `scope` and drop the engine call's affinity.
    pub async fn delete_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let framed = framed(scope);
        let scope = framed.as_ref();
        let key = scoped_key(call_id, scope);
        let result = self
            .select_key(&key)
            .delete_in(scope, call_id, from_tag)
            .await;
        self.affinity.remove(key.as_ref());
        result
    }

    /// Tear down a whole call under `scope` by id, on the instance that holds
    /// it.
    ///
    /// Affinity may not know this call — a reap runs before any of them were
    /// offered here — so it is sent to each instance until one accepts.
    pub async fn delete_call_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
    ) -> Result<(), RtpEngineError> {
        let framed = framed(scope);
        let scope = framed.as_ref();
        let key = scoped_key(call_id, scope);
        let mut last: Option<RtpEngineError> = None;
        for client in &self.clients {
            match client.delete_in(scope, call_id, "").await {
                Ok(()) => {
                    self.affinity.remove(key.as_ref());
                    return Ok(());
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            RtpEngineError::Protocol("no media engine to delete on".to_string())
        }))
    }
}

#[cfg(test)]
#[path = "per_call_tests.rs"]
mod tests;
