//! The media verbs a script may run under a **per-call scope**.
//!
//! Two legs of one call that the same siphon anchors separately share a
//! Call-ID: a proxy relays a request without changing it (RFC 3261 §16.6), so
//! the originating and the terminating leg of a call between two users of one
//! edge proxy arrive under one Call-ID. Each engine needs a distinct key for
//! each leg, and each backend makes one its own way:
//!
//! * **siphon-rtp** keys a call by `(scope, call_id)`. The frame carries the
//!   per-call scope where it would carry the node's own
//!   (`media.siphon_rtp.scope`), and the Call-ID is sent as it is.
//! * **rtpengine** and **rtpproxy** know a call by its call-id alone, so the
//!   engine call-id of a scoped leg is `<call-id>;<scope>`. A scope holds no
//!   `;` and a SIP Call-ID holds none either (RFC 3261 §25.1 `word`), so every
//!   `(Call-ID, scope)` names its own engine call, and none can be some
//!   unscoped call's. Each leg is then an ordinary engine call: its own
//!   monologues, its own address family, its own delete.
//!
//! `None` is the node's own scope, and every backend sends exactly what it
//! always has.
//!
//! The verbs here take the scope as an argument. Every other verb that
//! addresses a call (prompts, DTMF, gating, recording, subscriptions, tees,
//! bridges) reaches a scoped leg through [`MediaBackend::leg`], which names the
//! leg the way its backend knows it: the engine call-id for rtpengine and
//! rtpproxy, the frame's scope for siphon-rtp.
//!
//! Events come back the same way on every backend: a scoped leg's under its
//! engine call-id, which [`split_engine_call_id`] turns back into the SIP
//! Call-ID and the scope.

use std::borrow::Cow;
use std::future::Future;

use super::MediaBackend;
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::events::RtpEngineEvent;
use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::siphon_rtp::CallScope;

/// The call-id rtpengine and rtpproxy know the leg of `call_id` under `scope`
/// by: `<call-id>;<scope>`, or the Call-ID itself without a scope.
pub fn engine_call_id<'a>(call_id: &'a str, scope: Option<&CallScope>) -> Cow<'a, str> {
    match scope {
        Some(scope) => Cow::Owned(format!("{call_id};{scope}")),
        None => Cow::Borrowed(call_id),
    }
}

/// The SIP Call-ID and the per-call scope of an engine call-id: the inverse of
/// [`engine_call_id`]. An id with no `;`, or whose suffix is no scope, is a
/// Call-ID of its own: a SIP Call-ID never holds a `;` (RFC 3261 §25.1), so
/// only an engine call-id siphon composed has one.
pub fn split_engine_call_id(engine_call_id: &str) -> (&str, Option<CallScope>) {
    if let Some((call_id, scope)) = engine_call_id.rsplit_once(';') {
        if let Ok(scope) = CallScope::per_call(scope) {
            if !call_id.is_empty() {
                return (call_id, Some(scope));
            }
        }
    }
    (engine_call_id, None)
}

/// Rewrite an event of a leg anchored under a per-call scope to name the SIP
/// Call-ID, returning the scope. Every backend reports such a leg under its
/// engine call-id; a script sees the Call-ID it anchored and the scope beside
/// it. `None` (and the event unchanged) for the node's own calls.
pub fn split_event_scope(event: &mut RtpEngineEvent) -> Option<CallScope> {
    let call_id = event.call_id_mut()?;
    let (sip_call_id, scope) = split_engine_call_id(call_id);
    let scope = scope?;
    *call_id = sip_call_id.to_string();
    Some(scope)
}

/// The key siphon's own per-leg bookkeeping (playbacks, recordings) holds a
/// leg's engine call by: its engine call-id, whichever way the verb reached it
/// (an engine call-id already composed for rtpengine and rtpproxy, or a
/// siphon-rtp frame scope set for the task).
pub(super) fn leg_key(call_id: &str) -> Cow<'_, str> {
    match crate::rtpengine::siphon_rtp::frame_scope() {
        Some(scope) => Cow::Owned(engine_call_id(call_id, Some(&scope)).into_owned()),
        None => Cow::Borrowed(call_id),
    }
}

/// One leg's engine call, as a media verb addresses it: from
/// [`MediaBackend::leg`].
///
/// ```ignore
/// let leg = backend.leg(&call_id, scope.as_ref());
/// leg.run(backend.stop_media(leg.call_id(), &from_tag, None)).await
/// ```
#[derive(Debug, Clone)]
pub struct ScopedLeg {
    /// The call-id the verb names: the Call-ID, or for rtpengine and rtpproxy
    /// a scoped leg's engine call-id.
    call_id: String,
    /// The per-call scope of the leg; `None` for the node's call.
    scope: Option<CallScope>,
    /// Whether the verb runs under `scope` as a siphon-rtp frame scope.
    in_frame: bool,
}

impl ScopedLeg {
    /// The call-id to hand the verb.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The leg's per-call scope; `None` for the node's call.
    pub fn scope(&self) -> Option<&CallScope> {
        self.scope.as_ref()
    }

    /// Run `verb`, built against [`Self::call_id`], on the leg.
    pub async fn run<F: Future>(&self, verb: F) -> F::Output {
        match (&self.scope, self.in_frame) {
            (Some(scope), true) => {
                crate::rtpengine::siphon_rtp::in_frame_scope(scope.clone(), verb).await
            }
            _ => verb.await,
        }
    }
}

impl MediaBackend {
    /// The leg of `call_id` anchored under `scope` (the node's call when
    /// `None`), as the configured backend addresses it.
    pub fn leg(&self, call_id: &str, scope: Option<&CallScope>) -> ScopedLeg {
        let in_frame = matches!(self, Self::SiphonRtp(_));
        let engine_call_id = match in_frame {
            true => Cow::Borrowed(call_id),
            false => engine_call_id(call_id, scope),
        };
        ScopedLeg {
            call_id: engine_call_id.into_owned(),
            scope: scope.cloned(),
            in_frame,
        }
    }

    /// Whether `scope` is the node's own: the one every frame already carries
    /// (`media.siphon_rtp.scope`). A per-call scope equal to it names the
    /// node's call, not a call of its own. rtpengine and rtpproxy have no node
    /// scope.
    pub fn is_node_scope(&self, scope: &CallScope) -> bool {
        match self {
            Self::SiphonRtp(set) => set.node_scope() == Some(scope),
            Self::RtpEngine(_) | Self::RtpProxy(_) => false,
        }
    }

    /// [`MediaBackend::offer`] under `scope`.
    pub async fn offer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let Some(scope) = scope else {
            return self.offer(call_id, from_tag, sdp, flags).await;
        };
        match self {
            Self::SiphonRtp(set) => {
                set.offer_in(Some(scope), call_id, from_tag, sdp, flags)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                self.offer(&engine_call_id(call_id, Some(scope)), from_tag, sdp, flags)
                    .await
            }
        }
    }

    /// [`MediaBackend::reoffer`] under `scope`.
    pub async fn reoffer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let Some(scope) = scope else {
            return self.reoffer(call_id, from_tag, sdp, flags).await;
        };
        match self {
            Self::SiphonRtp(set) => {
                set.reoffer_in(Some(scope), call_id, from_tag, sdp, flags)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                self.reoffer(&engine_call_id(call_id, Some(scope)), from_tag, sdp, flags)
                    .await
            }
        }
    }

    /// [`MediaBackend::answer`] under `scope`.
    pub async fn answer_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let Some(scope) = scope else {
            return self.answer(call_id, from_tag, to_tag, sdp, flags).await;
        };
        match self {
            Self::SiphonRtp(set) => {
                set.answer_in(Some(scope), call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                let engine_call_id = engine_call_id(call_id, Some(scope));
                self.answer(&engine_call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
        }
    }

    /// [`MediaBackend::delete`] under `scope`.
    ///
    /// A scoped leg is never a conference seat (rooms take no scope), so its
    /// delete is only the engine call's.
    pub async fn delete_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let Some(scope) = scope else {
            return self.delete(call_id, from_tag).await;
        };
        match self {
            Self::SiphonRtp(set) => {
                // What `delete` drops for a call, dropped for the leg, keyed as
                // the leg's verbs keyed it.
                let key = engine_call_id(call_id, Some(scope));
                super::ACTIVE_PLAYBACKS.remove(&(key.to_string(), from_tag.to_string()));
                Self::recordings_session_ended(&key, std::time::Instant::now());
                set.delete_in(Some(scope), call_id, from_tag).await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                self.delete(&engine_call_id(call_id, Some(scope)), from_tag)
                    .await
            }
        }
    }

    /// [`MediaBackend::delete_call`] under `scope`: the whole engine call,
    /// tags unknown. rtpproxy cannot delete without a tag and says so.
    pub async fn delete_call_in(
        &self,
        scope: Option<&CallScope>,
        call_id: &str,
    ) -> Result<(), RtpEngineError> {
        let Some(scope) = scope else {
            return self.delete_call(call_id).await;
        };
        match self {
            Self::SiphonRtp(set) => set.delete_call_in(Some(scope), call_id).await,
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                self.delete_call(&engine_call_id(call_id, Some(scope)))
                    .await
            }
        }
    }
}

#[cfg(test)]
#[path = "scoped_tests.rs"]
mod tests;
