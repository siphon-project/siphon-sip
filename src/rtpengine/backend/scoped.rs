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

use std::borrow::Cow;

use super::MediaBackend;
use crate::rtpengine::error::RtpEngineError;
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

impl MediaBackend {
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
            Self::SiphonRtp(set) => set.delete_in(Some(scope), call_id, from_tag).await,
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
