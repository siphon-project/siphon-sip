//! Handler selection for a compiled [`ScriptState`].
//!
//! Every dispatch path asks the same question in a different shape: of the
//! handlers this script registered, which ones does *this* event reach? The
//! answer is a filter over one `Vec<HandlerEntry>`, and it is read-only — the
//! state is swapped atomically on reload, never mutated.
//!
//! Kept apart from [`super::engine`], which owns Python initialisation,
//! compilation, and the reload machinery. Selection needs none of that and is
//! the part the dispatcher touches per message.
//!
//! The eight rtpengine event selectors below are the same call-id/from-tag
//! filter eight times over; collapsing them behind one macro is the next edit
//! this module wants.

use super::engine::{HandlerEntry, HandlerKind, ScriptState};

/// A pipe-separated method filter (`"INVITE|SUBSCRIBE"`) matches `method`;
/// no filter matches every method.
fn method_filter_matches(filter: &Option<String>, method: &str) -> bool {
    match filter {
        None => true,
        Some(filter) => filter.split('|').any(|candidate| candidate == method),
    }
}

impl ScriptState {
    /// Return all handlers that match the given kind.
    pub fn handlers_for(&self, kind: &HandlerKind) -> Vec<&HandlerEntry> {
        self.handlers.iter().filter(|h| &h.kind == kind).collect()
    }

    /// Return all `ProxyRequest` handlers whose method filter matches `method`.
    /// A handler with `None` filter matches everything.
    pub fn proxy_request_handlers(&self, method: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::ProxyRequest(filter) => method_filter_matches(filter, method),
                _ => false,
            })
            .collect()
    }

    /// Return all `ProxyReply` handlers whose method filter matches
    /// `request_method`, the method of the request the response answers.
    /// A handler with `None` filter matches every response.
    pub fn proxy_reply_handlers(&self, request_method: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::ProxyReply(filter) => method_filter_matches(filter, request_method),
                _ => false,
            })
            .collect()
    }

    /// All `@diameter.on_request` handlers with their (already-validated)
    /// filter strings, in registration order. The diameter dispatch layer
    /// (`script::diameter_dispatch`) scores these against the inbound request by command
    /// **code** — not name — so the matching vocabulary stays consistent with
    /// decoration-time validation, and the generic engine stays free of any
    /// Diameter-dictionary coupling.
    pub fn diameter_request_handlers(&self) -> impl Iterator<Item = (Option<&str>, &HandlerEntry)> {
        self.handlers
            .iter()
            .filter_map(|handler| match &handler.kind {
                HandlerKind::DiameterOnRequest(filter) => Some((filter.as_deref(), handler)),
                _ => None,
            })
    }

    /// Return all `RtpEngineOnDtmf` handlers whose optional call-id/from-tag
    /// filters match the event.  `None` filters match everything.
    pub fn dtmf_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnDtmf {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnMediaTimeout` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn media_timeout_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnMediaTimeout {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnText` handlers whose optional call-id/from-tag
    /// filters match the event.  `None` filters match everything.
    pub fn text_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnText {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnWsTeeStarted` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn ws_tee_started_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnWsTeeStarted {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnWsTeeEnded` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn ws_tee_ended_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnWsTeeEnded {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnPlayFinished` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn play_finished_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnPlayFinished {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnWsBridgeStarted` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn ws_bridge_started_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnWsBridgeStarted {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnWsBridgeEnded` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn ws_bridge_ended_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnWsBridgeEnded {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnBeep` handlers whose optional call-id/from-tag
    /// filters match the event.  `None` filters match everything.
    pub fn beep_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnBeep {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all [`HandlerKind::Custom`] handlers whose registry key
    /// equals `kind`. The lookup is exact — no globbing or prefix match.
    pub fn handlers_for_custom(&self, kind: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| matches!(&h.kind, HandlerKind::Custom { kind: k } if k == kind))
            .collect()
    }

    /// Whether the script registered any B2BUA handlers.
    pub fn has_b2bua_handlers(&self) -> bool {
        self.handlers.iter().any(|h| {
            matches!(
                h.kind,
                HandlerKind::B2buaInvite
                    | HandlerKind::B2buaAnswer
                    | HandlerKind::B2buaFailure
                    | HandlerKind::B2buaBye
                    | HandlerKind::B2buaRefer
                    | HandlerKind::B2buaRouteFailure
            )
        })
    }

    /// Return all timer handlers.
    pub fn timer_handlers(&self) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| matches!(h.kind, HandlerKind::TimerEvery { .. }))
            .collect()
    }

    /// Whether the script registered any timer handlers.
    pub fn has_timer_handlers(&self) -> bool {
        self.handlers
            .iter()
            .any(|h| matches!(h.kind, HandlerKind::TimerEvery { .. }))
    }
}
