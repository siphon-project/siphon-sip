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
use crate::sip::message::{SipMessage, StartLine};

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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnRecordingFinished` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn recording_finished_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnRecordingFinished {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnMediaStarted` handlers whose optional
    /// call-id/from-tag filters match the event.  `None` filters match
    /// everything.
    pub fn media_started_handlers(&self, call_id: &str, from_tag: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnMediaStarted {
                    call_id: filter_cid,
                    from_tag: filter_ftag,
                } => {
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all `RtpEngineOnActiveSpeaker` handlers whose optional room
    /// filter matches `conference_id`.  A `None` filter matches every room.
    pub fn active_speaker_handlers(&self, conference_id: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnActiveSpeaker {
                    conference_id: filter,
                } => filter.as_deref().is_none_or(|v| v == conference_id),
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
                    filter_cid.as_deref().is_none_or(|v| v == call_id)
                        && filter_ftag.as_deref().is_none_or(|v| v == from_tag)
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
                HandlerKind::B2buaInvite { .. }
                    | HandlerKind::B2buaAnswer
                    | HandlerKind::B2buaFailure
                    | HandlerKind::B2buaBye
                    | HandlerKind::B2buaRefer
                    | HandlerKind::B2buaInfo
                    | HandlerKind::B2buaReoffer
                    | HandlerKind::B2buaReofferAnswered
                    | HandlerKind::B2buaRouteFailure
            )
        })
    }

    /// The `@b2bua.on_invite` handlers an INVITE for `request_uri` runs, in
    /// registration order: every unfiltered one, and every filtered one whose
    /// pattern matches `request_uri`.
    pub fn b2bua_invite_handlers(&self, request_uri: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::B2buaInvite {
                    request_uri: filter,
                } => filter
                    .as_ref()
                    .is_none_or(|filter| filter.matches(request_uri)),
                _ => false,
            })
            .collect()
    }

    /// Whether the script's B2BUA takes an INVITE that matches no B2BUA call,
    /// rather than the proxy path. `message` is the INVITE.
    ///
    /// Without B2BUA handlers it does not. With them it takes every such
    /// INVITE, as it always has, unless every `@b2bua.on_invite` handler
    /// carries a `request_uri` filter. Then it takes an initial INVITE (no
    /// To-tag) whose Request-URI a filter matches, and nothing else: an
    /// in-dialog INVITE that is no B2BUA call's belongs to a dialog the proxy
    /// path set up.
    ///
    /// `control.inbound` takes every INVITE whatever the script says; the
    /// dispatcher asks that first.
    pub fn b2bua_claims_invite(&self, message: &SipMessage) -> bool {
        if !self.has_b2bua_handlers() {
            return false;
        }
        let mut filters = Vec::new();
        for handler in &self.handlers {
            if let HandlerKind::B2buaInvite { request_uri } = &handler.kind {
                match request_uri {
                    Some(filter) => filters.push(filter),
                    None => return true,
                }
            }
        }
        if filters.is_empty() {
            return true;
        }
        let in_dialog = message
            .headers
            .get("To")
            .or_else(|| message.headers.get("t"))
            .is_some_and(|to| {
                to.split(';')
                    .any(|parameter| parameter.trim().starts_with("tag="))
            });
        if in_dialog {
            return false;
        }
        let StartLine::Request(request_line) = &message.start_line else {
            return false;
        };
        let request_uri = request_line.request_uri.to_string();
        filters.iter().any(|filter| filter.matches(&request_uri))
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pyo3::prelude::*;

    use super::*;
    use crate::script::engine::RequestUriFilter;
    use crate::sip::parser::parse_sip_message_bytes;

    fn entry(python: Python<'_>, kind: HandlerKind) -> HandlerEntry {
        HandlerEntry {
            kind,
            callable: std::sync::Arc::new(python.None()),
            is_async: false,
            takes_exchange: false,
            options: None,
            options_value: None,
        }
    }

    fn on_invite(pattern: Option<&str>) -> HandlerKind {
        HandlerKind::B2buaInvite {
            request_uri: pattern.map(|pattern| RequestUriFilter::new(pattern).unwrap()),
        }
    }

    fn state(kinds: Vec<HandlerKind>) -> ScriptState {
        Python::initialize();
        Python::attach(|python| ScriptState {
            source_path: PathBuf::from("<test>"),
            handlers: kinds.into_iter().map(|kind| entry(python, kind)).collect(),
        })
    }

    fn invite(request_uri: &str, to_tag: Option<&str>) -> SipMessage {
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@example.com>;tag={tag}"),
            None => "<sip:bob@example.com>".to_string(),
        };
        let raw = format!(
            "INVITE {request_uri} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1\r\n\
             From: <sip:alice@example.com>;tag=a\r\n\
             To: {to}\r\n\
             Call-ID: claim@192.0.2.10\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        parse_sip_message_bytes(raw.as_bytes()).unwrap()
    }

    #[test]
    fn without_b2bua_handlers_nothing_is_claimed() {
        let state = state(vec![HandlerKind::ProxyRequest(None)]);
        assert!(!state.b2bua_claims_invite(&invite("sip:transfer@example.com", None)));
    }

    #[test]
    fn an_unfiltered_on_invite_claims_every_invite() {
        let state = state(vec![on_invite(Some("^sip:transfer@")), on_invite(None)]);
        assert!(state.b2bua_claims_invite(&invite("sip:bob@example.com", None)));
        assert!(state.b2bua_claims_invite(&invite("sip:bob@example.com", Some("b"))));
    }

    #[test]
    fn b2bua_handlers_without_on_invite_still_claim_every_invite() {
        let state = state(vec![HandlerKind::B2buaBye]);
        assert!(state.b2bua_claims_invite(&invite("sip:bob@example.com", None)));
    }

    #[test]
    fn filtered_handlers_claim_only_the_initial_invites_they_match() {
        let state = state(vec![
            on_invite(Some("^sip:transfer@")),
            on_invite(Some("ssn=")),
            HandlerKind::B2buaBye,
        ]);
        assert!(state.b2bua_claims_invite(&invite("sip:transfer@example.com", None)));
        // Searched, not anchored: a parameter anywhere in the URI matches.
        assert!(state.b2bua_claims_invite(&invite("sip:x@example.com;ssn=1", None)));
        assert!(!state.b2bua_claims_invite(&invite("sip:bob@example.com", None)));
        // In-dialog and no B2BUA call's: a dialog the proxy path set up.
        assert!(!state.b2bua_claims_invite(&invite("sip:transfer@example.com", Some("b"))));
    }

    #[test]
    fn a_claimed_invite_runs_the_matching_and_unfiltered_handlers() {
        let state = state(vec![
            on_invite(Some("^sip:transfer@")),
            on_invite(None),
            on_invite(Some("^sip:other@")),
        ]);
        let selected = state.b2bua_invite_handlers("sip:transfer@example.com");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].kind, on_invite(Some("^sip:transfer@")));
        assert_eq!(selected[1].kind, on_invite(None));
        assert_eq!(state.b2bua_invite_handlers("sip:bob@example.com").len(), 1);
    }
}
