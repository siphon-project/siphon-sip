//! X2 for what siphon sends to a target.
//!
//! Interception records what siphon receives ([`super::intercept`]). Everything
//! siphon generates itself toward a target (a local answer, a 100 Trying, a
//! teardown, a NOTIFY, the copy a B2BUA builds for the dialled leg) leaves
//! through [`crate::transport::OutboundRouter::deliver`] and arrives nowhere, so
//! it is recorded here as it leaves. Together the two are every SIP message to
//! and from the target's user agent (TS 103 221-2 clause 5.2.6: direction 2 for
//! what is sent to the target, 3 for what is received from it).
//!
//! This runs on the transport send path, which any thread reaches, a thread
//! attached to Python included. So it never attaches to Python, never blocks
//! (the X2 channel is `try_send`) and holds no lock across anything but a map
//! lookup. A node with nothing intercepted pays one relaxed load per frame.
//!
//! Only X2 is emitted. The session's lifecycle (`note_message`) is driven by
//! what arrives: a BYE or 487 siphon sends does not end the session, and does
//! not detach X3.

use std::net::SocketAddr;

use bytes::Bytes;

use super::inbound::{message_instance_key, top_via_branch};
use super::request::to_has_tag;
use crate::b2bua::actor::CallActorStore;
use crate::li::{AuditOperation, Identities, IriEventType, LiManager, MessageFacts};
use crate::sip::message::{SipMessage, StartLine};
use crate::sip::parser::parse_sip_message_bytes;

/// The manager and call store the tap works against: the process's, or in a
/// test the ones it installed ([`tests_support::install`]). Everything else
/// the tap does, its gate included, is the same code.
fn with_tap<R>(work: impl FnOnce(&LiManager, Option<&CallActorStore>) -> R) -> Option<R> {
    #[cfg(test)]
    let work = match tests_support::with_installed(work) {
        Ok(result) => return Some(result),
        Err(work) => work,
    };
    let li = crate::server::li_manager_ref()?;
    let store = crate::b2bua::actor::global_call_store();
    Some(work(li, store.map(|store| &**store)))
}

/// Whether the tap has anything to do on `li`: some session is warranted, or
/// a warrant exists that an initial INVITE siphon originates may open one for.
fn tap_is_wanted(li: &LiManager) -> bool {
    li.any_warranted_session() || li.any_active_task()
}

/// Whether the outbound tap has anything to do. For a caller that would copy a
/// frame only to tap it.
pub(crate) fn li_tap_wanted() -> bool {
    with_tap(|li, _| tap_is_wanted(li)).unwrap_or(false)
}

/// Record one frame that is about to leave, if it goes to the target of a
/// warrant.
///
/// `relayed` frames are a proxy passing on what it received, already recorded
/// as it arrived: they are only marked as seen, so that a transaction
/// retransmission of the same bytes (which does not carry the flag) is not
/// taken for a new message.
pub(crate) fn li_tap_outbound(
    frame: &Bytes,
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    relayed: bool,
) {
    with_tap(|li, store| {
        if tap_is_wanted(li) {
            tap_frame(li, store, frame, destination, source_local_addr, relayed);
        }
    });
}

/// [`li_tap_outbound`] against a given manager and call store.
pub(crate) fn tap_frame(
    li: &LiManager,
    store: Option<&CallActorStore>,
    frame: &Bytes,
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    relayed: bool,
) {
    // An initial INVITE siphon sends on a Call-ID nothing has resolved (a call
    // it originates) may open a warranted session, but only while a warrant
    // exists.
    let may_decide = !relayed && li.any_active_task() && frame.starts_with(b"INVITE ");
    if !li.any_warranted_session() && !may_decide {
        return;
    }
    // A header scan first: a frame of a call that is not intercepted is not
    // parsed.
    let Some(call_id) = crate::capture::call_id_from_bytes(frame) else {
        return;
    };
    let owner_of = || store.and_then(|store| super::intercept::owner_of_leg(store, &call_id));
    // The leg's session before anything is parsed: a frame of a call that is
    // not intercepted costs the header scan and one lookup.
    let leg = li.outbound_leg(&call_id, owner_of);
    if leg.is_none() && !may_decide {
        return;
    }
    let Ok(message) = parse_sip_message_bytes(frame) else {
        return;
    };

    let request_uri = match &message.start_line {
        StartLine::Request(request_line) => Some(request_line.request_uri.to_string()),
        StartLine::Response(_) => None,
    };
    let from_uri = message.headers.get("From").map(String::as_str);
    let to_uri = message.headers.get("To").map(String::as_str);
    let method = match &message.start_line {
        StartLine::Request(request_line) => request_line.method.as_str(),
        StartLine::Response(_) => message
            .headers
            .get("CSeq")
            .and_then(|cseq| cseq.split_whitespace().nth(1))
            .unwrap_or("UNKNOWN"),
    };
    let status_code = match &message.start_line {
        StartLine::Request(_) => None,
        StartLine::Response(status_line) => Some(status_line.status_code),
    };
    let facts = MessageFacts {
        request: matches!(message.start_line, StartLine::Request(_)),
        method,
        status_code,
        to_tagged: to_has_tag(&message),
        branch: top_via_branch(&message),
    };
    let identities = Identities {
        request_uri: request_uri.as_deref(),
        from_uri,
        to_uri,
        source_ip: None,
    };

    let session_id = match leg {
        Some(session_id) => session_id,
        None => match li.decide_outbound_invite(&call_id, &facts, &identities, owner_of) {
            Some(session_id) => session_id,
            None => return,
        },
    };
    let Some(session) = li.outbound_matches(session_id, &call_id, &facts, &identities) else {
        return;
    };
    if session.matches.is_empty() {
        return;
    }
    // A retransmission is the same frame again, not another message.
    if !li.record_message_once(&session.session_id, outbound_instance_key(&message)) {
        return;
    }
    if relayed {
        return;
    }

    let event_type = event_type_of(&facts);
    let source_ip = source_local_addr
        .map(|address| address.ip())
        .or_else(|| crate::transport::cached_routable_local_ip(destination.is_ipv6()));
    for matched in &session.matches {
        let x_id = matched.task.details.x_id;
        let mut event = li.build_iri_event(
            matched,
            event_type,
            &call_id,
            &session.session_id,
            method,
            status_code,
            from_uri.unwrap_or_default(),
            to_uri.unwrap_or_default(),
            request_uri.clone(),
            source_ip,
            Some(frame.to_vec()),
        );
        event.destination_ip = Some(destination.ip());
        li.emit_iri(event);
        li.tasks().mark_intercept(x_id);
        li.audit(
            AuditOperation::InterceptMatch,
            Some(&x_id.to_string()),
            format!(
                "method={method} call_id={call_id} session={} delivery={} event={event_type:?} party={:?} sent",
                session.session_id, matched.task.details.delivery_type, matched.party
            ),
        );
    }
}

/// What tells one message siphon generates from a resend of it: the inbound
/// key (top Via branch, CSeq, method or status) and, for the provisionals of
/// one transaction that differ only there, the RSeq of a reliable one
/// (RFC 3262 §3) and the tag of the dialog it answers on. Retransmissions are
/// the same bytes, so they keep the key.
fn outbound_instance_key(message: &SipMessage) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut key = message_instance_key(message);
    for name in ["RSeq", "To"] {
        for byte in message
            .headers
            .get(name)
            .map(String::as_str)
            .unwrap_or_default()
            .bytes()
        {
            key = (key ^ u64::from(byte)).wrapping_mul(PRIME);
        }
        key = (key ^ 0xff).wrapping_mul(PRIME);
    }
    key
}

/// The event type of a frame siphon sends, from its shape alone: the
/// session's lifecycle belongs to what arrives.
fn event_type_of(facts: &MessageFacts<'_>) -> IriEventType {
    if facts.opens_dialog() {
        IriEventType::Begin
    } else if facts.request && facts.method == "BYE" {
        IriEventType::End
    } else {
        IriEventType::Continue
    }
}

/// Let a test point the tap at its own manager and call store: the production
/// one is a process-wide singleton, which parallel tests cannot share. Held
/// per thread, which is where a test's current-thread runtime runs its tasks.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Arc;

    thread_local! {
        static TAP: RefCell<Option<(LiManager, Option<Arc<CallActorStore>>)>> =
            const { RefCell::new(None) };
    }

    /// Stops pointing the tap at the test's manager when dropped.
    pub(crate) struct TapGuard;

    impl Drop for TapGuard {
        fn drop(&mut self) {
            TAP.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// Route this thread's outbound taps to `li` and `store`.
    pub(crate) fn install(li: &LiManager, store: Option<Arc<CallActorStore>>) -> TapGuard {
        TAP.with(|slot| *slot.borrow_mut() = Some((li.clone(), store)));
        TapGuard
    }

    /// Run `work` on the installed manager, or hand it back when a test
    /// installed none.
    pub(super) fn with_installed<R, F>(work: F) -> Result<R, F>
    where
        F: FnOnce(&LiManager, Option<&CallActorStore>) -> R,
    {
        TAP.with(|slot| match slot.borrow().as_ref() {
            Some((li, store)) => Ok(work(li, store.as_deref())),
            None => Err(work),
        })
    }
}
