//! The CANCEL of an INVITE, built from that INVITE as it was sent.
//!
//! RFC 3261 §9.1: "The Request-URI, Call-ID, To, the numeric part of CSeq, and
//! From header fields in the CANCEL request MUST be identical to those in the
//! request being cancelled, including tags. A CANCEL constructed by a client
//! MUST have only a single Via header field value matching the top Via value
//! in the request being cancelled." And: "If the request being cancelled
//! contains a Route header field, the CANCEL request MUST include that Route
//! header field's values."
//!
//! Every one of those is a property of the request on the wire, so the one
//! way to get them all right is to start from it: the INVITE a client
//! transaction retains as the octets it sent, or the INVITE a call leg keeps.

use crate::sip::message::{SipMessage, StartLine};

/// Build the CANCEL for `invite`, the INVITE exactly as it was sent.
///
/// The CANCEL MUST share the topmost Via branch and CSeq sequence number
/// of the request being cancelled — that is the contract that lets the
/// downstream UAS (and every proxy on the path) match the CANCEL to the
/// in-progress server transaction of the INVITE.  Building a CANCEL with
/// a fresh branch, or with the wrong CSeq number, makes every proxy hop
/// return 481 Call/Transaction Does Not Exist and the UAS keeps ringing.
///
/// Other headers (From, To, Call-ID, R-URI, Max-Forwards, Route) are
/// preserved verbatim from the INVITE.  Content-Length is forced to 0;
/// the body is dropped.  Everything else (Contact, Allow, Supported,
/// PAI, Session-Expires, SDP, …) is stripped — CANCEL is hop-by-hop and
/// carries no payload.
///
/// `reasons` are `Reason` header field values to carry (RFC 3326): what a
/// caller's own CANCEL said about why, relayed with the CANCEL of each branch.
///
/// `None` when `invite` is not a request or has no CSeq.
pub fn build_cancel(invite: &SipMessage, reasons: &[String]) -> Option<SipMessage> {
    // Method swap: INVITE → CANCEL on the request line.
    let mut cancel = invite.clone();
    let request_uri = match &mut cancel.start_line {
        StartLine::Request(rl) => {
            rl.method = crate::sip::message::Method::Cancel;
            rl.request_uri.clone()
        }
        StartLine::Response(_) => return None,
    };
    let _ = request_uri; // touched only to enforce the variant guard above

    // CSeq: keep the INVITE's sequence number, swap the method to CANCEL
    // (RFC 3261 §9.1 — "MUST contain the same value for the sequence
    //  number as was present in the request being cancelled, but the
    //  method parameter MUST be equal to CANCEL").
    let cseq_seq = invite
        .headers
        .cseq()?
        .split_whitespace()
        .next()?
        .to_string();
    cancel.headers.set("CSeq", format!("{} CANCEL", cseq_seq));

    // Topmost Via only.  The stashed B-leg INVITE has exactly one Via
    // (siphon overwrites Via on B-leg INVITE build), so set_all with a
    // single value is fine — but be defensive in case the assumption
    // ever drifts.
    if let Some(vias) = invite.headers.get_all("Via") {
        if let Some(top) = vias.first() {
            cancel.headers.set("Via", top.clone());
        }
    }

    // Drop the payload — CANCEL never carries a body.
    cancel.body.clear();
    cancel.headers.set("Content-Length", "0".to_string());

    // Strip headers that have no place on a CANCEL.  We keep:
    //   Via (topmost only — set above)
    //   From, To, Call-ID, CSeq, Max-Forwards, Route
    //   Content-Length
    // Everything else is dropped per RFC 3261 §9.1 + §20 (CANCEL is
    // hop-by-hop, carries no offer/answer, no dialog-establishing data).
    const KEEP: &[&str] = &[
        "via",
        "from",
        "to",
        "call-id",
        "cseq",
        "max-forwards",
        "route",
        "content-length",
    ];
    let to_remove: Vec<String> = cancel
        .headers
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|n| !KEEP.contains(&n.as_str()))
        .collect();
    for name in to_remove {
        cancel.headers.remove(&name);
    }

    for reason in reasons {
        cancel.headers.add("Reason", reason.clone());
    }

    Some(cancel)
}
