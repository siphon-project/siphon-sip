//! Building the messages a B2BUA leg sends on its own behalf.
//!
//! BYE, PRACK and the ACK for a non-2xx, each built from the leg dialog rather
//! than copied from the far side.

use crate::dispatcher::*;

pub fn build_b2bua_ack_for_non2xx(
    response: &SipMessage,
    branch: &str,
    target_uri: Option<&str>,
    downstream_transport: Transport,
    via_host: &str,
    via_port: u16,
) -> SipMessage {
    let request_uri = target_uri
        .and_then(|uri| parse_uri_standalone(uri).ok())
        .unwrap_or_else(|| SipUri::new("invalid".to_string()));

    let mut builder = SipMessageBuilder::new().request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch.
    //
    // The sent-by host:port MUST equal the top Via of the INVITE this ACK
    // acknowledges (RFC 3261 §17.1.1.3).  The trunk's server transaction keys
    // its ACK match on (branch, sent-by host:port, method) per §17.2.3, so the
    // host:port has to be the *advertised* address the INVITE went out with
    // (state.via_host/via_port) — NOT the raw bind address.  When this used
    // `local_addr`, an ACK with an internal sent-by reached a trunk that had
    // only ever seen the advertised one; the ACK never matched, so the trunk
    // kept retransmitting its 401/4xx on Timer G until the credentialed retry
    // happened to succeed.
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch
    ));

    // From: same as in the response (which echoes the B-leg INVITE's From)
    if let Some(from) = response.headers.from() {
        builder = builder.from(from.clone());
    }

    // To: from the response (includes To-tag from UAS)
    if let Some(to) = response.headers.to() {
        builder = builder.to(to.clone());
    }

    // Call-ID: same as in the response (B-leg Call-ID)
    if let Some(call_id) = response.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }

    // CSeq: same sequence number, ACK method
    if let Some(cseq) = response.headers.cseq() {
        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
        builder = builder.cseq(format!("{} ACK", cseq_num));
    }

    builder = builder.header("Max-Forwards", "70".to_string());
    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("B2BUA ACK builder failed (this should not happen): {error}");
            SipMessage {
                start_line: StartLine::Request(RequestLine {
                    method: Method::Ack,
                    request_uri: SipUri::new("invalid".to_string()),
                    version: Version::sip_2_0(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Send a SIP message to the B-leg, using the TCP connection pool for TCP/TLS
/// or the direct outbound channel for UDP. This ensures in-dialog messages
/// (ACK, BYE) reach the B-leg over the correct transport.
/// Build a clean in-dialog BYE for a B2BUA leg from stored dialog state.
///
/// A B2BUA generates new requests — it does NOT forward the other leg's BYE.
/// The BYE uses only the target leg's dialog identifiers (Call-ID, From/To
/// tags), route set, Contact, and CSeq. No headers from the originating leg
/// are included.
pub fn build_b2bua_bye(
    leg: &crate::b2bua::actor::Leg,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let dialog = &leg.dialog;

    // R-URI: remote Contact (RFC 3261 §12.2.1.1)
    let ruri = dialog
        .remote_contact
        .as_deref()
        .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
        .unwrap_or_else(|| {
            dialog
                .target_uri
                .as_deref()
                .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
                .unwrap_or_else(|| SipUri::new("invalid".to_string()))
        });

    let transport_str = format!("{}", leg.transport.transport).to_uppercase();
    let branch = TransactionKey::generate_branch();
    // Via sent-by is the socket this leg is anchored on — the A-leg's arrival
    // socket on a multi-homed host, the B-leg's flow socket when it was dialled
    // over one — so the response comes back to where the request left from.
    // Unanchored legs and single-listener hosts fall back to the per-transport
    // identity, unchanged.
    let (via_host, via_port) = leg_sent_by(leg, state);
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch,
    );

    // From/To: use stored URI strings from the dialog-creating INVITE
    // and stitch in the dialog tags via ensure_tag. Tags are stored
    // separately (local_tag / remote_tag) and must be present for the
    // remote endpoint to match BYE to the dialog (RFC 3261 §12.2.1.1).
    let from_header = match &dialog.local_from_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, Some(&dialog.local_tag)),
        None => format!(
            "<{}>;tag={}",
            dialog.local_contact.as_deref().unwrap_or("sip:invalid"),
            dialog.local_tag,
        ),
    };
    let to_header = match &dialog.remote_to_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, dialog.remote_tag.as_deref()),
        None => {
            let to_uri = dialog
                .remote_contact
                .as_deref()
                .unwrap_or(dialog.target_uri.as_deref().unwrap_or("sip:invalid"));
            match &dialog.remote_tag {
                Some(tag) => format!("<{}>;tag={}", to_uri, tag),
                None => format!("<{}>", to_uri),
            }
        }
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Bye, ruri)
        .via(via)
        .from(from_header)
        .to(to_header)
        .call_id(dialog.call_id.clone())
        .cseq(format!("{} BYE", dialog.local_cseq))
        .header("Max-Forwards", "70".to_string());

    // Contact: what we advertised to this leg
    if let Some(ref contact) = dialog.local_contact {
        builder = builder.header("Contact", contact.clone());
    }

    // User-Agent / Server header (topology hiding)
    if let Some(ref ua) = state.user_agent_header {
        builder = builder.header("User-Agent", ua.clone());
    } else if let Some(ref srv) = state.server_header {
        builder = builder.header("User-Agent", srv.clone());
    }

    // Route headers from stored dialog route set (RFC 3261 §12.2.1.1)
    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }

    match builder.content_length(0).build() {
        Ok(msg) => Some(msg),
        Err(error) => {
            warn!("B2BUA: failed to build BYE: {error}");
            None
        }
    }
}

/// The remote target of an early dialog, derived from the reliable provisional
/// response that established it (RFC 3262 §4 / RFC 3261 §12.1.2). Used to build
/// in-dialog requests generated before answer (the auto-PRACK) from THAT
/// response rather than from the single per-Leg `Dialog`, so a downstream fork
/// producing several early dialogs on one INVITE branch routes each request to
/// its own remote target instead of collapsing them onto the first.
pub struct EarlyDialogTarget {
    /// The response `Contact` (RFC 3261 §12.1.2 remote target) → the in-dialog
    /// Request-URI. `None` when the provisional carried no Contact.
    pub remote_contact: Option<String>,
    /// The response `To` value — already carries this early dialog's remote tag
    /// → the in-dialog `To` header.
    pub to_header: Option<String>,
    /// The response `Record-Route`, reversed for the UAC side (RFC 3261
    /// §12.1.2) → the in-dialog route set.
    pub route_set: Vec<String>,
}

/// Extract the early-dialog remote target (Contact, To, route set) from a
/// reliable provisional response. Reuses `extract_contact_uri` and
/// `uac_route_set_from_record_routes` so the PRACK routes exactly as the
/// eventual 2xx-confirmed dialog would.
pub fn early_dialog_target_from_response(response: &SipMessage) -> EarlyDialogTarget {
    let remote_contact = response
        .headers
        .get("Contact")
        .or_else(|| response.headers.get("m"))
        .map(|value| crate::b2bua::actor::extract_contact_uri(value));
    let to_header = response.headers.to().cloned();
    let route_set = uac_route_set_from_record_routes(
        &response
            .headers
            .get_all("Record-Route")
            .cloned()
            .unwrap_or_default(),
    );
    EarlyDialogTarget {
        remote_contact,
        to_header,
        route_set,
    }
}

/// Build an in-dialog PRACK request toward a leg, acknowledging the
/// reliable provisional response identified by `rseq`/`response_cseq_num`.
/// Used by the B2BUA's "auto-PRACK" mode (RFC 3262 §4): when the B-leg
/// sends a 1xx with `Require: 100rel`, siphon answers with a PRACK
/// locally rather than relying on the A-leg (which lives in a different
/// dialog) to do it.
///
/// The remote target (Request-URI, To, route set) comes from `target` — the
/// reliable provisional that established this early dialog (RFC 3261 §12.1.2) —
/// NOT from `leg.dialog`, so forked early dialogs each PRACK their own Contact.
/// `leg` still supplies OUR side (From/local-tag/Contact) and the CSeq counter,
/// which are identical across every early dialog of the leg.
///
/// `local_cseq` MUST already have been incremented for the dialog before
/// calling this — the value passed in is used as-is.
pub fn build_b2bua_prack(
    leg: &crate::b2bua::actor::Leg,
    state: &DispatcherState,
    target: &EarlyDialogTarget,
    rseq: u32,
    response_cseq_num: u32,
    response_cseq_method: &str,
    local_cseq: u32,
) -> Option<SipMessage> {
    // Via sent-by host:port is the socket this leg is anchored on (the A-leg's
    // arrival socket on a multi-homed host, the B-leg's flow socket when it was
    // dialled over one) so the response comes back to the socket the request
    // left from. On the A-leg the host is resolved per address family
    // (dual-stack Gm) so a v6 UE's PRACK carries the v6 identity, not the first
    // configured listener. Unanchored legs and single-listener hosts fall back
    // to the per-transport identity — no change there.
    let (via_host, via_port) = leg_sent_by(leg, state);
    build_b2bua_prack_message(
        &leg.dialog,
        leg.transport.transport,
        &via_host,
        via_port,
        target,
        rseq,
        response_cseq_num,
        response_cseq_method,
        local_cseq,
    )
}

/// Pure PRACK message construction (no `DispatcherState`): the Via sent-by
/// host:port are resolved by the caller. Split out so the RFC 3261 §12.1.2
/// remote-target / To-tag / route-set logic — the part the reliable-provisional
/// bug lives in — is unit-testable against known-answer response bytes.
#[allow(clippy::too_many_arguments)]
pub fn build_b2bua_prack_message(
    dialog: &crate::b2bua::actor::Dialog,
    transport: Transport,
    via_host: &str,
    via_port: u16,
    target: &EarlyDialogTarget,
    rseq: u32,
    response_cseq_num: u32,
    response_cseq_method: &str,
    local_cseq: u32,
) -> Option<SipMessage> {
    // R-URI: the early-dialog remote target — the Contact of the reliable
    // provisional that established this early dialog (RFC 3261 §12.1.2), NOT the
    // To AoR. Falls back to the leg's stored remote_contact, then target_uri,
    // only when the provisional carried no Contact.
    let ruri = target
        .remote_contact
        .as_deref()
        .or(dialog.remote_contact.as_deref())
        .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
        .unwrap_or_else(|| {
            dialog
                .target_uri
                .as_deref()
                .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
                .unwrap_or_else(|| SipUri::new("invalid".to_string()))
        });

    let transport_str = format!("{}", transport).to_uppercase();
    let branch = TransactionKey::generate_branch();
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch,
    );

    let from_header = match &dialog.local_from_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, Some(&dialog.local_tag)),
        None => format!(
            "<{}>;tag={}",
            dialog.local_contact.as_deref().unwrap_or("sip:invalid"),
            dialog.local_tag,
        ),
    };
    // To: the reliable provisional's To — it already carries THIS early
    // dialog's remote tag (RFC 3261 §12.2.1.1). Falls back to the leg's stored
    // remote_to_uri + remote_tag only when the response had no To (defensive).
    let to_header = match &target.to_header {
        Some(to) => to.clone(),
        None => match &dialog.remote_to_uri {
            Some(uri) => crate::b2bua::actor::ensure_tag(uri, dialog.remote_tag.as_deref()),
            None => {
                let to_uri = dialog
                    .remote_contact
                    .as_deref()
                    .unwrap_or(dialog.target_uri.as_deref().unwrap_or("sip:invalid"));
                match &dialog.remote_tag {
                    Some(tag) => format!("<{}>;tag={}", to_uri, tag),
                    None => format!("<{}>", to_uri),
                }
            }
        },
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Prack, ruri)
        .via(via)
        .from(from_header)
        .to(to_header)
        .call_id(dialog.call_id.clone())
        .cseq(format!("{} PRACK", local_cseq))
        .header("Max-Forwards", "70".to_string())
        // RFC 3262 §7.2: RAck = "<rseq> <cseq-num> <cseq-method>".
        .header(
            "RAck",
            format!("{rseq} {response_cseq_num} {response_cseq_method}"),
        );

    if let Some(ref contact) = dialog.local_contact {
        builder = builder.header("Contact", contact.clone());
    }
    // Route set: THIS early dialog's route set (the reliable provisional's
    // Record-Route reversed for the UAC side, RFC 3261 §12.1.2), so a forked
    // early dialog routes over its own proxies rather than the first dialog's.
    for route in &target.route_set {
        builder = builder.header("Route", route.clone());
    }

    match builder.content_length(0).build() {
        Ok(message) => Some(message),
        Err(error) => {
            warn!("B2BUA: failed to build PRACK: {error}");
            None
        }
    }
}
