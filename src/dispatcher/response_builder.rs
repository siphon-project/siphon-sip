//! Building responses and the ACK for a non-2xx.
//!
//! `build_response` is the single highest fan-in helper in the dispatcher (31
//! callers): every locally-generated status, from a 100 Trying to a 483, comes
//! through here, which is why the reply-header ops and the Record-Route echo
//! live with it.

use super::*;

/// Stamp the UAS To-tag of a B2BUA A-leg dialog onto a locally-generated
/// response.
///
/// RFC 3261 §8.2.6.2: a UAS MUST put a tag in the To header of every response
/// but 100, and siphon is the UAS on the A-leg. [`build_response`] copies the
/// request's To verbatim, which for a dialog-forming INVITE has no tag yet, so
/// any response siphon answers itself has to add the tag the A-leg dialog was
/// created with — the same one the caller saw on our provisionals, so a final
/// response terminates the dialog it belongs to.
///
/// No-op when the To header already carries a tag (an in-dialog request) or is
/// absent.
pub(super) fn stamp_uas_to_tag(response: &mut SipMessage, local_tag: &str) {
    if let Some(to) = response.headers.to() {
        let tagged = crate::b2bua::actor::ensure_tag(to, Some(local_tag));
        response.headers.set("To", tagged);
    }
}

/// Stamp the UAS To-tag *and* restore the caller's own From/To onto a
/// locally-generated A-leg response (RFC 3261 §8.2.6.2).
///
/// [`stamp_uas_to_tag`] fixes the tag; this also fixes the URIs. Every one of
/// these responses is built by [`build_response`] from the **stored** A-leg
/// INVITE, which is the shared buffer `@b2bua.on_invite` reshapes for the B-leg
/// — `call.rewrite_identities()`, `set_from_user` / `set_to_user`, a
/// `number_policy`. So a handler that normalised the caller's number for the
/// dial plan and then rejected the call answered it with a From/To it never
/// sent, which §8.2.6.2 does not allow: the response From MUST equal the
/// request's, and the response To MUST equal the request's To plus our tag.
///
/// `stored_from` / `stored_to` are the A-leg's arrival snapshot. Falls back to
/// tag-only stamping when there is none, which is the previous behaviour.
pub(super) fn stamp_uas_echo(
    response: &mut SipMessage,
    stored_from: Option<&String>,
    stored_to: Option<&String>,
    local_tag: &str,
) {
    if let Some(from) = stored_from {
        response.headers.set("From", from.clone());
    }
    match stored_to {
        Some(to) => {
            let tagged = crate::b2bua::actor::ensure_tag(to, Some(local_tag));
            response.headers.set("To", tagged);
        }
        None => stamp_uas_to_tag(response, local_tag),
    }
}

/// Whether a response to `request` with this status establishes a dialog (or
/// opens an early one), and so owes the Record-Route echo of RFC 3261 §12.1.1.
///
/// Three conditions, all of them necessary:
///
/// - **The method can form a dialog.** INVITE (§12.1.1), SUBSCRIBE (RFC 6665
///   §4.1.2) and REFER (RFC 3515 §2.4.4 — its implicit subscription). Nothing
///   else a UAS answers creates one. RFC 3265's dialog-forming NOTIFY is
///   deliberately absent: RFC 6665 §4.4.1 moved dialog creation onto the
///   SUBSCRIBE 2xx, and an out-of-dialog NOTIFY is answered 481 now.
/// - **The request is an initial one** — its To carries no tag. A re-INVITE or
///   an in-dialog REFER targets a dialog that already exists, and §12.2.1.2
///   forbids the UAC updating its route set from a mid-dialog response, so an
///   echo there is noise at best.
/// - **The status can establish one.** A 2xx does. A provisional above 100 does
///   when it carries a To tag (§12.1.2); 100 Trying never does. We do not test
///   for that tag, because the caller may stamp it after us via a reply header
///   — and a Record-Route on a tagless provisional is inert, since the UAC
///   builds no dialog from it and so reads nothing off it.
pub(super) fn response_establishes_dialog(request: &SipMessage, status_code: u16) -> bool {
    if !(101..300).contains(&status_code) {
        return false;
    }
    if !matches!(
        request.method(),
        Some(Method::Invite) | Some(Method::Subscribe) | Some(Method::Refer)
    ) {
        return false;
    }
    request.headers.to().is_some_and(|to| !to.contains(";tag="))
}

/// Build a SIP response from a request, copying mandatory headers.
pub(super) fn build_response(
    request: &SipMessage,
    status_code: u16,
    reason: &str,
    server_header: Option<&str>,
    reply_headers: &[(crate::script::api::request::ReplyHeaderOp, String, String)],
) -> SipMessage {
    use crate::script::api::request::ReplyHeaderOp;

    let mut builder = SipMessageBuilder::new().response(status_code, reason.to_string());

    // Copy all Via headers (response routing depends on this)
    if let Some(vias) = request.headers.get_all("Via") {
        for via in vias {
            builder = builder.via(via.clone());
        }
    }

    // Copy From, To, Call-ID, CSeq (mandatory in all responses per RFC 3261 §8.2.6.2)
    if let Some(from) = request.headers.from() {
        builder = builder.from(from.clone());
    }
    if let Some(to) = request.headers.to() {
        builder = builder.to(to.clone());
    }
    if let Some(call_id) = request.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }
    if let Some(cseq) = request.headers.cseq() {
        builder = builder.cseq(cseq.clone());
    }

    // RFC 3261 §12.1.1 — a UAS answering a dialog-forming request MUST copy
    // *every* Record-Route value from the request into the response that
    // establishes the dialog, in order, with all URI and header parameters
    // intact, "whether they are known or unknown to the UAS". The UAC reverses
    // that list to build its route set (§12.1.2), so dropping one entry hands
    // the peer a route set short by exactly one hop.
    //
    // This is protocol, not policy, which is why it lives here rather than in
    // each script: the rule is the same for every UAS, and a script could not
    // satisfy it anyway — `get_header` reads one value, so a request spreading
    // Record-Route over several lines was unreadable from Python until
    // `get_headers` landed alongside this.
    //
    // Lines are copied verbatim rather than parsed and re-emitted: a parameter
    // we do not understand still has to survive, and re-serializing is exactly
    // what cannot promise that.
    //
    // A script that wants something else still wins — the `reply_headers` loop
    // below runs after this, so `set_reply_header("Record-Route", …)` replaces
    // what we copied.
    if response_establishes_dialog(request, status_code) {
        if let Some(record_routes) = request.headers.get_all("Record-Route") {
            for record_route in record_routes {
                builder = builder.header("Record-Route", record_route.clone());
            }
        }
    }

    // Copy any auth challenge headers the script may have set.
    //
    // ALL values, not just the first: `auth.require_*_digest` stacks one
    // challenge per algorithm (MD5 + SHA-256 + SHA-512-256, RFC 7616 §3.7) so a
    // single 401/407 serves both RFC 2617 and RFC 7616 clients. Copying only
    // `get()` put the weakest one on the wire and silently dropped the rest,
    // which no client could then negotiate up from.
    for name in ["WWW-Authenticate", "Proxy-Authenticate"] {
        if let Some(values) = request.headers.get_all(name) {
            for value in values {
                builder = builder.header(name, value.clone());
            }
        }
    }

    // Copy Expires header for REGISTER responses (RFC 3261 §10.3 step 8).
    // The registrar.save() method sets this on the request to communicate
    // the granted expires value to the response builder.
    if let Some(expires) = request.headers.get("Expires") {
        builder = builder.header("Expires", expires.clone());
    }

    // Copy SIP-ETag for PUBLISH responses (RFC 3903 §4.1)
    if let Some(sip_etag) = request.headers.get("SIP-ETag") {
        builder = builder.header("SIP-ETag", sip_etag.clone());
    }

    if let Some(server) = server_header {
        builder = builder.header("Server", server.to_string());
    }

    // Inject script-provided reply headers before Content-Length so that
    // parsers that stop at Content-Length: 0 still see them.
    //
    // Replace semantics for `set_reply_header` are critical here: the
    // mandatory-copy block above already populated To/From/Call-ID/CSeq
    // and the optional-copy block populated Expires/SIP-ETag/Server.
    // A script calling `set_reply_header("To", "<...>;tag=...")` to add
    // a UAS-side To-tag (RFC 3261 §12.1.1.2 / RFC 6665 §4.1.3) MUST end
    // up with exactly one To header — append-only would produce two.
    // `add_reply_header` (op = Add) is reserved for genuinely multi-value
    // headers (Service-Route, P-Associated-URI, Path, etc.).
    for (op, name, value) in reply_headers {
        match op {
            ReplyHeaderOp::Replace => {
                builder = builder.set_header(name, value.clone());
            }
            ReplyHeaderOp::Add => {
                builder = builder.header(name, value.clone());
            }
        }
    }

    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("response builder failed (this should not happen): {error}");
            // Construct a minimal valid response directly
            SipMessage {
                start_line: StartLine::Response(StatusLine {
                    version: Version::sip_2_0(),
                    status_code: 500,
                    reason_phrase: "Internal Server Error".to_string(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Build an ACK for a non-2xx final response to INVITE (RFC 3261 §17.1.1.3).
///
/// The ACK is hop-by-hop: each proxy generates its own for non-2xx.
/// - Request-URI: same as the original INVITE
/// - Via: only our own Via (the branch that created the client transaction)
/// - From: from the original request
/// - To: from the response (includes To-tag added by UAS)
/// - Call-ID: from the original request
/// - CSeq: same sequence number, ACK method
/// - Route: same as original INVITE (if any)
pub(super) fn build_ack_for_non2xx(
    original_request: &SipMessage,
    response: &SipMessage,
    branch: &str,
    downstream_transport: Transport,
    local_addr: SocketAddr,
) -> SipMessage {
    let request_uri = match &original_request.start_line {
        StartLine::Request(rl) => rl.request_uri.clone(),
        _ => SipUri::new("invalid".to_string()),
    };

    let mut builder = SipMessageBuilder::new().request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    let host = format_sip_host(&local_addr.ip().to_string());
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        host,
        local_addr.port(),
        branch
    ));

    if let Some(from) = original_request.headers.from() {
        builder = builder.from(from.clone());
    }

    // To: from the response (includes To-tag from UAS)
    if let Some(to) = response.headers.to() {
        builder = builder.to(to.clone());
    }

    if let Some(call_id) = original_request.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }

    // CSeq: same sequence number, ACK method
    if let Some(cseq) = original_request.headers.cseq() {
        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
        builder = builder.cseq(format!("{} ACK", cseq_num));
    }

    // Route: copy from original request if present
    if let Some(routes) = original_request.headers.get_all("Route") {
        for route in routes {
            builder = builder.header("Route", route.clone());
        }
    }

    builder = builder.header("Max-Forwards", "70".to_string());
    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("ACK builder failed (this should not happen): {error}");
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
