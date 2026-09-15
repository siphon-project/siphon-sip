//! Scrubbing a B2BUA response before it crosses the trust boundary.
//!
//! Strips the far side's identity out of headers and the SDP origin line, so
//! the A-leg sees siphon rather than the B-leg peer.

use super::*;

/// Sanitize a B2BUA response before forwarding it to the A-leg.
///
/// A proper B2BUA terminates and regenerates the dialog, so B-leg-specific
/// headers must not leak to the A-leg. This function:
/// - Replaces Contact with siphon's own address (critical for dialog routing),
///   except on a 3xx, whose Contact is the redirect target
/// - Strips User-Agent (UAC header — not for responses), sets Server
/// - Replaces the B-leg's `Allow` with siphon's own methods and narrows its
///   `Supported` to the tags siphon may claim, under every preset (a B2BUA is a
///   UA in its own right)
/// - Strips B-leg-specific P-Asserted-Identity, P-Charging-Vector
pub(super) fn sanitize_b2bua_response(
    response: &mut SipMessage,
    state: &DispatcherState,
    a_leg_transport: Transport,
    a_leg_local_addr: Option<SocketAddr>,
    call_id: &str,
) {
    sanitize_b2bua_response_keeping(
        response,
        state,
        a_leg_transport,
        a_leg_local_addr,
        call_id,
        &[],
    );
}

/// [`sanitize_b2bua_response`] for a response a script shaped in
/// `@b2bua.on_answer` / `@b2bua.on_early_media`.
///
/// `script_shaped_headers` are the headers the script set or removed on it.
/// They go to the caller as the script left them, precedence 1 as on the B-leg
/// INVITE: the response policy neither strips nor rewrites them, and siphon's
/// own `Supported` / `Allow` do not replace them. What stays the framework's is
/// done regardless: siphon's `Contact`, no B-leg `Record-Route`, the reliability
/// of a provisional (`RSeq` and `100rel` in `Require`, which are siphon's own
/// toward the caller), `replaces` merged into `Supported`, and the SDP origin.
pub(super) fn sanitize_b2bua_response_keeping(
    response: &mut SipMessage,
    state: &DispatcherState,
    a_leg_transport: Transport,
    a_leg_local_addr: Option<SocketAddr>,
    call_id: &str,
    script_shaped_headers: &[String],
) {
    // Contact: must point to siphon so in-dialog requests (ACK, BYE, re-INVITE)
    // route through us, not directly to the B-leg.
    // via_host() applies advertised_address fallback and substitutes the
    // sanitized local_addr when bound to 0.0.0.0/[::] — never leak unspecified.
    // The Contact PORT is the listener the A-leg INVITE actually arrived on
    // (`a_leg_local_addr`), NOT via_port() (the first-configured listener): on a
    // multi-homed host that differs (INVITE to :5066, via_port :5060), and a
    // Contact advertising the wrong port sends every in-dialog request (ACK, BYE,
    // re-INVITE) to a port the dialog isn't anchored on. Falls back to via_port()
    // when the arrival socket is unknown (single-listener hosts, where they match).
    let a_leg_host = state.a_leg_advertised_host(a_leg_local_addr, &a_leg_transport);
    let a_leg_port = a_leg_advertised_port(a_leg_local_addr, state.via_port(&a_leg_transport));
    let contact_value = format!(
        "<sip:{}:{};transport={}>",
        a_leg_host,
        a_leg_port,
        a_leg_transport.to_string().to_lowercase(),
    );
    if !relayed_response_keeps_its_contact(response.status_code()) {
        response.headers.set("Contact", contact_value);
    }

    // Framework-auto strip — `Record-Route` carries the B-leg dialog route
    // set; leaking it to the A-leg breaks RFC 3261 §16 dialog independence
    // and topology hiding (two independent reasons).  No preset can opt in.
    //
    // `Proxy-Authenticate` is hop-by-hop per RFC 3261 §22.3 and every
    // built-in preset strips it (transparent-b2bua@2026 included — an
    // intentional behaviour change vs pre-policy siphon, which passed
    // it through as a latent bug).  Done as a preset strip rather than
    // framework-auto so transparent-proxy B2BUAs can opt back in via
    // `call.dial(copy=["Proxy-Authenticate"])` for the rare case.
    response.headers.remove("Record-Route");

    // Framework-owned — the callee's reliability never crosses.  siphon PRACKs
    // the callee's reliable provisional on the B-leg itself (`auto_prack_b_leg`),
    // so its `RSeq` and `Require: 100rel` describe that leg's numbering, not
    // anything the caller could PRACK; toward the caller siphon is the UAS and a
    // provisional is reliable on siphon's own numbering when the caller asked for
    // that (RFC 3262 §3, `send_a_leg_provisional`).  A plain trunk handed the
    // callee's contract CANCELs rather than PRACKs, and a 100rel caller handed it
    // PRACKs an `RSeq` nobody retransmits.  A correctness invariant, not topology
    // hygiene, so it runs whatever the preset or a script left.  Done before
    // `apply_to_response`, so a `Copy` preset cannot resurrect the removed `RSeq`
    // and the `Require` edit leaves the other option-tags for `Copy` to keep.
    crate::sip::headers::rseq::set_reliability(&mut response.headers, None);

    // Apply per-call header policy.  Resolves to the per-call preset (when
    // the script attached one via `call.dial(header_policy=…)`), otherwise
    // the configured `b2bua.default_header_policy` (defaults to
    // `transparent-b2bua@2026`, which reproduces siphon's pre-policy
    // sanitize_b2bua_response strips — Allow/Allow-Events/Supported/Require/
    // RSeq/Content-Disposition/User-Agent strip + Server rewrite).
    let policy = state.resolve_header_policy(call_id);
    let ctx = crate::b2bua::header_policy::PolicyContext {
        b2bua_host: &a_leg_host,
        b2bua_port: a_leg_port,
        user_agent_header: state.user_agent_header.as_deref(),
        server_header: state.server_header.as_deref(),
    };
    crate::b2bua::header_policy::apply_to_response_keeping(
        response,
        &policy,
        &ctx,
        script_shaped_headers,
    );

    // Advertise siphon's own capabilities, under every preset. A B2BUA terminates
    // the dialog, so the far leg's `Allow` and extensions are not siphon's to
    // claim toward this one (RFC 3261 §20.5, §20.37); only the tags the policy
    // passes end to end, and `100rel`/`timer`, survive from the far leg.
    // `Allow` is what siphon implements as a UA, so a peer that reads transfer
    // capability from it sees REFER/NOTIFY (some trunk peers pick their transfer
    // method this way and never send a REFER without it), and `Supported`
    // carries `replaces`, which RFC 5589 §7.3 has a transferor read off exactly
    // this response to decide whether it can offer an attended transfer.
    advertise_relayed_response_capabilities(&mut response.headers, script_shaped_headers, &policy);

    // Sanitize SDP: mask B-leg identity in o= and s= lines, and rewrite
    // the o= address to our advertised address for topology hiding.
    sanitize_sdp_identity(&mut response.body, &state.sdp_name, Some(&a_leg_host));

    // Update Content-Length after SDP rewrite (o=/s= changes may alter body size)
    if !response.body.is_empty() {
        response
            .headers
            .set("Content-Length", response.body.len().to_string());
    }
}

/// Whether a response relayed to the A-leg keeps the Contact the far end put on
/// it, rather than siphon's own.
///
/// A 3xx creates no dialog. Its Contact lists where the callee can be reached
/// instead (RFC 3261 §8.1.3.4, §21.3), which is the whole content of a redirect,
/// and replacing it with siphon's address sends the caller straight back here.
/// Every other response that reaches the A-leg either creates a dialog, whose
/// in-dialog requests must come through siphon, or carries no target the caller
/// acts on.
pub(super) fn relayed_response_keeps_its_contact(status_code: Option<u16>) -> bool {
    status_code.is_some_and(|code| (300..400).contains(&code))
}

/// Rewrite `o=` and `s=` lines in an SDP body to hide the remote endpoint's
/// identity.  Replaces the username and IP address in `o=` and the session
/// name in `s=` so that neither leg leaks the other's software name, hostname,
/// or network topology.
///
/// When `addr` is `Some(ip)`, the address field in the `o=` line is also
/// rewritten to `ip` (topology hiding).  When `None`, only the username is
/// replaced (backward-compatible behaviour).
/// Collapse whitespace runs to `-` so a value can be safely placed in the
/// SDP `o=` line's `<username>` field (RFC 4566 §5.2 — no whitespace).
pub(super) fn sanitize_o_username(name: &str) -> String {
    if !name.contains(|c: char| c.is_whitespace()) {
        return name.to_string();
    }
    let collapsed = name.split_whitespace().collect::<Vec<_>>().join("-");
    if collapsed.is_empty() {
        // Pure-whitespace input — fall back to RFC 4566's "no concept of
        // user IDs" sentinel rather than emitting an empty token.
        "-".to_string()
    } else {
        collapsed
    }
}

/// Resolve a substituted SDP origin address to its `(unicast-address, addrtype)`
/// pair for the `o=` line.  `via_host()` produces a **bracket-formatted** host
/// for IPv6, but brackets are illegal in SDP (RFC 4566 §5.2) and the address
/// family must match the `<addrtype>` token — so strip the brackets and derive
/// `IP4`/`IP6` from the address family.  Returns `addrtype = None` for a
/// non-literal host (an FQDN advertise address), signalling the caller to leave
/// the existing `<addrtype>` untouched.
pub(super) fn sdp_origin_address(addr: &str) -> (String, Option<&'static str>) {
    let bare = strip_ipv6_brackets(addr);
    if bare.parse::<std::net::Ipv6Addr>().is_ok() {
        (bare.to_string(), Some("IP6"))
    } else if bare.parse::<std::net::Ipv4Addr>().is_ok() {
        (bare.to_string(), Some("IP4"))
    } else {
        // FQDN / unparseable (e.g. a zoned link-local) — emit unbracketed and
        // leave <addrtype> as-is.  For an FQDN `bare == addr`; for a bracketed
        // non-literal this strips the brackets rather than leak them into SDP.
        (bare.to_string(), None)
    }
}

pub(super) fn sanitize_sdp_identity(body: &mut Vec<u8>, name: &str, addr: Option<&str>) {
    if body.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    // RFC 4566 §5.2: the `o=` <username> field MUST NOT contain whitespace
    // (the line is space-delimited and parsers tokenise on space). Collapse
    // any whitespace runs in the configured name into `-` for the o= line.
    // The s= session-name field permits whitespace (§5.3), so we leave that
    // path using the raw `name`.
    let o_line_name = sanitize_o_username(name);
    let mut changed = false;
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.starts_with("o=") {
            // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <addr>[\r\n]
            // Replace <username>, and (when addr is Some) the <addrtype>+<addr>.
            if let Some(rest) = line.strip_prefix("o=") {
                if let Some(sdp_addr) = addr {
                    let value = rest.trim_end_matches(['\r', '\n']);
                    let line_ending = &rest[value.len()..];
                    let fields: Vec<&str> = value.split(' ').collect();
                    if fields.len() == 6 {
                        // Well-formed origin: rewrite username + address, and
                        // flip <addrtype> to match the substituted address
                        // family.  The address is emitted UNbracketed (brackets
                        // are illegal in SDP) — a v6 via_host() carries them.
                        let (bare_addr, addrtype) = sdp_origin_address(sdp_addr);
                        result.push_str("o=");
                        result.push_str(&o_line_name);
                        result.push(' ');
                        result.push_str(fields[1]);
                        result.push(' ');
                        result.push_str(fields[2]);
                        result.push(' ');
                        result.push_str(fields[3]);
                        result.push(' ');
                        result.push_str(addrtype.unwrap_or(fields[4]));
                        result.push(' ');
                        result.push_str(&bare_addr);
                        result.push_str(line_ending);
                        changed = true;
                        continue;
                    }
                    // Malformed o= (not the six RFC fields — doubled spaces, a
                    // vendor-extended origin): still substitute the trailing
                    // address for topology hiding, bracket-stripped.  Skipping it
                    // would leak the peer's real address.  <addrtype> is left
                    // alone since it can't be reliably located on a malformed
                    // line.
                    if let Some(space_pos) = rest.find(' ') {
                        let (bare_addr, _addrtype) = sdp_origin_address(sdp_addr);
                        let after_username = &rest[space_pos..];
                        let trimmed = after_username.trim_end_matches(['\r', '\n']);
                        result.push_str("o=");
                        result.push_str(&o_line_name);
                        if let Some(last_space) = trimmed.rfind(' ') {
                            result.push_str(&trimmed[..last_space + 1]);
                            result.push_str(&bare_addr);
                            result.push_str(&after_username[trimmed.len()..]);
                        } else {
                            // Only a username + one token: nothing address-shaped
                            // to replace — keep the remainder as-is.
                            result.push_str(after_username);
                        }
                        changed = true;
                        continue;
                    }
                } else if let Some(space_pos) = rest.find(' ') {
                    // No address substitution — replace the username only.
                    result.push_str("o=");
                    result.push_str(&o_line_name);
                    result.push_str(&rest[space_pos..]);
                    changed = true;
                    continue;
                }
            }
            result.push_str(line);
        } else if line.starts_with("s=") {
            // s=<session name> — replace entirely
            if line.ends_with("\r\n") {
                result.push_str("s=");
                result.push_str(name);
                result.push_str("\r\n");
            } else if line.ends_with('\n') {
                result.push_str("s=");
                result.push_str(name);
                result.push('\n');
            } else {
                result.push_str("s=");
                result.push_str(name);
            }
            changed = true;
        } else {
            result.push_str(line);
        }
    }
    if changed {
        *body = result.into_bytes();
    }
}

/// Stamp siphon's owned `o=` identity onto an SDP body: rewrite the origin
/// line's username to `name`, its `<sess-id>` to `sess_id`, its `<sess-version>`
/// to `version`, and (when `addr` is `Some`) its unicast-address to `addr`. The
/// `<nettype>` token is preserved; `<addrtype>` is flipped to `IP4`/`IP6` to
/// match the substituted address family (and left untouched for an FQDN), and
/// the substituted address is emitted unbracketed (brackets are illegal in SDP,
/// RFC 4566 §5.2).
///
/// This is the piece [`sanitize_sdp_identity`] deliberately leaves alone: it
/// lets siphon own a stable per-leg session identity with a monotonic version
/// (RFC 4566 §5.2 / RFC 3264 §8) instead of passing the peer's through, so a
/// siphon-originated re-INVITE that changes the media presents a strictly
/// greater version than the last SDP the peer saw. Must be the LAST SDP
/// mutation before the message goes on the wire (after any rtpengine rewrite),
/// so siphon's `o=` is what the peer actually sees. A malformed `o=` line (not
/// the RFC-mandated six fields) is left untouched.
pub(super) fn stamp_sdp_origin(
    body: &mut Vec<u8>,
    name: &str,
    sess_id: u64,
    version: u64,
    addr: Option<&str>,
) {
    if body.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let o_line_name = sanitize_o_username(name);
    let mut changed = false;
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("o=") {
            // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <addr>[\r\n]
            let value = rest.trim_end_matches(['\r', '\n']);
            let line_ending = &rest[value.len()..];
            let fields: Vec<&str> = value.split(' ').collect();
            if fields.len() == 6 {
                // When substituting the address, strip any v6 brackets and flip
                // <addrtype> to the substituted family; otherwise keep the
                // origin's own address + addrtype verbatim.
                let (unicast_addr, addrtype) = match addr {
                    Some(a) => {
                        let (bare, at) = sdp_origin_address(a);
                        (bare, at.unwrap_or(fields[4]))
                    }
                    None => (fields[5].to_string(), fields[4]),
                };
                result.push_str("o=");
                result.push_str(&o_line_name);
                result.push(' ');
                result.push_str(&sess_id.to_string());
                result.push(' ');
                result.push_str(&version.to_string());
                result.push(' ');
                result.push_str(fields[3]);
                result.push(' ');
                result.push_str(addrtype);
                result.push(' ');
                result.push_str(&unicast_addr);
                result.push_str(line_ending);
                changed = true;
                continue;
            }
            result.push_str(line);
        } else {
            result.push_str(line);
        }
    }
    if changed {
        *body = result.into_bytes();
    }
}

/// Remove the `media.sdp_strip_attributes` names from the SDP a message carries
/// from one leg of a B2BUA call to the other, correcting `Content-Length` when
/// anything went.
///
/// The last SDP mutation on every relay path: after the media engine rewrote the
/// SDP, so an attribute the engine carried through or added is removed as well,
/// and after siphon's `o=`/`s=` rewrite. The engine itself is handed the SDP as
/// the peer sent it. With nothing configured it returns before looking at the
/// body, so the relay is byte-identical to one without the setting.
pub(super) fn strip_relayed_sdp_attributes(message: &mut SipMessage, state: &DispatcherState) {
    if state.sdp_strip_attributes.is_empty() || message.body.is_empty() {
        return;
    }
    let content_type = message_content_type(message).to_string();
    if crate::media::body::strip_sdp_attributes(
        &content_type,
        &mut message.body,
        &state.sdp_strip_attributes,
    ) {
        message
            .headers
            .set("Content-Length", message.body.len().to_string());
    }
}

/// siphon's identity on an SDP body it sends toward one leg of a call when
/// someone else described that SDP: the other party, a transfer target, a
/// `Replaces` newcomer, or the caller's stored offer on a session refresh.
///
/// The steps every relay path takes, in their order: [`sanitize_sdp_identity`]
/// puts siphon's name in the `o=` owner and `s=` (and siphon's `o=` address, when
/// `address` is given), [`stamp_sdp_origin`] gives the `o=` the leg's own session
/// id at its next version (RFC 3264 §8: one session id for the life of the leg,
/// the version moving on with each SDP it is sent), and the configured
/// `media.sdp_strip_attributes` go last. `content_type` scopes the strip to the
/// SDP part of a multipart body. An empty body is left alone and reserves no
/// version.
pub(super) fn own_sdp_toward_leg(
    body: &mut Vec<u8>,
    content_type: &str,
    state: &DispatcherState,
    call_id: &str,
    on_a_leg: bool,
    address: Option<&str>,
) {
    if body.is_empty() {
        return;
    }
    sanitize_sdp_identity(body, &state.sdp_name, address);
    if let Some((session_id, version)) =
        state.call_actors.reserve_leg_sdp_version(call_id, on_a_leg)
    {
        stamp_sdp_origin(body, &state.sdp_name, session_id, version, address);
    }
    if !state.sdp_strip_attributes.is_empty() {
        crate::media::body::strip_sdp_attributes(content_type, body, &state.sdp_strip_attributes);
    }
}

/// The session description a body carries: the whole body under
/// `application/sdp`, or the SDP part of a multipart body. `None` for an empty
/// body or one that carries no SDP.
pub(super) fn sdp_in_body(content_type: &str, body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    crate::media::body::sdp_from_body(content_type, body).ok()
}

/// Record a body's session description as the one siphon has in force on a
/// leg's dialog (`Dialog::last_sent_sdp`), the A-leg or the winning B-leg: the
/// answer siphon just sent that leg, or an offer the leg just accepted. A body
/// with no SDP records nothing.
pub(super) fn record_sdp_sent_to_leg(
    state: &DispatcherState,
    call_id: &str,
    on_a_leg: bool,
    content_type: &str,
    body: &[u8],
) {
    if let Some(sdp) = sdp_in_body(content_type, body) {
        state.call_actors.set_leg_sent_sdp(call_id, on_a_leg, sdp);
    }
}

/// [`record_sdp_sent_to_leg`] for a session description siphon sent a leg as it
/// was given, without putting its own `o=` on it: a script's or a media engine's
/// answer, the offer of a call siphon placed. Its `o=` session id and version
/// become the dialog's (RFC 3264 §8), so a session refresh offers it unchanged
/// and a later SDP on the dialog keeps that session id.
pub(super) fn adopt_sdp_sent_to_leg(
    state: &DispatcherState,
    call_id: &str,
    on_a_leg: bool,
    content_type: &str,
    body: &[u8],
) {
    if let Some(sdp) = sdp_in_body(content_type, body) {
        let origin = sdp_origin_identity(&sdp);
        state
            .call_actors
            .adopt_leg_sent_sdp(call_id, on_a_leg, sdp, origin);
    }
}

/// The `<sess-id>` and `<sess-version>` of an SDP's `o=` line, when the line has
/// the six fields RFC 4566 §5.2 gives it.
pub(super) fn sdp_origin_identity(sdp: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(sdp).ok()?;
    let origin = text.lines().find_map(|line| line.strip_prefix("o="))?;
    let fields: Vec<&str> = origin.trim_end_matches('\r').split(' ').collect();
    if fields.len() != 6 {
        return None;
    }
    Some((fields[1].parse().ok()?, fields[2].parse().ok()?))
}

/// Flip SDP direction attributes for an SRS answer.
///
/// The SRC offers `a=sendonly` (it sends forked media to the SRS).  The SRS
/// answer must mirror this as `a=recvonly` (RFC 3264 §5: answerer reverses
/// the direction).  RTPEngine's `offer` response preserves the offer direction,
/// so we flip it before placing the SDP in the 200 OK.
pub(super) fn fix_srs_answer_sdp_direction(body: &mut Vec<u8>) {
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    // Quick check: nothing to do if no direction attributes.
    if !text.contains("a=sendonly") && !text.contains("a=recvonly") {
        return;
    }
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "a=sendonly" {
            result.push_str("a=recvonly");
            result.push_str(&line[trimmed.len()..]);
        } else if trimmed == "a=recvonly" {
            result.push_str("a=sendonly");
            result.push_str(&line[trimmed.len()..]);
        } else {
            result.push_str(line);
        }
    }
    *body = result.into_bytes();
}
