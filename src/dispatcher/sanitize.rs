//! Scrubbing a B2BUA response before it crosses the trust boundary.
//!
//! Strips the far side's identity out of headers and the SDP origin line, so
//! the A-leg sees siphon rather than the B-leg peer.

use super::*;

/// Sanitize a B2BUA response before forwarding it to the A-leg.
///
/// A proper B2BUA terminates and regenerates the dialog, so B-leg-specific
/// headers must not leak to the A-leg. This function:
/// - Replaces Contact with siphon's own address (critical for dialog routing)
/// - Strips User-Agent (UAC header — not for responses), sets Server
/// - Strips the B-leg's Allow-Events/Supported/Require, and replaces Allow with
///   siphon's own supported methods (a B2BUA is a UA in its own right)
/// - Strips B-leg-specific P-Asserted-Identity, P-Charging-Vector
pub(super) fn sanitize_b2bua_response(
    response: &mut SipMessage,
    state: &DispatcherState,
    a_leg_transport: Transport,
    a_leg_local_addr: Option<SocketAddr>,
    a_leg_supports_100rel: bool,
    call_id: &str,
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
    response.headers.set("Contact", contact_value);

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

    // Framework-auto strip — never present a `100rel` reliability contract to
    // an A-leg that didn't advertise it.  The B-leg's reliable provisional is
    // PRACKed locally (RFC 3262 auto-PRACK, handle_b2bua_response); leaking
    // `Require: 100rel` / `RSeq` to a non-100rel A-leg (e.g. a plain PSTN
    // trunk) makes it CANCEL the call rather than PRACK.  This is a
    // correctness invariant, not topology hygiene, so it runs preset-independent
    // here rather than as a preset override.  Done before `apply_to_response`:
    // a `Copy`/`Rewrite` preset can't resurrect the removed `RSeq`, and the
    // `Require` edit leaves any surviving option-tags for `Copy` to preserve.
    // A 100rel-capable A-leg (gate true) still gets the reliable provisional
    // end-to-end (RFC 3262 §3).
    crate::sip::headers::rseq::strip_100rel_for_unsupported_peer(
        &mut response.headers,
        a_leg_supports_100rel,
    );

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
    crate::b2bua::header_policy::apply_to_response(response, &policy, &ctx);

    // Advertise siphon's own supported methods. The policy above strips the
    // B-leg's Allow (a B2BUA terminates the dialog, so the B-leg's capabilities
    // are not siphon's to relay); replace it with what siphon actually implements
    // as a UA, so a peer that reads transfer capability from the Allow sees
    // REFER/NOTIFY — Microsoft Teams Direct Routing selects its transfer method
    // this way, and without it never hands siphon a REFER. Gated on absence so a
    // script `call.set_header("Allow", …)` (policy precedence 1) still wins.
    advertise_supported_methods(&mut response.headers);

    // ...and the extensions, for the same reason and by the same route: the
    // policy stripped the B-leg's `Supported` (not siphon's to relay), so
    // without this the A-leg sees no option tags at all. RFC 5589 §7.3 has a
    // transferor read `Supported: replaces` off exactly this response to decide
    // whether it can offer an attended transfer.
    advertise_supported_options(&mut response.headers);

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
