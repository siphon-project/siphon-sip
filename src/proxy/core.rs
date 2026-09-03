//! Proxy core operations — RFC 3261 §16.
//!
//! Stateless header manipulation: Via insertion/stripping, Max-Forwards,
//! Record-Route insertion, and Route processing (loose routing).

use crate::sip::headers::route::RouteEntry;
use crate::sip::headers::via::Via;
use crate::sip::headers::SipHeaders;
use crate::transaction::key::TransactionKey;

/// Insert a Via header at the top of the message (for outgoing requests).
///
/// The branch is auto-generated with the RFC 3261 magic cookie.
pub fn add_via(headers: &mut SipHeaders, transport: &str, host: &str, port: Option<u16>) -> String {
    let branch = TransactionKey::generate_branch();
    let via_value = match port {
        Some(port) => format!("SIP/2.0/{transport} {host}:{port};branch={branch}"),
        None => format!("SIP/2.0/{transport} {host};branch={branch}"),
    };
    // Prepend our Via before existing ones, preserving header position
    let existing = headers.get_all("Via").cloned().unwrap_or_default();
    let mut all_vias = vec![via_value];
    all_vias.extend(existing);
    headers.set_all("Via", all_vias);
    branch
}

/// Strip the topmost Via header (for forwarding responses upstream).
///
/// Returns the removed Via, or `None` if no Via headers exist.
pub fn strip_top_via(headers: &mut SipHeaders) -> Option<Via> {
    let existing = headers.get_all("Via").cloned().unwrap_or_default();

    if existing.is_empty() {
        return None;
    }

    // Parse the first raw Via value (may contain multiple comma-separated)
    let first_raw = &existing[0];
    let mut vias = match Via::parse_multi(first_raw) {
        Ok(vias) => vias,
        Err(_) => return None,
    };

    if vias.is_empty() {
        return None;
    }

    let removed = vias.remove(0);

    // Reconstruct the Via headers, preserving header position
    let mut remaining_vias = Vec::new();

    // If the first raw value had multiple comma-separated Vias, put the rest back
    if !vias.is_empty() {
        let remaining: String = vias
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        remaining_vias.push(remaining);
    }

    // Re-add the rest of the original raw Via headers
    for via in existing.iter().skip(1) {
        remaining_vias.push(via.clone());
    }

    if remaining_vias.is_empty() {
        headers.remove("Via");
    } else {
        headers.set_all("Via", remaining_vias);
    }

    Some(removed)
}

/// Decrement Max-Forwards by 1.
///
/// Returns the new value. If already 0, returns `Err(())` (caller should send 483).
#[allow(clippy::result_unit_err)]
pub fn decrement_max_forwards(headers: &mut SipHeaders) -> Result<u8, ()> {
    let current = headers.max_forwards().unwrap_or(70); // RFC 3261 default

    if current == 0 {
        return Err(());
    }

    let new_value = current - 1;
    headers.set("Max-Forwards", new_value.to_string());
    Ok(new_value)
}

/// Insert a Record-Route header at the top of the message.
pub fn add_record_route(headers: &mut SipHeaders, uri: &str) {
    let rr_value = format!("<{uri};lr>");
    // Prepend: Record-Route order matters (topmost = closest proxy)
    let existing = headers.get_all("Record-Route").cloned().unwrap_or_default();
    headers.remove("Record-Route");
    headers.add("Record-Route", rr_value);
    for rr in existing {
        headers.add("Record-Route", rr);
    }
}

/// Process loose routing per RFC 3261 §16.12.
///
/// If the request has a Route header and the first route has `lr`:
/// - Returns `true` (loose routing in effect — forward to Request-URI as-is).
/// - The Route headers are left intact for the next hop to process.
///
/// If the first Route does NOT have `lr` (strict routing):
/// - Returns `false`.
///
/// If no Route header exists, returns `true` (no routing needed).
pub fn check_loose_route(headers: &SipHeaders) -> bool {
    let route_raw = match headers.get("Route") {
        Some(raw) => raw,
        None => return true, // No Route header — "loose" by default
    };

    match RouteEntry::parse_multi(route_raw) {
        Ok(entries) if !entries.is_empty() => entries[0].is_loose_route(),
        _ => true,
    }
}

/// Pop the top Route header entry (for strict routing or after processing).
///
/// Returns the removed entry, or `None` if no Route headers exist.
pub fn pop_top_route(headers: &mut SipHeaders) -> Option<RouteEntry> {
    let existing = headers.get_all("Route").cloned().unwrap_or_default();

    if existing.is_empty() {
        return None;
    }

    // Parse all Route entries
    let mut all_entries = Vec::new();
    for raw in &existing {
        match RouteEntry::parse_multi(raw) {
            Ok(mut entries) => all_entries.append(&mut entries),
            Err(_) => continue,
        }
    }

    if all_entries.is_empty() {
        return None;
    }

    let removed = all_entries.remove(0);

    // Reconstruct
    headers.remove("Route");
    if !all_entries.is_empty() {
        let remaining = all_entries
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        headers.add("Route", remaining);
    }

    Some(removed)
}

/// The host/port pairs that identify *this* proxy on the wire.
///
/// RFC 3261 §16.4 says a proxy removes the top Route only when it "indicates
/// this proxy", and §16.6 item 4 requires the URI it puts into Record-Route to
/// be one it "would be willing to receive requests on".  So the recogniser has
/// to cover exactly what we *stamp* — and nothing more, or we consume a Route
/// belonging to somebody else.
///
/// Two kinds of entry, because we know the port for some identities and not
/// others:
///
/// * **Aliases** ([`Self::add_alias`]) — operator-declared names with no port
///   attached (`domain.local`, `ipsec.path_host`).  Match on any port.
/// * **Transport identities** ([`Self::add_host`]) — every listener address and
///   advertised host, paired with the ports we actually answer on.  A Route at
///   our host but on a port we do not serve belongs to a *different* proxy
///   co-located on the same address, and must not be consumed.
///
/// Hosts are normalised (IPv6 brackets stripped, lowercased) on the way in and
/// on the way out, so a bracketed Route host — which is what
/// [`crate::sip::uri::format_sip_host`] stamps for v6 — matches a bare
/// configured address and vice versa.
#[derive(Debug, Clone, Default)]
pub struct SelfIdentity {
    /// `(host, ports)`.  An empty `ports` means "any port" (an alias).
    entries: Vec<(String, Vec<u16>)>,
}

impl SelfIdentity {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn normalise(host: &str) -> String {
        crate::sip::uri::strip_ipv6_brackets(host.trim()).to_ascii_lowercase()
    }

    /// Record a host we answer for on **any** port.
    pub fn add_alias(&mut self, host: &str) {
        let host = Self::normalise(host);
        if host.is_empty() {
            return;
        }
        match self.entries.iter_mut().find(|(known, _)| *known == host) {
            // Any-port subsumes any port-scoped entry for the same host.
            Some((_, ports)) => ports.clear(),
            None => self.entries.push((host, Vec::new())),
        }
    }

    /// Record a host we answer for on `ports` only.
    pub fn add_host(&mut self, host: &str, ports: &[u16]) {
        let host = Self::normalise(host);
        if host.is_empty() || ports.is_empty() {
            return;
        }
        match self.entries.iter_mut().find(|(known, _)| *known == host) {
            Some((_, known_ports)) => {
                // Already any-port — leave it alone, it is strictly wider.
                if known_ports.is_empty() {
                    return;
                }
                for port in ports {
                    if !known_ports.contains(port) {
                        known_ports.push(*port);
                    }
                }
            }
            None => self.entries.push((host, ports.to_vec())),
        }
    }

    /// Whether `host`/`port` identifies this proxy.
    ///
    /// A Route with no explicit port matches on the host alone: RFC 3261 §19.1.2
    /// makes the port optional, and refusing there would reintroduce the very
    /// 404 this type exists to prevent.
    pub fn matches(&self, host: &str, port: Option<u16>) -> bool {
        let candidate = Self::normalise(host);
        // Keep scanning on a host hit with a port miss — the same host can be
        // registered more than once (a listener entry plus an alias).
        for (known_host, ports) in &self.entries {
            if *known_host != candidate {
                continue;
            }
            if ports.is_empty() {
                return true;
            }
            match port {
                None => return true,
                Some(port) if ports.contains(&port) => return true,
                Some(_) => continue,
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Normalised `(host, ports)` entries, for assertions and diagnostics.
    pub fn entries(&self) -> &[(String, Vec<u16>)] {
        &self.entries
    }
}

/// Check if the top Route header identifies this proxy.
///
/// Per RFC 3261 §16.4, a proxy must only consume Route entries that identify
/// itself.  Returns `false` if there's no Route, the identity is empty, or the
/// top Route doesn't match.
pub fn top_route_is_local(headers: &SipHeaders, identity: &SelfIdentity) -> bool {
    let route_raw = match headers.get("Route") {
        Some(raw) => raw,
        None => return false,
    };
    let entries = match RouteEntry::parse_multi(route_raw) {
        Ok(entries) if !entries.is_empty() => entries,
        _ => return false,
    };
    identity.matches(&entries[0].uri.host, entries[0].uri.port)
}

/// Pop all leading Route entries whose URI host matches one of the local domains.
///
/// After double Record-Route (transport bridging), an in-dialog request may
/// carry two consecutive Route headers that both point to us — one per
/// transport.  RFC 3261 §16.4 says we remove Route entries that indicate
/// *this* proxy.  This function pops them all in one pass so the relay path
/// sees the first *external* Route (or falls back to the Request-URI).
///
/// Returns the popped entries in the order they were removed (top first) so
/// callers can expose pre-pop metadata (e.g. an `orig`/`term` user-part the
/// P-CSCF preloaded on the IMS service-route) to scripts.
pub fn pop_local_routes(headers: &mut SipHeaders, identity: &SelfIdentity) -> Vec<RouteEntry> {
    let mut popped = Vec::new();
    while let Some(route_raw) = headers.get("Route").cloned() {
        let entries = match RouteEntry::parse_multi(&route_raw) {
            Ok(entries) if !entries.is_empty() => entries,
            _ => break,
        };
        if identity.matches(&entries[0].uri.host, entries[0].uri.port) {
            if let Some(entry) = pop_top_route(headers) {
                popped.push(entry);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    popped
}

/// Consume every leading Route entry that identifies this proxy (RFC 3261
/// §16.4 / §16.12), leaving the first foreign Route as the apparent next hop.
///
/// The single implementation of "shed our own hops from an in-dialog request",
/// shared by the script-side `loose_route()` and the 2xx ACK path so the two can
/// never disagree about the same dialog's route set.  A `;lr`-less top Route is
/// strict-routed and left alone.
pub fn consume_self_routes(headers: &mut SipHeaders, identity: &SelfIdentity) -> Vec<RouteEntry> {
    if !check_loose_route(headers) {
        return Vec::new();
    }
    pop_local_routes(headers, identity)
}

/// Return the URI of the topmost Route header, if any.
///
/// RFC 3261 §16.6 step 6: when Route headers are present the proxy
/// must forward to the first Route URI (for loose-routed requests)
/// rather than the Request-URI.
pub fn next_hop_from_route(headers: &SipHeaders) -> Option<String> {
    let route_raw = headers.get("Route")?;
    let entries = RouteEntry::parse_multi(route_raw).ok()?;
    entries.first().map(|entry| entry.uri.to_string())
}

/// Build the Route header value for a target from the Path vector stored with
/// its registration binding (RFC 3327 §5.3).
///
/// The Path vector is preserved in order — Path\[0\] is the proxy nearest the
/// registrar, so it becomes the first Route entry and therefore this branch's
/// next hop.  Each stored value is normalized to a single `<uri;lr>` entry; a
/// stored value that itself holds several comma-separated entries (legal, one
/// Path header can carry a list) expands to that many Route entries, and any
/// header-level parameters after the `>` are preserved.
///
/// Returns `None` for an empty Path vector — the caller then leaves the
/// request's existing Route set alone.
///
/// This is what makes two bindings of one AoR independently routable: they
/// commonly traverse different edge proxies, or the same edge proxy with a
/// different per-registration Path token (RFC 3327 §5 / TS 24.229 §5.2.7.2),
/// so every fork branch needs *its own* route set rather than the one the
/// script happened to leave on the request.
pub fn route_set_from_path(path: &[String]) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    for raw in path {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        match RouteEntry::parse_multi(trimmed) {
            Ok(parsed) if !parsed.is_empty() => {
                // `RouteEntry`'s Display re-emits `<uri>;header-params`, so URI
                // parameters (`;lr`, `;ob`) and header parameters both survive.
                entries.extend(parsed.iter().map(|entry| entry.to_string()));
            }
            // Unparseable as a name-addr (e.g. a bare `sip:host;lr` addr-spec,
            // which RFC 3327's grammar allows when there are no header params).
            // Wrap it verbatim rather than dropping the hop — losing a Path
            // entry silently would route the branch to the wrong place.
            _ => entries.push(format!("<{}>", trimmed.trim_matches(['<', '>']).trim())),
        }
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries.join(", "))
    }
}

/// How one fork branch is routed: its own Route header set (from the
/// registration binding's Path vector) and the URI to actually send it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchRouting {
    /// Route header value to set on this branch, replacing any Route the
    /// request carried.  `None` when the binding has no Path — the branch then
    /// keeps the request's existing Route set (today's bare-URI behaviour).
    pub route_set: Option<String>,
    /// URI to resolve for this branch's next hop: the topmost Route when a
    /// route set applies (RFC 3261 §16.6 step 6), else the branch target.
    pub next_hop: String,
}

/// Decide how to route one fork branch, given the branch target (the Contact
/// URI, which stays the Request-URI) and the Path vector stored with that
/// binding.
///
/// Returns `None` when the binding has a Path that cannot be turned into a
/// usable route set.  The caller must drop that branch rather than fall back
/// to the target URI: a binding whose Path is unusable is not reachable by
/// Request-URI either, and silently sending it anyway is how a branch ends up
/// delivered to the *wrong* binding.
pub fn branch_routing(branch_path: &[String], target: &str) -> Option<BranchRouting> {
    let Some(route_set) = route_set_from_path(branch_path) else {
        return Some(BranchRouting {
            route_set: None,
            next_hop: target.to_string(),
        });
    };
    let mut headers = SipHeaders::new();
    headers.set("Route", route_set.clone());
    let next_hop = next_hop_from_route(&headers)?;
    Some(BranchRouting {
        route_set: Some(route_set),
        next_hop,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers() -> SipHeaders {
        let mut headers = SipHeaders::new();
        headers.add(
            "Via",
            "SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK-p1".to_string(),
        );
        headers.add(
            "Via",
            "SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK-c1".to_string(),
        );
        headers.add("Max-Forwards", "70".to_string());
        headers
    }

    fn route_headers(value: &str) -> SipHeaders {
        let mut headers = SipHeaders::new();
        headers.add("Route", value.to_string());
        headers
    }

    // -----------------------------------------------------------------------
    // Route self-identity (RFC 3261 §16.4 "indicates this proxy")
    // -----------------------------------------------------------------------

    /// Host-only identity (any port), matching what a bare list of local
    /// domains used to mean.
    fn aliases(hosts: &[&str]) -> SelfIdentity {
        let mut identity = SelfIdentity::new();
        for host in hosts {
            identity.add_alias(host);
        }
        identity
    }

    /// An identity for a proxy reachable at 192.0.2.40 on 5060/5061, serving
    /// the SIP domain example.com (which, as is normal, does not list the IP).
    fn identity() -> SelfIdentity {
        let mut identity = SelfIdentity::new();
        identity.add_host("192.0.2.40", &[5060, 5061]);
        identity.add_alias("example.com");
        identity
    }

    #[test]
    fn identity_matches_host_on_a_served_port() {
        assert!(identity().matches("192.0.2.40", Some(5060)));
        assert!(identity().matches("192.0.2.40", Some(5061)));
    }

    #[test]
    fn identity_rejects_host_on_a_port_we_do_not_serve() {
        // A co-located proxy on the same address — not us (RFC 3261 §16.4).
        assert!(!identity().matches("192.0.2.40", Some(6060)));
    }

    #[test]
    fn identity_matches_portless_route_on_host_alone() {
        // RFC 3261 §19.1.2 makes the port optional; refusing here would
        // reintroduce the 404 this type exists to prevent.
        assert!(identity().matches("192.0.2.40", None));
    }

    #[test]
    fn identity_alias_matches_any_port() {
        assert!(identity().matches("example.com", Some(9999)));
        assert!(identity().matches("example.com", None));
    }

    #[test]
    fn identity_rejects_unknown_host() {
        assert!(!identity().matches("scscf.example.net", Some(5060)));
        assert!(!identity().matches("scscf.example.net", None));
    }

    #[test]
    fn identity_normalises_case() {
        let mut identity = SelfIdentity::new();
        identity.add_host("SIP.Example.COM", &[5060]);
        assert!(identity.matches("sip.example.com", Some(5060)));
        assert!(identity.matches("SIP.EXAMPLE.COM", Some(5060)));
    }

    #[test]
    fn identity_matches_bracketed_ipv6_against_bare() {
        // format_sip_host() stamps IPv6 bracketed, so that is what comes back
        // on the Route — it must match the bare configured address either way.
        let mut identity = SelfIdentity::new();
        identity.add_host("2001:db8::1", &[5060]);
        assert!(identity.matches("[2001:db8::1]", Some(5060)));
        assert!(identity.matches("2001:db8::1", Some(5060)));

        let mut bracketed = SelfIdentity::new();
        bracketed.add_host("[2001:db8::1]", &[5060]);
        assert!(bracketed.matches("2001:db8::1", Some(5060)));
        assert!(bracketed.matches("[2001:db8::1]", Some(5060)));
    }

    #[test]
    fn identity_unions_ports_for_a_repeated_host() {
        let mut identity = SelfIdentity::new();
        identity.add_host("192.0.2.40", &[5060]);
        identity.add_host("192.0.2.40", &[5064, 5066]);
        assert_eq!(identity.entries().len(), 1);
        for port in [5060, 5064, 5066] {
            assert!(identity.matches("192.0.2.40", Some(port)), "port {port}");
        }
        assert!(!identity.matches("192.0.2.40", Some(6060)));
    }

    #[test]
    fn identity_alias_widens_a_port_scoped_host() {
        // An operator who lists their own IP under domain.local gets any-port
        // matching — the pre-existing workaround must keep working.
        let mut identity = SelfIdentity::new();
        identity.add_host("192.0.2.40", &[5060]);
        identity.add_alias("192.0.2.40");
        assert!(identity.matches("192.0.2.40", Some(6060)));
    }

    #[test]
    fn identity_port_scoped_host_never_narrows_an_alias() {
        // Reverse insertion order of the case above — any-port must win.
        let mut identity = SelfIdentity::new();
        identity.add_alias("192.0.2.40");
        identity.add_host("192.0.2.40", &[5060]);
        assert!(identity.matches("192.0.2.40", Some(6060)));
    }

    #[test]
    fn identity_keeps_scanning_past_a_port_miss_on_a_duplicate_host() {
        // Same host registered twice; the match must not stop at the first
        // entry whose port set misses.
        let mut identity = SelfIdentity::new();
        identity
            .entries
            .push(("192.0.2.40".to_string(), vec![5060]));
        identity
            .entries
            .push(("192.0.2.40".to_string(), vec![6060]));
        assert!(identity.matches("192.0.2.40", Some(6060)));
    }

    #[test]
    fn identity_ignores_empty_and_whitespace_hosts() {
        let mut identity = SelfIdentity::new();
        identity.add_alias("");
        identity.add_alias("   ");
        identity.add_host("", &[5060]);
        assert!(identity.is_empty());
    }

    #[test]
    fn identity_add_host_with_no_ports_is_a_noop() {
        // Guards against silently creating an any-port entry from an empty port
        // list, which would defeat the co-location check.
        let mut identity = SelfIdentity::new();
        identity.add_host("192.0.2.40", &[]);
        assert!(identity.is_empty());
        assert!(!identity.matches("192.0.2.40", Some(5060)));
    }

    #[test]
    fn empty_identity_matches_nothing() {
        let identity = SelfIdentity::new();
        assert!(!identity.matches("192.0.2.40", Some(5060)));
        assert!(!identity.matches("192.0.2.40", None));
    }

    #[test]
    fn top_route_is_local_matches_advertised_host_absent_from_domain_local() {
        // Regression: an IP-addressed proxy Record-Routes itself with its
        // advertised address, which the operator has no reason to also list
        // under `domain.local`. Matching only `domain.local` meant refusing to
        // consume our own Record-Route, 404-ing every in-dialog request.
        let headers = route_headers("<sip:192.0.2.40:5060;transport=udp;lr>");
        assert!(top_route_is_local(&headers, &identity()));
    }

    #[test]
    fn top_route_is_local_rejects_downstream_proxy_route() {
        // The other half of §16.4 — a Route addressed to someone else must be
        // left intact for the relay path to follow.
        let headers = route_headers("<sip:scscf.example.net:5060;lr>");
        assert!(!top_route_is_local(&headers, &identity()));
    }

    #[test]
    fn top_route_is_local_rejects_same_host_foreign_port() {
        // Co-located S-CSCF on our address, its own port.
        let headers = route_headers("<sip:192.0.2.40:6060;lr>");
        assert!(!top_route_is_local(&headers, &identity()));
    }

    #[test]
    fn pop_local_routes_consumes_our_route_and_keeps_the_next_hop() {
        let mut headers =
            route_headers("<sip:192.0.2.40:5060;transport=udp;lr>, <sip:scscf.example.net;lr>");
        let popped = pop_local_routes(&mut headers, &identity());
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].uri.host, "192.0.2.40");
        assert_eq!(
            next_hop_from_route(&headers).as_deref(),
            Some("sip:scscf.example.net;lr")
        );
    }

    #[test]
    fn pop_local_routes_consumes_double_record_route_across_transports() {
        // Transport bridging leaves two consecutive self-Routes (one per
        // listener). Consuming only the top would leave our own second Route
        // looking like the next hop — a loop.
        let mut identity = SelfIdentity::new();
        identity.add_host("sip.example.com", &[5060, 5061]);
        identity.add_host("192.0.2.40", &[5060, 5061]);
        let mut headers = route_headers(
            "<sip:sip.example.com:5061;transport=tls;lr>, \
             <sip:192.0.2.40:5060;transport=udp;lr>, \
             <sip:scscf.example.net;lr>",
        );
        let popped = pop_local_routes(&mut headers, &identity);
        assert_eq!(popped.len(), 2);
        assert_eq!(
            next_hop_from_route(&headers).as_deref(),
            Some("sip:scscf.example.net;lr")
        );
    }

    #[test]
    fn pop_local_routes_leaves_foreign_route_untouched() {
        let mut headers = route_headers("<sip:scscf.example.net;lr>");
        let popped = pop_local_routes(&mut headers, &identity());
        assert!(popped.is_empty());
        assert_eq!(
            next_hop_from_route(&headers).as_deref(),
            Some("sip:scscf.example.net;lr")
        );
    }

    #[test]
    fn pop_local_routes_stops_at_a_co_located_proxy_on_our_own_address() {
        // The F3 shape: P-CSCF :5060 and S-CSCF :6060 on one IP. Popping both
        // would bypass the S-CSCF entirely (losing its Rf STOP).
        let mut headers = route_headers(
            "<sip:192.0.2.40:5060;lr>, <sip:192.0.2.40:6060;lr>, <sip:ue.example.net;lr>",
        );
        let popped = pop_local_routes(&mut headers, &identity());
        assert_eq!(popped.len(), 1, "only our own Route may be consumed");
        assert_eq!(
            next_hop_from_route(&headers).as_deref(),
            Some("sip:192.0.2.40:6060;lr"),
            "the co-located proxy must remain the next hop",
        );
    }

    #[test]
    fn pop_local_routes_consumes_ipsec_protected_port_route() {
        // A P-CSCF Record-Routes with its protected port (TS 33.203 §7.1),
        // not its plain listen port.
        let mut identity = SelfIdentity::new();
        identity.add_host("192.0.2.40", &[5060, 5064, 5066]);
        let mut headers =
            route_headers("<sip:192.0.2.40:5066;transport=udp;lr>, <sip:scscf.example.net;lr>");
        let popped = pop_local_routes(&mut headers, &identity);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].uri.port, Some(5066));
    }

    #[test]
    fn add_via_prepends() {
        let mut headers = make_headers();
        let branch = add_via(&mut headers, "UDP", "proxy2.example.com", Some(5060));

        let all_vias = headers.get_all("Via").unwrap();
        assert_eq!(all_vias.len(), 3);
        // Our new Via should be first
        assert!(all_vias[0].contains("proxy2.example.com"));
        assert!(all_vias[0].contains(&branch));
        // Original Vias follow
        assert!(all_vias[1].contains("proxy1.example.com"));
        assert!(all_vias[2].contains("client.example.com"));
    }

    #[test]
    fn add_via_generates_rfc3261_branch() {
        let mut headers = SipHeaders::new();
        let branch = add_via(&mut headers, "TCP", "proxy.example.com", None);
        assert!(branch.starts_with("z9hG4bK"));
    }

    #[test]
    fn strip_top_via_removes_first() {
        let mut headers = make_headers();
        let removed = strip_top_via(&mut headers).unwrap();
        assert_eq!(removed.host, "proxy1.example.com");

        let remaining = headers.get_all("Via").unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].contains("client.example.com"));
    }

    #[test]
    fn strip_top_via_empty_returns_none() {
        let mut headers = SipHeaders::new();
        assert!(strip_top_via(&mut headers).is_none());
    }

    #[test]
    fn strip_top_via_comma_separated() {
        let mut headers = SipHeaders::new();
        headers.add("Via", "SIP/2.0/UDP first.example.com;branch=z9hG4bK-1, SIP/2.0/UDP second.example.com;branch=z9hG4bK-2".to_string());
        let removed = strip_top_via(&mut headers).unwrap();
        assert_eq!(removed.host, "first.example.com");

        let remaining = headers.get_all("Via").unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].contains("second.example.com"));
    }

    #[test]
    fn decrement_max_forwards_normal() {
        let mut headers = make_headers();
        let new = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(new, 69);
        assert_eq!(headers.max_forwards(), Some(69));
    }

    #[test]
    fn decrement_max_forwards_zero_returns_err() {
        let mut headers = SipHeaders::new();
        headers.add("Max-Forwards", "0".to_string());
        assert!(decrement_max_forwards(&mut headers).is_err());
    }

    #[test]
    fn decrement_max_forwards_missing_defaults_to_70() {
        let mut headers = SipHeaders::new();
        let new = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(new, 69);
    }

    #[test]
    fn add_record_route_prepends() {
        let mut headers = SipHeaders::new();
        headers.add("Record-Route", "<sip:existing.example.com;lr>".to_string());
        add_record_route(&mut headers, "sip:proxy.example.com");

        let all_rr = headers.get_all("Record-Route").unwrap();
        assert_eq!(all_rr.len(), 2);
        assert!(all_rr[0].contains("proxy.example.com"));
        assert!(all_rr[1].contains("existing.example.com"));
    }

    #[test]
    fn check_loose_route_with_lr() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:proxy.example.com;lr>".to_string());
        assert!(check_loose_route(&headers));
    }

    #[test]
    fn check_loose_route_without_lr() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:proxy.example.com>".to_string());
        assert!(!check_loose_route(&headers));
    }

    #[test]
    fn check_loose_route_no_route_header() {
        let headers = SipHeaders::new();
        assert!(check_loose_route(&headers));
    }

    #[test]
    fn pop_top_route_removes_first() {
        let mut headers = SipHeaders::new();
        headers.add(
            "Route",
            "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string(),
        );

        let removed = super::pop_top_route(&mut headers).unwrap();
        assert_eq!(removed.uri.host, "p1.example.com");

        let remaining = headers.get("Route").unwrap();
        assert!(remaining.contains("p2.example.com"));
        assert!(!remaining.contains("p1.example.com"));
    }

    #[test]
    fn pop_top_route_empty_returns_none() {
        let mut headers = SipHeaders::new();
        assert!(super::pop_top_route(&mut headers).is_none());
    }

    #[test]
    fn pop_top_route_last_entry_removes_header() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:p1.example.com;lr>".to_string());

        super::pop_top_route(&mut headers);
        assert!(!headers.has("Route"));
    }

    #[test]
    fn next_hop_from_route_returns_top_uri() {
        let mut headers = SipHeaders::new();
        headers.add(
            "Route",
            "<sip:scscf.example.com;lr>, <sip:pcscf.example.com;lr>".to_string(),
        );
        let hop = super::next_hop_from_route(&headers).unwrap();
        assert!(hop.contains("scscf.example.com"));
    }

    #[test]
    fn next_hop_from_route_none_when_no_route() {
        let headers = SipHeaders::new();
        assert!(super::next_hop_from_route(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // route_set_from_path (RFC 3327 §5.3)
    // -----------------------------------------------------------------------

    #[test]
    fn route_set_from_path_preserves_order() {
        // Path[0] is the hop nearest the registrar, so it must stay first —
        // it is the branch's next hop.
        let path = vec![
            "<sip:icscf.ims.example.com;lr>".to_string(),
            "<sip:pcscf.ims.example.com;lr>".to_string(),
        ];
        let route = super::route_set_from_path(&path).unwrap();
        assert_eq!(
            route,
            "<sip:icscf.ims.example.com;lr>, <sip:pcscf.ims.example.com;lr>"
        );
    }

    #[test]
    fn route_set_from_path_keeps_token_userpart() {
        // The whole point of per-branch route sets: the opaque per-registration
        // token in the Path userpart is what the edge proxy resolves back to a
        // binding (RFC 3327 §5 / TS 24.229 §5.2.7.2).
        let path = vec!["<sip:TOKEN-B@edge.example.com;lr>".to_string()];
        let route = super::route_set_from_path(&path).unwrap();
        assert!(route.contains("TOKEN-B@edge.example.com"));
    }

    #[test]
    fn route_set_from_path_expands_comma_separated_value() {
        // One Path header may carry a list; each entry becomes its own Route.
        let path = vec!["<sip:a.example.com;lr>, <sip:b.example.com;lr>".to_string()];
        let route = super::route_set_from_path(&path).unwrap();
        assert_eq!(route, "<sip:a.example.com;lr>, <sip:b.example.com;lr>");
        let entries = RouteEntry::parse_multi(&route).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn route_set_from_path_preserves_header_params() {
        let path = vec!["<sip:edge.example.com;lr>;ob".to_string()];
        let route = super::route_set_from_path(&path).unwrap();
        assert_eq!(route, "<sip:edge.example.com;lr>;ob");
    }

    #[test]
    fn route_set_from_path_wraps_bare_addr_spec() {
        // RFC 3327's path-value allows a bare addr-spec; it must not be dropped.
        let path = vec!["sip:edge.example.com;lr".to_string()];
        let route = super::route_set_from_path(&path).unwrap();
        assert_eq!(route, "<sip:edge.example.com;lr>");
        assert!(super::next_hop_from_route(&route_headers(&route)).is_some());
    }

    #[test]
    fn route_set_from_path_empty_is_none() {
        assert!(super::route_set_from_path(&[]).is_none());
        assert!(super::route_set_from_path(&["   ".to_string()]).is_none());
    }

    // -----------------------------------------------------------------------
    // branch_routing — the per-branch decision the proxy fork path makes
    // -----------------------------------------------------------------------

    #[test]
    fn branch_routing_sends_each_branch_through_its_own_path() {
        // The reported bug, at the decision that causes it: two bindings of one
        // AoR behind the same Path-token edge proxy.  Each branch must resolve
        // to its OWN token, otherwise branch 1 is just a retry of binding 0.
        let branch_a = super::branch_routing(
            &["<sip:TOKEN-A@edge.example.com;lr>".to_string()],
            "sip:alice@10.0.0.1:5060",
        )
        .unwrap();
        let branch_b = super::branch_routing(
            &["<sip:TOKEN-B@edge.example.com;lr>".to_string()],
            "sip:alice@10.0.0.2:5060",
        )
        .unwrap();

        assert_eq!(
            branch_a.route_set.as_deref(),
            Some("<sip:TOKEN-A@edge.example.com;lr>")
        );
        assert_eq!(
            branch_b.route_set.as_deref(),
            Some("<sip:TOKEN-B@edge.example.com;lr>")
        );
        assert_ne!(
            branch_a.route_set, branch_b.route_set,
            "the two branches must not share a route set"
        );
        // Both go to the same edge proxy host — the token in the Route is what
        // distinguishes the bindings, so the next hop being equal is correct.
        assert!(branch_a.next_hop.contains("TOKEN-A@edge.example.com"));
        assert!(branch_b.next_hop.contains("TOKEN-B@edge.example.com"));
    }

    #[test]
    fn branch_routing_without_path_keeps_target_routing() {
        let routing = super::branch_routing(&[], "sip:alice@10.0.0.1:5060").unwrap();
        assert!(
            routing.route_set.is_none(),
            "no Path must leave the request's Route set untouched"
        );
        assert_eq!(routing.next_hop, "sip:alice@10.0.0.1:5060");
    }

    #[test]
    fn branch_routing_next_hop_is_top_route_not_the_contact() {
        // RFC 3261 §16.6 step 6 — with a route set, the branch goes to the top
        // Route.  The Contact URI stays the Request-URI (applied by the caller).
        let routing = super::branch_routing(
            &[
                "<sip:icscf.ims.example.com;lr>".to_string(),
                "<sip:pcscf.ims.example.com;lr>".to_string(),
            ],
            "sip:alice@10.0.0.1:5060",
        )
        .unwrap();
        assert!(routing.next_hop.contains("icscf.ims.example.com"));
        assert!(!routing.next_hop.contains("10.0.0.1"));
    }

    #[test]
    fn branch_routing_drops_branch_with_unusable_path() {
        // A binding whose Path cannot be parsed into a route set is not
        // reachable by Request-URI either — falling back to the target would
        // deliver the branch to the wrong binding, which is the bug being fixed.
        assert!(super::branch_routing(&["not a uri at all".to_string()], "sip:a@b").is_none());
    }

    #[test]
    fn route_set_from_path_next_hop_is_first_entry() {
        let path = vec![
            "<sip:first.example.com;lr>".to_string(),
            "<sip:second.example.com;lr>".to_string(),
        ];
        let route = super::route_set_from_path(&path).unwrap();
        let hop = super::next_hop_from_route(&route_headers(&route)).unwrap();
        assert!(hop.contains("first.example.com"));
    }

    #[test]
    fn next_hop_from_route_after_pop() {
        let mut headers = SipHeaders::new();
        headers.add(
            "Route",
            "<sip:us.example.com;lr>, <sip:next.example.com;lr>".to_string(),
        );
        // Pop our own Route (simulates loose_route())
        super::pop_top_route(&mut headers);
        // Next hop should now be the next proxy
        let hop = super::next_hop_from_route(&headers).unwrap();
        assert!(hop.contains("next.example.com"));
    }

    #[test]
    fn full_proxy_flow_via_and_max_forwards() {
        let mut headers = make_headers();

        // Proxy adds its Via
        let branch = add_via(&mut headers, "UDP", "our-proxy.example.com", Some(5060));

        // Decrement Max-Forwards
        let mf = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(mf, 69);

        // Add Record-Route
        add_record_route(&mut headers, "sip:our-proxy.example.com");

        // Verify: 3 Vias, our proxy on top
        let vias = headers.get_all("Via").unwrap();
        assert_eq!(vias.len(), 3);
        assert!(vias[0].contains("our-proxy.example.com"));

        // When response comes back, strip our Via
        let removed = strip_top_via(&mut headers).unwrap();
        assert_eq!(removed.host, "our-proxy.example.com");
        assert_eq!(removed.branch.unwrap(), branch);

        let vias = headers.get_all("Via").unwrap();
        assert_eq!(vias.len(), 2);
    }

    #[test]
    fn add_via_ipv6_brackets() {
        let mut headers = SipHeaders::new();
        let branch = add_via(&mut headers, "UDP", "[2001:db8::1]", Some(5060));
        let via_raw = headers.get("Via").unwrap();
        assert!(
            via_raw.contains("[2001:db8::1]:5060"),
            "Via should contain bracketed IPv6: {via_raw}"
        );
        assert!(via_raw.contains(&branch));
    }

    #[test]
    fn add_via_ipv6_loopback() {
        let mut headers = SipHeaders::new();
        add_via(&mut headers, "TCP", "[::1]", Some(5060));
        let via_raw = headers.get("Via").unwrap();
        assert!(
            via_raw.contains("[::1]:5060"),
            "Via should contain [::1]:5060: {via_raw}"
        );
    }

    #[test]
    fn add_record_route_ipv6() {
        let mut headers = SipHeaders::new();
        add_record_route(&mut headers, "sip:[2001:db8::1]:5060");
        let rr_raw = headers.get("Record-Route").unwrap();
        assert_eq!(rr_raw, "<sip:[2001:db8::1]:5060;lr>");
    }

    #[test]
    fn strip_top_via_ipv6() {
        let mut headers = SipHeaders::new();
        headers.add(
            "Via",
            "SIP/2.0/UDP [::1]:5060;branch=z9hG4bK-v6".to_string(),
        );
        headers.add(
            "Via",
            "SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK-c1".to_string(),
        );
        let removed = strip_top_via(&mut headers).unwrap();
        assert_eq!(removed.host, "[::1]");
        assert_eq!(removed.port, Some(5060));
        let remaining = headers.get_all("Via").unwrap();
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn double_record_route_for_transport_bridging() {
        // When bridging TLS↔TCP, two Record-Route headers are needed
        // so each leg uses the correct transport for in-dialog requests.
        // The dispatcher calls add_record_route twice — verify ordering.
        let mut headers = SipHeaders::new();

        // Simulate dispatcher's double RR insertion (inbound first, outbound second)
        let rr_inbound = "sip:10.0.0.1:5061;transport=tls";
        let rr_outbound = "sip:10.0.0.1:5060;transport=tcp";
        add_record_route(&mut headers, rr_inbound);
        add_record_route(&mut headers, rr_outbound);

        let all_rr = headers.get_all("Record-Route").unwrap();
        assert_eq!(all_rr.len(), 2, "should have two Record-Route headers");
        // Outbound (topmost) should be first — the AS sees this as the next hop
        assert!(
            all_rr[0].contains("transport=tcp"),
            "topmost RR should be outbound transport: {}",
            all_rr[0]
        );
        // Inbound should be second — the subscriber sees this as the next hop
        assert!(
            all_rr[1].contains("transport=tls"),
            "second RR should be inbound transport: {}",
            all_rr[1]
        );
    }

    #[test]
    fn pop_local_routes_double_rr() {
        // Simulates in-dialog BYE from subscriber with double Record-Route.
        // Both Routes point to the proxy (different transports).
        let mut headers = SipHeaders::new();
        headers.add(
            "Route",
            "<sip:proxy.example.com:5060;transport=tcp;lr>, <sip:external.example.com;lr>"
                .to_string(),
        );

        let domains = aliases(&["proxy.example.com", "10.0.0.1"]);
        pop_local_routes(&mut headers, &domains);

        // The local Route should be popped, leaving only the external one
        let remaining = headers.get("Route").unwrap();
        assert!(remaining.contains("external.example.com"));
        assert!(!remaining.contains("proxy.example.com"));
    }

    #[test]
    fn pop_local_routes_double_rr_both_local() {
        // Both Routes point to us (TLS + TCP) — typical double Record-Route
        // scenario after loose_route() already popped the first one.
        let mut headers = SipHeaders::new();
        headers.add(
            "Route",
            "<sip:10.0.0.1:5060;transport=tcp;lr>, <sip:proxy.example.com:5061;transport=tls;lr>"
                .to_string(),
        );

        let domains = aliases(&["proxy.example.com", "10.0.0.1"]);
        pop_local_routes(&mut headers, &domains);

        // Both should be popped — no Route header left
        assert!(!headers.has("Route"), "both local Routes should be removed");
    }

    #[test]
    fn pop_local_routes_preserves_external() {
        // Two local Routes followed by an external one
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:10.0.0.1:5060;transport=tcp;lr>".to_string());
        headers.add("Route", "<sip:far-end.example.com:5060;lr>".to_string());

        let domains = aliases(&["10.0.0.1"]);
        pop_local_routes(&mut headers, &domains);

        let remaining = headers.get("Route").unwrap();
        assert!(remaining.contains("far-end.example.com"));
    }

    #[test]
    fn pop_local_routes_no_routes() {
        let mut headers = SipHeaders::new();
        let domains = aliases(&["proxy.example.com"]);
        // Should not panic
        pop_local_routes(&mut headers, &domains);
        assert!(!headers.has("Route"));
    }

    #[test]
    fn pop_local_routes_case_insensitive() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:PROXY.Example.COM:5060;lr>".to_string());

        let domains = aliases(&["proxy.example.com"]);
        pop_local_routes(&mut headers, &domains);
        assert!(!headers.has("Route"));
    }

    #[test]
    fn pop_local_routes_non_local_untouched() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:external.example.com;lr>".to_string());

        let domains = aliases(&["proxy.example.com"]);
        pop_local_routes(&mut headers, &domains);

        // Should still be there
        assert!(headers.has("Route"));
        assert!(headers
            .get("Route")
            .unwrap()
            .contains("external.example.com"));
    }

    #[test]
    fn single_record_route_when_same_transport() {
        // When inbound and outbound transports match, only one RR is needed.
        let mut headers = SipHeaders::new();
        let rr_uri = "sip:10.0.0.1:5060;transport=tcp";
        add_record_route(&mut headers, rr_uri);

        let all_rr = headers.get_all("Record-Route").unwrap();
        assert_eq!(all_rr.len(), 1);
        assert!(all_rr[0].contains("transport=tcp"));
    }
}
