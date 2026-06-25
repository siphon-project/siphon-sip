//! Proxy core operations — RFC 3261 §16.
//!
//! Stateless header manipulation: Via insertion/stripping, Max-Forwards,
//! Record-Route insertion, and Route processing (loose routing).

use crate::sip::headers::via::Via;
use crate::sip::headers::route::RouteEntry;
use crate::sip::headers::SipHeaders;
use crate::transaction::key::TransactionKey;

/// Insert a Via header at the top of the message (for outgoing requests).
///
/// The branch is auto-generated with the RFC 3261 magic cookie.
pub fn add_via(
    headers: &mut SipHeaders,
    transport: &str,
    host: &str,
    port: Option<u16>,
) -> String {
    let branch = TransactionKey::generate_branch();
    let via_value = match port {
        Some(port) => format!("SIP/2.0/{transport} {host}:{port};branch={branch}"),
        None => format!("SIP/2.0/{transport} {host};branch={branch}"),
    };
    // Prepend our Via before existing ones, preserving header position
    let existing = headers
        .get_all("Via")
        .cloned()
        .unwrap_or_default();
    let mut all_vias = vec![via_value];
    all_vias.extend(existing);
    headers.set_all("Via", all_vias);
    branch
}

/// Strip the topmost Via header (for forwarding responses upstream).
///
/// Returns the removed Via, or `None` if no Via headers exist.
pub fn strip_top_via(headers: &mut SipHeaders) -> Option<Via> {
    let existing = headers
        .get_all("Via")
        .cloned()
        .unwrap_or_default();

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
    let current = headers
        .max_forwards()
        .unwrap_or(70); // RFC 3261 default

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
    let existing = headers
        .get_all("Record-Route")
        .cloned()
        .unwrap_or_default();
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
    let existing = headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default();

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

/// Check if the top Route header's host matches one of the local domains.
///
/// Per RFC 3261 §16.4, a proxy must only consume Route entries that identify
/// itself.  Returns `false` if there's no Route, no local domains, or the
/// top Route host doesn't match.
pub fn top_route_is_local(headers: &SipHeaders, local_domains: &[String]) -> bool {
    let route_raw = match headers.get("Route") {
        Some(raw) => raw,
        None => return false,
    };
    let entries = match RouteEntry::parse_multi(route_raw) {
        Ok(entries) if !entries.is_empty() => entries,
        _ => return false,
    };
    let host = &entries[0].uri.host;
    local_domains
        .iter()
        .any(|domain| domain.eq_ignore_ascii_case(host))
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
pub fn pop_local_routes(
    headers: &mut SipHeaders,
    local_domains: &[String],
) -> Vec<RouteEntry> {
    let mut popped = Vec::new();
    while let Some(route_raw) = headers.get("Route").cloned() {
        let entries = match RouteEntry::parse_multi(&route_raw) {
            Ok(entries) if !entries.is_empty() => entries,
            _ => break,
        };
        let host = &entries[0].uri.host;
        let is_local = local_domains
            .iter()
            .any(|domain| domain.eq_ignore_ascii_case(host));
        if is_local {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    

    fn make_headers() -> SipHeaders {
        let mut headers = SipHeaders::new();
        headers.add("Via", "SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK-p1".to_string());
        headers.add("Via", "SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK-c1".to_string());
        headers.add("Max-Forwards", "70".to_string());
        headers
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
        headers.add("Route", "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string());

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
        headers.add("Route", "<sip:scscf.example.com;lr>, <sip:pcscf.example.com;lr>".to_string());
        let hop = super::next_hop_from_route(&headers).unwrap();
        assert!(hop.contains("scscf.example.com"));
    }

    #[test]
    fn next_hop_from_route_none_when_no_route() {
        let headers = SipHeaders::new();
        assert!(super::next_hop_from_route(&headers).is_none());
    }

    #[test]
    fn next_hop_from_route_after_pop() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:us.example.com;lr>, <sip:next.example.com;lr>".to_string());
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
        assert!(via_raw.contains("[2001:db8::1]:5060"), "Via should contain bracketed IPv6: {via_raw}");
        assert!(via_raw.contains(&branch));
    }

    #[test]
    fn add_via_ipv6_loopback() {
        let mut headers = SipHeaders::new();
        add_via(&mut headers, "TCP", "[::1]", Some(5060));
        let via_raw = headers.get("Via").unwrap();
        assert!(via_raw.contains("[::1]:5060"), "Via should contain [::1]:5060: {via_raw}");
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
        headers.add("Via", "SIP/2.0/UDP [::1]:5060;branch=z9hG4bK-v6".to_string());
        headers.add("Via", "SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK-c1".to_string());
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
        assert!(all_rr[0].contains("transport=tcp"),
            "topmost RR should be outbound transport: {}", all_rr[0]);
        // Inbound should be second — the subscriber sees this as the next hop
        assert!(all_rr[1].contains("transport=tls"),
            "second RR should be inbound transport: {}", all_rr[1]);
    }

    #[test]
    fn pop_local_routes_double_rr() {
        // Simulates in-dialog BYE from subscriber with double Record-Route.
        // Both Routes point to the proxy (different transports).
        let mut headers = SipHeaders::new();
        headers.add(
            "Route",
            "<sip:proxy.example.com:5060;transport=tcp;lr>, <sip:external.example.com;lr>".to_string(),
        );

        let domains = vec![
            "proxy.example.com".to_string(),
            "10.0.0.1".to_string(),
        ];
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
            "<sip:10.0.0.1:5060;transport=tcp;lr>, <sip:proxy.example.com:5061;transport=tls;lr>".to_string(),
        );

        let domains = vec![
            "proxy.example.com".to_string(),
            "10.0.0.1".to_string(),
        ];
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

        let domains = vec!["10.0.0.1".to_string()];
        pop_local_routes(&mut headers, &domains);

        let remaining = headers.get("Route").unwrap();
        assert!(remaining.contains("far-end.example.com"));
    }

    #[test]
    fn pop_local_routes_no_routes() {
        let mut headers = SipHeaders::new();
        let domains = vec!["proxy.example.com".to_string()];
        // Should not panic
        pop_local_routes(&mut headers, &domains);
        assert!(!headers.has("Route"));
    }

    #[test]
    fn pop_local_routes_case_insensitive() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:PROXY.Example.COM:5060;lr>".to_string());

        let domains = vec!["proxy.example.com".to_string()];
        pop_local_routes(&mut headers, &domains);
        assert!(!headers.has("Route"));
    }

    #[test]
    fn pop_local_routes_non_local_untouched() {
        let mut headers = SipHeaders::new();
        headers.add("Route", "<sip:external.example.com;lr>".to_string());

        let domains = vec!["proxy.example.com".to_string()];
        pop_local_routes(&mut headers, &domains);

        // Should still be there
        assert!(headers.has("Route"));
        assert!(headers.get("Route").unwrap().contains("external.example.com"));
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
