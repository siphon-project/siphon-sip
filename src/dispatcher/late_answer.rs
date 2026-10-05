//! A 2xx to a proxied INVITE that already has a final response upstream.
//!
//! RFC 3261 §16.7 step 5: "After a final response has been sent on the server
//! transaction, the following responses MUST be forwarded immediately: Any 2xx
//! response to an INVITE request." Step 9: "If the server transaction is no
//! longer available to handle the transmission, the element MUST forward the
//! response statelessly by sending it to the server transport."
//!
//! Such a 2xx comes from a branch the proxy had given up on:
//!
//! * another branch of a fork already answered, or declined with a 6xx;
//! * `reply.reject()` already failed the request;
//! * the caller cancelled, and was answered `487`.
//!
//! and either crossed the branch's CANCEL or came from a branch that never
//! sent the provisional its CANCEL was waiting for (§9.1), so that no CANCEL
//! was ever sent. Either way the callee now holds a dialog. A proxy cannot
//! release it; the caller's user agent can and must: it ACKs every 2xx its
//! INVITE draws and ends a dialog it does not want with a BYE (§13.2.2.4).
//! So the 2xx is handed to the caller, and the ACK and BYE that come back are
//! routed like any other dialog's.
//!
//! It is not the call's answer. The request it answers ended, for the script
//! and for accounting, when its final response went upstream: no
//! `@proxy.on_reply` runs for it, no answer time or destination is stamped on
//! the call's record, and no accounting session is opened.

use super::*;

/// Forward `message`, the response on `client_key`'s branch, if it is a 2xx to
/// an INVITE whose final response has already gone upstream. Returns whether
/// the response was taken.
///
/// `final_response_sent` is the session's own record of that (a reject, the
/// caller's CANCEL); a fork that settled on a 2xx or a 6xx is asked through
/// its aggregator. That costs a fork one lock of its aggregator per 2xx to an
/// INVITE, and every other response nothing.
#[allow(clippy::too_many_arguments)]
pub(super) fn forward_if_late_2xx(
    message: &SipMessage,
    status_code: u16,
    client_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    final_response_sent: bool,
    fork_aggregator: Option<&Arc<Mutex<crate::proxy::fork::ForkAggregator>>>,
    branch_index: Option<usize>,
    inbound: &InboundMessage,
    state: &DispatcherState,
) -> bool {
    if !(200..300).contains(&status_code) || client_key.method != Method::Invite {
        return false;
    }
    if !final_response_sent {
        let (Some(aggregator), Some(index)) = (fork_aggregator, branch_index) else {
            return false;
        };
        let action = match aggregator.lock() {
            Ok(mut aggregator) if aggregator.has_settled() => {
                aggregator.on_branch_response(index, status_code)
            }
            Ok(_) => return false,
            Err(_) => {
                error!("fork aggregator lock poisoned");
                return false;
            }
        };
        if action != crate::proxy::fork::ForkAction::ForwardAnother2xx {
            // This branch's own 2xx again: its retransmission, which goes to
            // the caller like any other and is nobody's answer a second time.
            forward_2xx_statelessly(inbound, message, status_code, state);
            return true;
        }
    }
    let mut late = message.clone();
    core::strip_top_via(&mut late.headers);
    send_late_2xx_upstream(late, client_key, session_arc, inbound, state);
    true
}

/// Send `message`, a late 2xx with the proxy's own Via already removed, to the
/// caller, and keep the dialog it opens routable for the caller's ACK.
///
/// Through the INVITE server transaction while that can still take a 2xx, and
/// straight to the transport when it cannot (§16.7 step 9).
pub(super) fn send_late_2xx_upstream(
    message: SipMessage,
    client_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    let (server_key, source_addr, transport, connection_id, inbound_local_addr) = {
        let Ok(session) = session_arc.read() else {
            error!("proxy session lock poisoned while forwarding a late 2xx");
            return;
        };
        (
            session.server_key.clone(),
            session.source_addr,
            session.transport,
            session.connection_id,
            session.inbound_local_addr,
        )
    };
    // The same Contact fixup an ordinary response gets, so the ACK and BYE
    // the caller sends for this dialog reach the callee.
    let message = if state.nat_fix_contact {
        fix_response_contact(message, inbound.remote_addr)
    } else {
        message
    };

    // The caller's ACK for this 2xx is a request of its own, routed by dialog,
    // and the BYE that ends this dialog ends this dialog only.
    state.session_store.keep_dialog_for_late_answer(session_arc);
    state.session_store.note_late_dialog(&message);

    info!(
        client_key = %client_key,
        destination = %source_addr,
        "forwarding a 2xx that arrived after the request's final response (RFC 3261 §16.7 step 5)"
    );
    let mut sent_by_transaction = false;
    if let Ok(actions) = state.transaction_manager.process_server_event(
        &server_key,
        ServerEvent::Ist(IstEvent::Tu2xx(message.clone())),
    ) {
        sent_by_transaction = actions
            .iter()
            .any(|action| matches!(action, Action::SendMessage(_)));
        process_timer_actions(
            &actions,
            &server_key,
            Some(source_addr),
            Some(transport),
            Some(connection_id),
            Some(inbound_local_addr),
            state,
        );
    }
    if !sent_by_transaction {
        send_message_from(
            message,
            transport,
            source_addr,
            connection_id,
            Some(inbound_local_addr),
            state,
        );
    }

    // The branch has its final response.
    state.session_store.remove_client_key(client_key);
}

/// The Via values of `message`, in order, whether they came one per header
/// line or several to a line.
fn via_stack(message: &SipMessage) -> Option<Vec<Via>> {
    let mut stack = Vec::new();
    for line in message.headers.get_all("Via")? {
        stack.extend(Via::parse_multi(line).ok()?);
    }
    Some(stack)
}

/// Whether `via` is one this instance puts on a request it forwards: its
/// branch has the form siphon generates (the RFC 3261 cookie, a hyphen and 32
/// hexadecimal digits), and its sent-by is an address this instance answers
/// on. What a stateless forward goes by, since no transaction vouches for the
/// response: a response whose top Via fails this was not sent in answer to
/// anything this instance forwarded.
pub(super) fn is_own_forwarding_via(via: &Via, state: &DispatcherState) -> bool {
    let own_branch = via
        .branch
        .as_deref()
        .and_then(|branch| branch.strip_prefix("z9hG4bK-"))
        .is_some_and(|unique| {
            unique.len() == 32 && unique.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
    if !own_branch {
        return false;
    }
    let Some(port) = via.port else {
        // siphon always stamps a port.
        return false;
    };
    if state.self_identity.matches(&via.host, Some(port)) {
        return true;
    }
    strip_ipv6_brackets(&via.host)
        .parse::<IpAddr>()
        .is_ok_and(|ip| state.is_own_address(&SocketAddr::new(ip, port)))
}

/// Where a response goes by the Via `via` under the proxy's own (RFC 3261
/// §18.2.2): the `received` address when there is one, else the sent-by host;
/// the `rport` port when it has a value (RFC 3581), else the sent-by port,
/// else the transport's default.
fn response_hop(via: &Via, state: &DispatcherState) -> Option<(SocketAddr, Transport)> {
    let transport = Transport::from_scheme(&via.transport)?;
    let default_port = match transport {
        Transport::Tls | Transport::WebSocketSecure => 5061,
        _ => 5060,
    };
    let port = via.rport.flatten().or(via.port).unwrap_or(default_port);
    let host = via.received.as_deref().unwrap_or(&via.host);
    if let Ok(ip) = strip_ipv6_brackets(host).parse::<IpAddr>() {
        return Some((SocketAddr::new(ip, port), transport));
    }
    let uri = format!(
        "sip:{}:{port};transport={}",
        format_sip_host(host),
        transport.as_scheme()
    );
    resolve_target(&uri, &state.dns_resolver).map(|target| (target.address, transport))
}

/// Forward a 2xx to an INVITE that matched no client transaction and no
/// session, by its Via stack (RFC 3261 §16.7 step 9: "the element MUST forward
/// the response statelessly by sending it to the server transport"). Returns
/// whether the response was taken.
///
/// That is the retransmission of an answer the proxy already forwarded (its
/// state went with the first copy; the callee repeats the 2xx until the
/// caller's ACK reaches it, §13.3.1.4, so a copy lost toward the caller is
/// only ever made good by forwarding the next one), and the answer of a
/// branch whose state is gone for another reason, such as one the proxy timed
/// out.
///
/// Guarded, because nothing else vouches for such a response: the top Via must
/// be one this instance generates ([`is_own_forwarding_via`]) and a second Via
/// must say where the request came from.
///
/// It is forwarded with what the framework itself does to a 2xx on its way
/// upstream and nothing else: the proxy's Via removed, and the Contact fixed
/// when `nat.fix_contact` is on. No `@proxy.on_reply` runs (the script saw the
/// request end with the first 2xx, and what it changed on that one cannot be
/// repeated here), and nothing is counted: no CDR, no Rf.
///
/// Reached only where a response would otherwise be logged as for an unknown
/// branch, so a response anything still claims never pays for it.
pub(super) fn forward_2xx_statelessly(
    inbound: &InboundMessage,
    response: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    if !(200..300).contains(&status_code) {
        return false;
    }
    let to_invite = response
        .headers
        .get("CSeq")
        .and_then(|cseq| crate::sip::headers::cseq::CSeq::parse(cseq).ok())
        .is_some_and(|cseq| cseq.method == Method::Invite);
    if !to_invite {
        return false;
    }
    let Some(stack) = via_stack(response) else {
        return false;
    };
    let [own, upstream, ..] = stack.as_slice() else {
        return false;
    };
    if !is_own_forwarding_via(own, state) {
        return false;
    }
    let Some((destination, transport)) = response_hop(upstream, state) else {
        warn!(
            via = %upstream,
            "cannot forward a 2xx statelessly: its second Via names no address this proxy can reach"
        );
        return false;
    };

    let mut forwarded = response.clone();
    core::strip_top_via(&mut forwarded.headers);
    let forwarded = if state.nat_fix_contact {
        fix_response_contact(forwarded, inbound.remote_addr)
    } else {
        forwarded
    };
    info!(
        %destination,
        %transport,
        "forwarding a 2xx to an INVITE statelessly, by its Via (RFC 3261 §16.7 step 9)"
    );
    let data = Bytes::from(forwarded.to_bytes());
    if transport.is_stream() {
        // RFC 3261 §18.2.2: over the connection the request came in on, if it
        // is still open; else a new one to the address the Via gives.
        match state.stream_connections.reuse(destination, transport) {
            Some(connection_id) => {
                send_outbound_from(data, transport, destination, connection_id, None, state);
            }
            None => {
                send_to_target(
                    data,
                    &RelayTarget {
                        address: destination,
                        transport: Some(transport),
                        server_name: None,
                    },
                    transport,
                    ConnectionId::default(),
                    None,
                    state,
                );
            }
        }
    } else {
        send_outbound_from(
            data,
            transport,
            destination,
            ConnectionId::default(),
            None,
            state,
        );
    }
    true
}
