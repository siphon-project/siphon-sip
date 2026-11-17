//! The NOTIFY of a subscription siphon is the notifier of (`handle.notify()`,
//! `handle.terminate()`, the expiry sweep): where it goes, the message, and
//! the watch on its final response.

use std::sync::Arc;

use pyo3::prelude::*;
use tracing::debug;
use uuid::Uuid;

use super::super::proxy_utils::ReplyGate;
use super::{format_default_contact, received_transport, SEND_RESOLVER, UAC_SENDER};
use crate::dns::SipResolver;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_uri_standalone;
use crate::subscribe_state::{watch_notify, SubscribeDialog, SubscribeStore};
use crate::transport::Transport;
use crate::uac::UacSender;

/// Finish expired notifier dialogs outside the dispatcher task: DNS resolution
/// must not stall SIP dispatch. State has already been removed by the sweep.
pub(crate) async fn notify_expired(store: &Arc<SubscribeStore>, mut dialog: SubscribeDialog) {
    if dialog.terminated || dialog.is_outbound {
        return;
    }
    dialog.next_cseq();
    if let Err(error) = send_notify(
        store,
        &dialog,
        "terminated;reason=timeout",
        None,
        None,
        None,
        &[],
    )
    .await
    {
        tracing::error!(id = %dialog.id, %error, "failed to notify subscription expiry");
    }
}

/// Send a NOTIFY in `dialog` through the process-wide UAC and resolver.
pub(super) async fn send_notify(
    store: &Arc<SubscribeStore>,
    dialog: &SubscribeDialog,
    subscription_state: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    gate: Option<&ReplyGate>,
    extra_headers: &[(String, String)],
) -> PyResult<()> {
    let uac_sender = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state.notify() unavailable: UAC sender not initialized",
        )
    })?;
    let resolver = SEND_RESOLVER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state.notify() unavailable: DNS resolver not initialized",
        )
    })?;
    send_notify_through(
        uac_sender,
        resolver,
        store,
        dialog,
        subscription_state,
        content_type,
        body,
        gate,
        extra_headers,
    )
    .await
}

/// Send a NOTIFY in `dialog` and leave a watch on its final response, which
/// removes the subscription when RFC 6665 §4.2.2 says a failed NOTIFY does
/// ([`SubscribeStore::notify_ended`]).  Returns once the NOTIFY is handed to
/// the transport, or held behind the reply of the SUBSCRIBE being handled:
/// the response is not waited for here.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_notify_through(
    uac_sender: &UacSender,
    resolver: &SipResolver,
    store: &Arc<SubscribeStore>,
    dialog: &SubscribeDialog,
    subscription_state: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    gate: Option<&ReplyGate>,
    extra_headers: &[(String, String)],
) -> PyResult<()> {
    // Determine transport destination: first Route URI or remote_target.
    let ruri = parse_uri_standalone(&dialog.remote_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid remote target: {error}"))
    })?;
    let (destination, transport) = if let (true, Some(address), Some(transport)) = (
        dialog.route_set.is_empty(),
        dialog.received_address,
        dialog.received_transport.as_deref(),
    ) {
        let transport = received_transport(transport);
        (address, transport)
    } else {
        let resolve_target: String = dialog
            .route_set
            .first()
            .map(|route| {
                route
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
            .unwrap_or_else(|| dialog.remote_target.clone());

        let resolve_uri = parse_uri_standalone(&resolve_target).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid route/target URI '{resolve_target}': {error}"
            ))
        })?;

        let transport_hint = resolve_uri
            .get_param("transport")
            .map(|s: &str| s.to_string());
        let scheme = resolve_uri.scheme.clone();

        let destination = resolver
            .resolve(
                &resolve_uri.host,
                resolve_uri.port,
                scheme.as_str(),
                transport_hint.as_deref(),
            )
            .await;

        let target = destination.into_iter().next().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cannot resolve destination for '{resolve_target}'"
            ))
        })?;

        let transport = match target.transport.as_deref().or(transport_hint.as_deref()) {
            Some(hint) => match hint.to_lowercase().as_str() {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                "sctp" => Transport::Sctp,
                _ => Transport::Udp,
            },
            None => {
                if scheme == "sips" {
                    Transport::Tls
                } else {
                    Transport::Udp
                }
            }
        };

        (target.address, transport)
    };

    // The listener of the subscriber's connection, when known, names us.
    let connection = dialog
        .received_connection_id
        .map(crate::transport::ConnectionId);
    let (local_host, local_port) =
        uac_sender.sent_by_for(transport, Some(destination), connection.unwrap_or_default());
    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    let via = format!("SIP/2.0/{transport} {local_host}:{local_port};branch={branch}");
    let cseq_str = format!("{} NOTIFY", dialog.cseq);

    // NOTIFY tag orientation (RFC 6665 §4.4.1): From = notifier (us),
    // To = subscriber (peer).
    let from_header = format!("<{}>;tag={}", dialog.local_uri, dialog.local_tag);
    let to_header = format!("<{}>;tag={}", dialog.remote_uri, dialog.remote_tag);

    let mut builder = SipMessageBuilder::new()
        .request(Method::Notify, ruri)
        .via(via)
        .call_id(dialog.call_id.clone())
        .cseq(cseq_str)
        .max_forwards(70)
        .from(from_header)
        .to(to_header)
        .header(
            "Contact",
            format_default_contact(&local_host, local_port, transport),
        )
        .header("Event", dialog.event.clone())
        .header("Subscription-State", subscription_state.to_string());

    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }
    for (name, value) in extra_headers {
        builder = builder.header(name, value.clone());
    }

    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct.to_string());
    }

    if let Some(body_bytes) = body {
        builder = builder.body(body_bytes.to_vec());
    } else {
        builder = builder.content_length(0);
    }

    let message = builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to build NOTIFY: {error}"))
    })?;
    // A stream subscriber keeps its connection; else over the MTU goes TCP (RFC 3261 §18.1.1).
    let stream_flow = dialog.route_set.is_empty()
        && dialog.received_address.is_some()
        && transport != Transport::Udp;
    let super::super::uac_resolved::Routed {
        message,
        destination,
        transport,
    } = super::super::uac_resolved::ResolvedEgress::of_dialog(dialog, destination, transport)
        .route(uac_sender, resolver, message)
        .await;

    // The final response is watched (RFC 6665 §4.2.2), from a registration
    // made before the NOTIFY can leave, so an answer that overtakes the rest
    // of this function still finds its transaction.
    let answered = uac_sender.expect_final_response(&branch);

    // Sent from the handler that accepted the subscription: hold it behind the
    // SUBSCRIBE's reply, which the dispatcher sends once the handler returns
    // (RFC 6665 §4.1.2.3). Once the gate has closed it goes out now.
    let message = match gate {
        Some(gate) => match gate.hold(message, destination, transport) {
            None => {
                watch_notify(Arc::clone(store), dialog, answered);
                return Ok(());
            }
            Some(message) => message,
        },
        None => message,
    };
    if stream_flow {
        // Exact match only: IP-only reuse can select another subscriber's
        // connection when several phones share one front proxy.
        let Some(connection_id) = super::super::stream_connections()
            .and_then(|registry| registry.get(&destination, transport))
            .filter(|connection_id| {
                dialog
                    .received_connection_id
                    .is_none_or(|expected| connection_id.0 == expected)
            })
        else {
            // No NOTIFY left, so there is no transaction to wait on.
            uac_sender.expire_branch(&branch);
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "SUBSCRIBE transport flow is no longer connected",
            ));
        };
        watch_notify(Arc::clone(store), dialog, answered);
        uac_sender.send_request_on_connection(message, destination, transport, connection_id);
    } else {
        watch_notify(Arc::clone(store), dialog, answered);
        uac_sender.send_request(message, destination, transport);
    }
    debug!(id = %dialog.id, "subscribe_state: NOTIFY sent");
    Ok(())
}

#[cfg(test)]
#[path = "subscribe_notify_tests.rs"]
mod tests;
