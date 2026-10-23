//! The in-dialog SUBSCRIBE of a subscription siphon made (`handle.refresh()`,
//! `handle.terminate()`): where it goes, and the message.

use std::sync::Arc;

use uuid::Uuid;

use super::{SEND_RESOLVER, UAC_SENDER};
use crate::dns::SipResolver;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_uri_standalone;
use crate::subscribe_state::SubscribeDialog;
use crate::transport::Transport;
use crate::uac::UacSender;
use pyo3::prelude::*;

/// Send an in-dialog SUBSCRIBE (refresh or Expires:0 termination)
/// without waiting for a response. Used by `terminate()` on outbound
/// dialogs — the response carries no information we need.
pub(super) async fn send_in_dialog_subscribe(
    dialog: &SubscribeDialog,
    expires_secs: u64,
) -> PyResult<()> {
    let (uac, resolver) = in_dialog_senders()?;
    send_in_dialog(
        uac,
        resolver,
        crate::registrant::manager().map(Arc::as_ref),
        dialog,
        expires_secs,
        None,
    )
    .await
}

/// Send an in-dialog SUBSCRIBE and block until the peer responds.
/// Used by `refresh()` so the script learns about a non-2xx refresh
/// failure synchronously.
pub(super) async fn send_in_dialog_subscribe_with_timeout(
    dialog: &SubscribeDialog,
    expires_secs: u64,
    timeout_ms: u64,
) -> PyResult<()> {
    let (uac, resolver) = in_dialog_senders()?;
    send_in_dialog(
        uac,
        resolver,
        crate::registrant::manager().map(Arc::as_ref),
        dialog,
        expires_secs,
        Some(std::time::Duration::from_millis(timeout_ms)),
    )
    .await
}

fn in_dialog_senders() -> PyResult<(&'static UacSender, &'static SipResolver)> {
    let uac = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state outbound unavailable: UAC sender not initialized",
        )
    })?;
    let resolver = SEND_RESOLVER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state outbound unavailable: DNS resolver not initialized",
        )
    })?;
    Ok((uac, resolver))
}

/// Where an in-dialog SUBSCRIBE goes.
enum InDialogEgress {
    /// Over the security association of the registration the subscription
    /// was made over, as that registration holds it now.
    Flow(super::super::uac_flow::FlowEgress),
    /// To the first Route of the dialog's route set, else its remote target.
    Resolved {
        address: std::net::SocketAddr,
        transport: Transport,
        sent_by: String,
    },
}

/// Send an in-dialog SUBSCRIBE, and with `wait` wait that long for a 2xx.
///
/// A subscription made over a registration's flow goes over that
/// registration's current SA set (it is looked up in `registrants` for every
/// request, since a re-registration replaces the set), carrying the dialog's
/// route set as Route headers. It raises rather than send outside the SA when
/// the registration has none.
pub(super) async fn send_in_dialog(
    uac: &UacSender,
    resolver: &SipResolver,
    registrants: Option<&crate::registrant::RegistrantManager>,
    dialog: &SubscribeDialog,
    expires_secs: u64,
    wait: Option<std::time::Duration>,
) -> PyResult<()> {
    let egress = in_dialog_egress(uac, resolver, registrants, dialog).await?;
    let (sent_by, transport) = match &egress {
        InDialogEgress::Flow(flow) => (flow.sent_by.as_str(), flow.transport),
        InDialogEgress::Resolved {
            sent_by, transport, ..
        } => (sent_by.as_str(), *transport),
    };
    let message = build_in_dialog_subscribe(dialog, expires_secs, transport, sent_by)?;
    let Some(wait) = wait else {
        match &egress {
            InDialogEgress::Flow(flow) => flow.send_and_forget(uac, message),
            InDialogEgress::Resolved {
                address, transport, ..
            } => uac.send_request(message, *address, *transport),
        }
        return Ok(());
    };
    let receiver = match &egress {
        InDialogEgress::Flow(flow) => flow.send(uac, message),
        InDialogEgress::Resolved {
            address, transport, ..
        } => uac.send_request_with_response(message, *address, *transport),
    };
    match tokio::time::timeout(wait, receiver).await {
        Ok(Ok(crate::uac::UacResult::Response(message))) => {
            let status = message.status_code().unwrap_or(0);
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "subscribe refresh got non-2xx response: {status}"
                )))
            }
        }
        _ => Err(pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe refresh timed out waiting for 2xx",
        )),
    }
}

async fn in_dialog_egress(
    uac: &UacSender,
    resolver: &SipResolver,
    registrants: Option<&crate::registrant::RegistrantManager>,
    dialog: &SubscribeDialog,
) -> PyResult<InDialogEgress> {
    if let Some(registrant) = &dialog.registrant_flow {
        let flow = registrants
            .and_then(|manager| {
                super::super::flow_kind::registrant_flow(manager, &registrant.aor, registrant.ue_ip)
            })
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "subscribe_state: {} has no security association to send the in-dialog \
                     SUBSCRIBE over",
                    registrant.aor
                ))
            })?;
        return Ok(InDialogEgress::Flow(
            super::super::uac_flow::FlowEgress::of(&flow, uac)?,
        ));
    }

    // Same routing rules as send_notify() — first Route URI if present,
    // otherwise the remote target.
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
    let transport = resolved_transport(target.transport.as_deref(), transport_hint, &scheme);
    // Our own sent-by, so the response comes back to us (RFC 3261 §18.2.2).
    let (host, port) = uac.sent_by_for(
        transport,
        Some(target.address),
        crate::transport::ConnectionId::default(),
    );
    Ok(InDialogEgress::Resolved {
        address: target.address,
        transport,
        sent_by: format!("{host}:{port}"),
    })
}

/// The transport a resolved destination is reached over: the resolver's, else
/// the URI's `transport` parameter, else TLS for `sips` and UDP otherwise.
pub(super) fn resolved_transport(
    resolved: Option<&str>,
    transport_hint: Option<String>,
    scheme: &crate::sip::uri::Scheme,
) -> Transport {
    match resolved.or(transport_hint.as_deref()) {
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
    }
}

/// Build a SUBSCRIBE message inside an established dialog. Used for
/// both refresh (`Expires: <new>`) and termination (`Expires: 0`).
fn build_in_dialog_subscribe(
    dialog: &SubscribeDialog,
    expires_secs: u64,
    transport: Transport,
    sent_by: &str,
) -> PyResult<crate::sip::message::SipMessage> {
    let ruri = parse_uri_standalone(&dialog.remote_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "invalid remote_target URI '{}': {error}",
            dialog.remote_target
        ))
    })?;

    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    let via = format!("SIP/2.0/{transport} {sent_by};branch={branch}");
    let cseq_str = format!("{} SUBSCRIBE", dialog.cseq);

    // Outbound watcher orientation: From = us (subscriber), To = peer.
    let from_header = format!("<{}>;tag={}", dialog.local_uri, dialog.local_tag);
    let to_header = format!("<{}>;tag={}", dialog.remote_uri, dialog.remote_tag);

    let mut builder = SipMessageBuilder::new()
        .request(Method::Subscribe, ruri)
        .via(via)
        .call_id(dialog.call_id.clone())
        .cseq(cseq_str)
        .max_forwards(70)
        .from(from_header)
        .to(to_header)
        .header("Event", dialog.event.clone())
        .header("Expires", expires_secs.to_string());

    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }
    builder = builder.content_length(0);

    builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to build SUBSCRIBE: {error}"))
    })
}
