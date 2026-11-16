//! Running the handler of an inbound request and sending its answer.

use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use tracing::{error, warn};

use super::{NativeHandler, NativeHandlers, NativeOutcome, NativeRequest};
use crate::diameter::codec::DiameterMsg;
use crate::diameter::dictionary;
use crate::diameter::forward;
use crate::diameter::peer::{DiameterPeer, IncomingRequest};

/// The connection a request arrived on and the identity it is answered as.
pub(crate) struct Inbound<'a> {
    pub(crate) peer: &'a Arc<DiameterPeer>,
    /// The configured name of the peer.
    pub(crate) peer_name: &'a str,
    pub(crate) tenant: &'a str,
    /// This node's Origin-Host and Origin-Realm on the connection.
    pub(crate) origin: (&'a str, &'a str),
}

/// What became of a request offered to the native handlers.
pub(crate) enum Served {
    /// A handler answered it; the answer is sent and counted.
    Answered,
    /// No handler took it: it goes to `@diameter.on_request`, as received.
    /// Nothing was sent and nothing was counted.
    Script(IncomingRequest),
}

/// Offer `incoming` to the handlers installed for this process.
pub(crate) async fn serve(
    inbound: Inbound<'_>,
    incoming: IncomingRequest,
    request_features: u64,
    start: Instant,
) -> Served {
    match super::installed() {
        Some(handlers) => serve_with(handlers, inbound, incoming, request_features, start).await,
        None => Served::Script(incoming),
    }
}

/// Offer `incoming` to `handlers`. A request one of them answers gets what
/// an answer of the script path gets: the DOIC report of this node (RFC
/// 7683) for a requester that advertised it, and the inbound metrics.
pub(crate) async fn serve_with(
    handlers: &NativeHandlers,
    inbound: Inbound<'_>,
    incoming: IncomingRequest,
    request_features: u64,
    start: Instant,
) -> Served {
    let Some(handler) = handlers.resolve(incoming.application_id, incoming.command_code) else {
        return Served::Script(incoming);
    };
    // A request that does not parse is the script path's to refuse (5014).
    let Ok(message) = DiameterMsg::from_wire(&incoming.raw) else {
        return Served::Script(incoming);
    };
    let Some(wire) = answer_wire(handler, message, &inbound).await else {
        return Served::Script(incoming);
    };

    // Counted whether or not the write succeeds, as on the script path.
    let result_label = forward::emitted_answer_result_label(&wire);
    let wire = crate::diameter::overload::annotate_answer(request_features, wire);
    if let Err(error) = inbound.peer.send_response(wire).await {
        warn!(%error, "Diameter server: failed to send answer upstream");
    }
    crate::metrics::record_diameter_inbound(
        incoming.command_code,
        result_label,
        start.elapsed(),
        crate::metrics::DIAMETER_PATH_NATIVE,
    );
    Served::Answered
}

/// Run `handler` on `message` and return the answer to send, None when it
/// hands the request to the script. A handler that fails, panics or is not
/// done within the handler timeout of the script path
/// (`script.handler_timeout_secs`) is answered DIAMETER_UNABLE_TO_COMPLY
/// (5012).
pub(crate) async fn answer_wire(
    handler: &NativeHandler,
    message: DiameterMsg,
    inbound: &Inbound<'_>,
) -> Option<Vec<u8>> {
    let limit = match crate::script::async_pool::AsyncPool::global() {
        Some(pool) => pool.coroutine_timeout(),
        None => crate::config::coroutine_timeout(None),
    };
    answer_wire_within(handler, message, inbound, limit).await
}

/// [`answer_wire`] with the time a handler gets.
pub(crate) async fn answer_wire_within(
    handler: &NativeHandler,
    message: DiameterMsg,
    inbound: &Inbound<'_>,
    limit: Duration,
) -> Option<Vec<u8>> {
    let request = NativeRequest::new(
        message,
        Arc::clone(inbound.peer),
        inbound.peer_name,
        inbound.tenant,
        inbound.origin,
    );
    let (application_id, command_code) = (request.application_id(), request.command_code());
    // Kept for the answer made in the handler's place.
    let header = request.received_header();
    let cannot_comply = |reason: &str| {
        forward::build_error_answer(
            &header,
            inbound.origin.0,
            inbound.origin.1,
            dictionary::DIAMETER_UNABLE_TO_COMPLY,
            reason,
        )
        .to_wire()
    };

    // A panic in the handler, or in its future at any poll, unwinds to here.
    let outcome = match std::panic::catch_unwind(AssertUnwindSafe(|| handler(request))) {
        Ok(future) => {
            let guarded = AssertUnwindSafe(future).catch_unwind();
            let Ok(outcome) = tokio::time::timeout(limit, guarded).await else {
                error!(
                    application_id,
                    command_code,
                    timeout_secs = limit.as_secs(),
                    "Diameter server: native handler timed out; answering 5012"
                );
                return Some(cannot_comply("native handler timed out"));
            };
            outcome
        }
        Err(panic) => Err(panic),
    };
    match outcome {
        Ok(Ok(NativeOutcome::Answer(answer))) => Some(answer.to_wire()),
        Ok(Ok(NativeOutcome::Script)) => None,
        Ok(Err(error)) => {
            error!(
                application_id,
                command_code,
                %error,
                "Diameter server: native handler failed; answering 5012"
            );
            Some(cannot_comply("native handler failed"))
        }
        Err(panic) => {
            error!(
                application_id,
                command_code,
                panic = panic_message(panic.as_ref()),
                "Diameter server: native handler panicked; answering 5012"
            );
            Some(cannot_comply("native handler panicked"))
        }
    }
}

/// What a panic was raised with, when it was a string.
fn panic_message(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic>")
}
