//! Answering a request DIAMETER_TOO_BUSY without running the script.

use std::time::Instant;

use tracing::warn;

use crate::diameter::dictionary;
use crate::diameter::peer::{DiameterPeer, IncomingRequest};

/// Answer `incoming` DIAMETER_TOO_BUSY (3004) without running the script, as
/// `diameter.overload.reporting.admission_limit` asks or because no asyncio
/// driver had room for its handler (`reason` says which, in the shed metric),
/// with the overload this node reports (RFC 7683) for a requester that
/// advertised DOIC.
pub(super) async fn shed_too_busy(
    inbound_peer: &DiameterPeer,
    incoming: &IncomingRequest,
    local_origin: (&str, &str),
    reason: &str,
    start: Instant,
) {
    let Some(wire) =
        crate::diameter::overload::too_busy_answer(&incoming.raw, local_origin, reason)
    else {
        warn!("Diameter server: shed a request that does not parse, no answer sent");
        return;
    };
    if let Err(error) = inbound_peer.send_response(wire).await {
        warn!(%error, "Diameter server: failed to send the 3004 of the admission limit");
    }
    crate::metrics::record_diameter_inbound(
        incoming.command_code,
        dictionary::answer_result_label(Some(dictionary::DIAMETER_TOO_BUSY), None),
        start.elapsed(),
        crate::metrics::DIAMETER_PATH_SCRIPT,
    );
}
