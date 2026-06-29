"""SIPhon as a Diameter server.

siphon terminates inbound Diameter from authenticated peers, runs the CER/CEA
handshake and the DWR/DWA watchdog, and hands each inbound request to a Python
handler. What the server *does* with a request — answer it locally, or relay it
to a backend — is entirely script policy.

This example front-ends a backend node: inbound requests are relayed to the
configured backend, the answer is rewritten on the way back (topology hiding),
and a signalling event is emitted per transaction.

The two Rust-side admission gates (source-IP ACL + Origin-Host validation) have
already passed before any handler runs — a script bug cannot admit an
unauthenticated peer.

    siphon --config examples/diameter_server.yaml
"""

from siphon import diameter, log

# Diameter Result-Code (RFC 6733 §7.1).
DIAMETER_UNABLE_TO_DELIVER = 3002


def _identity():
    config = diameter.config
    return config["origin_host"], config["origin_realm"]


@diameter.on_inbound_cer
def cer_received(peer_addr, peer_name, asserted_origin_host):
    """Advertise this server's identity back in the CEA."""
    origin_host, origin_realm = _identity()
    log.info(f"CER from {peer_name}@{peer_addr} ({asserted_origin_host})")
    return origin_host, origin_realm


@diameter.on_request
async def handle(req):
    """Relay each inbound request to the backend and return the answer.

    siphon transports the request; it does not interpret the application. A
    real deployment would answer some commands locally (acting as the node of
    record) and relay others — that decision is yours, here in Python.
    """
    peer = diameter.peer_pool("backend").pick_round_robin()
    if peer is None:
        log.warn(f"no live backend for {req.command_name}")
        return req.reject(DIAMETER_UNABLE_TO_DELIVER)

    # forward_to handles Route-Record loop detection and synthesises an error
    # answer (3005/3002/3004) on loop / unreachable / timeout.
    return await req.forward_to(peer, timeout_secs=10)


@diameter.on_reply
def rewrite(req, answer):
    """Rewrite answer AVPs centrally before they go back upstream.

    Here: topology hiding — replace the backend's Origin-Host/-Realm with this
    server's identity so peers never learn the internal node name. One place to
    do it for every answer, instead of repeating it in each on_request handler.
    """
    origin_host, origin_realm = _identity()
    answer.set_avp("Origin-Host", origin_host.encode())
    answer.set_avp("Origin-Realm", origin_realm.encode())


@diameter.on_request_completed
def completed(req, answer, latency_us):
    """Emit a signalling event per transaction (after the answer is sent)."""
    diameter.event_sink.emit(
        {
            "peer": req.peer.name,
            "command": req.command_name,
            "session_id": req.session_id,
            "result_code": answer.result_code if answer else None,
            "latency_us": latency_us,
        }
    )
