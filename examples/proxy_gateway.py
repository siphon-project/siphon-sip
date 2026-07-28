"""
SIPhon proxy gateway routing script for functional testing.

Routes INVITE requests to a gateway selected by gateway.select()
instead of looking up registered contacts.  Proves end-to-end gateway
wiring: YAML config -> Rust DispatcherManager -> Python API -> relay.
"""
from siphon import proxy, registrar, auth, gateway, log

DOMAIN = "siphon.test"


@proxy.on_request
def route(request):
    # Local OPTIONS keepalive
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # In-dialog sequential requests
    if request.in_dialog:
        # loose_route() consumes only Route entries that identify us
        # (RFC 3261 §16.4).  A False return means the top Route belongs to
        # another proxy, and relay() follows it (§16.6) — so forward either
        # way.  Rejecting here would 404 a perfectly routable in-dialog
        # request whose route set simply points somewhere else next.
        request.loose_route()
        request.relay()
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return

    # For INVITE (and other out-of-dialog requests), use gateway dispatcher
    destination = gateway.select("gateways")
    if not destination:
        log.error("no healthy gateway in 'gateways' group")
        request.reply(503, "Service Unavailable")
        return

    log.info(f"gateway selected: {destination.uri}")
    request.record_route()
    request.relay(destination.uri)
