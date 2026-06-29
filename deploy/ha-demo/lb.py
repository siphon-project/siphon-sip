"""
HA-demo FRONTEND load-balancer script.

A thin SIPhon proxy that spreads new transactions across a `gateway` group of
backend nodes (configured in siphon-frontend.yaml). This is the "front LB" from
docs/deployment.md, dogfooded with SIPhon itself.

Affinity: requests are hashed on the AoR (To-URI) so a subscriber's REGISTER and the
terminating calls to them deterministically land on the SAME backend — which is the
node that then holds their binding in its node-local registrar. That's what makes
any-node terminating delivery work without live cross-node state sharing.
"""
from siphon import proxy, gateway, log


@proxy.on_request
def route(request):
    # In-dialog requests follow the established route set, not the LB.
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # Consistent-hash on the AoR for subscriber affinity.
    destination = gateway.select("backends", key=str(request.to_uri))
    if not destination:
        log.error("no healthy backend in 'backends' group")
        request.reply(503, "Service Unavailable")
        return

    log.info(f"LB {request.method} {request.to_uri} -> {destination.uri}")
    request.record_route()
    request.relay(destination.uri)
