"""
HA-demo BACKEND proxy script.

Deliberately minimal — this exists only to demonstrate the scaling/redundancy
topology, NOT as a production script. It:

- answers local OPTIONS pings (used as a readiness check),
- saves REGISTERs into the (Redis-backed) registrar — WITHOUT digest auth, so the
  demo driver can register with a plain REGISTER,
- looks up the registrar and relays INVITE/other out-of-dialog requests,
- loose-routes in-dialog requests.

For a realistic starting point use scripts/proxy_default.py (which adds digest auth,
sanity checks, presence, etc.).
"""
from siphon import proxy, registrar, log


@proxy.on_request
def route(request):
    # Local OPTIONS keepalive / readiness ping.
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # In-dialog sequential requests follow the route set.
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # REGISTER -> persist into the registrar (Redis write-through). No auth in the
    # demo. registrar.save() also sends the 200 OK.
    if request.method == "REGISTER":
        registrar.save(request)
        log.info(f"registered {request.to_uri}")
        return

    # Everything else (INVITE, MESSAGE, ...) -> location lookup + relay.
    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        # 404 here is the signal the demo uses to prove a binding is NOT known to
        # this node (e.g. on a sibling node that never saw the REGISTER, or before
        # a restart restores the snapshot).
        request.reply(404, "Not Found")
        return

    request.record_route()
    request.fork(contacts)
