"""
SIPhon default residential proxy script.

Handles:
- OPTIONS keepalive (local)
- REGISTER with digest auth
- In-dialog sequential requests (loose routing)
- INVITE / other requests via location lookup with parallel forking
"""
from siphon import proxy, registrar, auth, log, presence

DOMAIN = "example.com"


@proxy.on_request
def route(request):
    # Reject malformed / RFC 4475 torture traffic before doing any work.
    # The Rust side already drops unparseable messages and auto-483s
    # Max-Forwards==0; sanity_check adds the *semantic* checks on a message that
    # parses: mandatory headers (Via/From/To/Call-ID/CSeq), CSeq method matching
    # the request, and Content-Length matching the body. Scoped to out-of-dialog
    # requests (in-dialog traffic belongs to a dialog siphon already tracks) and
    # dropped silently (no response) so we don't fingerprint the server to
    # fuzzers/scanners. If you interwork with non-compliant legacy UAs, scope
    # this to untrusted sources only (e.g. `and not request.source_ip_in(TRUSTED)`).
    if not request.in_dialog and not proxy.sanity_check(request):
        return

    # Local OPTIONS ping (e.g. from SBC/gateway keepalive)
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # Sequential requests within an existing dialog
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return

    # PUBLISH — handle locally as Event State Compositor (RFC 3903)
    if request.method == "PUBLISH":
        body = request.body
        if body is not None:
            body = body.decode("utf-8") if isinstance(body, bytes) else body
        etag = presence.publish(
            str(request.ruri),
            body or "",
            expires=3600,
        )
        request.set_header("SIP-ETag", etag)
        request.reply(200, "OK")
        return

    # SUBSCRIBE/NOTIFY/MESSAGE — relay to registered contact like INVITE
    # (A real deployment would have a presence server; here we just proxy them.)

    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    request.record_route()
    # Pass the Contact objects (not just .uri): for a binding this process
    # accepted, fork() routes over its captured inbound flow — RFC 5626 §5.3
    # connection reuse, which is the only way to reach a WebSocket UE
    # (RFC 7118 §5).  Cross-instance / non-local contacts fall back to URI
    # routing automatically.
    request.fork(contacts)
