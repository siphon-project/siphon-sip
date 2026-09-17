"""Reports, on the wire, which address siphon believes a request came from.

The whole point of the PROXY protocol support is that consumers stop keying on
the front's address and start keying on the client's.  A container test cannot
read siphon's memory, so this script copies what each consumer actually holds
into response headers the SIPp caller can assert on:

  X-Seen-Source        request.source_ip            — the live request
  X-Seen-In-Ua-Range   request.source_ip_in([...])  — the CIDR predicate
  X-Binding-Flow       contact.flow.remote_addr     — the stored registration

`fix_nated_register()` is asserted straight off the wire instead: it rewrites
the REGISTER's Via, and the 200 OK echoes that Via back, so the caller checks
`received=` on the response itself. Deliberately NOT `contact.uri` — that is the
UA's own self-declared Contact, identical whether or not the substitution ran,
so asserting on it would pass against broken wiring.

Behind the front every one of these must read the UA's address (192.0.2.30).
If the substitution is not wired through, they read the front's (192.0.2.20)
and the caller fails the run.  A test that only asserted "a 200 came back"
would pass either way, which is exactly the hole this closes.
"""
from siphon import cdr, log, proxy, registrar

# The AoR the caller registers, looked up again on the INVITE so the assertion
# reads the *stored* binding rather than the request in hand.
AOR = "sip:ua@pbx.example"

# The UA's address on the compose network. The front is 192.0.2.20 and is
# deliberately not in here: a match proves the client was seen, not the proxy.
UA_RANGE = ["192.0.2.30/32"]


@proxy.on_request
def route(request):
    method = request.method

    # Container healthcheck, over the plain UDP listener.
    if method == "OPTIONS":
        request.reply(200, "OK")
        return

    if method == "REGISTER":
        # Writes received=/rport= from the address siphon believes the request
        # came from, so the stored contact carries it too.
        request.fix_nated_register()
        # save() sends its own 200; the assertions ride on the INVITE below.
        registrar.save(request)
        log.info(f"REGISTER seen from {request.source_ip}")
        return

    if method == "INVITE":
        contacts = registrar.lookup(AOR)
        binding_flow = "none"
        if contacts:
            flow = contacts[0].flow
            if flow is not None:
                binding_flow = flow.remote_addr

        request.set_reply_header("X-Seen-Source", request.source_ip)
        request.set_reply_header(
            "X-Seen-In-Ua-Range",
            "yes" if request.source_ip_in(UA_RANGE) else "no",
        )
        request.set_reply_header("X-Binding-Flow", binding_flow)
        # The CDR row's source_ip comes from the same address, and the driver
        # script asserts it off the file: that consumer's decision point is
        # private to the dispatcher, so this is the only place it is provable.
        cdr.write(request, extra={"case": "proxy-protocol"})
        log.info(f"INVITE seen from {request.source_ip}, binding flow {binding_flow}")
        request.reply(200, "OK")
        return

    # ACK for the locally generated 200 arrives as a fresh request; there is
    # nothing to answer and nowhere to relay it. Anything else is not part of
    # this test. Returning without reply()/relay() drops silently.
    return
