"""Test fixture B2BUA for routing a binding through its RFC 3327 Path.

The B2BUA builds a *fresh* B-leg INVITE rather than forwarding the caller's, so
none of the proxy-side Path work applies to it.  Four acceptance scenarios share
this script, one AoR each, and every one of them registers a binding whose
Contact is somewhere the call can NOT be completed — exactly like a UE behind
NAT, an IPsec SA, or with a `.invalid` contact.  The only routable statement is
the Path, so a B-leg that reaches its edge proves it was routed by the route set
and not by the Contact URI.

  sip:bob@…      parallel call.fork() over ONE binding.  The plainest form of
                 the bug: a callee registered through an edge proxy was
                 unreachable in B2BUA mode even with a single binding.

  sip:bobseq@…   sequential call.fork() over TWO bindings with different Path
                 tokens.  The first edge answers 404 — its binding is gone — so
                 the second branch has to be routed by the *second* binding's
                 own Path.  Shared route sets deliver it back to the dead edge.

  sip:bobdial@…  call.dial(uri, route=contact.path).  `route=` predates this
                 fixture but only ever set the header, so the INVITE was
                 correctly formed and sent to the wrong place.

  sip:bobmtu@…   parallel call.fork() over one binding whose Contact host is a
                 resolvable DNS name with a live TCP listener, driven by an
                 over-MTU INVITE.  The RFC 3261 §18.1.1 UDP→TCP re-probe must
                 follow the same URI the destination came from; probing the
                 Contact instead resolves that name and lands the B-leg there,
                 bypassing the Path on precisely the messages most likely to
                 need it.

Run by scripts/b2bua_path_test.sh via sipp/docker-compose.yaml
(`--profile b2bua-path`), config sipp/configs/siphon.b2bua-path-test.yaml.
"""
from siphon import b2bua, proxy, registrar, log


@proxy.on_request
def route(request):
    # Same shape as the other B2BUA fixtures: OPTIONS keepalive (the container
    # healthcheck) and REGISTER handled here, everything else — INVITE — falls
    # through to @b2bua.on_invite.
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
    if request.method == "REGISTER":
        # No auth: the fixture is about routing, and each UE registers once.
        # registrar.save() stores the REGISTER's Path vector with the binding,
        # which is the whole input to every scenario below.
        registrar.save(request)
        return


@b2bua.on_invite
def on_invite(call):
    # call.ruri is a SipUri here (not the plain string a Call's other URI
    # properties hand back), so the AoR userpart selects the scenario directly.
    user = call.ruri.user or ""
    contacts = registrar.lookup(call.ruri)
    if not contacts:
        log.warn(f"[b2bua-path] no binding for {call.ruri}")
        call.reject(404, "Not Found")
        return

    for contact in contacts:
        log.info(
            f"[b2bua-path] {user} binding {contact.uri} "
            f"path={contact.path} q={contact.q} is_local={contact.is_local}"
        )

    if user == "bobdial":
        # One binding, dialled explicitly with its Path as the route set.
        contact = contacts[0]
        call.dial(contact.uri, route=contact.path)
        return

    if user == "bobseq":
        # Sequential: each branch has to carry its own binding's route set.
        call.fork(contacts, strategy="sequential")
        return

    # bob / bobmtu: parallel fork, Contact objects so the Path comes with them.
    call.fork(contacts)


@b2bua.on_answer
def on_answer(call, reply):
    log.info(f"[b2bua-path] answered {call.id} ({reply.status_code})")


@b2bua.on_failure
def on_failure(call, code, reason):
    # Reject rather than let the caller time out: a scenario that fails should
    # fail fast and say what the B-leg said.
    log.warn(f"[b2bua-path] every B-leg failed {code} {reason} for {call.id}")
    call.reject(code, reason)


