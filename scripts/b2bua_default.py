"""
SIPhon default B2BUA script.

Bridges calls between two legs with parallel forking:
- on_invite: look up all registered contacts, fork to all (ring all)
- on_early_media: log provisional responses with SDP (183/180 early media)
- on_answer: both legs connected (first B leg to answer wins)
- on_failure: all B legs failed — propagate to A leg
- on_bye: terminate both legs
"""
from siphon import b2bua, proxy, registrar, auth, log

DOMAIN = "siphon.test"


@proxy.on_request
def route(request):
    # OPTIONS keepalive
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # REGISTER with digest auth
    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return


@b2bua.on_invite
def new_call(call):
    contacts = registrar.lookup(call.ruri)
    if not contacts:
        call.reject(404, "Not Found")
        return

    log.info(f"Forking {call.from_uri} -> {len(contacts)} contact(s)")
    # Pass the Contact objects: for a binding this process accepted, fork()
    # routes the B-leg INVITE over its captured inbound flow — RFC 5626 §5.3
    # connection reuse, the only way to reach a WebSocket callee (RFC 7118 §5).
    # Non-local contacts fall back to URI routing.
    call.fork(
        contacts,
        strategy="parallel",
        timeout=30,
    )


@b2bua.on_early_media
def early_media(call, reply):
    log.info(f"Call {call.id} early media ({reply.status_code})")


@b2bua.on_answer
def call_answered(call, reply):
    log.info(f"Call {call.id} answered ({reply.status_code})")


@b2bua.on_failure
def call_failed(call, code, reason):
    log.warn(f"All B legs failed {code} {reason} for call {call.id}")
    call.reject(code, reason)


@b2bua.on_bye
def call_ended(call, initiator):
    log.info(f"Call {call.id} ended (initiator: {initiator.side})")
    call.terminate()
