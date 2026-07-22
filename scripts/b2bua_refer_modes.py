"""
SIPhon B2BUA REFER mode-dispatch script (functional-test fixture).

Same bridging as the default B2BUA script, but on_refer picks the transfer mode
from an optional X-Refer-Mode header on the REFER (transparent | terminate |
reject), defaulting to transparent. This lets the SIPp REFER acceptance
scenarios exercise every inbound mode against a single running siphon.
"""
from siphon import b2bua, proxy, registrar, auth, log

DOMAIN = "siphon.test"


@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
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
    call.fork(contacts, strategy="parallel", timeout=30)


@b2bua.on_answer
def answered(call, reply):
    log.info(f"Call {call.id} answered ({reply.status_code})")
    # Outbound (siphon-originated) transfer: when the caller asked for it via an
    # X-Outbound-Refer header, send a REFER back to the caller (A-leg) once the
    # call is up — the IVR / TAS offload pattern.
    target = call.get_header("X-Outbound-Refer")
    if target:
        log.info(f"Call {call.id} outbound REFER -> {target}")
        call.refer(target)


@b2bua.on_refer
def on_refer(call):
    mode = (call.get_header("X-Refer-Mode") or "transparent").strip().lower()
    log.info(f"Call {call.id} REFER -> {call.refer_to} (mode={mode})")
    if mode == "reject":
        call.reject_refer(603, "Decline")
    elif mode == "terminate":
        call.accept_refer(mode="terminate")
    else:
        call.accept_refer(mode="transparent")


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"Call {call.id} ended (initiator: {initiator.side})")
    call.terminate()
