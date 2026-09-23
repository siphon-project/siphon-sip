"""
SIPhon B2BUA gateway routing script for functional testing.

Uses gateway.select() to pick the B-leg target instead of registrar.lookup().
Proves end-to-end: YAML gateway config -> Python API -> call.dial().
"""
from siphon import b2bua, proxy, registrar, auth, gateway, log

DOMAIN = "siphon.test"


@proxy.on_request
async def route(request):
    # OPTIONS keepalive
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # REGISTER with digest auth
    if request.method == "REGISTER":
        if not await auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return


@b2bua.on_invite
def new_call(call):
    destination = gateway.select("gateways")
    if not destination:
        log.error("no healthy gateway in 'gateways' group")
        call.reject(503, "Service Unavailable")
        return

    log.info(f"gateway selected for B-leg: {destination.uri}")
    call.dial(destination.uri, timeout=30)


@b2bua.on_answer
def call_answered(call, reply):
    log.info(f"Call {call.id} answered ({reply.status_code})")


@b2bua.on_failure
def call_failed(call, code, reason):
    log.warn(f"B-leg failed {code} {reason} for call {call.id}")
    call.reject(code, reason)


@b2bua.on_bye
def call_ended(call, initiator):
    log.info(f"Call {call.id} ended (initiator: {initiator.side})")
    call.terminate()
