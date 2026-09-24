"""
SIPhon B2BUA test script — IR.92-style 100rel advertiser.

Mimics an IMS BGCF/MGCF bridging a plain SIP trunk (A-leg, no 100rel) to an
IMS UE (B-leg).  Before dialing, it adds `Supported: 100rel` + `Allow: PRACK`
to the incoming INVITE so the B-leg UE offers reliable provisionals (IR.92
handsets won't raise the alerting UI otherwise).

This deliberately mutates the *shared* incoming INVITE (the only API available
to shape B-leg headers).  It is the regression guard for the gate-poisoning
bug: siphon must snapshot the A-leg's on-wire 100rel capability BEFORE this
handler runs, so the reliable-1xx strip toward the non-100rel A-leg trunk is
still applied.  If siphon read the (now-mutated) INVITE back, it would conclude
the trunk supports 100rel and leak the reliable 183 — and the trunk would
CANCEL the call.
"""
from siphon import b2bua, proxy, registrar, auth, log

DOMAIN = "siphon.test"


@proxy.on_request("REGISTER")
async def register(request):
    # Split out of `route` because it is the only branch that awaits. An
    # `async def` handler goes through an asyncio driver, a `def` handler runs
    # on the synchronous pool, and a coroutine that reaches no `await` still
    # costs a build, a cross-thread handoff and a resolve per message. Keeping
    # the per-message path synchronous roughly halves CPU at scale.
    if not await auth.require_digest(request, realm=DOMAIN):
        return
    registrar.save(request)


@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return


@b2bua.on_invite
def new_call(call):
    contacts = registrar.lookup(call.ruri)
    if not contacts:
        call.reject(404, "Not Found")
        return

    # Advertise reliable provisionals toward the B-leg UE (IR.92).  This mutates
    # the shared incoming INVITE — siphon must have already snapshotted the
    # A-leg's on-wire (no-100rel) capability for the reliable-1xx strip gate.
    call.set_header("Supported", "timer, 100rel")
    call.set_header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, PRACK")

    log.info(f"Forking {call.from_uri} -> {len(contacts)} contact(s) with 100rel advertised")
    call.fork(
        [c.uri for c in contacts],
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
