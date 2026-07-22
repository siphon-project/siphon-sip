"""
SIPhon B2BUA with prepaid Ro online charging (reserve-before-connect).

Same registrar-based parallel forking as b2bua_default.py, but every call is
gated on a Diameter Ro credit reservation:

- on_invite: reserve credit (CCR-INITIAL) BEFORE forking the B-leg. A grant
  forks; a denial rejects with 402 and no B-leg is ever created (prepaid: no
  call unless the OCS allows it).
- After the grant siphon runs the SCUR lifecycle itself from the `ro:` config —
  CCR-UPDATE on the OCS-granted cadence, mid-call disconnect on credit
  exhaustion, CCR-TERMINATION on BYE. The handler is just the gate.

Requires an `ro:` block in siphon.yaml pointing a Diameter route at the OCS.
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
async def new_call(call):
    contacts = registrar.lookup(call.ruri)
    if not contacts:
        call.reject(404, "Not Found")
        return

    # Reserve prepaid credit BEFORE connecting the B-leg. Charged party and
    # rating come from the `ro:` config; pass subscription_id=... to override.
    decision = await call.ro_authorize()
    if not decision["authorized"]:
        log.warn(f"Call {call.id} denied credit (rc={decision['result_code']}) -> 402")
        call.reject(402, "Payment Required")
        return

    log.info(
        f"Call {call.id} reserved {decision['granted_time']}s "
        f"(session {decision['session_id']}) -> forking {len(contacts)} contact(s)"
    )
    # Non-local contacts fall back to URI routing; a binding this process
    # accepted forks over its captured inbound flow (RFC 5626 §5.3).
    call.fork(contacts, strategy="parallel", timeout=30)


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
