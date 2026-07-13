"""
SIPhon B2BUA auth-passthrough test script.

Models an outbound call that siphon B2BUAs toward a downstream PBX / SIP trunk,
which challenges the *caller* with 407 Proxy Authentication Required. The caller
(not siphon) holds the credentials, so siphon relays the challenge end-to-end
instead of answering it — call.dial(auth_passthrough=True).

Used by the b2bua_auth SIPp scenario to prove siphon:
  1. forwards the B-leg 407 (with its Proxy-Authenticate challenge) to the caller,
  2. does NOT emit a spurious 502 in response to the caller's ACK for that 407.
"""
from siphon import b2bua, proxy, log

# The downstream PBX / SIP trunk the outbound call is routed to. In the test
# this is the SIPp UAS; in production it is the PBX/trunk that challenges the
# caller. The 407 comes from HERE, not from a registered endpoint.
PBX_NEXT_HOP = "sip:172.20.0.52:5060"


@proxy.on_request
def route(request):
    # OPTIONS keepalive (health probe)
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")


@b2bua.on_invite
def new_call(call):
    # Route the outbound call to the downstream PBX/trunk. The PBX challenges
    # (407); auth_passthrough relays that challenge to the caller instead of
    # siphon answering it, so the endpoint authenticates end-to-end and re-INVITEs.
    # (A production script would authorise the caller first, e.g. by checking
    # registrar.is_registered(call.from_uri) — omitted here to keep the gate
    # focused on the 407-relay behaviour.)
    log.info(f"auth-passthrough dial {call.from_uri} -> {PBX_NEXT_HOP}")
    call.dial(str(call.ruri), timeout=30, next_hop=PBX_NEXT_HOP, auth_passthrough=True)


@b2bua.on_failure
def call_failed(call, code, reason):
    log.warn(f"B leg failed {code} {reason} for call {call.id}")
    call.reject(code, reason)


@b2bua.on_bye
def call_ended(call, initiator):
    call.terminate()
