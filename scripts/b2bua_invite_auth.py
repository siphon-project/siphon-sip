"""
SIPhon B2BUA A-leg INVITE authentication test script.

siphon itself challenges the *caller* before dialling anything — the opposite of
scripts/b2bua_auth_passthrough.py, where the downstream PBX issues the challenge
and siphon merely relays it.

The point being gated: with any ``@b2bua.*`` handler registered, the dispatcher
routes INVITE straight to the B2BUA path, so ``@proxy.on_request`` never sees it.
Authenticating the caller therefore has to happen against the ``Call`` object:

    auth.require_proxy_digest(call, realm=...)

Returning ``False`` arms the 407 as the call's deferred reject, so siphon answers
the A-leg and drops the call actor without ever building a B-leg INVITE.

Used by the b2bua_invite_auth SIPp scenario to prove:
  1. an unauthenticated INVITE is answered 407 with a Proxy-Authenticate
     challenge, and no INVITE reaches the B-leg UAS,
  2. the authenticated re-INVITE is let through and bridged normally,
  3. the caller's hop-by-hop Proxy-Authorization does not cross to the B-leg.
"""
from siphon import auth, b2bua, log, proxy

# The downstream UAS the authenticated call is bridged to.
NEXT_HOP = "sip:172.20.0.101:5060"

REALM = "siphon.test"


@proxy.on_request
def route(request):
    # OPTIONS keepalive (health probe)
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")


@b2bua.on_invite
def new_call(call):
    # Challenge the caller. On the first INVITE this arms a 407 carrying a fresh
    # nonce and returns False — siphon answers the A-leg itself and no B-leg is
    # dialled. On the authenticated re-INVITE it returns True and strips the
    # hop-by-hop Proxy-Authorization off the message the B-leg INVITE is built
    # from.
    if not auth.require_proxy_digest(call, realm=REALM):
        log.info(f"challenged {call.from_uri} with 407 (realm={REALM})")
        return

    log.info(f"authenticated {call.auth_user} -> dialling {NEXT_HOP}")
    call.dial(str(call.ruri), timeout=30, next_hop=NEXT_HOP)


@b2bua.on_failure
def call_failed(call, code, reason):
    log.warn(f"B leg failed {code} {reason} for call {call.id}")
    call.reject(code, reason)


@b2bua.on_bye
def call_ended(call, initiator):
    call.terminate()
