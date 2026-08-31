"""SIPhon B2BUA script for the inbound-`Replaces` acceptance test (fixture).

Deliberately the plainest possible B2BUA: every INVITE is bridged to the one
fixed callee. There is no registrar and no routing logic, so the test is
measuring what siphon does with `Replaces` and nothing else.

The takeover INVITE reaches `on_invite` exactly like any other call and is
admitted here — that is the point. siphon resolves the `Replaces` before the
script runs but does NOT act on it until the script has had its say, because
RFC 3891 §5 makes the header a call-hijack primitive for anyone who learns a
dialog's identifiers. A script that challenges or rejects here stops the
takeover; this one admits it, and siphon then performs the handover instead of
the `call.dial()` below.
"""
import os

from siphon import b2bua, log, proxy

CALLEE = os.environ.get("REPLACES_CALLEE", "sip:bob@172.20.0.70:6002")


@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local:
        request.reply(200, "OK")


@b2bua.on_invite
def new_call(call):
    log.info(f"[{call.id}] INVITE from {call.source_ip} -> {CALLEE}")
    call.dial(CALLEE, timeout=30)


@b2bua.on_answer
def answered(call, reply):
    log.info(f"[{call.id}] answered ({reply.status_code})")


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"[{call.id}] BYE (initiator: {initiator.side})")
    call.terminate()
