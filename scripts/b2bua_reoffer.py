"""B2BUA script for the @b2bua.on_reoffer SIPp test
(scripts/b2bua_reoffer_test.sh).

`on_invite` dials a fixed callee. The caller's hold is answered here
(`offer.answer()`), so the callee is sent nothing and could be played music on
hold; any other offer is relayed, marked with what it was read as. Both hooks
log what they saw for the test to check.
"""

import os

from siphon import b2bua, log, proxy

TARGET = os.environ.get("REOFFER_TARGET", "sip:bob@127.0.0.1:5074")


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    call.dial(TARGET)


@b2bua.on_reoffer
def reoffer(call, offer):
    log.info(f"reoffer seen: {offer.method} {offer.side} {offer.kind}")
    if offer.kind == "hold":
        offer.answer()
    else:
        offer.request.set_header("X-Reoffer", offer.kind)


@b2bua.on_reoffer_answered
def reoffer_answered(call, offer):
    log.info(
        f"reoffer answered: {offer.kind} {offer.status_code} "
        f"{offer.answer_direction} {offer.answered_locally}"
    )


@b2bua.on_bye
def ended(call, initiator):
    call.terminate()
