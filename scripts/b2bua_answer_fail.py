"""B2BUA script for the answer-time failure SIPp test
(scripts/b2bua_answer_fail_test.sh).

`on_invite` dials a fixed callee that answers. `on_answer` then fails the call,
in whichever way ``MODE`` selects:

  ``raise``      the handler raises, standing in for a media backend that
                 refused the answer — the shape of the real incident, where
                 ``rtpengine.answer()`` could not build a pipeline for the
                 negotiated codec.
  ``terminate``  the handler calls ``call.terminate()``, the explicit form.

Either way siphon must fail the caller and release the answered B-leg, instead
of connecting a call that has no media path and letting it bill.
"""

import os

from siphon import b2bua, log, proxy

TARGET = os.environ.get("ANSWER_FAIL_TARGET", "sip:bob@127.0.0.1:5072")
MODE = os.environ.get("MODE", "raise")


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    call.dial(TARGET)


@b2bua.on_answer
def answered(call, reply):
    if MODE == "terminate":
        log.info(f"[{call.id}] answer refused by policy — terminating")
        call.terminate()
        return
    # Stands in for a media backend that answered the offer with an error. The
    # handler cannot recover, and what it must NOT do is let the call connect.
    raise RuntimeError("media answer failed: no pipeline for the negotiated codec")


@b2bua.on_failure
def failed(call, code, reason):
    log.info(f"[{call.id}] call failed {code} {reason}")


@b2bua.on_bye
def ended(call, initiator):
    call.terminate()
