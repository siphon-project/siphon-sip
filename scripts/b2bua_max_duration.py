"""B2BUA script for the maximum-call-duration SIPp test
(scripts/b2bua_max_duration_test.sh).

The call is dialled with a short ``max_duration``; both parties then sit on the
answered call doing nothing. Nobody sends a BYE, no session timer is configured,
and the ring timeout stopped applying at the 200 OK — so if the cap does not
fire, the call simply stays up and both SIPp peers time out.

``MODE`` selects where the cap comes from, because the two paths reach the call
actor differently and only one of them goes through the script:

  ``dial``    ``call.dial(max_duration=...)`` — the per-call kwarg.
  ``config``  no kwarg at all; the cap is ``b2bua.max_call_duration_secs`` in
              the config, which is what covers calls the dial plan says nothing
              about.
  ``optout``  the config cap is set AND the call passes ``max_duration=0``, so
              the call must survive it. This is the arm that catches a cap
              applied unconditionally.
"""

import os

from siphon import b2bua, log, proxy

TARGET = os.environ.get("MAX_DURATION_TARGET", "sip:bob@127.0.0.1:5072")
MODE = os.environ.get("MODE", "dial")
MAX_DURATION_SECS = int(os.environ.get("MAX_DURATION_SECS", "5"))


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    if MODE == "dial":
        call.dial(TARGET, timeout=10, max_duration=MAX_DURATION_SECS)
    elif MODE == "optout":
        # Explicitly uncapped, against a configured ceiling this call is well past.
        call.dial(TARGET, timeout=10, max_duration=0)
    else:
        # The cap comes from b2bua.max_call_duration_secs; the dial says nothing.
        call.dial(TARGET, timeout=10)


@b2bua.on_failure
def failed(call, code, reason):
    log.info(f"[{call.id}] call failed {code} {reason}")


@b2bua.on_bye
def ended(call, initiator):
    # A duration cut is a framework teardown, so this must NOT fire for it —
    # only for a BYE an actual peer sent.
    log.info(f"[{call.id}] on_bye fired, initiator={initiator.side}")
