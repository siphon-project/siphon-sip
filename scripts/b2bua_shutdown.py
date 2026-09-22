"""B2BUA script for the shutdown-teardown SIPp test
(scripts/shutdown_teardown_test.sh).

The call is dialled and answered, and then both parties sit still. Nobody sends
a BYE, no session timer and no duration cap are configured, and the ring timeout
stopped applying at the 200 OK — so if the drain deadline does not tear the call
down, the call simply stays up and both SIPp peers time out.

``@b2bua.on_answer`` logs the line the runner polls for before it signals.
``@b2bua.on_bye`` logs so the runner can assert it stays quiet: a framework
teardown is not a peer hangup, and a shutdown that fired the handler would mean
siphon had mistaken its own BYE for the caller's.
"""

import os

from siphon import b2bua, log, proxy

TARGET = os.environ.get("SHUTDOWN_TARGET", "sip:bob@127.0.0.1:5072")


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    call.dial(TARGET, timeout=10)


@b2bua.on_answer
def answered(call, reply):
    # The runner polls for this: the SIGTERM has to land while the call is
    # answered, because a signal that arrived before the 200 OK would exercise
    # the ringing arm of the teardown instead.
    log.info(f"[{call.id}] shutdown-test call answered")


@b2bua.on_failure
def failed(call, code, reason):
    log.info(f"[{call.id}] call failed {code} {reason}")


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"[{call.id}] on_bye fired, initiator={initiator.side}")
