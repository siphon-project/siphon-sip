"""Routing script for the `bridge` acceptance harness.

One decision only: an INVITE for `bridge@` is answered locally against the media
backend and handed to the control application, which then places the second leg
and joins the two. Everything after the handover happens over the WebSocket rail
(sipp/control/bridge_app.py).

The handover is deferred — the call is parked, not answered. The application
answers it itself with a held description (RFC 3264 §8.4), which is what a
controller doing callback-and-connect does: take the caller, say nothing, then
go and find the other party. That also puts the interesting shape under test:
the leg the caller is on has no media session of its own, while the leg the
application then places does, so the bridge has to anchor on the second one —
and that one was answered by the engine itself (`answer_local`), which cannot be
renegotiated into a relay in place. The bridge has to notice and move the pair
onto a fresh engine call.
"""

from siphon import b2bua, proxy, log

APP = "bridge-app"

# Generous: the app places a second call, waits for it to answer, joins the two,
# parts them and joins them again before anything else happens on this leg. A
# slow CI box must not turn that into a handoff-deadline 503.
GENEROUS_DEADLINE_MS = 20000


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


def dialled_user(call) -> str:
    """The R-URI userpart, or "" when the R-URI has none.

    `call.ruri` is a `SipUri`, not a string — reading `.user` off it is the
    supported way; string-splitting it raises AttributeError.
    """
    ruri = call.ruri
    if ruri is None:
        return ""
    return ruri.user or ""


@b2bua.on_invite
def route(call):
    user = dialled_user(call)
    log.info(f"[{call.id}] bridge harness: INVITE for {user!r}")

    if user == "bridge":
        call.handover(
            APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "bridge"},
        )
    else:
        log.warn(f"[{call.id}] bridge harness: no case for {user!r}")
        call.reject(404, "Not Found")


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"[{call.id}] bridge harness: call ended by {initiator.side}")
