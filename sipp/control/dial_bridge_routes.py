"""Routing script for the `dial-bridge` acceptance harness.

Two decisions only. A REGISTER is saved, so the phone can be rung at its AoR
over the binding it made. An INVITE for `ivr@` is handed to the control
application, which answers it anchored on the engine and then rings the phone
with `dial {on_answer: "bridge"}` (sipp/control/dial_bridge_app.py).
"""

from siphon import b2bua, proxy, registrar, log

APP = "dial-bridge-app"

# The application answers, dials and waits for the phone before anything else
# happens on this leg; a slow CI box must not turn that into a handoff 503.
GENEROUS_DEADLINE_MS = 20000


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@proxy.on_request("REGISTER")
def register(request):
    registrar.save(request)


def dialled_user(call) -> str:
    """The R-URI userpart, or "" when the R-URI has none."""
    ruri = call.ruri
    if ruri is None:
        return ""
    return ruri.user or ""


@b2bua.on_invite
def route(call):
    user = dialled_user(call)
    log.info(f"[{call.id}] dial-bridge harness: INVITE for {user!r}")
    if user == "ivr":
        call.handover(APP, deadline_ms=GENEROUS_DEADLINE_MS, vars={"case": "ivr"})
    else:
        log.warn(f"[{call.id}] dial-bridge harness: no case for {user!r}")
        call.reject(404, "Not Found")
