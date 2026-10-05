"""Routing script for the `control-transfer` acceptance harness.

Two decisions only. A REGISTER is saved, so an AoR can be rung at every contact
bound to it. An INVITE is handed to the control application un-answered, with
the dialled user as the case to run (sipp/control/transfer_app.py):

  cancel-dial         — answer anchored, ring two phones, give the dial up.
  refer-callee        — connect a phone, which then REFERs: once rejected, once
                        accepted and carried out by siphon.
  refer-controller    — connect a phone, which REFERs three times; the
                        application carries each transfer out and reports it.
  replace-aor         — connect a phone, then replace it with an AoR that has
                        two registered contacts, one of which answers.
  replace-aor-refused — the same, with both contacts refusing.
  media               — connect a phone through the engine, then `hold` and
                        `play` on the relayed call.
"""

from siphon import b2bua, proxy, registrar, log

APP = "transfer-app"

CASES = (
    "cancel-dial",
    "refer-callee",
    "refer-controller",
    "replace-aor",
    "replace-aor-refused",
    "media",
)

# The application dials and waits on a phone before anything reaches the
# caller; a slow CI box must not turn that into a handoff 503.
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
    log.info(f"[{call.id}] control-transfer harness: INVITE for {user!r}")
    if user in CASES:
        call.handover(APP, deadline_ms=GENEROUS_DEADLINE_MS, vars={"case": user})
    else:
        log.warn(f"[{call.id}] control-transfer harness: no case for {user!r}")
        call.reject(404, "Not Found")
