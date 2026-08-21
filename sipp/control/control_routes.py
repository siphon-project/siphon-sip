"""Routing script for the control-plane functional harness.

The only in-process decision here is *which* control application a call is
handed to and in what mode — everything after the handover is driven by the
out-of-process app over the WebSocket rail (sipp/control/control_app.py).

The dialled user selects the case, and the case is echoed into the handover's
`vars` so the app knows what to do without a second channel of coordination:

  handover@ — deferred handover to the per-call-connect app; the app answers.
  media@    — answer-first (AI-park) handover; the app drives media verbs on the
              already-connected channel.
  deadline@ — deferred handover to an app that deliberately never acts, so the
              configured `control.limits.handoff_deadline_ms` is what ends the
              call. No `deadline_ms` here on purpose: the config value is what
              this case exists to exercise.
  owner@    — deferred handover to the persistent app, which holds several
              connections; exactly one of them must be given the call.
  resync@   — deferred handover to the persistent app, which answers, drops the
              owning socket, reconnects and re-claims the call.

The non-deadline cases pass a generous explicit `deadline_ms` so a slow CI box
cannot turn a controller round trip into a spurious 503 — the deadline is a
separate case with its own scenario.
"""

from siphon import b2bua, proxy, log

# The per-call WebSocket bridge for the answer-first case. The media engine in
# this profile is a mock that records the control commands and never dials the
# bridge, so the address only has to be well formed (RFC 5737 TEST-NET-2).
AI_WS_URI = "ws://198.51.100.30:9001/stream/{call_id}"

PERSISTENT_APP = "ivr-app"
PER_CALL_CONNECT_APP = "edge-app"

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
    log.info(f"[{call.id}] control harness: INVITE for {user!r}")

    if user == "handover":
        call.handover(
            PER_CALL_CONNECT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "handover"},
        )
    elif user == "media":
        call.handover(
            PER_CALL_CONNECT_APP,
            answer=True,
            profile="voice_ai",
            ws_uri=AI_WS_URI,
            vars={"case": "media"},
        )
    elif user == "deadline":
        # No deadline_ms: control.limits.handoff_deadline_ms is the thing under
        # test, and the app handed this call never acts.
        call.handover(PERSISTENT_APP, vars={"case": "deadline"})
    elif user == "owner":
        call.handover(
            PERSISTENT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "owner"},
        )
    elif user == "resync":
        call.handover(
            PERSISTENT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "resync"},
        )
    else:
        log.warn(f"[{call.id}] control harness: no case for {user!r}")
        call.reject(404, "Not Found")


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"[{call.id}] control harness: call ended by {initiator.side}")
