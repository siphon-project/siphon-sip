"""Routing script for the control-plane functional harness.

The only in-process decision here is *which* control application a call is
handed to and in what mode — everything after the handover is driven by the
out-of-process app over the WebSocket rail (sipp/control/control_app.py).

The dialled user selects the case, and the case is echoed into the handover's
`vars` so the app knows what to do without a second channel of coordination:

  handover@ — deferred handover to the per-call-connect app; the app answers.
  progress@ — deferred handover; the app rings, holds the ring on its own clock,
              then opens early media, then answers — so a plain 180 and a
              183-with-SDP are two separate verbs on the wire.
  media@    — answer-first (AI-park) handover; the app drives media verbs on the
              already-connected channel.
  info@     — deferred handover; the app answers, so the call stays one-legged and
              siphon is the party that answers the caller's in-dialog INFO.
  record@   — answer-first handover with NO ws_uri: the engine terminates the
              leg and nothing streams anywhere, which is the voicemail-box shape.
              The app records the call, stops it, and waits for the closed file.
  early@    — deferred handover; the app opens early media anchored on the engine,
              plays into it, then answers — the 200 must repeat the 183's SDP.
  deadline@ — deferred handover to an app that deliberately never acts, so the
              configured `control.limits.handoff_deadline_ms` is what ends the
              call. No `deadline_ms` here on purpose: the config value is what
              this case exists to exercise.
  owner@    — deferred handover to the persistent app, which holds several
              connections; exactly one of them must be given the call.
  resync@   — deferred handover to the persistent app, which answers, drops the
              owning socket, reconnects and re-claims the call.
  dial@     — deferred handover; the app rings a target that never answers, and
              the point is what happens next: the caller is STILL unanswered and
              still the app's, so the app answers it itself. That is the whole
              reason `dial` exists and the thing `route` cannot express.
  failure-handover@ — dialled at a name that never resolves, so the call fails
              503 before anything answers; `@b2bua.on_failure` hands the failed
              call to the per-call-connect app, which answers it.

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
    elif user == "progress":
        call.handover(
            PER_CALL_CONNECT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "progress"},
        )
    elif user == "media":
        call.handover(
            PER_CALL_CONNECT_APP,
            answer=True,
            profile="voice_ai",
            ws_uri=AI_WS_URI,
            vars={"case": "media"},
        )
    elif user == "info":
        call.handover(
            PER_CALL_CONNECT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "info"},
        )
    elif user == "record":
        # No ws_uri on purpose: a recorded leg is anchored on the engine and
        # written to a file, and a controller should not have to open an AI
        # audio bridge it does not want in order to get there.
        call.handover(
            PER_CALL_CONNECT_APP,
            answer=True,
            profile="voice_ai",
            vars={"case": "record"},
        )
    elif user == "early":
        call.handover(
            PER_CALL_CONNECT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "early"},
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
    elif user == "dial":
        call.handover(
            PER_CALL_CONNECT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "dial"},
        )
    elif user == "resync":
        call.handover(
            PERSISTENT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "resync"},
        )
    elif user == "failure-handover":
        # A name under RFC 6761's .invalid never resolves, so the B-leg INVITE
        # never leaves and the call fails 503 at once. @b2bua.on_failure below
        # decides what happens to it.
        call.dial("sip:nobody@unroutable.invalid", timeout=15)
    else:
        log.warn(f"[{call.id}] control harness: no case for {user!r}")
        call.reject(404, "Not Found")


@b2bua.on_failure
def failed(call, code, reason):
    user = dialled_user(call)
    log.info(f"[{call.id}] control harness: {user!r} failed {code} {reason}")
    if user == "failure-handover":
        call.handover(
            PER_CALL_CONNECT_APP,
            deadline_ms=GENEROUS_DEADLINE_MS,
            vars={"case": "failure-handover", "failed_with": str(code)},
        )


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"[{call.id}] control harness: call ended by {initiator.side}")
