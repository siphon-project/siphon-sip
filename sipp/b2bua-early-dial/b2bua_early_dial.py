"""A dial behind siphon's own early answer, against the real media engine.

The caller is answered in early media by the engine (`call.progress(anchor=True)`,
`answer_local` in a 183) and then dialled through to a callee, one case per
Request-URI user:

  connect  the callee is offered the engine's far leg (`offer_far`), answers,
           and the caller is sent the answer it already holds, byte for byte.
  busy     the callee refuses 486; the far leg is given back to the engine
           before `@b2bua.on_failure` runs, which then rejects the caller.

The second case is checked from inside the failure handler, because nothing on
the SIP wire can say when the far leg went: the handler reads the engine's own
counters and logs one EARLY-DIAL-FAILURE line that CI asserts on. One delete
since the dial (the far leg) with the caller's session still up means the leg
was released first; no delete means it was still there when the handler ran.
"""

import json
import os
import urllib.request

from siphon import b2bua, log, proxy

ENGINE_METRICS = os.environ.get("ENGINE_METRICS", "http://172.20.0.130:9091/metrics")
CALLEES = {
    "connect": "sip:callee@172.20.0.4:5060",
    "busy": "sip:busy@172.20.0.5:5060",
}

# The engine's delete count when each call was dialled, by call id.
DELETES_AT_DIAL = {}


def engine_counters():
    with urllib.request.urlopen(ENGINE_METRICS, timeout=2) as response:
        body = response.read().decode("utf-8", "replace")
    counters = {}
    for line in body.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        name, value = line.rsplit(" ", 1)
        counters[name.split("{", 1)[0]] = float(value)
    return counters


def case_of(call):
    ruri = call.ruri
    return ruri.user if ruri is not None else None


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def announce_then_dial(call):
    target = CALLEES.get(case_of(call))
    if target is None:
        call.reject(404, "Not Found")
        return
    call.progress(183, "Session Progress", anchor=True, profile="early_dial")
    DELETES_AT_DIAL[call.id] = engine_counters().get("siphon_rtp_deletes_total", 0.0)
    call.dial(target, timeout=15)


@b2bua.on_failure
def failed(call, code, reason):
    counters = engine_counters()
    deletes = counters.get("siphon_rtp_deletes_total", 0.0) - DELETES_AT_DIAL.pop(call.id, 0.0)
    sessions = counters.get("siphon_rtp_sessions", 0.0)
    verdict = {
        "case": case_of(call),
        "code": code,
        "deletes_since_dial": deletes,
        "engine_sessions": sessions,
        "pass": deletes == 1 and sessions >= 1,
    }
    log.warn("EARLY-DIAL-FAILURE " + json.dumps(verdict))
    call.reject(code, reason)
