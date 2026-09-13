"""Parallel ``call.fork()`` acceptance cases, one per Request-URI user.

Each case forks to two SIPp callees scripted for one branch outcome apiece, and
the callee scenarios assert what siphon owes that branch:

  fork-busy     busy (486 at once)     + late (rings, answers at 2 s)
                A failed branch must not fail the call while a sibling rings.
  fork-cancel   early (answers at 1 s) + cancelled (rings, expects a CANCEL)
                The losing branch is CANCELled, its 487 ACKed, the call kept.
  fork-glare    early (answers at 1 s) + glare (rings, answers the CANCEL
                with a 2xx)
                A losing branch's 2xx is ACKed and released with a BYE.
  fork-allfail  busy (486 at once)     + unavailable (rings, 480 at 2 s)
                The caller gets one final response, once the last branch fails.
"""

from siphon import b2bua, log, proxy

BUSY = "sip:busy@172.20.0.185:5060"
LATE = "sip:late@172.20.0.186:5060"
EARLY = "sip:early@172.20.0.187:5060"
CANCELLED = "sip:cancelled@172.20.0.188:5060"
GLARE = "sip:glare@172.20.0.189:5060"
UNAVAILABLE = "sip:unavailable@172.20.0.190:5060"

CASES = {
    "fork-busy": [BUSY, LATE],
    "fork-cancel": [EARLY, CANCELLED],
    "fork-glare": [EARLY, GLARE],
    "fork-allfail": [BUSY, UNAVAILABLE],
}


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    # `call.ruri` is a SipUri, not a string.
    ruri = call.ruri
    targets = CASES.get(ruri.user if ruri is not None else None)
    if targets is None:
        call.reject(404, "Not Found")
        return
    call.fork(targets, strategy="parallel", timeout=15)


@b2bua.on_failure
def failed(call, code, reason):
    # CI counts these lines: only fork-allfail may fail, and it must fail once.
    log.warn(f"FORK-FAILURE {code} {reason}")
