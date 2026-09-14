"""Parallel ``call.fork()`` acceptance cases, one per Request-URI user.

Each case forks to SIPp callees scripted for one branch outcome apiece, and the
callee scenarios assert what siphon owes that branch:

  fork-busy      busy (486 at once)     + late (rings, answers at 2 s)
                 A failed branch must not fail the call while a sibling rings.
  fork-cancel    early (answers at 1 s) + cancelled (rings, expects a CANCEL)
                 The losing branch is CANCELled, its 487 ACKed, the call kept.
  fork-glare     early (answers at 1 s) + glare (rings, answers the CANCEL
                 with a 2xx)
                 A losing branch's 2xx is ACKed and released with a BYE.
  fork-allfail   busy (486 at once)     + unavailable (rings, 480 at 2 s)
                 The caller gets one final response, once the last branch fails.
  fork-timeout   busy (486 at once)     + cancelled (rings, expects a CANCEL),
                 with a 3 s ring timeout
                 The timeout relays the 486 rather than a bare 408, and CANCELs
                 the branch still ringing.
  fork-class     busy (486 at once)     + service unavailable (503 at once)
                 RFC 3261 §16.7 step 6: the lower class wins, so the caller gets
                 the 486, not the 503.
  fork-503       service unavailable (503 at once), alone
                 A 503 that is all there is goes upstream as a generated 500.
  fork-redirect  busy (486 at once)     + redirect (302 naming another target)
                 The 302 wins and reaches the caller with the callee's Contact,
                 not siphon's own address.
  fork-seqbest   cancelled (rings out at 2 s) then service unavailable (503),
                 in sequence
                 An exhausted sequence sends its best attempt, the 408, not the
                 500 the last carrier's 503 would have become.
"""

from siphon import b2bua, log, proxy

BUSY = "sip:busy@172.20.0.185:5060"
LATE = "sip:late@172.20.0.186:5060"
EARLY = "sip:early@172.20.0.187:5060"
CANCELLED = "sip:cancelled@172.20.0.188:5060"
GLARE = "sip:glare@172.20.0.189:5060"
UNAVAILABLE = "sip:unavailable@172.20.0.190:5060"
SERVICE_UNAVAILABLE = "sip:overloaded@172.20.0.193:5060"
REDIRECT = "sip:moved@172.20.0.194:5060"

# Request-URI user -> (branch targets, ring timeout in seconds, strategy)
CASES = {
    "fork-busy": ([BUSY, LATE], 15, "parallel"),
    "fork-cancel": ([EARLY, CANCELLED], 15, "parallel"),
    "fork-glare": ([EARLY, GLARE], 15, "parallel"),
    "fork-allfail": ([BUSY, UNAVAILABLE], 15, "parallel"),
    "fork-timeout": ([BUSY, CANCELLED], 3, "parallel"),
    "fork-class": ([BUSY, SERVICE_UNAVAILABLE], 15, "parallel"),
    "fork-503": ([SERVICE_UNAVAILABLE], 15, "parallel"),
    "fork-redirect": ([BUSY, REDIRECT], 15, "parallel"),
    "fork-seqbest": ([CANCELLED, SERVICE_UNAVAILABLE], 2, "sequential"),
}


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    # `call.ruri` is a SipUri, not a string.
    ruri = call.ruri
    case = CASES.get(ruri.user if ruri is not None else None)
    if case is None:
        call.reject(404, "Not Found")
        return
    targets, timeout, strategy = case
    call.fork(targets, strategy=strategy, timeout=timeout)


@b2bua.on_failure
def failed(call, code, reason):
    # CI counts these lines: every case but fork-busy, fork-cancel and fork-glare
    # fails, once each.
    log.warn(f"FORK-FAILURE {code} {reason}")
