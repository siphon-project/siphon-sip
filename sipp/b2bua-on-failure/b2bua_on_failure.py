"""``@b2bua.on_failure`` decides how a failed call ends, one case per Request-URI user.

Each case sets a call up to fail one way, and the failure handler picks what
happens next. The callee scenarios, and the caller's own, assert that the
decision was carried out rather than logged and dropped:

  fail-redial         busy (486)                        -> dials the early callee
                      The caller is answered by the target the handler chose.
  fail-reject         busy (486)                        -> rejects 480
                      The caller gets the handler's 480, not the callee's 486.
  timeout-redial      ringing callee, 2 s ring timeout  -> dials the early callee
                      The timed-out callee is CANCELled, the caller answered.
  undialed-redial     a destination that never resolves -> dials the early callee
                      An INVITE that never left the box is routed again the same way.
  answer-fail-redial  the early callee answers and on_answer ends the call (500)
                                                        -> dials the late callee
                      The answered leg is released, and the call is routed again.
  fail-answer         busy (486)                        -> answers the caller itself
                      A UAS-mode answer from the failure handler keeps the call.
"""

from siphon import b2bua, log, proxy

BUSY = "sip:busy@172.20.0.185:5060"
LATE = "sip:late@172.20.0.186:5060"
EARLY_IP = "172.20.0.187"
EARLY = f"sip:early@{EARLY_IP}:5060"
RINGING = "sip:cancelled@172.20.0.188:5060"
UNROUTABLE = "sip:nobody@unroutable.invalid"

# Request-URI user -> (first target, ring timeout in seconds)
FIRST_DIAL = {
    "fail-redial": (BUSY, 15),
    "fail-reject": (BUSY, 15),
    "timeout-redial": (RINGING, 2),
    "undialed-redial": (UNROUTABLE, 15),
    "answer-fail-redial": (EARLY, 15),
    "fail-answer": (BUSY, 15),
}

ANSWER_SDP = (
    "v=0\r\n"
    "o=siphon 1 1 IN IP4 172.20.0.191\r\n"
    "s=-\r\n"
    "c=IN IP4 172.20.0.191\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
)


def case_of(call):
    # `call.ruri` is a SipUri, not a string.
    ruri = call.ruri
    return ruri.user if ruri is not None else None


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def route(call):
    first = FIRST_DIAL.get(case_of(call))
    if first is None:
        call.reject(404, "Not Found")
        return
    target, timeout = first
    call.dial(target, timeout=timeout)


@b2bua.on_answer
def answered(call, reply):
    # Only the first answer is refused, told apart by who sent it: the late
    # callee's answer, after the re-route, connects the call.
    if case_of(call) == "answer-fail-redial" and reply.source_ip == EARLY_IP:
        call.terminate()


@b2bua.on_failure
def failed(call, code, reason):
    case = case_of(call)
    # CI counts these lines: every case fails exactly once, on its first attempt.
    log.warn(f"ON-FAILURE {case} {code} {reason}")
    if case in ("fail-redial", "timeout-redial", "undialed-redial"):
        call.dial(EARLY, timeout=15)
    elif case == "answer-fail-redial":
        call.dial(LATE, timeout=15)
    elif case == "fail-reject":
        call.reject(480, "Temporarily Unavailable")
    elif case == "fail-answer":
        call.answer(200, "OK", body=ANSWER_SDP, content_type="application/sdp")
