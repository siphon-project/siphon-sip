"""``b2bua.inbound_limit``: siphon refuses a call past the limit before this runs.

The handler answers every call it is handed itself, so no callee is needed, and
logs one line per call. CI counts those lines: a refused call must leave none,
which is the proof that it never reached the script.

The limit is one concurrent call (siphon-b2bua-admission.yaml). Two callers:

  holder   places a call and holds it for 8 s, taking the one slot.
  caller   while the holder is up: an ordinary call is refused 503 with
           Retry-After, and an emergency call (urn:service:sos) is answered.
           Once the holder has hung up, an ordinary call is answered.
"""

from siphon import b2bua, log, proxy

ANSWER_SDP = (
    "v=0\r\n"
    "o=siphon 1 1 IN IP4 172.20.0.222\r\n"
    "s=-\r\n"
    "c=IN IP4 172.20.0.222\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
)


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
def admitted(call):
    # CI counts these lines: one per call that got past the limit.
    log.warn(f"ADMITTED {call.ruri}")
    call.answer(200, "OK", body=ANSWER_SDP, content_type="application/sdp")
