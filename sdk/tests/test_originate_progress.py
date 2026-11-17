"""``@b2bua.on_originate_progress``: the provisionals of a leg a script placed.

The handlers note what they are called with on the reply, which the harness
hands back.
"""

from __future__ import annotations

import pytest

from siphon_sdk.reply import Reply
from siphon_sdk.testing import SipTestHarness

OFFER = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"

SCRIPT = """
from siphon import b2bua

@b2bua.on_originate_progress
def ringing(call_id, code, reason, reply):
    reply.set_header("X-Seen", f"{call_id} {code} {reason} {reply.status_code}")
    if reply.body:
        reply.set_header("X-Body", str(len(reply.body)))

@b2bua.on_provisional
def relayed(call, reply):
    reply.set_header("X-Relayed", "yes")
"""

ASYNC_SCRIPT = """
from siphon import b2bua

@b2bua.on_originate_progress
async def ringing(call_id, code, reason, reply):
    reply.set_header("X-Seen", f"{call_id} {code}")
"""


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


def place():
    import siphon

    return siphon.b2bua.originate("sip:callee@example.com", sdp=OFFER.decode())


def test_a_180_runs_the_handler_with_the_call_id_originate_returned(harness):
    harness.load_source(SCRIPT)
    call_id = place()
    reply = harness.send_originate_progress(call_id, 180)
    assert reply.get_header("X-Seen") == f"{call_id} 180 Ringing 180"
    assert reply.get_header("X-Body") is None
    # The hooks of a relayed provisional are not for a leg siphon placed.
    assert reply.get_header("X-Relayed") is None


def test_a_183_hands_over_its_body_and_headers(harness):
    harness.load_source(SCRIPT)
    call_id = place()
    reply = harness.send_originate_progress(
        call_id, 183, "Session Progress", body=OFFER,
        headers={"P-Early-Media": "sendrecv"},
    )
    assert reply.get_header("X-Seen") == f"{call_id} 183 Session Progress 183"
    assert reply.get_header("X-Body") == str(len(OFFER))
    assert reply.get_header("P-Early-Media") == "sendrecv"


def test_a_reply_passed_in_is_the_one_the_handler_gets(harness):
    harness.load_source(SCRIPT)
    ringing = Reply(status_code=180, reason="Ringing")
    assert harness.send_originate_progress("leg-1", 180, reply=ringing) is ringing
    assert ringing.get_header("X-Seen") == "leg-1 180 Ringing 180"


def test_a_100_runs_nothing(harness):
    harness.load_source(SCRIPT)
    reply = harness.send_originate_progress("leg-1", 100, "Trying")
    assert reply.get_header("X-Seen") is None


def test_an_async_handler_is_awaited(harness):
    harness.load_source(ASYNC_SCRIPT)
    reply = harness.send_originate_progress("leg-1", 180)
    assert reply.get_header("X-Seen") == "leg-1 180"


def test_a_final_status_is_not_a_provisional(harness):
    harness.load_source(SCRIPT)
    with pytest.raises(ValueError, match="provisional"):
        harness.send_originate_progress("leg-1", 200, "OK")


def test_no_handler_registered_is_a_no_op(harness):
    harness.load_source("from siphon import b2bua\n")
    reply = harness.send_originate_progress("leg-1", 180)
    assert reply.status_code == 180
