"""Tests for @b2bua.on_reoffer / @b2bua.on_reoffer_answered.

An in-dialog re-INVITE or UPDATE on a bridged call is shown to the script
before it is relayed: a hold (RFC 3264 §8.4), its resume, a session refresh
(RFC 4028), with the script free to relay it, refuse it or answer it itself.
"""

from __future__ import annotations

import pytest

from siphon_sdk.reoffer import Reoffer, classify, direction_of
from siphon_sdk.testing import SipTestHarness

TALKING = (
    "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n"
    "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
)
HELD = TALKING + "a=sendonly\r\n"
OLD_HOLD = TALKING.replace("c=IN IP4 192.0.2.10", "c=IN IP4 0.0.0.0")


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestReading:
    def test_directions(self):
        assert direction_of(TALKING) == "sendrecv"
        assert direction_of(HELD) == "sendonly"
        assert direction_of(TALKING + "a=inactive\r\n") == "inactive"
        assert direction_of(OLD_HOLD) == "sendonly"
        assert direction_of(None) is None

    def test_kinds(self):
        assert classify(HELD, TALKING) == "hold"
        assert classify(OLD_HOLD, TALKING) == "hold"
        assert classify(TALKING, HELD) == "resume"
        assert classify(HELD, HELD) == "refresh"
        assert classify(None, HELD) == "refresh"
        assert classify(TALKING.replace("RTP/AVP 0", "RTP/AVP 8"), TALKING) == "change"


class TestOnReoffer:
    def test_relays_by_default(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_reoffer
def on_reoffer(call, offer):
    offer.request.set_header("X-Kind", offer.kind)
"""
        )
        offer = harness.send_reoffer(sdp=HELD, previous_sdp=TALKING)
        assert offer.decision == ("relay",)
        assert offer.request.get_header("X-Kind") == "hold"
        assert offer.side == "a"
        assert offer.method == "INVITE"

    def test_takes_a_hold_over(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_reoffer
async def on_reoffer(call, offer):
    if offer.kind == "hold":
        offer.answer()
"""
        )
        assert harness.send_reoffer(sdp=HELD, previous_sdp=TALKING).decision == ("answer", None)
        assert harness.send_reoffer(sdp=HELD, previous_sdp=HELD).decision == ("relay",)

    def test_refuses_and_checks_the_status(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_reoffer
def on_reoffer(call, offer):
    if offer.method == "UPDATE":
        offer.reject(488, "Not Acceptable Here")
"""
        )
        offer = harness.send_reoffer(sdp=HELD, previous_sdp=TALKING, method="UPDATE", side="b")
        assert offer.decision == ("reject", 488, "Not Acceptable Here")
        with pytest.raises(ValueError):
            Reoffer(sdp=HELD).reject(200, "OK")

    def test_a_raise_decides_nothing(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_reoffer
def on_reoffer(call, offer):
    offer.reject(403, "Forbidden")
    raise RuntimeError("boom")
"""
        )
        assert harness.send_reoffer(sdp=HELD).decision == ("relay",)


class TestOnReofferAnswered:
    def test_reports_the_final_response(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_reoffer_answered
def answered(call, offer):
    call.set_header("X-Answered", f"{offer.status_code} {offer.answer_direction} {offer.answered_locally}")
"""
        )
        offer = harness.send_reoffer(sdp=HELD, previous_sdp=TALKING)
        result = harness.send_reoffer_answered(offer, answer_sdp=TALKING + "a=recvonly\r\n")
        assert result.status_code == 200
        assert result.answer_direction == "recvonly"
        assert result.request is None
        with pytest.raises(RuntimeError):
            result.answer()


WEBRTC = (
    "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nt=0 0\r\n"
    "a=group:BUNDLE 0\r\na=fingerprint:sha-256 AB:CD\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 192.0.2.10\r\n"
    "a=mid:0\r\na=ice-ufrag:uf1\r\na=ice-pwd:pw1\r\na=setup:actpass\r\n"
    "a=rtpmap:111 opus/48000/2\r\n"
)


def test_a_recordpref_only_offer_is_a_refresh_and_an_ice_restart_a_change():
    assert classify(WEBRTC + "a=recordpref:on\r\n", WEBRTC) == "refresh"
    assert classify(WEBRTC.replace("uf1", "uf2"), WEBRTC) == "change"
    assert classify(WEBRTC.replace("AB:CD", "EF:01"), WEBRTC) == "change"


def test_a_refresh_is_answered_from_the_session_in_force_with_one_attribute_more(harness):
    harness.load_source(
        """
from siphon import b2bua

@b2bua.on_reoffer
def toggle(call, offer):
    if offer.kind == "refresh" and offer.session_sdp:
        offer.answer(offer.session_sdp + "a=record:on\\r\\n")
"""
    )
    session = ("v=0\r\no=- 7 7 IN IP4 198.51.100.1\r\ns=-\r\nc=IN IP4 198.51.100.1\r\n"
               "t=0 0\r\nm=audio 30000 RTP/AVP 0\r\n")
    offer = harness.send_reoffer(sdp=TALKING + "a=recordpref:on\r\n", previous_sdp=TALKING,
                                 session_sdp=session)
    assert offer.session_sdp == session
    assert offer.decision == ("answer", session + "a=record:on\r\n")
