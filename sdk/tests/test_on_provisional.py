"""Tests for the @b2bua.on_provisional hook.

It runs for every provisional response of the callee that siphon relays to
the caller, with or without SDP. ``@b2bua.on_early_media`` runs after it, and
only for a response that carries a body.
"""

from __future__ import annotations

import pytest

from siphon_sdk.reply import Reply
from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


SDP = b"v=0\r\no=- 1 1 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\nm=audio 41000 RTP/AVP 0\r\n"


class TestB2buaOnProvisional:
    def test_ringing_without_sdp_runs_the_handler(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_provisional
def on_provisional(call, reply):
    if reply.status_code == 180:
        reply.set_header("Privacy", "id")

@b2bua.on_early_media
def on_early_media(call, reply):
    reply.set_header("X-Early", "yes")
"""
        )
        ringing = Reply(status_code=180, reason="Ringing")
        harness.send_provisional(reply=ringing)
        assert ringing.get_header("Privacy") == "id"
        assert ringing.get_header("X-Early") is None

    def test_a_provisional_with_sdp_runs_both_in_order(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_early_media
def on_early_media(call, reply):
    reply.set_header("X-Order", (reply.get_header("X-Order") or "") + " early_media")

@b2bua.on_provisional
def on_provisional(call, reply):
    reply.set_header("X-Order", "provisional")
"""
        )
        progress = Reply(
            status_code=183,
            reason="Session Progress",
            body=SDP,
            content_type="application/sdp",
        )
        harness.send_provisional(reply=progress)
        assert progress.get_header("X-Order") == "provisional early_media"

    def test_async_handler_is_awaited(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_provisional
async def on_provisional(call, reply):
    reply.set_header("X-Status", str(reply.status_code))
"""
        )
        ringing = Reply(status_code=180, reason="Ringing")
        harness.send_provisional(reply=ringing)
        assert ringing.get_header("X-Status") == "180"


RINGBACK = """
from siphon import b2bua

@b2bua.on_provisional
def on_provisional(call, reply):
    early_media = reply.get_header("P-Early-Media") or ""
    authorised = "sendrecv" in early_media or "sendonly" in early_media
    if reply.has_body("application/sdp") and not authorised:
        reply.relay(body=False)
"""


def progress(**headers):
    return Reply(
        status_code=183,
        reason="Session Progress",
        body=SDP,
        content_type="application/sdp",
        headers=headers,
    )


class TestWhatTheCallerIsSent:
    def test_a_handler_that_decides_nothing_relays_the_response_whole(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_provisional
def on_provisional(call, reply):
    reply.set_header("X-Seen", "yes")
"""
        )
        reply = progress()
        harness.send_provisional(reply=reply)
        assert reply.provisional_relay == "whole"

    def test_relay_without_the_body(self, harness):
        harness.load_source(RINGBACK)
        reply = progress()
        harness.send_provisional(reply=reply)
        assert reply.provisional_relay == "without_body"
        assert reply.last_action.kind == "relay"
        assert reply.last_action.extras == {"body": False}
        # The handlers still read the session description.
        assert reply.has_body("application/sdp")

    def test_an_authorised_provisional_is_relayed_whole(self, harness):
        harness.load_source(RINGBACK)
        reply = progress(**{"P-Early-Media": "sendrecv"})
        harness.send_provisional(reply=reply)
        assert reply.provisional_relay == "whole"

    def test_ringing_without_a_body_is_relayed_as_it_is(self, harness):
        harness.load_source(RINGBACK)
        ringing = Reply(status_code=180, reason="Ringing")
        harness.send_provisional(reply=ringing)
        assert ringing.provisional_relay == "whole"
        assert ringing.actions == []

    def test_withhold(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_provisional
def on_provisional(call, reply):
    reply.withhold()
"""
        )
        reply = progress()
        harness.send_provisional(reply=reply)
        assert reply.provisional_relay == "withheld"
        assert reply.last_action.kind == "withhold"

    def test_the_last_decision_stands(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_provisional
def on_provisional(call, reply):
    reply.withhold()
    reply.relay(body=False)

@b2bua.on_early_media
def on_early_media(call, reply):
    reply.relay()
"""
        )
        reply = progress()
        harness.send_provisional(reply=reply)
        assert reply.provisional_relay == "whole"

    def test_refused_on_a_reply_that_is_not_a_relayed_provisional(self):
        reply = progress()
        with pytest.raises(RuntimeError, match="@b2bua.on_provisional"):
            reply.relay(body=False)
        with pytest.raises(RuntimeError, match="@b2bua.on_provisional"):
            reply.withhold()
        assert reply.actions == []
        reply.relay()
        assert reply.last_action.kind == "relay"
