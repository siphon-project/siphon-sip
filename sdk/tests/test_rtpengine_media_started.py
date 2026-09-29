"""Tests for the ``@rtpengine.on_media_started`` hook in the SDK mock.

The media engine reports the first packet on each of a call's legs once. The
hook takes the same ``call_id`` / ``from_tag`` filters as its siblings and
hands the handler the leg, the latched source and the signalled address.
"""

from __future__ import annotations

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness()
    h.reset()
    return h


class TestOnMediaStarted:
    def test_bare_handler_is_a_catch_all(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_media_started
def flowing(call_id, from_tag, to_tag, leg, source, signalled):
    log.info(f"started {call_id} {leg}")
"""
        )
        assert harness.rtpengine.fire_media_started("any-call", "any-tag") == 1

    def test_filters_scope_to_call_and_tag(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_media_started
def any_start(call_id, from_tag, to_tag, leg, source, signalled):
    log.info("any")

@rtpengine.on_media_started(call_id="abc", from_tag="caller-tag")
def specific(call_id, from_tag, to_tag, leg, source, signalled):
    log.info("specific")
"""
        )
        assert harness.rtpengine.fire_media_started("xyz", "other") == 1
        assert harness.rtpengine.fire_media_started("abc", "caller-tag") == 2
        assert harness.rtpengine.fire_media_started("abc", "other") == 1

    def test_handler_receives_the_full_payload(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_media_started
def flowing(call_id, from_tag, to_tag, leg, source, signalled):
    log.info(f"{call_id}|{from_tag}|{to_tag}|{leg}|{source}|{signalled}")
"""
        )
        harness.rtpengine.fire_media_started(
            "call-1",
            "caller-tag",
            to_tag="phone-tag",
            leg="far",
            source="203.0.113.7:40000",
            signalled="192.0.2.10:4000",
        )
        assert (
            "call-1|caller-tag|phone-tag|far|203.0.113.7:40000|192.0.2.10:4000"
            in [message for _, message in harness.log.messages]
        )

    def test_an_unknown_leg_is_refused(self, harness):
        with pytest.raises(ValueError):
            harness.rtpengine.fire_media_started("c", "f", leg="middle")

    def test_clear_drops_registered_handlers(self, harness):
        harness.load_source(
            """
from siphon import rtpengine

@rtpengine.on_media_started
def flowing(call_id, from_tag, to_tag, leg, source, signalled):
    pass
"""
        )
        harness.rtpengine.clear()
        assert harness.rtpengine.fire_media_started("c", "f") == 0
