"""Tests for the @proxy.on_cancel / @b2bua.on_cancel teardown hooks.

These hooks fire when an INVITE is CANCELled before any final response
(RFC 3261 §9) — the one teardown that on_reply/on_failure/on_bye never
deliver. They exist so a script can release per-call resources (rtpengine
media anchors, Diameter Rx/N5 QoS) that no BYE will ever clear.
"""

from __future__ import annotations

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestProxyOnCancel:
    def test_sync_handler_receives_original_invite(self, harness):
        # The handler proves it ran (and got a usable request) by tagging the
        # request — no module-level state, which siphon scripts must avoid.
        harness.load_source(
            """
from siphon import proxy

@proxy.on_cancel
def on_cancel(request):
    request.set_header("X-Cancelled", request.call_id)
"""
        )
        result = harness.send_cancel(call_id="abc123@example.com")
        assert result.request.get_header("X-Cancelled") == "abc123@example.com"

    def test_async_handler_releases_rtpengine(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_cancel
async def on_cancel(request):
    await rtpengine.delete(request)
"""
        )
        harness.send_cancel(call_id="cid-rtp@example.com")
        assert ("delete", None) in harness.rtpengine.operations

    def test_no_handler_is_noop(self, harness):
        harness.load_source(
            """
from siphon import proxy

@proxy.on_request
def route(request):
    request.relay()
"""
        )
        # No on_cancel registered — dispatch must not raise.
        result = harness.send_cancel(call_id="x@example.com")
        assert result.request.call_id == "x@example.com"


class TestB2buaOnCancel:
    def test_sync_handler_receives_call(self, harness):
        harness.load_source(
            """
from siphon import b2bua, log

@b2bua.on_cancel
def on_cancel(call):
    log.info(f"b2bua cancel cid={call.call_id}")
"""
        )
        result = harness.send_call_cancel(call_id="call-1")
        assert result.call.call_id == "call-1"

    def test_async_handler_releases_rtpengine(self, harness):
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_cancel
async def on_cancel(call):
    await rtpengine.delete(call)
"""
        )
        harness.send_call_cancel(call_id="call-rtp")
        assert ("delete", None) in harness.rtpengine.operations
