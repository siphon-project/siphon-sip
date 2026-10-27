"""Tests for the imperative b2bua.reoffer(call_id) re-INVITE.

A script tells one party something about the session it did not ask about,
RFC 7866's a=record when a recording starts or stops on its own, and learns the
final status so a crossing offer's 491 can be retried.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


def test_records_the_offer_and_resolves_to_the_status(harness):
    import siphon

    status = asyncio.run(siphon.b2bua.reoffer("rec@example.com", sdp="v=0\r\na=record:off\r\n"))
    assert status == 200
    assert harness.b2bua.reoffers[-1] == {
        "call_id": "rec@example.com",
        "sdp": "v=0\r\na=record:off\r\n",
        "leg": "caller",
    }
    harness.b2bua.reoffer_status = 491
    assert asyncio.run(siphon.b2bua.reoffer("rec@example.com", leg="callee")) == 491
    assert harness.b2bua.reoffers[-1]["sdp"] is None


def test_an_unknown_leg_is_refused(harness):
    import siphon

    with pytest.raises(ValueError):
        asyncio.run(siphon.b2bua.reoffer("rec@example.com", leg="both"))


def test_the_session_in_force_is_what_the_test_set(harness):
    import siphon

    assert siphon.b2bua.session_sdp("rec@example.com") is None
    harness.b2bua.session_sdps[("rec@example.com", "caller")] = "v=0\r\n"
    assert siphon.b2bua.session_sdp("rec@example.com") == "v=0\r\n"
    assert siphon.b2bua.session_sdp("rec@example.com", leg="callee") is None
