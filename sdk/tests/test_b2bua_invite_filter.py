"""Tests for ``@b2bua.on_invite(request_uri=...)``: one script that is a B2BUA
for the INVITEs a filter matches and a proxy for the rest."""

from __future__ import annotations

import pytest

import siphon_sdk.mock_module as mock_module
from siphon_sdk.testing import CallResult, RequestResult, SipTestHarness

MIXED = """
from siphon import b2bua, proxy

@b2bua.on_invite(request_uri=r"^sip:transfer@")
def take(call):
    call.dial("sip:bob@198.51.100.7:5060")

@proxy.on_request
def route(request):
    request.relay()
"""


@pytest.fixture
def harness():
    harness = SipTestHarness()
    harness.load_source(MIXED)
    return harness


def test_an_invite_a_filter_matches_is_a_b2bua_call(harness):
    result = harness.dispatch_invite("sip:transfer@example.com")
    assert isinstance(result, CallResult)
    assert result.action == "dial"


def test_an_invite_no_filter_matches_is_proxied(harness):
    result = harness.dispatch_invite("sip:bob@example.com")
    assert isinstance(result, RequestResult)
    assert result.action == "relay"


def test_an_in_dialog_invite_is_proxied_even_when_it_matches(harness):
    result = harness.dispatch_invite("sip:transfer@example.com", to_tag="callee-tag")
    assert isinstance(result, RequestResult)


def test_send_invite_runs_only_the_matching_and_unfiltered_handlers():
    harness = SipTestHarness()
    harness.load_source(
        """
from siphon import b2bua

SEEN = []

@b2bua.on_invite(request_uri=r"^sip:transfer@")
def transfer(call):
    SEEN.append("transfer")

@b2bua.on_invite
def every(call):
    SEEN.append("every")
    call.reject(486, "Busy Here")
"""
    )
    # An unfiltered handler takes every INVITE.
    assert isinstance(harness.dispatch_invite("sip:bob@example.com"), CallResult)
    selected = mock_module.b2bua_invite_handlers("sip:transfer@example.com")
    assert len(selected) == 2
    assert len(mock_module.b2bua_invite_handlers("sip:bob@example.com")) == 1


def test_without_b2bua_handlers_every_invite_is_proxied():
    harness = SipTestHarness()
    harness.load_source(
        """
from siphon import proxy

@proxy.on_request
def route(request):
    request.relay()
"""
    )
    assert isinstance(harness.dispatch_invite("sip:transfer@example.com"), RequestResult)


@pytest.mark.parametrize(
    "filter_source, error",
    [('"("', ValueError), ('""', ValueError), ("42", TypeError)],
)
def test_a_bad_filter_is_refused_at_decoration(filter_source, error):
    harness = SipTestHarness()
    with pytest.raises(error):
        harness.load_source(
            "from siphon import b2bua\n\n"
            f"@b2bua.on_invite(request_uri={filter_source})\n"
            "def take(call):\n    pass\n"
        )


def test_a_positional_filter_is_refused():
    harness = SipTestHarness()
    with pytest.raises(TypeError):
        harness.load_source(
            "from siphon import b2bua\n\n"
            "@b2bua.on_invite(\"^sip:\")\n"
            "def take(call):\n    pass\n"
        )
