"""Tests for @b2bua.on_info and the harness's send_info driver.

An in-dialog INFO (RFC 6086) on a call is shown to the script: answered here
(an Info Package spoken between the script and one party), refused, or left, in
which case a call with a far leg relays it and one without answers 200.
"""

from __future__ import annotations

import pytest

from siphon_sdk.testing import SipTestHarness

PACKAGE_HEADERS = {"Info-Package": "example-package", "Content-Disposition": "Info-Package"}


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestAnswering:
    def test_answers_with_a_status_a_body_and_a_header(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    request.set_reply_body(b"<done/>", "application/example+xml")
    request.set_reply_header("X-Seen", request.content_type)
    request.reply(200, "OK")
"""
        )
        result = harness.send_info(
            content_type="application/example+xml", body="<do/>", headers=PACKAGE_HEADERS
        )
        assert result.answered and not result.relayed
        assert (result.status_code, result.reason) == (200, "OK")
        assert result.body == b"<done/>"
        assert result.content_type == "application/example+xml"
        assert ("X-Seen", "application/example+xml") in result.headers

    def test_a_package_refused_with_469_lists_what_is_accepted(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    if request.get_header("Info-Package") != "example-package":
        request.set_reply_header("Recv-Info", "example-package")
        request.reply(469, "Bad Info Package")
"""
        )
        result = harness.send_info(headers={"Info-Package": "other-package"})
        assert result.status_code == 469
        assert ("Recv-Info", "example-package") in result.headers
        # The package it knows is not refused: nothing answered, so relayed.
        assert harness.send_info(headers=PACKAGE_HEADERS).relayed

    def test_a_handler_may_refuse_before_the_answer(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    if call.state != "answered":
        request.reply(403, "Forbidden")
"""
        )
        from siphon_sdk.call import Call

        assert harness.send_info(call=Call(state="calling")).status_code == 403
        assert harness.send_info(call=Call(state="answered")).relayed


class TestDefaults:
    def test_a_bridged_call_relays_what_no_handler_answers(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    pass
"""
        )
        result = harness.send_info(content_type="application/dtmf-relay", body="Signal=5\r\n")
        assert result.relayed and result.status_code is None

    def test_a_call_with_no_far_leg_answers_200(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    pass
"""
        )
        result = harness.send_info(bridged=False)
        assert not result.relayed
        assert (result.status_code, result.reason) == (200, "OK")

    def test_a_handler_that_raises_leaves_the_default(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    request.reply(486, "Busy Here")
    raise RuntimeError("boom")
"""
        )
        assert harness.send_info().relayed
        assert harness.send_info(bridged=False).status_code == 200


class TestLeg:
    SOURCE = """
from siphon import b2bua

@b2bua.on_info
{signature}:
    request.set_reply_body({expression}.encode(), "text/plain")
    request.reply(200, "OK")
"""

    @pytest.mark.parametrize("leg", ["caller", "callee"])
    @pytest.mark.parametrize(
        "signature,expression",
        [
            ("def on_info(call, request, leg)", "leg"),
            ("async def on_info(call, request, leg)", "leg"),
            ("def on_info(call, request, **extra)", "extra['leg']"),
        ],
    )
    def test_a_handler_that_declares_leg_gets_it(self, harness, leg, signature, expression):
        harness.load_source(self.SOURCE.format(signature=signature, expression=expression))
        assert harness.send_info(leg=leg).body == leg.encode()

    @pytest.mark.parametrize("signature", ["def on_info(call, request)", "async def on_info(call, request)"])
    def test_a_two_argument_handler_still_runs(self, harness, signature):
        harness.load_source(self.SOURCE.format(signature=signature, expression="'plain'"))
        assert harness.send_info(leg="callee").body == b"plain"

    def test_an_unknown_leg_is_refused(self, harness):
        with pytest.raises(ValueError):
            harness.send_info(leg="both")


class TestState:
    def test_a_provisional_moves_a_calling_call_to_ringing(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_info
def on_info(call, request):
    request.set_reply_body(call.state.encode(), "text/plain")
    request.reply(200, "OK")
"""
        )
        from siphon_sdk.call import Call

        call = Call()
        assert harness.send_info(call=call).body == b"calling"
        harness.send_provisional(call=call)
        assert harness.send_info(call=call).body == b"ringing"
        harness.send_answer(call=call)
        assert harness.send_info(call=call).body == b"answered"
