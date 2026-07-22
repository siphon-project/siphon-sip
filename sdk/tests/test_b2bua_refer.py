"""Tests for the B2BUA REFER / call-transfer API.

Covers both the call-scoped handler path (``@b2bua.on_refer`` +
``call.accept_refer`` / ``call.reject_refer`` / ``call.refer``) and the
imperative ``b2bua.refer(call_id, target)`` used from out-of-band event
callbacks (``@rtpengine.on_dtmf``, timers) where no ``call`` object is in
scope and deferred call actions are no-ops — the twin of ``b2bua.terminate``.

A REFER is a SIP *request*, so ``@b2bua.on_refer`` is single-arg ``(call)``
with no ``reply`` object.
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


class TestOnReferHandler:
    def test_single_arg_and_blind_refer_to_readable(self, harness):
        # Handler is single-arg (call). If it were (call, reply) the harness'
        # fn(call) dispatch would raise TypeError, so a clean run proves the
        # single-arg contract.  Blind transfer => refer_replaces is None.
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    assert call.refer_replaces is None
    call.set_header("X-Seen-Refer-To", call.refer_to)
    call.accept_refer()
"""
        )

        result = harness.send_refer(refer_to="sip:+15550142@example.com")
        assert result.call.refer_to == "sip:+15550142@example.com"
        assert result.call.get_header("X-Seen-Refer-To") == "sip:+15550142@example.com"
        assert result.action == "accept_refer"

    def test_attended_replaces_passes_all_four_keys(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    repl = call.refer_replaces
    call.set_header("X-Repl-CallId", repl["call_id"])
    call.set_header("X-Repl-FromTag", repl["from_tag"])
    call.set_header("X-Repl-ToTag", repl["to_tag"])
    call.set_header("X-Repl-EarlyOnly", str(repl["early_only"]))
    call.accept_refer()
"""
        )

        result = harness.send_refer(
            refer_to="sip:+15550142@example.com",
            refer_replaces={
                "call_id": "held-dialog@example.com",
                "from_tag": "ft-held",
                "to_tag": "tt-held",
                "early_only": True,
            },
        )
        repl = result.call.refer_replaces
        assert set(repl) == {"call_id", "from_tag", "to_tag", "early_only"}
        assert repl["early_only"] is True
        assert result.call.get_header("X-Repl-CallId") == "held-dialog@example.com"
        assert result.call.get_header("X-Repl-EarlyOnly") == "True"


class TestAcceptRefer:
    def test_default_mode_is_none_and_no_target(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    call.accept_refer()
"""
        )

        result = harness.send_refer()
        action = result.call.last_action
        assert action.kind == "accept_refer"
        assert action.extras["mode"] is None
        assert action.targets is None
        assert action.next_hop is None

    def test_target_and_transparent_mode_recorded(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    call.accept_refer(target="sip:+15550142@example.com",
                      next_hop="sip:trunk.example.com:5060",
                      mode="transparent")
"""
        )

        result = harness.send_refer()
        action = result.call.last_action
        assert action.kind == "accept_refer"
        assert action.extras["mode"] == "transparent"
        assert action.targets == ["sip:+15550142@example.com"]
        assert action.next_hop == "sip:trunk.example.com:5060"

    def test_invalid_mode_raises_value_error(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    call.accept_refer(mode="bridge")
"""
        )

        with pytest.raises(ValueError):
            harness.send_refer()


class TestRejectRefer:
    def test_reject_recorded(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    call.reject_refer(603, "Decline")
"""
        )

        result = harness.send_refer()
        action = result.call.last_action
        assert action.kind == "reject_refer"
        assert action.status_code == 603
        assert action.reason == "Decline"


class TestOutboundCallRefer:
    def test_blind_refer_from_on_answer(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_answer
def on_answer(call, reply):
    call.refer("sip:+15550142@example.com")
"""
        )

        result = harness.send_answer()
        action = result.call.last_action
        assert action.kind == "refer"
        assert action.targets == ["sip:+15550142@example.com"]
        assert action.extras["replaces"] is None

    def test_attended_refer_records_replaces(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_answer
def on_answer(call, reply):
    call.refer(
        "sip:+15550142@example.com",
        replaces={"call_id": "held@example.com",
                  "from_tag": "ft", "to_tag": "tt"},
    )
"""
        )

        result = harness.send_answer()
        action = result.call.last_action
        assert action.kind == "refer"
        assert action.extras["replaces"] == {
            "call_id": "held@example.com",
            "from_tag": "ft",
            "to_tag": "tt",
        }

    def test_refer_bad_replaces_raises(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_answer
def on_answer(call, reply):
    call.refer("sip:+15550142@example.com",
               replaces={"call_id": "held@example.com"})
"""
        )

        with pytest.raises(ValueError):
            harness.send_answer()


class TestImperativeB2buaRefer:
    def test_refer_from_on_dtmf_star_digit(self, harness):
        # Cross-worker-safe transfer by Call-ID from an out-of-band DTMF
        # callback — no stashed `call` object.
        harness.load_source(
            """
from siphon import rtpengine, b2bua

XFER_DIGIT = "*"

@rtpengine.on_dtmf
def on_ivr_dtmf(call_id, from_tag, digit, duration_ms, volume):
    if digit == XFER_DIGIT:
        b2bua.refer(call_id, "sip:+15550142@example.com")
"""
        )

        # A non-transfer digit does nothing.
        harness.rtpengine.fire_dtmf("call-abc@example.com", "ft", "5")
        assert harness.b2bua.refers == []

        # The transfer digit refers by call-id.
        fired = harness.rtpengine.fire_dtmf("call-abc@example.com", "ft", "*")
        assert fired == 1
        assert harness.b2bua.refers == [
            {
                "call_id": "call-abc@example.com",
                "target": "sip:+15550142@example.com",
                "replaces": None,
            }
        ]

    def test_direct_call_returns_true_and_records(self, harness):
        import siphon

        assert siphon.b2bua.refer("x@example.com", "sip:+15550111@example.com") is True
        assert harness.b2bua.refers[-1] == {
            "call_id": "x@example.com",
            "target": "sip:+15550111@example.com",
            "replaces": None,
        }

    def test_reset_clears_recorded_refers(self, harness):
        import siphon

        siphon.b2bua.refer("x@example.com", "sip:+15550111@example.com")
        assert harness.b2bua.refers
        harness.reset()
        assert harness.b2bua.refers == []
