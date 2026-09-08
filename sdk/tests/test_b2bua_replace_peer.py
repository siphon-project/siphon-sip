"""Tests for ``b2bua.replace_peer()`` — siphon-decided leg replacement.

The same dial / promote / BYE round a siphon-terminated REFER runs, reachable
without a REFER having arrived. The point of the verb is that the call's own
state goes with it: the replaced leg is BYE'd through the real teardown, so
``@b2bua.on_bye``, the CDR and the charging stop all fire, and the surviving
party is re-INVITEd onto the new media rather than left pointing at a leg that
is gone.
"""

import pytest

from siphon_sdk import mock_module
from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def b2bua():
    b = mock_module.get_b2bua()
    b.clear()
    yield b
    b.clear()


class TestRecording:
    def test_records_every_argument(self, b2bua):
        b2bua.replace_peer(
            "call-1@example.com",
            "sip:operator@pbx.example",
            next_hop="sip:10.0.0.9:5060",
            replace_a_leg=True,
            profile="ims_to_trunk",
            timeout=45,
        )
        assert b2bua.replacements == [
            {
                "call_id": "call-1@example.com",
                "target": "sip:operator@pbx.example",
                "next_hop": "sip:10.0.0.9:5060",
                "replace_a_leg": True,
                "profile": "ims_to_trunk",
                "timeout": 45,
                "number_policy": None,
            }
        ]

    def test_records_the_number_policy_for_the_replacement_leg(self, b2bua):
        # A replacement leg never re-enters @b2bua.on_invite, so the carrier's
        # number format has to be asked for on the verb itself.
        b2bua.replace_peer(
            "call-1@example.com",
            "sip:+15550142@carrier.example",
            number_policy="carrier-plain@2026",
        )
        assert b2bua.replacements[-1]["number_policy"] == "carrier-plain@2026"

    def test_defaults_replace_the_callee_and_ring_for_thirty(self, b2bua):
        b2bua.replace_peer("call-2@example.com", "sip:bob@example.com")
        recorded = b2bua.replacements[-1]
        # Replacing the callee is the common case, so it is the default; the
        # caller is the party that normally survives a transfer.
        assert recorded["replace_a_leg"] is False
        assert recorded["timeout"] == 30
        assert recorded["next_hop"] is None
        assert recorded["profile"] is None

    def test_returns_true_without_waiting_for_the_target(self, b2bua):
        # True means the INVITE is on the wire, not that the target answered —
        # the promotion happens later.
        assert b2bua.replace_peer("call-3@example.com", "sip:x@example.com") is True

    def test_clear_empties_the_recording(self, b2bua):
        b2bua.replace_peer("call-4@example.com", "sip:x@example.com")
        b2bua.clear()
        assert b2bua.replacements == []


class TestRefusals:
    def test_an_unroutable_target_raises_rather_than_returning_false(self, b2bua):
        # A caller that cannot tell a refused replacement from a started one
        # will tear down a call that is still up, so every refusal is an
        # exception carrying its stable cause token.
        with pytest.raises(ValueError, match="bad_request"):
            b2bua.replace_peer("call-5@example.com", "")
        assert b2bua.replacements == []


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestFromAnEventCallback:
    def test_dtmf_digit_hands_the_caller_to_an_operator(self, harness):
        # The shape the verb exists for: an out-of-band callback holding only a
        # Call-ID, where the deferred call.* API is a silent no-op.
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@rtpengine.on_dtmf
def on_digit(call_id, from_tag, digit, duration_ms, volume):
    if digit == "0":
        b2bua.replace_peer(call_id, "sip:operator@example.com", timeout=45)
"""
        )

        # A digit the script ignores replaces nothing.
        harness.rtpengine.fire_dtmf("call-9@example.com", "ft", "5")
        assert harness.b2bua.replacements == []

        fired = harness.rtpengine.fire_dtmf("call-9@example.com", "ft", "0")
        assert fired == 1
        assert harness.b2bua.replacements == [
            {
                "call_id": "call-9@example.com",
                "target": "sip:operator@example.com",
                "next_hop": None,
                "replace_a_leg": False,
                "profile": None,
                "timeout": 45,
                "number_policy": None,
            }
        ]

    def test_direct_call_returns_true_and_records(self, harness):
        import siphon

        assert (
            siphon.b2bua.replace_peer("x@example.com", "sip:agent@example.com") is True
        )
        assert harness.b2bua.replacements[-1]["target"] == "sip:agent@example.com"
