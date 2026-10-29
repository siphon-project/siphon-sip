"""Tests for ``b2bua.adopt_replaced``: a REFER with ``Replaces`` inside a
conference dialog merges a call this node holds into the room.

The mock applies the same ownership comparison siphon does to the calls
``b2bua.hold_call(...)`` registered, and seats the far leg in the mock room, so
a script whose authorisation is wrong fails here as it would on a live node:
each refusal below is a status that reaches the REFER's report.
"""

from __future__ import annotations

import pytest

from siphon_sdk import mock_module
from siphon_sdk.call import Call
from siphon_sdk.mock_module import HeldLeg
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.types import Flow

MERGE_SCRIPT = """
from siphon import b2bua

@b2bua.on_refer
async def on_refer(call):
    call.accept_refer(mode="script")
    status = await b2bua.adopt_replaced(call, "room-1")
    b2bua.complete_refer(call.call_id, status)
"""

SUBSCRIBER = "192.0.2.10:5060"
CARRIER = "198.51.100.77:5060"


@pytest.fixture
def bare_harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


@pytest.fixture
def harness(bare_harness):
    bare_harness.load_source(MERGE_SCRIPT)
    return bare_harness


def subscriber_leg(call_id="held-a@192.0.2.1", source=SUBSCRIBER, auth_user=None,
                   transport="udp", connection_id=0, user="15550100001"):
    return HeldLeg(call_id=call_id, local_tag="sb-ours", remote_tag="subscriber-tag",
                   source=source, uri=f"<sip:{user}@example.com>", transport=transport,
                   connection_id=connection_id, auth_user=auth_user)


def carrier_leg(call_id="held-b@192.0.2.1"):
    return HeldLeg(call_id=call_id, local_tag="sb-carrier", remote_tag="carrier-tag",
                   source=CARRIER, uri="<sip:15550100042@carrier.example.com>")


def conference_dialog(replaces, *, auth_user=None, source_ip="192.0.2.10", flow=None,
                      user="15550100001"):
    call = Call(call_id="conf@192.0.2.10", state="answered",
                from_uri=f"sip:{user}@example.com", source_ip=source_ip,
                refer_to="sip:15550100042@example.com", refer_replaces=replaces,
                refer_side="a", flow=flow)
    call.auth_user = auth_user
    return call


def merge(harness, call):
    harness.send_refer(call=call)
    reports = mock_module.get_b2bua().refer_reports
    assert reports, "the script reported"
    return reports[-1]["code"]


def assert_untouched(held, room="room-1"):
    assert held.caller is not None and held.callee is not None
    assert held.adoption is None
    assert room not in mock_module.get_rtpengine().conferences


class TestMerge:
    def test_the_subscribers_caller_leg_is_ended_and_the_carrier_seated(self, harness):
        b2bua = mock_module.get_b2bua()
        held = b2bua.hold_call(subscriber_leg(auth_user="1001"), carrier_leg())
        code = merge(harness, conference_dialog(held.caller.replaces(), auth_user="1001"))
        assert code == 200
        seat = mock_module.get_rtpengine().conferences["room-1"]["carrier-tag"]
        assert seat["call_id"] == "held-a@192.0.2.1"
        assert seat["role"] == "talker"
        assert held.caller is None and held.callee is not None
        adoption = b2bua.adoptions[-1]
        assert adoption["replaced_leg"] == "caller"
        assert adoption["bye"] == {"call_id": "held-a@192.0.2.1",
                                   "reason": 'SIP;cause=200;text="Merged into conference"'}

    def test_the_subscribers_callee_leg_is_ended_and_the_carrier_seated(self, harness):
        # An inbound call to the subscriber, authorised by registration source:
        # no auth_user on either leg, so the source and the user decide.
        b2bua = mock_module.get_b2bua()
        held = b2bua.hold_call(carrier_leg("in-a@192.0.2.1"), subscriber_leg("in-b@192.0.2.1"))
        code = merge(harness, conference_dialog(held.callee.replaces()))
        assert code == 200
        assert "carrier-tag" in mock_module.get_rtpengine().conferences["room-1"]
        assert held.callee is None and held.caller is not None
        assert b2bua.adoptions[-1]["replaced_leg"] == "callee"


class TestRefusals:
    def test_another_identity_is_403_with_digest(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(auth_user="1002"), carrier_leg())
        assert merge(harness, conference_dialog(held.caller.replaces(), auth_user="1001")) == 403
        assert_untouched(held)

    def test_another_source_is_403_without_digest(self, harness):
        held = mock_module.get_b2bua().hold_call(
            carrier_leg("in-a@192.0.2.1"), subscriber_leg("in-b@192.0.2.1", source="192.0.2.66:5060"))
        assert merge(harness, conference_dialog(held.callee.replaces())) == 403
        assert_untouched(held)

    def test_the_same_source_with_another_user_is_403(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(user="15550100009"), carrier_leg())
        assert merge(harness, conference_dialog(held.caller.replaces())) == 403
        assert_untouched(held)

    def test_another_connection_on_a_stream_transport_is_403(self, harness):
        held = mock_module.get_b2bua().hold_call(
            subscriber_leg(transport="tls", connection_id=8, source="192.0.2.10:40000"), carrier_leg())
        flow = Flow(transport="tls", remote_addr="192.0.2.10:40000",
                    local_addr="192.0.2.1:5061", connection_id=7)
        assert merge(harness, conference_dialog(held.caller.replaces(), flow=flow)) == 403
        assert_untouched(held)

    def test_the_same_connection_on_a_stream_transport_is_the_subscriber(self, harness):
        held = mock_module.get_b2bua().hold_call(
            subscriber_leg(transport="tls", connection_id=7, source="192.0.2.10:40000"), carrier_leg())
        flow = Flow(transport="tls", remote_addr="192.0.2.10:40000",
                    local_addr="192.0.2.1:5061", connection_id=7)
        assert merge(harness, conference_dialog(held.caller.replaces(), flow=flow)) == 200

    def test_no_matching_dialog_is_481(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(), carrier_leg())
        replaces = dict(held.caller.replaces(), to_tag="someone-else")
        assert merge(harness, conference_dialog(replaces)) == 481
        assert_untouched(held)

    def test_an_early_call_is_481(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(), carrier_leg(), state="ringing")
        assert merge(harness, conference_dialog(held.caller.replaces())) == 481
        assert_untouched(held)

    def test_a_refer_without_replaces_is_481(self, harness):
        mock_module.get_b2bua().hold_call(subscriber_leg(), carrier_leg())
        assert merge(harness, conference_dialog(None)) == 481

    def test_a_seat_the_engine_refuses_is_488(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(), carrier_leg())
        mock_module.get_rtpengine().refuse_conference_seat("room full")
        assert merge(harness, conference_dialog(held.caller.replaces())) == 488
        assert_untouched(held)

    def test_an_engine_without_conference_seat_is_501(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(), carrier_leg())
        mock_module.get_rtpengine().set_conference_seat_supported(False)
        assert merge(harness, conference_dialog(held.caller.replaces())) == 501
        assert_untouched(held)


class TestArguments:
    def test_unknown_role_and_owner_policy_and_misuse_raise(self, bare_harness):
        harness = bare_harness
        b2bua = mock_module.get_b2bua()
        held = b2bua.hold_call(subscriber_leg(), carrier_leg())
        call = conference_dialog(held.caller.replaces())
        loop = harness._loop
        with pytest.raises(ValueError, match="role"):
            loop.run_until_complete(b2bua.adopt_replaced(call, "room-1", role="whisper"))
        with pytest.raises(ValueError, match="on_owner_leave"):
            loop.run_until_complete(b2bua.adopt_replaced(call, "room-1", on_owner_leave="linger"))
        with pytest.raises(ValueError, match="conference_id"):
            loop.run_until_complete(b2bua.adopt_replaced(call, ""))
        outside = Call(call_id="plain@192.0.2.10", state="answered")
        with pytest.raises(ValueError, match="on_refer"):
            loop.run_until_complete(b2bua.adopt_replaced(outside, "room-1"))
        assert_untouched(held)

    def test_the_script_reads_the_facts_it_is_compared_on(self, harness):
        held = mock_module.get_b2bua().hold_call(subscriber_leg(auth_user="1001"), carrier_leg())
        call = conference_dialog(held.caller.replaces())
        assert call.refer_replaces_call == {
            "call_id": "held-a@192.0.2.1",
            "leg": "caller",
            "source": SUBSCRIBER,
            "transport": "udp",
            "from_uri": "<sip:15550100001@example.com>",
            "auth_user": "1001",
        }
        assert conference_dialog(None).refer_replaces_call is None


class TestOwnerLeaves:
    def test_the_conference_dialog_ending_ends_what_it_adopted_unless_kept(self, bare_harness):
        harness = bare_harness
        harness.load_source("""
from siphon import b2bua

@b2bua.on_refer
async def on_refer(call):
    call.accept_refer(mode="script")
    keep = call.refer_replaces["call_id"].startswith("kept")
    status = await b2bua.adopt_replaced(call, "room-1", on_owner_leave="keep" if keep else "end")
    b2bua.complete_refer(call.call_id, status)
""")
        b2bua = mock_module.get_b2bua()
        ended = b2bua.hold_call(subscriber_leg("ended@192.0.2.1"), carrier_leg("ended-b@192.0.2.1"))
        kept = b2bua.hold_call(
            subscriber_leg("kept@192.0.2.1"),
            HeldLeg("kept-b@192.0.2.1", "sb-kept", "kept-carrier-tag", CARRIER,
                    "<sip:15550100043@carrier.example.com>"))
        assert merge(harness, conference_dialog(ended.caller.replaces())) == 200
        assert merge(harness, conference_dialog(kept.caller.replaces())) == 200
        room = mock_module.get_rtpengine().conferences["room-1"]
        assert set(room) == {"carrier-tag", "kept-carrier-tag"}

        assert b2bua.conference_dialog_ended("conf@192.0.2.10") == ["ended@192.0.2.1"]
        assert b2bua.terminates[-1] == {"call_id": "ended@192.0.2.1", "reason": "Q.850;cause=16"}
        assert set(mock_module.get_rtpengine().conferences["room-1"]) == {"kept-carrier-tag"}
        assert kept in b2bua.held_calls and ended not in b2bua.held_calls
