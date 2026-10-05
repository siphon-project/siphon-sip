"""Tests for the harness model of ``b2bua.inbound_limit``.

siphon refuses an inbound call past the limit before ``@b2bua.on_invite`` runs,
so the thing a script author has to test is what happens to the calls that do
get through, and that nothing in the script depends on seeing the ones that do
not. The harness refuses in the same place: ahead of the handler.
"""

from __future__ import annotations

import pytest

from siphon_sdk.call import Call
from siphon_sdk.testing import SipTestHarness

DIAL = """
from siphon import b2bua

SEEN = []

@b2bua.on_invite
def on_invite(call):
    SEEN.append(call.call_id)
    call.dial("sip:bob@198.51.100.7:5060")

@b2bua.on_failure
def on_failure(call, code, reason):
    pass
"""

REJECT = """
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    call.reject(403, "Forbidden")
"""

SILENT = """
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    pass
"""

REROUTE = """
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    call.dial("sip:bob@198.51.100.7:5060")

@b2bua.on_failure
def on_failure(call, code, reason):
    call.dial("sip:bob@198.51.100.8:5060")
"""


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


def test_with_no_limit_every_call_is_admitted_and_counted(harness):
    harness.load_source(DIAL)
    results = [harness.send_invite() for _ in range(20)]
    assert not any(result.was_refused for result in results)
    assert harness.inbound_calls_active == 20


def test_the_call_past_the_concurrent_ceiling_is_refused_and_no_handler_runs(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)

    first = harness.send_invite(call_id="first@example.com")
    assert first.action == "dial"

    second = harness.send_invite(call_id="second@example.com")
    assert second.was_refused
    assert second.action == "refused"
    assert second.status_code == 503
    assert second.actions[-1].reason == "Service Unavailable"
    assert second.retry_after_secs == 1
    assert second.call.actions == [], "the handler never touched the call"
    assert harness.inbound_calls_active == 1


def test_the_refusal_uses_the_configured_code_and_no_retry_after_at_zero(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1, reject_code=486, retry_after_secs=0)
    harness.send_invite()

    refused = harness.send_invite()
    assert refused.status_code == 486
    assert refused.actions[-1].reason == "Busy Here"
    assert refused.retry_after_secs is None


def test_a_reject_code_that_is_not_a_failure_response_is_an_error(harness):
    for code in (200, 302, 399, 700):
        with pytest.raises(ValueError, match="reject_code"):
            harness.set_inbound_limit(max_concurrent_calls=1, reject_code=code)


@pytest.mark.parametrize("ending", ["bye", "cancel", "failure"])
def test_the_slot_comes_back_when_the_call_ends(harness, ending):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)

    call = Call(call_id="held@example.com")
    assert harness.send_invite(call).action == "dial"
    assert harness.send_invite().was_refused

    if ending == "bye":
        harness.send_bye(call)
    elif ending == "cancel":
        harness.send_call_cancel(call)
    else:
        harness.send_failure(call, 486, "Busy Here")

    assert harness.inbound_calls_active == 0
    assert not harness.send_invite().was_refused


def test_a_failure_the_handler_routes_again_keeps_its_slot(harness):
    harness.load_source(REROUTE)
    harness.set_inbound_limit(max_concurrent_calls=1)

    call = Call(call_id="rerouted@example.com")
    harness.send_invite(call)
    harness.send_failure(call, 503, "Service Unavailable")

    assert harness.inbound_calls_active == 1
    assert harness.send_invite().was_refused


@pytest.mark.parametrize("script", [REJECT, SILENT])
def test_a_call_the_script_does_not_dial_holds_no_slot(harness, script):
    harness.load_source(script)
    harness.set_inbound_limit(max_concurrent_calls=1)
    for _ in range(3):
        assert not harness.send_invite().was_refused
        assert harness.inbound_calls_active == 0


def test_the_rate_admits_a_burst_of_one_seconds_worth_then_one_per_interval(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_calls_per_second=4)

    burst = [harness.send_invite().was_refused for _ in range(5)]
    assert burst == [False, False, False, False, True]

    harness.advance_time(0.249)
    assert harness.send_invite().was_refused, "one interval has not passed"
    harness.advance_time(0.001)
    assert not harness.send_invite().was_refused
    assert harness.send_invite().was_refused


def test_a_call_refused_on_rate_holds_no_slot(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_calls_per_second=1)
    assert not harness.send_invite().was_refused
    assert harness.send_invite().was_refused
    assert harness.inbound_calls_active == 1


def test_a_call_refused_for_a_slot_spends_no_rate(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1, max_calls_per_second=2)

    held = Call(call_id="held@example.com")
    harness.send_invite(held)
    for _ in range(10):
        assert harness.send_invite().was_refused
    harness.send_bye(held)

    assert not harness.send_invite().was_refused, "the second call of the second"


@pytest.mark.parametrize("ruri", ["urn:service:sos", "URN:SERVICE:SOS", "urn:service:sos.fire"])
def test_an_emergency_call_is_admitted_at_the_ceiling(harness, ruri):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_invite()
    assert harness.send_invite().was_refused

    emergency = harness.send_invite(ruri=ruri)
    assert not emergency.was_refused
    assert emergency.action == "dial"
    assert harness.inbound_calls_active == 2, "it still holds a slot"


def test_only_the_sos_services_are_exempt(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_invite()
    for ruri in ("urn:service:counseling", "urn:service:sosx", "sip:112@example.com"):
        assert harness.send_invite(ruri=ruri).was_refused, ruri


def test_clearing_the_limit_stops_refusing(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_invite()
    assert harness.send_invite().was_refused

    harness.clear_inbound_limit()
    assert not harness.send_invite().was_refused


def test_reset_clears_the_limit_and_the_slots(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_invite()
    assert harness.inbound_calls_active == 1

    harness.reset()
    harness.load_source(DIAL)
    assert harness.inbound_calls_active == 0
    assert not harness.send_invite().was_refused
    assert not harness.send_invite().was_refused


def test_ending_a_call_that_never_held_a_slot_is_harmless(harness):
    harness.load_source(DIAL)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_bye()
    harness.send_call_cancel()
    assert harness.inbound_calls_active == 0
