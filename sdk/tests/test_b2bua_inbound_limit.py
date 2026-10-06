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


# -- gateway.groups[].inbound_limit -------------------------------------------

CARRIER = "203.0.113.10"
OTHER_CARRIER = "203.0.113.20"


def carrier_group(harness, name="carrier-a", address=CARRIER):
    harness.gateway.add_group(name, [
        {"uri": f"sip:{address}:5060", "address": f"{address}:5060"},
    ])


def test_a_carrier_past_its_groups_limit_is_refused_in_the_groups_name(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit(
        "carrier-a", max_concurrent_calls=1, reject_code=486, retry_after_secs=0
    )

    assert harness.send_invite(source_ip=CARRIER).action == "dial"
    refused = harness.send_invite(source_ip=CARRIER)
    assert refused.was_refused
    assert refused.status_code == 486
    assert refused.retry_after_secs is None
    assert refused.refusal_scope == "gateway"
    assert refused.refusal_gateway_group == "carrier-a"
    assert refused.call.actions == [], "the handler never touched the call"
    assert harness.gateway.inbound_calls_active("carrier-a") == 1


def test_a_caller_outside_the_group_is_not_held_to_its_limit(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)
    harness.send_invite(source_ip=CARRIER)

    for _ in range(3):
        assert not harness.send_invite(source_ip="192.0.2.99").was_refused
    assert harness.gateway.inbound_calls_active("carrier-a") == 1
    assert harness.inbound_calls_active == 4


def test_a_group_with_no_limit_keeps_no_count(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    assert harness.gateway.inbound_calls_active("carrier-a") is None
    assert not harness.send_invite(source_ip=CARRIER).was_refused
    assert harness.gateway.inbound_calls_active("carrier-a") is None


@pytest.mark.parametrize("ending", ["bye", "cancel", "failure"])
def test_a_groups_slot_comes_back_when_the_call_ends(harness, ending):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)

    call = Call(call_id="held@example.com", source_ip=CARRIER)
    harness.send_invite(call)
    assert harness.send_invite(source_ip=CARRIER).was_refused

    if ending == "bye":
        harness.send_bye(call)
    elif ending == "cancel":
        harness.send_call_cancel(call)
    else:
        harness.send_failure(call, 486, "Busy Here")

    assert harness.gateway.inbound_calls_active("carrier-a") == 0
    assert not harness.send_invite(source_ip=CARRIER).was_refused


def test_the_instance_limit_still_applies_to_a_carrier_inside_its_own(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=10, reject_code=486)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_invite(source_ip="192.0.2.99")

    refused = harness.send_invite(source_ip=CARRIER)
    assert refused.was_refused
    assert refused.refusal_scope == "global"
    assert refused.refusal_gateway_group is None
    assert refused.status_code == 503
    assert harness.gateway.inbound_calls_active("carrier-a") == 0


def test_the_groups_limit_is_judged_before_the_instances(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1, reject_code=486)
    harness.set_inbound_limit(max_concurrent_calls=1)
    harness.send_invite(source_ip=CARRIER)

    # Both are full; the carrier is answered in its own name, with its own code.
    refused = harness.send_invite(source_ip=CARRIER)
    assert refused.refusal_scope == "gateway"
    assert refused.status_code == 486


def test_a_source_two_limited_groups_admit_is_counted_against_both(harness):
    harness.load_source(DIAL)
    carrier_group(harness, "wide")
    carrier_group(harness, "narrow")
    harness.gateway.set_inbound_limit("wide", max_concurrent_calls=2)
    harness.gateway.set_inbound_limit("narrow", max_concurrent_calls=1)

    harness.send_invite(source_ip=CARRIER)
    assert harness.gateway.inbound_calls_active("wide") == 1
    assert harness.gateway.inbound_calls_active("narrow") == 1

    refused = harness.send_invite(source_ip=CARRIER)
    assert refused.refusal_gateway_group == "narrow"
    assert harness.gateway.inbound_calls_active("wide") == 1, "nothing left taken in wide"


def test_a_groups_rate_is_its_own_and_runs_on_the_harness_clock(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    carrier_group(harness, "carrier-b", OTHER_CARRIER)
    harness.gateway.set_inbound_limit("carrier-a", max_calls_per_second=1)

    assert not harness.send_invite(source_ip=CARRIER).was_refused
    refused = harness.send_invite(source_ip=CARRIER)
    assert refused.was_refused and refused.refusal_gateway_group == "carrier-a"
    assert not harness.send_invite(source_ip=OTHER_CARRIER).was_refused

    harness.advance_time(1.0)
    assert not harness.send_invite(source_ip=CARRIER).was_refused


def test_an_emergency_call_from_a_carrier_at_its_limit_is_admitted_and_counted(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)
    harness.send_invite(source_ip=CARRIER)

    emergency = harness.send_invite(source_ip=CARRIER, ruri="urn:service:sos")
    assert not emergency.was_refused
    assert harness.gateway.inbound_calls_active("carrier-a") == 2


def test_a_changed_group_limit_applies_to_the_calls_already_up(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=3)
    for _ in range(3):
        harness.send_invite(source_ip=CARRIER)

    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)
    assert harness.gateway.inbound_calls_active("carrier-a") == 3
    assert harness.send_invite(source_ip=CARRIER).was_refused


def test_removing_the_group_or_its_limit_stops_the_refusals(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)
    harness.send_invite(source_ip=CARRIER)
    assert harness.send_invite(source_ip=CARRIER).was_refused

    harness.gateway.clear_inbound_limit("carrier-a")
    assert not harness.send_invite(source_ip=CARRIER).was_refused

    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)
    harness.gateway.remove_group("carrier-a")
    assert not harness.send_invite(source_ip=CARRIER).was_refused
    assert harness.gateway.inbound_calls_active("carrier-a") is None


def test_a_limit_on_an_unknown_group_or_with_a_bad_code_is_an_error(harness):
    with pytest.raises(KeyError):
        harness.gateway.set_inbound_limit("nobody", max_concurrent_calls=1)
    carrier_group(harness)
    with pytest.raises(ValueError, match="reject_code"):
        harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1, reject_code=302)


def test_reset_clears_group_limits_too(harness):
    harness.load_source(DIAL)
    carrier_group(harness)
    harness.gateway.set_inbound_limit("carrier-a", max_concurrent_calls=1)
    harness.send_invite(source_ip=CARRIER)

    harness.reset()
    harness.load_source(DIAL)
    carrier_group(harness)
    assert harness.gateway.inbound_calls_active("carrier-a") is None
    assert not harness.send_invite(source_ip=CARRIER).was_refused
    assert not harness.send_invite(source_ip=CARRIER).was_refused
