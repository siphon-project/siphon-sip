"""Tests for ``diameter.s6c_rsr`` (Report-SM-Delivery-Status, TS 29.338)."""

import asyncio

import pytest

from siphon_sdk.mock_module import install, reset


def setup_function():
    install()
    reset()


def run(coroutine):
    return asyncio.run(coroutine)


def recorded():
    from siphon import diameter
    return diameter.rsrs


def test_the_delivery_is_reported_through_the_mme_by_default():
    from siphon import diameter

    answer = run(diameter.s6c_rsr("001010000000001", "441632960000", 0))

    assert answer["result_code"] == 2001
    assert recorded()[-1] == {
        "user_name": "001010000000001",
        "sc_address": "441632960000",
        "delivery_outcome": 0,
        "node": "mme",
        "absent_user_diagnostic": None,
    }


@pytest.mark.parametrize("node", ["mme", "sgsn", "msc", "ip_sm_gw", "SGSN"])
def test_each_node_is_accepted(node):
    from siphon import diameter

    run(diameter.s6c_rsr("001010000000001", "441632960000", 2, node=node))

    assert recorded()[-1]["node"] == node.lower()


def test_an_absent_user_can_carry_a_diagnostic():
    from siphon import diameter

    run(diameter.s6c_rsr("001010000000001", "441632960000", 1,
                         node="sgsn", absent_user_diagnostic=6))

    assert recorded()[-1]["node"] == "sgsn"
    assert recorded()[-1]["absent_user_diagnostic"] == 6


@pytest.mark.parametrize("delivery_outcome", [0, 2])
def test_a_diagnostic_is_refused_unless_the_user_was_absent(delivery_outcome):
    from siphon import diameter

    with pytest.raises(ValueError, match="absent_user_diagnostic is only sent"):
        run(diameter.s6c_rsr("001010000000001", "441632960000", delivery_outcome,
                             absent_user_diagnostic=1))


@pytest.mark.parametrize("node", ["", "smsf", "ip-sm-gw"])
def test_an_unknown_node_is_refused(node):
    from siphon import diameter

    with pytest.raises(ValueError, match="invalid node"):
        run(diameter.s6c_rsr("001010000000001", "441632960000", 0, node=node))


@pytest.mark.parametrize("delivery_outcome", [3, 4, -1])
def test_an_outcome_that_names_no_cause_is_refused(delivery_outcome):
    from siphon import diameter

    with pytest.raises(ValueError, match="invalid delivery_outcome"):
        run(diameter.s6c_rsr("001010000000001", "441632960000", delivery_outcome))
