"""``diameter.rx_aar(specific_actions=...)`` in the SDK mock.

The mock refuses what siphon refuses. Otherwise a script passes its unit tests
and raises ``ValueError`` the first time it runs against a PCRF.
"""
import pytest

from siphon_sdk.testing import SipTestHarness

# TS 29.214 §5.3.13. 0 and 5 are Void.
DEFINED = [1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]


@pytest.fixture
def diameter():
    return SipTestHarness(local_domains=["ims.mnc001.mcc001.3gppnetwork.org"]).diameter


def test_default_requests_nothing_and_keeps_the_answer_shape(diameter):
    result = diameter.rx_aar(framed_ip="192.0.2.1")
    assert result == {"result_code": 2001, "session_id": result["session_id"]}


@pytest.mark.parametrize("value", DEFINED)
def test_every_defined_value_is_accepted(diameter, value):
    assert diameter.rx_aar(specific_actions=[value])["result_code"] == 2001


def test_several_values_and_an_empty_list(diameter):
    assert diameter.rx_aar(specific_actions=[2, 6, 9]) is not None
    assert diameter.rx_aar(specific_actions=[]) is not None
    assert diameter.rx_aar(specific_actions=(7, 8)) is not None


@pytest.mark.parametrize("value", [0, 5, 22, -1, 2**32])
def test_unknown_value_raises_value_error_naming_it(diameter, value):
    with pytest.raises(ValueError, match=rf" {value} "):
        diameter.rx_aar(specific_actions=[6, value])


@pytest.mark.parametrize("bad", [["6"], [6.0], 6, "6"])
def test_non_integer_list_raises_type_error(diameter, bad):
    with pytest.raises(TypeError):
        diameter.rx_aar(specific_actions=bad)


def test_value_past_64_bits_raises_overflow_error(diameter):
    # siphon reads each entry as a 64-bit int before checking it.
    with pytest.raises(OverflowError):
        diameter.rx_aar(specific_actions=[2**70])


def test_docstring_names_every_value(diameter):
    doc = type(diameter).rx_aar.__doc__
    for name in (
        "INDICATION_OF_LOSS_OF_BEARER",
        "IP-CAN_CHANGE",
        "INDICATION_OF_OUT_OF_CREDIT",
        "INDICATION_OF_FAILED_RESOURCES_ALLOCATION",
        "CN_HEALTH_MONITOR",
    ):
        assert name in doc
