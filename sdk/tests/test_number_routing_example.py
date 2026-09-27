"""The LNP handler in examples/number_routing.py, run against the mock.

The example once shipped a call to a method the runtime did not have; running
it here keeps the cookbook honest.
"""

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    h.load_script("../examples/number_routing.py")
    yield h
    h.reset()
    h.close()


def test_ported_number_gets_npdi_and_rn(harness):
    result = harness.send_request("INVITE", "sip:+15551234567@example.com")
    assert result.action == "relay"
    ruri = result.request.ruri
    assert str(ruri) == (
        "sip:+15551234567;npdi;rn=+15559990000@carrier.example.net;user=phone"
    )
    assert ruri.user == "+15551234567"
    assert ruri.user_params == {"npdi": "", "rn": "+15559990000"}


def test_not_ported_number_gets_npdi_only(harness):
    result = harness.send_request("INVITE", "sip:+15550001111@example.com")
    assert result.action == "relay"
    assert str(result.request.ruri) == "sip:+15550001111;npdi@carrier.example.net;user=phone"


def test_already_dipped_request_is_not_dipped_again(harness):
    already = "sip:+15551234567;npdi;rn=+15557770000@upstream.example.com;user=phone"
    result = harness.send_request("INVITE", already)
    assert result.action == "relay"
    assert str(result.request.ruri) == already, "the upstream rn must survive"
