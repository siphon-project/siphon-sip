"""Tests for the IMS UE B2BUA example (examples/ims_ue_b2bua.py).

The example declares its IMS-AKA + IPsec registration in YAML
(`registrant.entries`), not in the script — so the SDK harness (which doesn't
process YAML) stands in for it by registering through the mock. The script
itself is just the bridge:
  - MT: an INVITE whose A-leg came from the P-CSCF is bridged to the tester.
  - MO: an INVITE from the tester is dialled toward the IMS over the UE SA
    flow, carrying the (mock-empty) Service-Route and a P-Preferred-Identity.

Uses the example's env defaults (3GPP test range MCC 001 / MNC 01).
"""
import pytest

from siphon_sdk import mock_module
from siphon_sdk.testing import SipTestHarness

PCSCF = "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060"
PCSCF_IP = "10.0.0.10"
HOME = "ims.mnc01.mcc001.3gppnetwork.org"
IMPU = f"sip:001010000000001@{HOME}"
IMPI = f"001010000000001@{HOME}"
TESTER = "sip:5555@10.0.0.100:5060"


def _register():
    """Stand in for the YAML `registrant.entries` declaration."""
    registration = mock_module.get_registration()
    registration._entries.clear()
    registration.add(
        IMPU, PCSCF, user=IMPI,
        auth="aka",
        k="465b5ce8b199b49faa5f0a2ee238a6bc",
        opc="cd63cb71954a9f4e48a5994e37a02baf",
        ipsec=True, ue_port_c=6100, ue_port_s=6101,
    )


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["10.0.0.20"])
    h.load_script("../examples/ims_ue_b2bua.py")
    _register()
    yield h
    h.reset()
    h.close()


def test_script_loads_without_module_level_registration(harness):
    # The script must NOT call registration.add at top level (it would hit the
    # unconfigured stub at load time). Loading it should not raise.
    assert mock_module.get_registration()._entries[IMPU]["ipsec"] is True


def test_mt_call_bridges_to_tester(harness):
    # A-leg from the P-CSCF → terminating → dial the tester.
    result = harness.send_invite(source_ip=PCSCF_IP, ruri=IMPU)
    assert result.action == "dial"
    assert result.targets == [TESTER]


def test_mo_call_dials_ims_over_sa_flow(harness):
    # A-leg from the tester → originating → dial toward the IMS.
    result = harness.send_invite(
        source_ip="10.0.0.100",
        ruri="sip:1234@10.0.0.20",
        from_uri="sip:tester@10.0.0.100",
    )
    assert result.action == "dial"
    # R-URI rebuilt as the dialled number @ the IMS home domain.
    assert result.targets == [f"sip:1234@{HOME}"]

    dial = result.actions[-1]
    # Sourced over the UE→P-CSCF SA flow (mock returns one for ipsec entries).
    assert dial.extras["flow"] is not None
    # Service-Route carried (empty in the mock — no live handshake).
    assert dial.extras["route"] == []
    # P-Preferred-Identity asserted, and the intra-trust preset preserves it.
    assert result.call.get_header("P-Preferred-Identity") == f"<{IMPU}>"
    assert dial.extras["header_policy"] == "ims-intra-trust-domain@2026"


def test_mo_call_rejected_when_not_registered(harness):
    # If the registration isn't up (no ipsec flow), MO is rejected 503.
    mock_module.get_registration()._entries[IMPU]["ipsec"] = False
    result = harness.send_invite(source_ip="10.0.0.100", ruri="sip:1234@10.0.0.20")
    assert result.was_rejected
    assert result.status_code == 503
