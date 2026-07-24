"""Tests for the WhatsApp Business Calling gateway example
(examples/whatsapp_calling.py), driven through the SDK mocks.

Covers both directions and the WhatsApp-specific invariants:
  * inbound (Meta -> internal) is detected by source-IP membership of the
    "whatsapp" gateway group (call.from_gateway), anchored with the SDES inbound
    profile, and bridged to the internal gateway;
  * outbound (internal -> Meta) rewrites From to the business number, sets the
    digest credentials SIPhon uses to answer Meta's 407, anchors with the SDES
    outbound profile, and dials wa.meta.vc over TLS;
  * missing credentials / destination number are rejected, not dialled;
  * MODE=dtls selects the DTLS-SRTP media profiles.
"""
import asyncio
import importlib.util
import os
import pathlib

import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import gateway  # noqa: E402  (must come after install)
from siphon_sdk.call import Call  # noqa: E402

EXAMPLE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "examples"
    / "whatsapp_calling.py"
)
INTERNAL_URI = "sip:pbx.internal.example.net:5060"
# RFC 5737 TEST-NET-3 addresses standing in for Meta's WhatsApp source range
# and an internal caller.
WHATSAPP_IP = "203.0.113.50"
INTERNAL_IP = "203.0.113.20"


def _load_example(business="+15551234567", password="s3cret", mode="sdes"):
    """Import a fresh copy of the example with the given environment.

    The example reads its config from the environment at import time, so each
    scenario re-imports it.
    """
    os.environ["WHATSAPP_BUSINESS_NUMBER"] = business
    os.environ["WHATSAPP_SIP_PASSWORD"] = password
    os.environ["WHATSAPP_MEDIA_MODE"] = mode
    spec = importlib.util.spec_from_file_location("whatsapp_calling_example", EXAMPLE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _fresh_mocks():
    mock_module.reset()
    gateway.add_group("internal", [{"uri": INTERNAL_URI, "address": f"{INTERNAL_IP}:5060"}])
    # In production source_networks carries Meta's published ranges; the mock
    # matches source IP against the group's destination addresses, so a single
    # representative address stands in for the range here.
    gateway.add_group(
        "whatsapp",
        [{"uri": "sip:wa.meta.vc:5061;transport=tls", "address": f"{WHATSAPP_IP}:5061"}],
    )
    yield
    mock_module.reset()


def _rtpengine_profiles():
    return [profile for op, profile in mock_module.get_rtpengine().operations if op == "offer"]


def _actions(call, kind):
    return [action for action in call._actions if action.kind == kind]


def test_inbound_from_whatsapp_bridges_to_internal():
    module = _load_example()
    call = Call(
        ruri="sip:+15551234567@whatsapp-gw.example.com",
        source_ip=WHATSAPP_IP,
        headers={"x-wa-meta-wacid": "wacid-abc"},
    )
    asyncio.run(module.route(call))

    assert "srtp_to_rtp" in _rtpengine_profiles()
    dials = _actions(call, "dial")
    assert [d.targets for d in dials] == [[INTERNAL_URI]]
    assert not _actions(call, "reject")


def test_outbound_to_whatsapp_sets_from_creds_and_dials_meta():
    module = _load_example(business="+15559876543", password="metapass")
    call = Call(ruri="sip:+31612345678@whatsapp-gw.example.com", source_ip=INTERNAL_IP)
    asyncio.run(module.route(call))

    # From user rewritten to the business number — Meta cross-checks it against
    # the digest username.
    assert call.from_uri.user == "+15559876543"
    creds = _actions(call, "set_credentials")
    assert creds and creds[0].extras["username"] == "+15559876543"
    assert creds[0].extras["password"] == "metapass"

    assert "rtp_to_srtp" in _rtpengine_profiles()
    dials = _actions(call, "dial")
    assert [d.targets for d in dials] == [["sip:+31612345678@wa.meta.vc:5061;transport=tls"]]


def test_outbound_without_credentials_is_rejected_not_dialled():
    module = _load_example(business="", password="")
    call = Call(ruri="sip:+31612345678@whatsapp-gw.example.com", source_ip=INTERNAL_IP)
    asyncio.run(module.route(call))

    rejects = _actions(call, "reject")
    assert rejects and rejects[0].status_code == 503
    assert not _actions(call, "dial")


def test_outbound_without_destination_number_is_rejected_404():
    module = _load_example()
    call = Call(ruri="sip:whatsapp-gw.example.com", source_ip=INTERNAL_IP)  # no user part
    asyncio.run(module.route(call))

    rejects = _actions(call, "reject")
    assert rejects and rejects[0].status_code == 404
    assert not _actions(call, "dial")


def test_dtls_mode_selects_dtls_profiles():
    module = _load_example(mode="dtls")
    call = Call(ruri="sip:+15551234567@whatsapp-gw.example.com", source_ip=WHATSAPP_IP)
    asyncio.run(module.route(call))

    assert "whatsapp_dtls_in" in _rtpengine_profiles()
    assert "srtp_to_rtp" not in _rtpengine_profiles()
