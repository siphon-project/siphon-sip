"""Tests for cdr.write() — accepts a proxy Request or a B2BUA Call.

The engine's cdr.write() is polymorphic: proxy handlers pass a Request,
b2bua handlers (on_answer / on_bye / …) pass a Call. Both carry the
Call-ID, From/To/R-URI, source IP and transport the CDR needs. The mock
mirrors that so script tests can assert on the written record for either.
"""

from __future__ import annotations

import pytest

from siphon_sdk.call import Call
from siphon_sdk.mock_module import get_cdr
from siphon_sdk.request import Request


@pytest.fixture(autouse=True)
def _clear_cdr():
    get_cdr().clear()
    yield
    get_cdr().clear()


def test_write_from_request():
    cdr = get_cdr()
    request = Request(
        method="INVITE",
        from_uri="sip:alice@example.com",
        to_uri="sip:bob@example.com",
        ruri="sip:bob@example.com",
        call_id="cid-1",
        source_ip="10.0.0.1",
        transport="tcp",
    )
    assert cdr.write(request, extra={"billing_id": "B-1"}) is True
    record = cdr.records[-1]
    assert record["method"] == "INVITE"
    assert record["call_id"] == "cid-1"
    assert record["from_uri"] == "sip:alice@example.com"
    assert record["transport"] == "tcp"
    assert record["billing_id"] == "B-1"


def test_write_from_call():
    cdr = get_cdr()
    call = Call(
        call_id="call-1",
        from_uri="sip:alice@example.com",
        to_uri="sip:bob@example.com",
        ruri="sip:bob@example.com",
        source_ip="10.0.0.2",
        transport="tcp",
    )
    # This is the case that used to raise
    # "'Call' object is not an instance of 'Request'".
    assert cdr.write(call, extra={"billing_id": "B-2"}) is True
    record = cdr.records[-1]
    assert record["method"] == "INVITE"  # a B2BUA call is INVITE-driven
    assert record["call_id"] == "call-1"
    assert record["to_uri"] == "sip:bob@example.com"
    assert record["transport"] == "tcp"  # threaded off the A-leg
    assert record["billing_id"] == "B-2"


def test_write_from_call_defaults_transport_to_udp():
    cdr = get_cdr()
    call = Call(call_id="call-2")
    assert cdr.write(call) is True
    assert cdr.records[-1]["transport"] == "udp"


def test_write_rejects_other_types():
    cdr = get_cdr()
    with pytest.raises(TypeError):
        cdr.write("not a request or call")
    with pytest.raises(TypeError):
        cdr.write(42)
