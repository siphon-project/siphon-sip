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


def test_auto_emit_merges_into_the_tracked_record():
    """With auto_emit on, the fields attach to the record siphon already keeps
    for the call — one row carrying both the script's fields and the timings,
    not a billing row beside a duration row."""
    cdr = get_cdr()
    cdr.auto_emit = True
    call = Call(call_id="call-3")

    assert cdr.write(call, extra={"billing_id": "B-3"}) is True
    assert cdr.records == [], "nothing is emitted until the call ends"
    assert cdr.pending[call.id]["billing_id"] == "B-3"

    # A second write merges on top rather than adding a record.
    assert cdr.write(call, extra={"carrier_id": "carrier-a"}) is True
    assert cdr.records == []

    # The BYE emits the one record.
    record = cdr.finalize(call, duration_secs=42.0, disconnect_initiator="caller")
    assert record is not None
    assert cdr.records == [record]
    assert record["billing_id"] == "B-3"
    assert record["carrier_id"] == "carrier-a"
    assert record["duration_secs"] == 42.0
    assert record["disconnect_initiator"] == "caller"


def test_auto_emit_keys_a_proxy_request_on_the_dialog():
    cdr = get_cdr()
    cdr.auto_emit = True
    request = Request(
        method="BYE",
        call_id="cid-9",
        from_tag="tag-caller",
    )
    assert cdr.write(request, extra={"billing_id": "B-9"}) is True
    assert cdr.pending["cid-9\0tag-caller"]["billing_id"] == "B-9"


def test_write_rejects_other_types():
    cdr = get_cdr()
    with pytest.raises(TypeError):
        cdr.write("not a request or call")
    with pytest.raises(TypeError):
        cdr.write(42)
