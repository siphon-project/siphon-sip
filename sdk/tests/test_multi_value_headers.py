"""Multi-value header reads — ``get_headers`` vs ``get_header``.

RFC 3261 §7.3.1 lets a peer spread one header over several lines, and several
of the headers a script cares about routinely arrive that way: Record-Route,
Via, Route, Contact, Supported, Path, the P-* family.  ``get_header`` returns
the first value only, so anything read through it is silently truncated.

The case that made this load-bearing is RFC 3261 §12.1.1: a UAS answering a
dialog-forming request has to echo *every* Record-Route into the 2xx, in order.
A proxy that Record-Routes once per socket it bridges (a P-CSCF joining its
protected access port to its core port) sends two, and the second is the one
the UE's in-dialog requests have to leave on.
"""

import pytest

from siphon_sdk.reply import Reply
from siphon_sdk.request import Request


ACCESS_RR = "<sip:198.51.100.1:5066;transport=udp;lr>"
CORE_RR = "<sip:198.51.100.1:5060;transport=udp;lr>"


@pytest.fixture
def subscribe() -> Request:
    return Request(
        method="SUBSCRIBE",
        ruri="sip:alice@ims.example.com",
        from_uri="sip:alice@ims.example.com",
        to_uri="sip:alice@ims.example.com",
        headers={"Record-Route": [CORE_RR, ACCESS_RR], "Event": "reg"},
    )


def test_get_headers_returns_every_value_in_order(subscribe):
    assert subscribe.get_headers("Record-Route") == [CORE_RR, ACCESS_RR]


def test_get_header_returns_only_the_first(subscribe):
    """The truncation ``get_headers`` exists to fix."""
    assert subscribe.get_header("Record-Route") == CORE_RR
    assert subscribe.header("Record-Route") == CORE_RR


def test_get_headers_is_case_insensitive(subscribe):
    assert subscribe.get_headers("record-route") == subscribe.get_headers("Record-Route")


def test_get_headers_is_empty_when_absent(subscribe):
    assert subscribe.get_headers("X-Nothing-Here") == []


def test_single_valued_header_still_reads_as_a_one_entry_list(subscribe):
    assert subscribe.get_headers("Event") == ["reg"]
    assert subscribe.get_header("Event") == "reg"


def test_reply_side_reads_the_same_way():
    reply = Reply(
        status_code=200,
        reason="OK",
        headers={"Record-Route": [CORE_RR, ACCESS_RR]},
    )
    assert reply.get_headers("Record-Route") == [CORE_RR, ACCESS_RR]
    assert reply.get_header("Record-Route") == CORE_RR
    assert reply.get_headers("Via") == []


def test_echoing_a_full_route_set_into_a_dialog_forming_2xx(subscribe):
    """RFC 3261 §12.1.1, written the way a script now can.

    The framework does this by itself on a dialog-forming 2xx; a script that
    wants to reshape the route set does it explicitly, and needs both values to
    do so without dropping a hop.
    """
    for record_route in subscribe.get_headers("Record-Route"):
        subscribe.add_reply_header("Record-Route", record_route)
    subscribe.reply(200, "OK")

    echoed = [value for name, value in subscribe.reply_headers if name == "Record-Route"]
    assert echoed == [CORE_RR, ACCESS_RR], "order carries the hop sequence"
