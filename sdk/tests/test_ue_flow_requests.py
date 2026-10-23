"""A UE's MESSAGE and SUBSCRIBE over its own SA: ``flow=`` and ``route=`` on
``proxy.send_request`` and ``proxy.subscribe_state.send``."""

import asyncio

import pytest

from siphon_sdk import mock_module
from siphon_sdk.types import Flow

ROUTE = ["<sip:pcscf.example.invalid:5066;lr>", "<sip:orig@scscf.example.invalid;lr>"]
FLOW = Flow(transport="udp", local_addr="192.0.2.10:6100")


def test_send_request_records_flow_and_route():
    proxy = mock_module.get_proxy()
    asyncio.run(proxy.send_request("MESSAGE", "sip:+15550100@example.invalid",
                                   flow=FLOW, route=ROUTE))
    record = proxy.sent_requests[-1]
    assert record["flow"] is FLOW
    assert record["route"] == ROUTE


def test_send_request_refuses_ambiguous_routing():
    proxy = mock_module.get_proxy()
    with pytest.raises(ValueError):
        asyncio.run(proxy.send_request("MESSAGE", "sip:a@example.invalid",
                                       flow=FLOW, next_hop="sip:192.0.2.60"))
    with pytest.raises(ValueError):
        asyncio.run(proxy.send_request("MESSAGE", "sip:a@example.invalid",
                                       headers={"Route": "<sip:192.0.2.60;lr>"},
                                       route=ROUTE))


def test_subscribe_send_records_flow_and_route():
    state = mock_module.get_proxy().subscribe_state
    asyncio.run(state.send("sip:001010000000001@example.invalid", event="reg",
                           expires=600000, flow=FLOW, route=ROUTE))
    assert state.sends[-1]["flow"] is FLOW
    assert state.sends[-1]["route"] == ROUTE
    with pytest.raises(ValueError):
        state.send("sip:001010000000001@example.invalid", event="reg", expires=600,
                   target_uri="sip:192.0.2.60", route=ROUTE)
