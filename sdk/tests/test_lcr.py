"""
Tests for LCR: the wire-contract models, ``Call.route`` / ``Call.active_route``,
and the mock ``lcr`` namespace.
"""

import asyncio

import pytest

from siphon_sdk import mock_module
from siphon_sdk.call import Call
from siphon_sdk.lcr import LcrRequest, LcrReject, LcrResponse, LcrSource, Route


class TestContract:
    def test_route_round_trip_with_per_carrier_fields(self):
        route = Route(
            carrier_id="carrier-a", gateway_group="pool-a", tech_prefix="1010288",
            rate=0.0042, currency="USD", billing_increment=60,
            headers={"X-Account": "42"}, reroute_causes=[404, 503], timeout_secs=12,
        )
        data = route.to_dict()
        assert data["tech_prefix"] == "1010288"
        assert data["headers"] == {"X-Account": "42"}
        assert data["reroute_causes"] == [404, 503]
        assert Route.from_dict(data) == route

    def test_minimal_route_omits_empty_fields(self):
        data = Route(carrier_id="c", next_hop="sip:h").to_dict()
        assert "tech_prefix" not in data
        assert "headers" not in data
        assert "reroute_causes" not in data

    def test_request_from_to_aliasing(self):
        request = LcrRequest(
            call_id="c", from_uri="sip:a@h", to_uri="sip:b@h",
            dialed_number="+12025550123", source=LcrSource(ip="203.0.113.5"),
        )
        data = request.to_dict()
        assert data["from"] == "sip:a@h" and data["to"] == "sip:b@h"
        assert LcrRequest.from_dict(data) == request

    def test_response_and_reject_round_trip(self):
        ok = LcrResponse(routes=[Route(carrier_id="a", gateway_group="g")], cache_ttl_secs=300)
        assert LcrResponse.from_dict(ok.to_dict()) == ok
        rejected = LcrResponse(reject=LcrReject(code=503, reason="No Route"))
        assert LcrResponse.from_dict(rejected.to_dict()).reject == LcrReject(503, "No Route")


class TestCallRoute:
    def test_route_records_carriers_in_order(self):
        call = Call(ruri="sip:+12025550123@sbc.example")
        call.route([
            Route(carrier_id="a", gateway_group="pool-a"),
            Route(carrier_id="b", next_hop="sip:203.0.113.21:5060"),
        ])
        assert len(call._actions) == 1
        action = call._actions[0]
        assert action.kind == "route"
        assert action.targets == ["a", "b"]
        assert len(action.extras["routes"]) == 2

    def test_active_route_default_none(self):
        assert Call().active_route is None

    def test_active_route_settable_for_on_answer(self):
        call = Call(active_route=Route(carrier_id="carrier-a", rate=0.0042))
        assert call.active_route.carrier_id == "carrier-a"
        assert call.active_route.rate == 0.0042

    def test_route_validates_send_socket(self):
        with pytest.raises(ValueError):
            Call().route([Route(carrier_id="a", next_hop="sip:h")], send_socket="bad")


class TestMockLcrNamespace:
    def setup_method(self):
        mock_module.install()
        mock_module.reset()

    def teardown_method(self):
        mock_module.reset()

    def test_route_returns_configured_routes_and_records_query(self):
        from siphon import lcr
        namespace = mock_module.get_lcr()
        namespace.set_routes([Route(carrier_id="carrier-a", gateway_group="pool-a", rate=0.0042)])
        call = Call(ruri="sip:+12025550123@sbc.example")

        decision = asyncio.run(lcr.route(call, trunk_group="cust-trunks"))

        assert decision is not None
        assert decision.reject is None
        assert [r.carrier_id for r in decision.routes] == ["carrier-a"]
        assert namespace.queries[-1]["trunk_group"] == "cust-trunks"
        assert namespace.queries[-1]["dialed_number"] == "+12025550123"

    def test_route_reject(self):
        from siphon import lcr
        mock_module.get_lcr().set_reject(503, "No Route")
        decision = asyncio.run(lcr.route(Call()))
        assert decision.reject == {"code": 503, "reason": "No Route"}
        assert decision.routes == []

    def test_route_unavailable_returns_none(self):
        from siphon import lcr
        mock_module.get_lcr().set_unavailable()
        assert asyncio.run(lcr.route(Call())) is None

    def test_end_to_end_on_invite_handler(self):
        from siphon import lcr
        mock_module.get_lcr().set_routes([
            Route(carrier_id="carrier-a", gateway_group="pool-a", rate=0.0042),
            Route(carrier_id="carrier-b", gateway_group="pool-b", rate=0.0051),
        ])
        call = Call(ruri="sip:+12025550123@sbc.example")

        async def on_invite(call):
            decision = await lcr.route(call, trunk_group="cust-trunks")
            if decision is None:
                call.reject(503, "Route Unavailable")
                return
            if decision.reject:
                call.reject(decision.reject["code"], decision.reject["reason"])
                return
            call.route(decision.routes)

        asyncio.run(on_invite(call))

        assert call._actions[-1].kind == "route"
        assert call._actions[-1].targets == ["carrier-a", "carrier-b"]
