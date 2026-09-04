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
            number_policy="pstn-national@2026", rate=0.0042, currency="USD",
            billing_increment=60, headers={"X-Account": "42"},
            cdr_fields={"carrier_zone": "us-east"}, reroute_causes=[404, 503],
            timeout_secs=12,
        )
        data = route.to_dict()
        assert data["tech_prefix"] == "1010288"
        assert data["number_policy"] == "pstn-national@2026"
        assert data["headers"] == {"X-Account": "42"}
        assert data["cdr_fields"] == {"carrier_zone": "us-east"}
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

    def test_route_attempts_default_empty(self):
        # Read on every Call a script sees, LCR or not, so it must never be None.
        assert Call().route_attempts == []

    def test_route_attempts_records_the_carriers_that_were_burned(self):
        # The counterpart to active_route: a call that ANSWERED after failing
        # over still names the carrier it burned, which is the record that did
        # not exist before.
        call = Call(
            active_route=Route(carrier_id="carrier-b"),
            route_attempts=[
                {
                    "carrier_id": "carrier-a",
                    "status": 503,
                    "elapsed_ms": 1204,
                    "dialed": True,
                },
            ],
        )
        assert call.active_route.carrier_id == "carrier-b"
        assert [a["carrier_id"] for a in call.route_attempts] == ["carrier-a"]
        assert call.route_attempts[0]["status"] == 503
        assert call.route_attempts[0]["elapsed_ms"] == 1204
        assert call.route_attempts[0]["dialed"] is True

    def test_an_undialled_carrier_is_recorded_but_marked_not_dialled(self):
        # siphon never reached this carrier (group down, or the destination
        # would not resolve), so the status is siphon's verdict on the route and
        # not something the carrier answered. A script counting carrier faults
        # filters on `dialed` — otherwise a local DNS problem is trended against
        # the carrier and taken to them.
        call = Call(
            active_route=Route(carrier_id="carrier-b"),
            route_attempts=[
                {
                    "carrier_id": "carrier-a",
                    "status": 503,
                    "elapsed_ms": 0,
                    "dialed": False,
                },
            ],
        )
        assert call.route_attempts[0]["dialed"] is False
        blameable = [a for a in call.route_attempts if a["dialed"]]
        assert blameable == []


class TestOnRouteFailure:
    """`@b2bua.on_route_failure` — one carrier of a sequence failed."""

    def setup_method(self):
        mock_module.install()
        mock_module.reset()

    def test_decorator_registers_under_the_engine_event_name(self):
        # The name has to match what the Rust side maps to
        # HandlerKind::B2buaRouteFailure, or a script that tests green here
        # registers a handler the engine never calls.
        from siphon import b2bua

        @b2bua.on_route_failure
        def carrier_failed(call, route, code):
            pass

        registered = mock_module._registry.get("b2bua.on_route_failure")
        assert [fn for fn, _ in registered] == [carrier_failed]

    def test_async_handler_is_recorded_as_async(self):
        from siphon import b2bua

        @b2bua.on_route_failure
        async def carrier_failed(call, route, code):
            pass

        registered = mock_module._registry.get("b2bua.on_route_failure")
        assert [is_async for _, is_async in registered] == [True]


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
